"""Strict extraction schema, type/edge policy, and entity resolution."""
from __future__ import annotations
import hashlib
import re
from typing import Literal
from pydantic import BaseModel, Field
from rapidfuzz.fuzz import ratio

EntityType = Literal["ThreatGroup", "Campaign", "Malware", "Technique", "Vulnerability", "Mitigation", "Target"]
Predicate = Literal["USES", "IMPLEMENTS", "EXPLOITS", "TARGETS", "MITIGATED_BY", "ATTRIBUTED_TO"]
TYPES = ("ThreatGroup", "Campaign", "Malware", "Technique", "Vulnerability", "Mitigation", "Target")
ALLOWED = {
    "USES": {("ThreatGroup", "Malware"), ("ThreatGroup", "Technique"), ("Campaign", "Malware"), ("Campaign", "Technique")},
    "IMPLEMENTS": {("Malware", "Technique")},
    "EXPLOITS": {("Campaign", "Vulnerability"), ("Malware", "Vulnerability"), ("ThreatGroup", "Vulnerability")},
    "TARGETS": {("ThreatGroup", "Target"), ("Campaign", "Target")},
    "MITIGATED_BY": {("Technique", "Mitigation"), ("Vulnerability", "Mitigation")},
    "ATTRIBUTED_TO": {("Campaign", "ThreatGroup")},
}
ATTACK_ID = re.compile(r"^(?:[GSCTM]\d{4}(?:\.\d{3})?)$", re.I)
CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)


class Entity(BaseModel):
    id: str = ""   # local id valid only within one extraction response
    name: str = Field(min_length=2)
    entity_type: EntityType
    aliases: list[str] = Field(default_factory=list)
    attack_id: str = ""
    cve_id: str = ""
    description: str = ""
    confidence_score: float = Field(default=0.75, ge=0, le=1)


class Relation(BaseModel):
    source_id: str
    target_id: str
    predicate: Predicate
    evidence_text: str = Field(min_length=8)
    confidence_score: float = Field(default=0.75, ge=0, le=1)


class ExtractionBatch(BaseModel):
    entities: list[Entity] = Field(default_factory=list)
    relations: list[Relation] = Field(default_factory=list)


def clean_name(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", s.casefold()).strip()


def canonical_id(e: Entity) -> str:
    if e.entity_type == "Vulnerability" and (e.cve_id or CVE_ID.fullmatch(e.name.strip())):
        v = (e.cve_id or e.name).strip().upper()
        if CVE_ID.fullmatch(v):
            return "CVE:" + v
    if e.attack_id and ATTACK_ID.fullmatch(e.attack_id.strip()):
        return "ATTACK:" + e.attack_id.strip().upper()
    key = e.entity_type + ":" + clean_name(e.name)
    return e.entity_type + ":" + hashlib.sha1(key.encode()).hexdigest()[:16]


def evidence_in_chunk(evidence: str, chunk: str) -> bool:
    # Normalize punctuation/space but do not accept completely unsupported edges.
    normalized = clean_name(evidence)
    return bool(normalized) and normalized in clean_name(chunk)


def validate_batch(batch: ExtractionBatch, chunk: str) -> tuple[list[Entity], list[Relation], list[dict]]:
    entities = [e for e in batch.entities if e.confidence_score >= 0.50]
    by_id = {e.id: e for e in entities if e.id}
    accepted, review = [], []
    for r in batch.relations:
        src, tgt = by_id.get(r.source_id), by_id.get(r.target_id)
        reason = None
        if src is None or tgt is None:
            reason = "missing_endpoint"
        elif (src.entity_type, tgt.entity_type) not in ALLOWED[r.predicate]:
            reason = "disallowed_type_pair"
        elif not evidence_in_chunk(r.evidence_text, chunk):
            reason = "evidence_not_in_source_chunk"
        elif r.confidence_score < .70 or src.confidence_score < .70 or tgt.confidence_score < .70:
            reason = "human_review_confidence"
        if reason:
            review.append({"relation": r.model_dump(), "reason": reason})
        else:
            accepted.append(r)
    return entities, accepted, review


class Resolver:
    """Official IDs > exact aliases > fuzzy. Uncertain matches are reviewed, never auto-merged."""
    def __init__(self, verifier=None):
        self.verifier = verifier
        self.entities: dict[str, Entity] = {}
        self.names: dict[tuple[str, str], str] = {}
        self.review: list[dict] = []

    def resolve(self, entity: Entity) -> str:
        official = bool(entity.attack_id or entity.cve_id or CVE_ID.fullmatch(entity.name.strip()))
        ident = canonical_id(entity)
        if ident in self.entities:
            return ident
        keys = [clean_name(entity.name)] + [clean_name(a) for a in entity.aliases]
        candidates = set()
        if not official:
            for key in keys:
                if (entity.entity_type, key) in self.names:
                    candidates.add(self.names[(entity.entity_type, key)])
            if len(candidates) == 1:
                return next(iter(candidates))
            if len(candidates) > 1:
                self.review.append({"name": entity.name, "reason": "conflicting_aliases", "candidates": sorted(candidates)})
            else:
                best = (0, None)
                for (typ, candidate), cid in self.names.items():
                    if typ == entity.entity_type:
                        s = ratio(clean_name(entity.name), candidate)
                        if s > best[0]:
                            best = s, cid
                if best[1] is not None and best[0] >= 92:
                    return best[1]
                if best[1] is not None and best[0] >= 80:
                    if self.verifier is not None and self.verifier(entity, self.entities[best[1]]):
                        for key in keys:
                            self.names[(entity.entity_type, key)] = best[1]
                        return best[1]
                    self.review.append({"name": entity.name, "reason": "fuzzy_requires_verification", "score": best[0], "candidate": best[1]})
        self.entities[ident] = entity
        for key in keys:
            self.names.setdefault((entity.entity_type, key), ident)
        return ident
