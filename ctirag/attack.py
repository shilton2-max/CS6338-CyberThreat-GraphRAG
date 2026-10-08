"""Import a bounded, verifiable MITRE Enterprise ATT&CK STIX 2.1 subgraph."""
from __future__ import annotations
import json
from pathlib import Path
import requests
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .graph import Graph

ATTACK_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
TYPE_MAP = {"intrusion-set": "ThreatGroup", "campaign": "Campaign", "malware": "Malware",
            "tool": "Malware", "attack-pattern": "Technique", "course-of-action": "Mitigation"}


def stix_attack_id(obj: dict) -> str:
    for entry in obj.get("external_references", []):
        if entry.get("source_name") == "mitre-attack":
            return entry.get("external_id", "")
    return ""


def relation_predicate(source: dict, target: dict, kind: str) -> tuple[str, bool] | None:
    src, dst = source.get("type"), target.get("type")
    if kind == "uses":
        if src in {"intrusion-set", "campaign"} and dst in {"malware", "tool", "attack-pattern"}:
            return "USES", False
        if src in {"malware", "tool"} and dst == "attack-pattern":
            return "IMPLEMENTS", False
    if kind == "mitigates" and src == "course-of-action" and dst == "attack-pattern":
        return "MITIGATED_BY", True
    if kind == "attributed-to" and src == "campaign" and dst == "intrusion-set":
        return "ATTRIBUTED_TO", False
    return None


def build_stix_subgraph(bundle: dict, focus_ids: set[str], limit: int = 300) -> tuple[list[dict], list[dict]]:
    objects = {o["id"]: o for o in bundle.get("objects", [])
               if not o.get("revoked") and not o.get("x_mitre_deprecated") and "id" in o}
    entities = {sid: o for sid, o in objects.items()
                if o.get("type") in TYPE_MAP and stix_attack_id(o)}
    relationships = []
    for o in objects.values():
        if o.get("type") != "relationship":
            continue
        src, dst = entities.get(o.get("source_ref")), entities.get(o.get("target_ref"))
        if src is None or dst is None:
            continue
        pred = relation_predicate(src, dst, o.get("relationship_type", ""))
        if pred:
            relationships.append((o, src, dst, pred[0], pred[1]))
    # Seed by official group/technique/software ID. One hop plus technique mitigations.
    chosen = [r for r in relationships
              if stix_attack_id(r[1]) in focus_ids or stix_attack_id(r[2]) in focus_ids]
    first_ids = {stix_attack_id(obj) for r in chosen for obj in (r[1], r[2])}
    chosen += [r for r in relationships
               if r[3] == "MITIGATED_BY" and (stix_attack_id(r[1]) in first_ids or stix_attack_id(r[2]) in first_ids)]
    dedup, selected = set(), []
    for record in chosen:
        if record[0]["id"] not in dedup:
            selected.append(record)
            dedup.add(record[0]["id"])
        if len(selected) >= limit:
            break
    e_by_id, edges = {}, []
    for rel, src, dst, predicate, reverse in selected:
        left, right = (dst, src) if reverse else (src, dst)
        for obj in (left, right):
            aid = stix_attack_id(obj)
            e_by_id[aid] = {"id": "ATTACK:" + aid, "name": obj.get("name", aid),
                            "entity_type": TYPE_MAP[obj["type"]], "aliases": obj.get("aliases", []),
                            "attack_id": aid, "description": obj.get("description", "")[:1000]}
        excerpt = rel.get("description", "").strip()
        if not excerpt:
            excerpt = f"MITRE ATT&CK STIX relationship {rel['id']} links {left.get('name')} and {right.get('name')}."
        edges.append({"source_id": "ATTACK:" + stix_attack_id(left),
                      "target_id": "ATTACK:" + stix_attack_id(right),
                      "predicate": predicate, "source_doc_id": "MITRE-STIX:" + rel["id"],
                      "source_url": "https://attack.mitre.org/", "source_kind": "MITRE_STIX_VERIFIED",
                      "chunk_id": rel["id"], "evidence_text": excerpt[:1000], "confidence_score": 1.0})
    return list(e_by_id.values()), edges


def import_attack(graph: "Graph", cache: Path, focus_ids: set[str], limit: int = 300):
    cache.parent.mkdir(parents=True, exist_ok=True)
    if not cache.exists():
        response = requests.get(ATTACK_URL, timeout=240,
                                headers={"User-Agent": "CS6338-GraphRAG-Research/1.0"})
        response.raise_for_status()
        cache.write_bytes(response.content)
    bundle = json.loads(cache.read_text(encoding="utf-8"))
    entities, relations = build_stix_subgraph(bundle, focus_ids, limit)
    for e in entities:
        graph.upsert_structured_entity(e)
    for r in relations:
        graph.upsert_relation(r)
    return {"entities": len(entities), "verified_relations": len(relations),
            "focus_attack_ids": sorted(focus_ids), "source": ATTACK_URL}
