"""CISA -> strict JSON -> evidence audit -> dedup -> graph-ready records."""
from __future__ import annotations
import json
from pathlib import Path
from .llm import json_chat
from .schema import ExtractionBatch, Entity, Relation, Resolver, validate_batch, canonical_id
from .source import chunk_document, load_advisories

EXTRACT_SYSTEM = """You extract cyber threat intelligence from the supplied CISA text ONLY.
Return ONE JSON object with keys 'entities' (list) and 'relations' (list).
Allowed entity_type: ThreatGroup,Campaign,Malware,Technique,Vulnerability,Mitigation,Target.
Allowed predicate: USES,IMPLEMENTS,EXPLOITS,TARGETS,MITIGATED_BY,ATTRIBUTED_TO.
Each entity must have id (local E1),name,entity_type,aliases (list),attack_id, cve_id,
confidence_score (0 to 1),description.
Each relation must have source_id,target_id,predicate,evidence_text,confidence_score.
The evidence_text MUST be a VERBATIM contiguous excerpt from the given text. Never
infer a relation just because it is plausible. Only extract explicitly stated facts.
If nothing qualifies return {"entities":[],"relations":[]}.
Type examples: ThreatGroup USES Malware, Malware IMPLEMENTS Technique,
Campaign EXPLOITS Vulnerability, Technique MITIGATED_BY Mitigation,
Campaign ATTRIBUTED_TO ThreatGroup. Don't add unsupported links.
"""


def extract_corpus(input_dir: Path, output: Path, cache: Path, max_chunks: int = 0) -> dict:
    docs = load_advisories(input_dir)
    cache.mkdir(parents=True, exist_ok=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    def verify_fuzzy(a, b):
        """An uncertain 80-91% name match gets one explicit local-LLM identity check."""
        try:
            response = json_chat(
                "Determine whether two security entities refer to the exact same real-world item. "
                "Return JSON {\"same\": true/false}. When evidence is weak, return false.",
                json.dumps({"a": a.model_dump(), "b": b.model_dump()}))
            return response.get("same") is True
        except Exception:
            return False

    resolver = Resolver(verifier=verify_fuzzy)
    counts = {"documents": len(docs), "chunks": 0, "accepted_relations": 0,
              "review_items": 0, "failures": 0}
    review_path = output.parent / "review_queue.jsonl"
    # Replace outputs on each run; cached extraction text ensures deterministic reuse.
    with output.open("w", encoding="utf-8") as f, review_path.open("w", encoding="utf-8") as rev:
        for doc in docs:
            for chunk in chunk_document(doc):
                if max_chunks and counts["chunks"] >= max_chunks:
                    break
                counts["chunks"] += 1
                cached = cache / (chunk["id"].replace(":", "_") + ".json")
                try:
                    if cached.exists():
                        raw = json.loads(cached.read_text(encoding="utf-8"))
                    else:
                        raw = json_chat(EXTRACT_SYSTEM,
                                        f"DOCUMENT {doc['doc_id']}\nTEXT:\n{chunk['text']}")
                        cached.write_text(json.dumps(raw, indent=2), encoding="utf-8")
                    # Validate individual objects so one malformed LLM item does not
                    # discard an otherwise useful chunk. Invalid objects go to the
                    # review queue instead of failing the whole extraction batch.
                    pre_review = []
                    raw_entities = raw.get("entities", []) if isinstance(raw, dict) else []
                    raw_relations = raw.get("relations", []) if isinstance(raw, dict) else []

                    valid_entities = []
                    for i, item in enumerate(raw_entities):
                        try:
                            valid_entities.append(Entity.model_validate(item))
                        except Exception as item_exc:
                            pre_review.append({
                                "reason": "invalid_entity_schema",
                                "item_index": i,
                                "entity_raw": item,
                                "error": str(item_exc),
                            })

                    valid_relations = []
                    for i, item in enumerate(raw_relations):
                        try:
                            valid_relations.append(Relation.model_validate(item))
                        except Exception as item_exc:
                            pre_review.append({
                                "reason": "invalid_relation_schema",
                                "item_index": i,
                                "relation_raw": item,
                                "error": str(item_exc),
                            })

                    batch = ExtractionBatch(
                        entities=valid_entities,
                        relations=valid_relations,
                    )
                    ents, relations, review = validate_batch(batch, chunk["text"])
                    review = pre_review + review
                except Exception as exc:
                    counts["failures"] += 1
                    rev.write(json.dumps({"chunk_id": chunk["id"], "reason": "extract_failed", "error": str(exc)}) + "\n")
                    continue
                id_map = {e.id: resolver.resolve(e) for e in ents if e.id}
                good_entities = [e for e in ents if e.confidence_score >= .70]
                for e in ents:
                    if .50 <= e.confidence_score < .70:
                        review.append({"entity": e.model_dump(), "reason": "human_review_confidence"})
                output_relations = []
                for r in relations:
                    if r.source_id in id_map and r.target_id in id_map:
                        output_relations.append({**r.model_dump(), "source_id": id_map[r.source_id],
                                                 "target_id": id_map[r.target_id], "source_doc_id": doc["doc_id"],
                                                 "source_url": doc["source_url"], "chunk_id": chunk["id"]})
                counts["accepted_relations"] += len(output_relations)
                counts["review_items"] += len(review)
                for q in review:
                    rev.write(json.dumps({"chunk_id": chunk["id"], **q}) + "\n")
                f.write(json.dumps({"document": {k: v for k, v in doc.items() if k != "text"},
                                    "chunk": chunk,
                                    "entities": [{**e.model_dump(), "id": id_map[e.id]} for e in good_entities if e.id in id_map],
                                    "relations": output_relations}, ensure_ascii=False) + "\n")
            if max_chunks and counts["chunks"] >= max_chunks:
                break
    for q in resolver.review:
        with review_path.open("a", encoding="utf-8") as rev:
            rev.write(json.dumps(q) + "\n")
    counts["review_items"] += len(resolver.review)
    return counts
