"""Generate unverified annotation candidates WITHOUT pretending they are ground truth."""
import json
from pathlib import Path


def make_gold_candidates(extraction_file: Path, output: Path, cap: int = 60):
    if not extraction_file.exists():
        raise FileNotFoundError(extraction_file)
    items = {}
    for line in extraction_file.read_text(encoding="utf-8").splitlines():
        record = json.loads(line)
        for rel in record.get("relations", []):
            key = (rel["source_id"], rel["predicate"], rel["target_id"])
            if key not in items:
                items[key] = {"source_id": rel["source_id"], "predicate": rel["predicate"],
                              "target_id": rel["target_id"], "source_doc_id": rel.get("source_doc_id"),
                              "source_url": rel.get("source_url"), "evidence_text": rel["evidence_text"],
                              "verified_by_human": False, "reviewer_notes": ""}
    candidates = list(items.values())[:cap]
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(candidates, indent=2, ensure_ascii=False), encoding="utf-8")
    return {"unverified_candidates": len(candidates), "output": str(output)}
