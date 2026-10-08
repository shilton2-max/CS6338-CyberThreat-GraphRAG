from pathlib import Path
import shutil

root = Path.cwd()
extract_path = root / "ctirag" / "extract.py"

if not extract_path.exists():
    raise SystemExit("Run this from the CS6338_CyberThreat_GraphRAG project root.")

backup = extract_path.with_suffix(extract_path.suffix + ".bak_before_partial_validation")
if not backup.exists():
    shutil.copy2(extract_path, backup)

text = extract_path.read_text(encoding="utf-8")

old_import = "from .schema import ExtractionBatch, Resolver, validate_batch, canonical_id"
new_import = "from .schema import ExtractionBatch, Entity, Relation, Resolver, validate_batch, canonical_id"
if old_import in text:
    text = text.replace(old_import, new_import, 1)
elif new_import not in text:
    raise SystemExit("Could not find the expected schema import in ctirag/extract.py")

old_block = '''                    batch = ExtractionBatch.model_validate(raw)
                    ents, relations, review = validate_batch(batch, chunk["text"])
'''
new_block = '''                    # Validate individual objects so one malformed LLM item does not
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
'''
if old_block in text:
    text = text.replace(old_block, new_block, 1)
elif new_block not in text:
    raise SystemExit("Could not find the expected batch-validation block in ctirag/extract.py")

extract_path.write_text(text, encoding="utf-8")

print("Partial extraction validation fix installed.")
print("Malformed individual entities/relations will now go to review instead of failing the whole chunk.")
print("Backup created beside extract.py.")
print("Next: python -m unittest discover -s tests -v")
