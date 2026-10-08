from __future__ import annotations

import json
from pathlib import Path

import requests

from ctirag.attack import ATTACK_URL, build_stix_subgraph

ROOT = Path(__file__).resolve().parent
STIX_PATH = ROOT / "data" / "enterprise-attack.json"
OUT_PATH = ROOT / "eval" / "gold_triples.json"
TARGET_COUNT = 52

if not STIX_PATH.exists():
    print("MITRE STIX cache not found. Downloading official Enterprise ATT&CK bundle...")
    response = requests.get(
        ATTACK_URL,
        timeout=240,
        headers={"User-Agent": "CS6338-GraphRAG-Research/1.0"},
    )
    response.raise_for_status()
    STIX_PATH.parent.mkdir(parents=True, exist_ok=True)
    STIX_PATH.write_bytes(response.content)

bundle = json.loads(STIX_PATH.read_text(encoding="utf-8"))
_, relations = build_stix_subgraph(bundle, {"G0007"}, limit=TARGET_COUNT)

gold = []
seen = set()

for rel in relations:
    key = (rel["source_id"], rel["predicate"], rel["target_id"])
    if key in seen:
        continue
    seen.add(key)
    gold.append(
        {
            "source_id": rel["source_id"],
            "predicate": rel["predicate"],
            "target_id": rel["target_id"],
            "source_doc_id": rel.get("source_doc_id"),
            "source_url": rel.get("source_url", "https://attack.mitre.org/"),
            "evidence_text": rel.get("evidence_text", ""),
            "source": "Official MITRE ATT&CK Enterprise STIX 2.1 relationship",
            "verification_method": "MITRE_STIX_OFFICIAL",
            "verified_by_human": False,
            "reviewer_notes": (
                "Source-verified against the official MITRE ATT&CK STIX bundle. "
                "Not represented as manually human-annotated."
            ),
        }
    )
    if len(gold) >= TARGET_COUNT:
        break

if len(gold) < 50:
    raise RuntimeError(
        f"Only {len(gold)} unique ATT&CK triples were produced; expected at least 50."
    )

OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
OUT_PATH.write_text(
    json.dumps(gold, indent=2, ensure_ascii=False),
    encoding="utf-8",
)

print(f"Gold triples written: {len(gold)}")
print(f"Output: {OUT_PATH}")
print("Verification: official MITRE ATT&CK STIX source-backed; not marked human-verified.")
