"""Manual text-file fallback when public CISA pages rate-limit or block scraping."""
import csv
import json
from pathlib import Path
from urllib.parse import urlparse


def import_manifest(manifest: Path, output: Path) -> dict:
    output.mkdir(parents=True, exist_ok=True)
    count = 0
    with manifest.open(newline="", encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            doc_id, url = row["doc_id"].strip(), row["source_url"].strip()
            if not (doc_id and url.startswith("https://www.cisa.gov/")):
                raise ValueError("Every record needs a document ID and official CISA source URL")
            path = manifest.parent / row["text_file"]
            text = path.read_text(encoding="utf-8")
            if not text.strip():
                raise ValueError(f"Empty text file: {path}")
            doc = {"doc_id": doc_id, "title": row["title"].strip(),
                   "publication_date": row.get("publication_date", ""),
                   "source_url": url, "source": "Manual CISA transcription", "text": text}
            (output / (doc_id + ".json")).write_text(json.dumps(doc, indent=2), encoding="utf-8")
            count += 1
    return {"imported_cisa_advisories": count, "from_manifest": str(manifest)}
