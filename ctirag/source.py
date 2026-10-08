"""Acquire real CISA Cybersecurity Advisories, with explicit provenance and no invented text."""
from __future__ import annotations
import hashlib
import json
import re
import time
from pathlib import Path
from urllib.parse import urljoin, urlparse
import requests
from bs4 import BeautifulSoup

LIST_URL = "https://www.cisa.gov/news-events/cybersecurity-advisories?f%5B0%5D=advisory_type%3A94&items_per_page=100"
ADVISORY_PATH = "/news-events/cybersecurity-advisories/"
USER_AGENT = "CS6338-research-advisory-collector/1.0 (educational; polite caching)"


def clean_html(html: str, url: str) -> dict:
    soup = BeautifulSoup(html, "html.parser")
    title = (soup.select_one("h1") or soup.select_one("title"))
    title = title.get_text(" ", strip=True) if title else "Untitled advisory"
    container = (soup.select_one("article .field--name-body")
                 or soup.select_one("article") or soup.select_one("main"))
    if container is None:
        raise ValueError("No article/main content found")
    for x in container.select("script,style,nav,footer,form,aside"):
        x.decompose()
    text = re.sub(r"\n{3,}", "\n\n", container.get_text("\n", strip=True))
    if len(text) < 350:
        raise ValueError("Advisory body too small; possibly blocked/error page")
    match = re.search(r"\bAA\d{2}-\d{3}[A-Z]\b", url.upper() + " " + text[:1500])
    doc_id = match.group(0) if match else "CISA-" + hashlib.sha1(url.encode()).hexdigest()[:12]
    date = (soup.select_one('meta[property="article:published_time"]') or
            soup.select_one('meta[name="date"]') or soup.select_one('time[datetime]'))
    date_value = date.get("content") or date.get("datetime") if date else ""
    return {"doc_id": doc_id, "title": title, "publication_date": date_value,
            "source_url": url, "text": text, "source": "CISA Cybersecurity Advisory"}


def discover_urls(session: requests.Session, pages: int = 4) -> list[str]:
    urls = set()
    for page in range(pages):
        url = LIST_URL + f"&page={page}"
        response = session.get(url, timeout=30)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")
        for link in soup.select('a[href*="/news-events/cybersecurity-advisories/"]'):
            absolute = urljoin("https://www.cisa.gov", link.get("href", "")).split("?")[0].rstrip("/")
            path = urlparse(absolute).path
            if path.startswith(ADVISORY_PATH) and path != ADVISORY_PATH.rstrip("/") and urlparse(absolute).netloc == "www.cisa.gov":
                urls.add(absolute)
        time.sleep(0.7)
    return sorted(urls)


def download_advisories(output: Path, limit: int = 100, urls_file: Path | None = None) -> dict:
    output.mkdir(parents=True, exist_ok=True)
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})
    if urls_file is not None:
        urls = [s.strip() for s in urls_file.read_text(encoding="utf-8").splitlines()
                if s.strip() and not s.strip().startswith("#")]
    else:
        urls = discover_urls(session)
    success, failed = [], []
    for url in urls[:limit]:
        if not url.startswith("https://www.cisa.gov/news-events/cybersecurity-advisories/"):
            failed.append({"url": url, "error": "disallowed URL; require official CISA advisory"})
            continue
        try:
            response = session.get(url, timeout=30)
            response.raise_for_status()
            doc = clean_html(response.text, url)
            path = output / (doc["doc_id"] + ".json")
            path.write_text(json.dumps(doc, indent=2, ensure_ascii=False), encoding="utf-8")
            success.append(doc["doc_id"])
        except (requests.RequestException, ValueError) as exc:
            failed.append({"url": url, "error": str(exc)})
        time.sleep(0.75)
    report = {"requested": min(limit, len(urls)), "downloaded": len(success), "ids": success, "failures": failed}
    (output / "download_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def load_advisories(folder: Path) -> list[dict]:
    docs = []
    for path in sorted(folder.glob("*.json")):
        if path.name == "download_report.json":
            continue
        doc = json.loads(path.read_text(encoding="utf-8"))
        needed = ("doc_id", "source_url", "title", "text")
        if not all(doc.get(k) for k in needed):
            raise ValueError(f"Missing metadata in {path}")
        docs.append(doc)
    return docs


def chunk_document(doc: dict, length: int = 2500, overlap: int = 300) -> list[dict]:
    if not 0 <= overlap < length:
        raise ValueError("Invalid chunk overlap")
    text = doc["text"]
    out = []
    step = length - overlap
    for start in range(0, len(text), step):
        chunk = text[start:start + length]
        if not chunk.strip():
            continue
        digest = hashlib.sha1((doc["doc_id"] + str(start) + chunk).encode()).hexdigest()[:16]
        out.append({"id": f"chunk:{digest}", "doc_id": doc["doc_id"],
                    "source_url": doc["source_url"], "title": doc["title"], "text": chunk,
                    "start_offset": start})
        if start + length >= len(text):
            break
    return out
