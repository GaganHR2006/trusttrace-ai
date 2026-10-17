"""Download the pinned official PDF sources and build the local legal index.

Run explicitly from the repository root. No fetching happens when FastAPI starts.
"""

from __future__ import annotations

import hashlib
import io
import json
import sys
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

from pypdf import PdfReader

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
SOURCE_DIR = BACKEND / "data" / "source_pdfs"
sys.path.insert(0, str(ROOT))
from backend.app.legal_rag import index_passages, list_legal_sources, split_provisions  # noqa: E402

MAX_PDF_BYTES = 12_000_000
ALLOWED_HOSTS = {"www.meity.gov.in", "egazette.gov.in"}


class SameHostHttpsRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        before = urlsplit(req.full_url)
        after = urlsplit(newurl)
        if after.scheme != "https" or (after.hostname or "").lower() != (before.hostname or "").lower():
            raise RuntimeError("Official-source redirect changed scheme or host; refusing download.")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download_pdf(source: dict) -> bytes:
    url = source["source_url"]
    parts = urlsplit(url)
    if parts.scheme != "https" or parts.hostname not in ALLOWED_HOSTS or parts.username or parts.password:
        raise ValueError(f"Source URL is outside the pinned official host allowlist: {url}")
    request = urllib.request.Request(url, headers={"User-Agent": "TRUSTTRACE-AI-Legal-Corpus/0.3"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), SameHostHttpsRedirect())
    with opener.open(request, timeout=20) as response:
        if response.status != 200 or response.headers.get_content_type() != "application/pdf":
            raise RuntimeError(f"Expected an official PDF for {source['source_id']}.")
        content = response.read(MAX_PDF_BYTES + 1)
    if len(content) > MAX_PDF_BYTES or not content.startswith(b"%PDF-"):
        raise RuntimeError(f"The PDF for {source['source_id']} is invalid or exceeds 12 MB.")
    return content


def extract_source(source: dict, pdf_bytes: bytes) -> list[dict]:
    reader = PdfReader(io.BytesIO(pdf_bytes), strict=False)
    pages = [page.extract_text() or "" for page in reader.pages]
    source_text = "\n".join(page for page in pages if page.strip())
    provisions = split_provisions(source_text, source["kind"])
    if not provisions:
        raise RuntimeError(f"No text provisions extracted from {source['source_id']}.")
    digest = hashlib.sha256(pdf_bytes).hexdigest()
    return [
        {
            "passage_id": f"{source['source_id']}::{item['provision_id']}",
            "source_id": source["source_id"],
            "title": source["title"],
            "source_url": source["source_url"],
            "issuer": source["issuer"],
            "instrument_number": source["instrument_number"],
            "published_date": source["published_date"],
            "version": source["version"],
            "sha256": digest,
            "effective_date": source["effective_date"],
            "provision_id": item["provision_id"],
            "heading": item["heading"],
            "text": item["text"],
        }
        for item in provisions
    ]


def main() -> None:
    SOURCE_DIR.mkdir(parents=True, exist_ok=True)
    sources = list_legal_sources()
    passages = []
    for source in sources:
        print(f"Obtaining {source['instrument_number']} — {source['title']}")
        pdf_bytes = download_pdf(source)
        target = SOURCE_DIR / source["filename"]
        target.write_bytes(pdf_bytes)
        rows = extract_source(source, pdf_bytes)
        passages.extend(rows)
        print(f"  SHA-256 {hashlib.sha256(pdf_bytes).hexdigest()} | {len(rows)} provision passage(s)")
    count = index_passages(passages)
    print(f"Indexed {count} passage(s) locally at backend/data/legal_index.sqlite3.")
    print("Check the official source URLs and version metadata before relying on any retrieved passage.")


if __name__ == "__main__":
    main()
