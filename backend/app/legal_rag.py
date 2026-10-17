"""Local, source-grounded retrieval for official Indian DPDP instruments.

The index uses deterministic TF-IDF vectors persisted in SQLite. It is a local
retriever only: it does not interpret law, decide compliance, or call an LLM.
"""

from __future__ import annotations

import json
import hashlib
import math
import re
import sqlite3
from collections import Counter
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parents[1]
REGISTRY_PATH = ROOT / "data" / "legal_sources.json"
INDEX_PATH = ROOT / "data" / "legal_index.sqlite3"
TOKEN_RE = re.compile(r"[a-z0-9]+", re.IGNORECASE)
MIN_SCORE = 0.12


class LegalSearchRequest(BaseModel):
    query: str = Field(min_length=3, max_length=500)
    limit: int = Field(default=5, ge=1, le=10)


def list_legal_sources() -> list[dict[str, Any]]:
    return json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))


def tokenize(text: str) -> list[str]:
    return [term.lower() for term in TOKEN_RE.findall(text) if len(term) > 1]


def vectorize(text: str, idf: dict[str, float]) -> dict[str, float]:
    counts = Counter(tokenize(text))
    raw = {term: (1 + math.log(count)) * idf.get(term, 1.0) for term, count in counts.items()}
    norm = math.sqrt(sum(value * value for value in raw.values()))
    return {term: value / norm for term, value in raw.items()} if norm else {}


def split_provisions(text: str, document_kind: str) -> list[dict[str, str]]:
    """Split numbered statutory provisions while retaining source wording."""
    normalized = "\n".join(line.rstrip() for line in text.replace("\r\n", "\n").split("\n"))
    if document_kind == "act":
        pattern = re.compile(r"(?m)^\s*(\d{1,2})\.\s+(?=[A-Z(])")
    elif document_kind == "rules":
        # Rule 17 in the Gazette PDF is set as "17.Appointment" with no
        # whitespace after the number; permit that typographic form.
        pattern = re.compile(r"(?m)^\s*(\d{1,2})\.\s*(?=[A-Z])")
    else:
        return [{"provision_id": "instrument", "heading": "Instrument text", "text": normalized.strip()}] if normalized.strip() else []

    # Schedules contain their own numbered paragraphs and tables. They are not
    # top-level sections/rules; including them creates duplicate or false
    # statutory locators (for example, Schedule row "1." as rule_1).
    schedule = re.search(
        r"(?im)^[ \t]*(?:THE[ \t]+SCHEDULE|(?:FIRST|SECOND|THIRD|FOURTH|FIFTH|SIXTH|SEVENTH)[ \t]+SCHEDULE)[ \t]*\r?\n[ \t]*\[See (?:section|rule)",
        normalized,
    )
    provision_text = normalized[:schedule.start()] if schedule else normalized

    starts = list(pattern.finditer(provision_text))
    provisions: list[dict[str, str]] = []
    schedule_fragments: list[str] = []
    seen_numbers: set[str] = set()
    for index, match in enumerate(starts):
        end = starts[index + 1].start() if index + 1 < len(starts) else len(provision_text)
        body = provision_text[match.start():end].strip()
        if not body:
            continue
        number = match.group(1)
        if number in seen_numbers:
            # Some PDF text layers place a schedule table before its printed
            # heading. Keep it in a schedule passage instead of issuing a
            # duplicate section/rule citation.
            schedule_fragments.append(body)
            continue
        seen_numbers.add(number)
        heading = _heading_for(body, number, document_kind)
        provisions.append({"provision_id": f"{'section' if document_kind == 'act' else 'rule'}_{number}", "heading": heading, "text": body})
    if schedule:
        schedule_fragments.append(normalized[schedule.start():].strip())
    schedule_text = "\n\n".join(fragment for fragment in schedule_fragments if fragment)
    if schedule_text:
        provisions.append({"provision_id": "schedule", "heading": "Schedule text", "text": schedule_text})
    return provisions


def _heading_for(body: str, number: str, kind: str) -> str:
    first_line = body.splitlines()[0].strip()
    if kind == "rules":
        heading = re.sub(rf"^0*{number}\.\s*", "", first_line).strip(" .—–-")
        heading = re.split(r"[.—–]", heading, maxsplit=1)[0].strip()
        return heading[:180] or f"Rule {number}"
    # In the official Act Gazette layout, section headings are printed beside
    # their body. Preserve the exact provision and expose a stable locator even
    # when PDF text extraction cannot safely associate that side-column label.
    return f"Section {number}"


def _connect(path: Path = INDEX_PATH) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.execute("""CREATE TABLE IF NOT EXISTS passages (
        passage_id TEXT PRIMARY KEY,
        source_id TEXT NOT NULL,
        title TEXT NOT NULL,
        source_url TEXT NOT NULL,
        issuer TEXT NOT NULL,
        instrument_number TEXT,
        published_date TEXT NOT NULL,
        version TEXT NOT NULL,
        sha256 TEXT NOT NULL,
        effective_date TEXT NOT NULL,
        provision_id TEXT NOT NULL,
        heading TEXT NOT NULL,
        text TEXT NOT NULL,
        token_counts TEXT NOT NULL
    )""")
    connection.execute("CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
    connection.commit()
    return connection


def index_passages(passages: list[dict[str, Any]], path: Path = INDEX_PATH) -> int:
    """Replace the local index atomically with supplied verified passages."""
    if not passages:
        raise ValueError("Refusing to create an empty legal corpus.")
    tokenized = [Counter(tokenize(str(item["text"]))) for item in passages]
    document_frequency: Counter[str] = Counter()
    for counts in tokenized:
        document_frequency.update(counts.keys())
    total = len(passages)
    idf = {term: math.log(1 + (total + 1) / (frequency + 1)) + 1 for term, frequency in document_frequency.items()}
    vectors = [vectorize(str(item["text"]), idf) for item in passages]
    connection = _connect(path)
    try:
        with connection:
            connection.execute("DELETE FROM passages")
            for item, counts, vector in zip(passages, tokenized, vectors, strict=True):
                connection.execute(
                    "INSERT INTO passages VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        item["passage_id"], item["source_id"], item["title"], item["source_url"],
                        item["issuer"], item.get("instrument_number"), item["published_date"],
                        item["version"], item["sha256"], item["effective_date"], item["provision_id"], item["heading"],
                        item["text"], json.dumps({"counts": counts, "vector": vector}, ensure_ascii=False),
                    ),
                )
            connection.execute("INSERT OR REPLACE INTO metadata(key,value) VALUES ('idf', ?)", (json.dumps(idf),))
    finally:
        connection.close()
    return len(passages)


def search_legal_sources(query: str, limit: int = 5, path: Path = INDEX_PATH) -> dict[str, Any]:
    terms = tokenize(query)
    if not terms:
        return {"status": "insufficient_evidence", "query": query, "results": [], "message": "No matching source passage was found in the indexed corpus."}
    if not path.is_file():
        raise FileNotFoundError(path)
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    try:
        try:
            idf = json.loads(connection.execute("SELECT value FROM metadata WHERE key='idf'").fetchone()[0])
        except (sqlite3.OperationalError, TypeError):
            raise FileNotFoundError(path) from None
        query_vector = vectorize(query, idf)
        rows = connection.execute("SELECT * FROM passages").fetchall()
    finally:
        connection.close()
    corpus_version = _corpus_version(rows)
    ranked: list[tuple[float, sqlite3.Row]] = []
    for row in rows:
        stored = json.loads(row["token_counts"])["vector"]
        score = sum(weight * stored.get(term, 0.0) for term, weight in query_vector.items())
        if score >= MIN_SCORE:
            ranked.append((score, row))
    ranked.sort(key=lambda pair: (-pair[0], pair[1]["source_id"], pair[1]["provision_id"]))
    results = []
    for score, row in ranked[:limit]:
        text = row["text"]
        results.append({
            "score": round(score, 6),
            "passage": text,
            "citation": {
                "passage_id": row["passage_id"], "corpus_version": corpus_version,
                "source_id": row["source_id"], "title": row["title"], "source_url": row["source_url"],
                "issuer": row["issuer"], "instrument_number": row["instrument_number"],
                "published_date": row["published_date"], "version": row["version"],
                "effective_date": row["effective_date"], "provision_id": row["provision_id"],
                "heading": row["heading"], "start": 0, "end": len(text), "quote": text,
                "offset_unit": "Python Unicode code points; end is exclusive",
                "sha256": row["sha256"],
            },
        })
    status = "sufficient_evidence" if results else "insufficient_evidence"
    return {
        "status": status,
        "query": query,
        "results": results,
        "message": "Retrieved source passages are evidence for research only; no legal conclusion is generated." if results else "No matching source passage was found in the indexed corpus.",
    }


def _corpus_version(rows: list[sqlite3.Row]) -> str:
    """Fingerprint the indexed source records so references stale on rebuild."""
    digest = hashlib.sha256()
    for row in sorted(rows, key=lambda item: item["passage_id"]):
        record = [row[key] for key in (
            "passage_id", "source_id", "title", "source_url", "issuer", "instrument_number",
            "published_date", "version", "sha256", "effective_date", "provision_id", "heading", "text",
        )]
        digest.update(json.dumps(record, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()


def current_corpus_version(path: Path = INDEX_PATH) -> str:
    """Return the deterministic version of the current local passage corpus."""
    if not path.is_file():
        raise FileNotFoundError(path)
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    try:
        rows = connection.execute("SELECT * FROM passages").fetchall()
    except sqlite3.OperationalError:
        raise FileNotFoundError(path) from None
    finally:
        connection.close()
    if not rows:
        raise FileNotFoundError(path)
    return _corpus_version(rows)


def verify_legal_reference(reference: dict[str, Any], path: Path = INDEX_PATH) -> dict[str, Any] | None:
    """Resolve and verify a client citation against the current indexed row."""
    if not path.is_file():
        raise FileNotFoundError(path)
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    try:
        rows = connection.execute("SELECT * FROM passages").fetchall()
    except sqlite3.OperationalError:
        raise FileNotFoundError(path) from None
    finally:
        connection.close()
    if not rows:
        raise FileNotFoundError(path)
    version = _corpus_version(rows)
    passage_id = reference.get("passage_id")
    row = next((item for item in rows if item["passage_id"] == passage_id), None)
    if row is None:
        return None
    text = row["text"]
    expected = {
        "passage_id": row["passage_id"], "corpus_version": version,
        "source_id": row["source_id"], "title": row["title"], "source_url": row["source_url"],
        "issuer": row["issuer"], "instrument_number": row["instrument_number"],
        "published_date": row["published_date"], "version": row["version"],
        "effective_date": row["effective_date"], "provision_id": row["provision_id"],
        "heading": row["heading"], "start": 0, "end": len(text), "quote": text,
        "offset_unit": "Python Unicode code points; end is exclusive", "sha256": row["sha256"],
    }
    return expected if reference == expected else None
