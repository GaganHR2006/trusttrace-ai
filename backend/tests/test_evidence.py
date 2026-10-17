import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from fastapi import HTTPException
from starlette.requests import Request

from backend.app.evidence import EvidenceBundle
from backend.app.legal_rag import current_corpus_version, index_passages, search_legal_sources, verify_legal_reference
from backend.app.main import MAX_ANALYSIS_REQUEST_BYTES, analyze_evidence, analyze_evidence_bundle


def policy_bundle(text="", *, state="not_provided", domains=None, legal_query=None, legal_references=None):
    excerpts = []
    source_url = "https://example.com/privacy" if state in {"fetch_failed", "empty_extraction"} else None
    if state == "reviewed":
        source_url = "https://example.com/privacy"
        excerpts = [{"source_url": source_url, "start": 0, "end": len(text), "text": text}] if text else []
    return {
        "observation": {
            "page_origin": "https://example.com", "total_requests": sum(item["count"] for item in (domains or [])),
            "domains": domains or [],
        },
        "policy": {"state": state, "source_url": source_url, "text": text if state == "reviewed" else None, "excerpts": excerpts},
        "legal_query": legal_query,
        "legal_references": legal_references or [],
    }


class EvidenceSchemaTests(unittest.TestCase):
    def test_exact_offsets_and_complete_excerpt_coverage_are_required(self):
        value = policy_bundle("😀 We retain data for 30 days.", state="reviewed")
        self.assertEqual(EvidenceBundle.model_validate(value).policy.excerpts[0].text, value["policy"]["text"])
        bad_quote = json.loads(json.dumps(value))
        bad_quote["policy"]["excerpts"][0]["text"] = "fabricated"
        with self.assertRaises(ValueError):
            EvidenceBundle.model_validate(bad_quote)
        gap = json.loads(json.dumps(value))
        gap["policy"]["excerpts"] = [{"source_url": "https://example.com/privacy", "start": 1, "end": len(value["policy"]["text"]), "text": value["policy"]["text"][1:]}]
        with self.assertRaises(ValueError):
            EvidenceBundle.model_validate(gap)

    def test_collection_bounds_and_unknown_fields_are_rejected(self):
        value = policy_bundle()
        value["observation"]["domains"] = [{"host": f"h{i}.example", "party": "third-party", "count": 1} for i in range(501)]
        value["observation"]["total_requests"] = 501
        with self.assertRaises(ValueError):
            EvidenceBundle.model_validate(value)
        value = policy_bundle()
        value["surprise"] = "ignored data must not be accepted"
        with self.assertRaises(ValueError):
            EvidenceBundle.model_validate(value)

    def test_invalid_source_scheme_is_rejected(self):
        value = policy_bundle("Privacy statement.", state="reviewed")
        value["policy"]["source_url"] = "javascript:alert(1)"
        value["policy"]["excerpts"][0]["source_url"] = "javascript:alert(1)"
        with self.assertRaises(ValueError):
            EvidenceBundle.model_validate(value)

    def test_host_values_must_be_hostnames_or_ip_literals_without_ports(self):
        for host in ("tracker.example.com:443", "https://tracker.example.com", "not a host"):
            value = policy_bundle(domains=[{"host": host, "party": "third-party", "count": 1}])
            value["observation"]["total_requests"] = 1
            with self.subTest(host=host), self.assertRaises(ValueError):
                EvidenceBundle.model_validate(value)


class CorrelationAndRiskTests(unittest.TestCase):
    def test_missing_fetch_failed_empty_and_reviewed_without_match_are_distinct(self):
        cases = [
            (policy_bundle(state="not_provided"), "No policy was supplied"),
            (policy_bundle(state="fetch_failed"), "fetching failed"),
            (policy_bundle(state="empty_extraction"), "extraction was empty"),
            (policy_bundle("An unrelated statement.", state="reviewed"), "No category-related statement"),
        ]
        for value, expected in cases:
            with self.subTest(expected=expected):
                result = analyze_evidence_bundle(EvidenceBundle.model_validate(value))
                self.assertTrue(all(f["review_priority"] == "unassessed" for f in result["findings"]))
                self.assertTrue(all(expected.lower() in f["rationale"].lower() for f in result["findings"]))

    def test_irrelevant_third_party_request_does_not_create_sharing_or_tracking_finding(self):
        value = policy_bundle(
            "We retain records for 30 days.", state="reviewed",
            domains=[{"host": "cdn.other.example", "party": "third-party", "count": 20}],
        )
        findings = analyze_evidence_bundle(EvidenceBundle.model_validate(value))["findings"]
        by_category = {finding["category"]: finding for finding in findings}
        self.assertEqual(by_category["third_party_disclosure"]["status"], "insufficient_evidence")
        self.assertEqual(by_category["tracking_related_activity"]["status"], "insufficient_evidence")
        self.assertEqual(by_category["data_retention"]["review_priority"], "low")

    def test_restrictive_policy_and_third_party_host_are_ambiguous_not_conflicting(self):
        value = policy_bundle(
            "We do not share personal data with third parties.", state="reviewed",
            domains=[{"host": "assets.other.example", "party": "third-party", "count": 4}],
        )
        findings = analyze_evidence_bundle(EvidenceBundle.model_validate(value))["findings"]
        third_party = next(f for f in findings if f["category"] == "third_party_disclosure")
        self.assertEqual(third_party["status"], "ambiguous")
        self.assertEqual(third_party["review_priority"], "medium")
        self.assertIn("not a demonstrated contradiction", third_party["rationale"])

    def test_policy_categories_use_policy_text_not_unrelated_host_count(self):
        text = "We retain personal data for 30 days. Users may request deletion. Children under 18 need a guardian."
        value = policy_bundle(text, state="reviewed", domains=[{"host": "many.other.example", "party": "third-party", "count": 999}])
        findings = analyze_evidence_bundle(EvidenceBundle.model_validate(value))["findings"]
        for category in ("data_retention", "deletion_rights", "childrens_data"):
            finding = next(f for f in findings if f["category"] == category)
            self.assertEqual(finding["review_priority"], "low")
            self.assertEqual(finding["inputs_relied_on"], ["exact policy excerpt"])
            self.assertEqual(finding["policy_excerpts"][0]["text"], text)
            self.assertEqual(text[finding["policy_excerpts"][0]["start"]:finding["policy_excerpts"][0]["end"]], finding["policy_excerpts"][0]["text"])

    def test_identical_inputs_produce_identical_versioned_outputs_without_high_priority(self):
        value = EvidenceBundle.model_validate(policy_bundle("We use cookies for analytics.", state="reviewed"))
        first = analyze_evidence_bundle(value)
        second = analyze_evidence_bundle(value)
        self.assertEqual(first, second)
        self.assertEqual(first["rule_set_version"], "trusttrace-phase4-review-v1")
        self.assertTrue(all(f["rule_set_version"] == first["rule_set_version"] for f in first["findings"]))
        self.assertNotIn("high", [f["review_priority"] for f in first["findings"]])
        self.assertTrue(all(f["rule_ids"] and f["inputs_relied_on"] for f in first["findings"]))

    def test_corpus_unavailable_is_explicit_and_does_not_become_negative_legal_evidence(self):
        value = EvidenceBundle.model_validate(policy_bundle(state="not_provided"))
        with patch("backend.app.main.current_corpus_version", side_effect=FileNotFoundError):
            result = analyze_evidence_bundle(value)
        self.assertEqual(result["corpus_status"], "unavailable")
        self.assertIsNone(result["corpus_version"])
        self.assertTrue(any("unavailable" in message for message in result["limitations"]))


class AnalysisEndpointLimitTests(unittest.IsolatedAsyncioTestCase):
    async def _request(self, body):
        payload = body if isinstance(body, bytes) else json.dumps(body).encode()
        sent = False

        async def receive():
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": payload, "more_body": False}
            return {"type": "http.disconnect"}

        return Request({"type": "http", "method": "POST", "path": "/analysis/evidence", "headers": [(b"content-type", b"application/json")]}, receive)

    async def test_oversized_streaming_request_is_rejected(self):
        payload = b" " * (MAX_ANALYSIS_REQUEST_BYTES + 1)
        sent = False

        async def receive():
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": payload, "more_body": False}
            return {"type": "http.disconnect"}

        request = Request({"type": "http", "method": "POST", "path": "/analysis/evidence", "headers": [(b"content-type", b"application/json")]}, receive)
        with self.assertRaises(HTTPException) as caught:
            await analyze_evidence(request)
        self.assertEqual(caught.exception.status_code, 413)

    async def test_malformed_json_and_invalid_evidence_are_rejected_by_endpoint(self):
        for payload in (b"{", json.dumps({"observation": {}, "policy": {}}).encode()):
            with self.subTest(payload=payload), self.assertRaises(HTTPException) as caught:
                await analyze_evidence(await self._request(payload))
            self.assertEqual(caught.exception.status_code, 422)

    async def test_fabricated_citation_is_rejected_by_analysis_endpoint(self):
        with TemporaryDirectory(dir=Path(__file__).resolve().parents[2]) as temp:
            db = Path(temp) / "index.sqlite3"
            passage = {
                "passage_id": "source::section_1", "source_id": "source", "title": "Example Act",
                "source_url": "https://official.example/act.pdf", "issuer": "Official issuer",
                "instrument_number": "Act 1", "published_date": "2025-01-01", "version": "official text",
                "sha256": "c" * 64, "effective_date": "as notified", "provision_id": "section_1",
                "heading": "Section 1", "text": "Personal data deletion and retention.",
            }
            index_passages([passage], db)
            citation = search_legal_sources("data deletion retention", path=db)["results"][0]["citation"]
            citation["quote"] = "fabricated quote"
            payload = policy_bundle(state="not_provided", legal_query="data deletion retention", legal_references=[citation])
            with patch("backend.app.main.current_corpus_version", return_value=current_corpus_version(db)), \
                 patch("backend.app.correlation.search_legal_sources", side_effect=lambda query, limit=5: search_legal_sources(query, limit, db)), \
                 patch("backend.app.correlation.verify_legal_reference", side_effect=lambda reference: verify_legal_reference(reference, db)):
                with self.assertRaises(HTTPException) as caught:
                    await analyze_evidence(await self._request(payload))
            self.assertEqual(caught.exception.status_code, 422)


class LegalReferenceAnalysisTests(unittest.TestCase):
    def test_verified_citation_is_accepted_and_fabricated_or_stale_citations_rejected(self):
        with TemporaryDirectory(dir=Path(__file__).resolve().parents[2]) as temp:
            db = Path(temp) / "index.sqlite3"
            passage = {
                "passage_id": "source::section_1", "source_id": "source", "title": "Example Act",
                "source_url": "https://official.example/act.pdf", "issuer": "Official issuer",
                "instrument_number": "Act 1", "published_date": "2025-01-01", "version": "official text",
                "sha256": "c" * 64, "effective_date": "as notified", "provision_id": "section_1",
                "heading": "Section 1", "text": "Personal data deletion and retention.",
            }
            index_passages([passage], db)
            citation = search_legal_sources("data deletion retention", path=db)["results"][0]["citation"]
            bundle = EvidenceBundle.model_validate(policy_bundle(state="not_provided", legal_query="data deletion retention", legal_references=[citation]))
            result = analyze_evidence_bundle(bundle, index_path=db)
            self.assertEqual(result["corpus_status"], "available")
            self.assertEqual(result["legal_evidence_status"], "sufficient_evidence")
            self.assertEqual(result["verified_legal_references"][0], citation)
            self.assertIn(passage["passage_id"], next(f for f in result["findings"] if f["category"] == "deletion_rights")["legal_reference_ids"])

            for key, changed in (("quote", "fabricated"), ("source_url", "https://evil.example/"), ("sha256", "d" * 64), ("corpus_version", "0" * 64)):
                forged = {**citation, key: changed}
                candidate = EvidenceBundle.model_validate(policy_bundle(state="not_provided", legal_query="data deletion retention", legal_references=[forged]))
                with self.subTest(key=key), self.assertRaises(ValueError):
                    analyze_evidence_bundle(candidate, index_path=db)

            unsupported = EvidenceBundle.model_validate(policy_bundle(
                state="not_provided", legal_query="unsupported quantum question", legal_references=[citation],
            ))
            with self.assertRaisesRegex(ValueError, "insufficient retrieval"):
                analyze_evidence_bundle(unsupported, index_path=db)
            no_match = EvidenceBundle.model_validate(policy_bundle(state="not_provided", legal_query="unsupported quantum question"))
            self.assertEqual(analyze_evidence_bundle(no_match, index_path=db)["legal_evidence_status"], "insufficient_evidence")


if __name__ == "__main__":
    unittest.main()
