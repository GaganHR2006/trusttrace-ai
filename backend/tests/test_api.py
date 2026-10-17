import unittest
import json
from unittest.mock import AsyncMock, patch

from fastapi import HTTPException

from starlette.requests import Request

from backend.app.main import LegalSearchRequest, PolicyExtractRequest, analyze_evidence, app, extract_policy, health_check, legal_search, legal_sources


class PolicyEndpointTests(unittest.IsolatedAsyncioTestCase):
    async def test_health_endpoint_is_preserved(self):
        self.assertEqual(health_check(), {"status": "ok", "service": "trusttrace-api", "phase": "0"})
        self.assertIn("/health", app.openapi()["paths"])

    async def test_extract_endpoint_returns_literal_source_and_text(self):
        result = {"source_url": "https://example.com/privacy", "text": "Policy text", "excerpts": [], "truncated": False, "redirect_count": 0}
        with patch("backend.app.main.fetch_policy", new=AsyncMock(return_value=result)) as fetch:
            response = await extract_policy(PolicyExtractRequest(url="https://example.com/privacy"))
        self.assertEqual(response, result)
        fetch.assert_awaited_once_with("https://example.com/privacy")
        self.assertIn("/policy/extract", app.openapi()["paths"])

    async def test_extract_endpoint_reports_invalid_and_unsafe_urls(self):
        for url in ("javascript:alert(1)", "http://127.0.0.1/"):
            with self.subTest(url=url), self.assertRaises(HTTPException) as caught:
                await extract_policy(PolicyExtractRequest(url=url))
            self.assertEqual(caught.exception.status_code, 400)

    async def test_excerpt_offset_unit_is_documented_in_openapi_schema(self):
        schema = app.openapi()["components"]["schemas"]["PolicyExcerpt"]["properties"]
        self.assertIn("Unicode code-point", schema["start"]["description"])
        self.assertIn("exclusive", schema["end"]["description"].lower())
        self.assertIn("text[start:end]", schema["text"]["description"])

    async def test_legal_routes_are_registered_and_uninitialized_index_is_explicit(self):
        self.assertIn("/legal/search", app.openapi()["paths"])
        self.assertIn("/legal/sources", app.openapi()["paths"])
        self.assertTrue(legal_sources()["sources"])
        with patch("backend.app.main.search_legal_sources", side_effect=FileNotFoundError):
            with self.assertRaises(HTTPException) as caught:
                legal_search(LegalSearchRequest(query="does the corpus have text?"))
        self.assertEqual(caught.exception.status_code, 503)

    async def test_analysis_route_is_registered_and_returns_insufficient_status_without_policy(self):
        self.assertIn("/analysis/evidence", app.openapi()["paths"])
        payload = {
            "observation": {"page_origin": "https://example.com", "total_requests": 0, "domains": []},
            "policy": {"state": "not_provided", "source_url": None, "text": None, "excerpts": []},
            "legal_references": [],
        }
        sent = False
        async def receive():
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": json.dumps(payload).encode(), "more_body": False}
            return {"type": "http.disconnect"}
        request = Request({"type": "http", "method": "POST", "path": "/analysis/evidence", "headers": [(b"content-type", b"application/json")]}, receive)
        with patch("backend.app.main.current_corpus_version", side_effect=FileNotFoundError):
            response = await analyze_evidence(request)
        self.assertEqual(response["corpus_status"], "unavailable")
        self.assertTrue(all(item["review_priority"] == "unassessed" for item in response["findings"]))

    async def test_analysis_rejects_non_json_content_type(self):
        request = Request({"type": "http", "method": "POST", "path": "/analysis/evidence", "headers": []}, lambda: None)
        with self.assertRaises(HTTPException) as caught:
            await analyze_evidence(request)
        self.assertEqual(caught.exception.status_code, 415)


if __name__ == "__main__":
    unittest.main()
