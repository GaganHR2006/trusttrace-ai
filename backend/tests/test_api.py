import unittest
from unittest.mock import AsyncMock, patch

from fastapi import HTTPException

from backend.app.main import LegalSearchRequest, PolicyExtractRequest, app, extract_policy, health_check, legal_search, legal_sources


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


if __name__ == "__main__":
    unittest.main()
