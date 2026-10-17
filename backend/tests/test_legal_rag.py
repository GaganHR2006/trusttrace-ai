import tempfile
import unittest
from pathlib import Path

from backend.app.legal_rag import index_passages, list_legal_sources, search_legal_sources, split_provisions, verify_legal_reference


class LegalProvisionSplitTests(unittest.TestCase):
    def test_act_provisions_keep_boundaries_and_literal_text(self):
        source = """CHAPTER I\nPRELIMINARY\n1. (1) This Act may be called the Act.\n(2) It comes into force as notified.\nShort title and commencement.\n2. (a) “child” means an individual under eighteen.\nDefinitions."""
        provisions = split_provisions(source, "act")
        self.assertEqual([item["provision_id"] for item in provisions], ["section_1", "section_2"])
        self.assertEqual(provisions[0]["heading"], "Section 1")
        self.assertIn("Short title and commencement.", provisions[0]["text"])
        self.assertIn("“child” means", provisions[1]["text"])
        self.assertNotIn("2. (a)", provisions[0]["text"])

    def test_rule_heading_is_preserved(self):
        source = """1. Short title and commencement.—(1) These rules may be called the Rules.\n2. Definitions.—(1) In these rules, Act means the Act."""
        provisions = split_provisions(source, "rules")
        self.assertEqual([item["heading"] for item in provisions], ["Short title and commencement", "Definitions"])
        self.assertIn("1. Short title", provisions[0]["text"])

    def test_act_schedule_numbering_is_not_misclassified_as_sections(self):
        source = """41. Rule-making power.\n42. Power to amend the Schedule.\nTHE SCHEDULE\n[See section 33 (1)]\n1. Penalty\n2. Another table row"""
        provisions = split_provisions(source, "act")
        self.assertEqual([item["provision_id"] for item in provisions], ["section_41", "section_42", "schedule"])
        self.assertNotIn("Penalty", provisions[1]["text"])
        self.assertIn("Penalty", provisions[2]["text"])

    def test_rules_schedule_numbering_is_not_misclassified_as_rules(self):
        source = """22. Appeals. — An appeal may be filed.\n23. Furnishing information. — The details apply.\nFIRST SCHEDULE\n[See rule 4]\nPART A\n1. The applicant has sufficient capacity."""
        provisions = split_provisions(source, "rules")
        self.assertEqual([item["provision_id"] for item in provisions], ["rule_22", "rule_23", "schedule"])
        self.assertNotIn("applicant", provisions[1]["text"])
        self.assertIn("applicant", provisions[2]["text"])

    def test_rule_number_without_space_after_period_is_recognized(self):
        provisions = split_provisions("16. Transfer. — Text.\n17.Appointment of Chairperson. — Text.", "rules")
        self.assertEqual([item["provision_id"] for item in provisions], ["rule_16", "rule_17"])
        self.assertEqual(provisions[1]["heading"], "Appointment of Chairperson")


class LegalRetrievalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[2])
        self.db = Path(self.temp.name) / "test-index.sqlite3"
        # This short passage is transcribed from section 6 of the official
        # MeitY-hosted Gazette PDF listed in legal_sources.json.
        self.source_text = "The consent given by the Data Principal shall be free, specific, informed, unconditional and unambiguous with a clear affirmative action,"
        self.passages = [{
            "passage_id": "dpdp-act-2023::section_6", "source_id": "dpdp-act-2023",
            "title": "The Digital Personal Data Protection Act, 2023",
            "source_url": "https://www.meity.gov.in/static/uploads/2024/06/2bf1f0e9f04e6fb4f8fef35e82c42aa5.pdf",
            "issuer": "Ministry of Law and Justice, Legislative Department; hosted by MeitY",
            "instrument_number": "Act No. 22 of 2023", "published_date": "2023-08-11",
            "version": "Official Gazette text as enacted", "sha256": "a" * 64,
            "effective_date": "Provision-specific; see G.S.R. 843(E)",
            "provision_id": "section_6", "heading": "Section 6", "text": self.source_text,
        }]
        index_passages(self.passages, self.db)

    def tearDown(self):
        self.temp.cleanup()

    def test_result_has_exact_quote_and_traceable_source_metadata(self):
        result = search_legal_sources("consent clear affirmative action", path=self.db)
        self.assertEqual(result["status"], "sufficient_evidence")
        citation = result["results"][0]["citation"]
        passage = result["results"][0]["passage"]
        self.assertEqual(citation["source_url"], self.passages[0]["source_url"])
        self.assertEqual(citation["provision_id"], "section_6")
        self.assertEqual(passage[citation["start"]:citation["end"]], citation["quote"])
        self.assertEqual(citation["quote"], self.source_text)
        self.assertEqual(citation["passage_id"], self.passages[0]["passage_id"])
        self.assertEqual(len(citation["corpus_version"]), 64)
        self.assertEqual(verify_legal_reference(citation, self.db), citation)

    def test_citation_verification_rejects_fabricated_mismatched_and_stale_references(self):
        citation = search_legal_sources("consent clear affirmative action", path=self.db)["results"][0]["citation"]
        for key, value in (("passage_id", "fabricated"), ("quote", "changed quote"), ("start", 1), ("end", len(self.source_text) - 1), ("source_url", "https://evil.example/"), ("sha256", "b" * 64), ("corpus_version", "0" * 64)):
            altered = {**citation, key: value}
            with self.subTest(key=key):
                self.assertIsNone(verify_legal_reference(altered, self.db))
        changed = [{**self.passages[0], "text": self.source_text + " changed"}]
        index_passages(changed, self.db)
        self.assertIsNone(verify_legal_reference(citation, self.db))

    def test_unsupported_question_returns_explicit_insufficient_evidence(self):
        result = search_legal_sources("quantum banana teleportation", path=self.db)
        self.assertEqual(result["status"], "insufficient_evidence")
        self.assertEqual(result["results"], [])
        self.assertIn("No matching source passage", result["message"])

    def test_empty_index_is_rejected(self):
        with self.assertRaises(ValueError):
            index_passages([], self.db)

    def test_registry_tracks_authoritative_updated_instruments(self):
        sources = {source["source_id"]: source for source in list_legal_sources()}
        self.assertIn("dpdp-rules-2025", sources)
        self.assertIn("dpdp-rules-corrigendum-2025-892e", sources)
        self.assertIn("dpdp-commencement-2025-843e", sources)
        self.assertIn("dpdp-removal-difficulties-2026-5458e", sources)
        self.assertTrue(all(source["source_url"].startswith("https://") for source in sources.values()))


if __name__ == "__main__":
    unittest.main()
