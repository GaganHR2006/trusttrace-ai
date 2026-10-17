"""Conservative, deterministic matching of category language to supplied evidence."""

from __future__ import annotations

import re

from .evidence import Category, EvidenceBundle, FindingStatus, PolicyState
from .legal_rag import search_legal_sources, verify_legal_reference

RULE_SET_VERSION = "trusttrace-phase4-review-v1"

CATEGORY_TERMS: dict[Category, re.Pattern[str]] = {
    Category.THIRD_PARTY_DISCLOSURE: re.compile(r"\b(?:third[- ]part(?:y|ies)|share|sharing|disclos(?:e|ure)|sell|service providers|partners)\b", re.I),
    Category.TRACKING: re.compile(r"\b(?:track(?:ing)?|cookies?|advertis(?:e|ing)|analytics|pixels?)\b", re.I),
    Category.RETENTION: re.compile(r"\b(?:retain|retention|stored|storage|period)\b", re.I),
    Category.DELETION: re.compile(r"\b(?:delet(?:e|ion)|eras(?:e|ure)|remov(?:e|al))\b", re.I),
    Category.CHILDREN: re.compile(r"\b(?:child(?:ren)?|minor(?:s)?|under\s+18)\b", re.I),
}
DENIAL_OF_SHARING = re.compile(
    r"\b(?:do not|does not|will not|never|not)\s+(?:share|sell|disclose|provide)\b.{0,80}\b(?:third[- ]part(?:y|ies)|others|partner|advertis)",
    re.I,
)


def correlate(bundle: EvidenceBundle, verified_legal: list[dict[str, object]]) -> list[dict[str, object]]:
    """Create category findings without converting absence into a contradiction."""
    policy_text = bundle.policy.text or ""
    third_party_domains = [domain for domain in bundle.observation.domains if domain.party == "third-party"]
    findings: list[dict[str, object]] = []
    for category, terms in CATEGORY_TERMS.items():
        refs = [index for index, excerpt in enumerate(bundle.policy.excerpts) if terms.search(excerpt.text)]
        matching_legal = [
            item for item in verified_legal
            if terms.search(str(item["quote"]))
        ]
        base = {
            "category": category,
            "rule_set_version": RULE_SET_VERSION,
            "rule_ids": [],
            "inputs_relied_on": [],
            "policy_excerpt_refs": refs,
            "policy_excerpts": [bundle.policy.excerpts[index].model_dump() for index in refs],
            "legal_reference_ids": [str(item["passage_id"]) for item in matching_legal],
        }
        if bundle.policy.state != PolicyState.REVIEWED:
            state_message = {
                PolicyState.NOT_PROVIDED: "No policy was supplied; this is a missing input, not a risk finding.",
                PolicyState.FETCH_FAILED: "Policy fetching failed; no policy claim can be assessed.",
                PolicyState.EMPTY: "The extraction was empty; no policy claim can be assessed.",
            }[bundle.policy.state]
            findings.append({
                **base, "status": FindingStatus.INSUFFICIENT,
                "inputs_relied_on": [f"policy.state={bundle.policy.state.value}"],
                "rationale": state_message,
            })
            continue
        if not refs:
            findings.append({
                **base, "status": FindingStatus.INSUFFICIENT,
                "rule_ids": ["P4-POLICY-NO-MATCH"], "inputs_relied_on": ["reviewed policy text"],
                "rationale": "No category-related statement was found in the supplied policy excerpts. Absence of a matching statement does not prove concealment, noncompliance, or contradiction.",
            })
            continue

        if category == Category.THIRD_PARTY_DISCLOSURE and third_party_domains and DENIAL_OF_SHARING.search(policy_text):
            findings.append({
                **base, "status": FindingStatus.AMBIGUOUS,
                "rule_ids": ["P4-TP-OBSERVED-HOST-WITH-RESTRICTIVE-CLAIM"],
                "inputs_relied_on": ["third-party host/count metadata", "exact policy excerpt containing restrictive sharing language"],
                "rationale": "A third-party request host co-occurs with restrictive sharing language. Request metadata does not reveal request purpose, payload, or personal-data transfer, so this is a manual-review signal and not a demonstrated contradiction.",
            })
            continue

        findings.append({
            **base, "status": FindingStatus.AVAILABLE,
            "rule_ids": ["P4-POLICY-CATEGORY-STATEMENT"],
            "inputs_relied_on": ["exact policy excerpt"],
            "rationale": "A category-related policy statement is available for review. This finding records the policy claim only; it does not assess adequacy, truth, legal applicability, or compliance.",
        })
    return findings


def validate_references(bundle: EvidenceBundle, *, index_path=None) -> tuple[list[dict[str, object]], str]:
    """Require supplied citations to be actual hits for the submitted local query."""
    if not bundle.legal_query:
        return [], "not_supplied"
    retrieval = search_legal_sources(bundle.legal_query, limit=10, path=index_path) if index_path else search_legal_sources(bundle.legal_query, limit=10)
    if retrieval["status"] != "sufficient_evidence":
        if bundle.legal_references:
            raise ValueError("Legal references cannot be attached to an insufficient retrieval query.")
        return [], "insufficient_evidence"
    retrieved = {item["citation"]["passage_id"]: item["citation"] for item in retrieval["results"]}
    verified = []
    for reference in bundle.legal_references:
        hit = retrieved.get(reference.passage_id)
        if hit is None or hit != reference.model_dump():
            raise ValueError(f"Legal reference {reference.passage_id!r} was not returned for the supplied legal query.")
        expected = verify_legal_reference(reference.model_dump(), path=index_path) if index_path else verify_legal_reference(reference.model_dump())
        if expected is None:
            raise ValueError(f"Legal reference {reference.passage_id!r} is fabricated, stale, or mismatched.")
        verified.append(expected)
    return verified, "sufficient_evidence"
