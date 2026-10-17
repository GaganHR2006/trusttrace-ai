"""Versioned deterministic review-priority rules, independent of LLMs."""

from __future__ import annotations

from .evidence import FindingStatus, ReviewPriority
from .correlation import RULE_SET_VERSION


def assign_review_priorities(findings: list[dict[str, object]]) -> list[dict[str, object]]:
    """Add auditable triage priorities; no current rule asserts a legal violation."""
    prioritized = []
    for finding in findings:
        item = dict(finding)
        status = item["status"]
        rule_ids = list(item["rule_ids"])
        if status == FindingStatus.INSUFFICIENT:
            priority = ReviewPriority.UNASSESSED
            rule_ids.append("P4-RISK-INSUFFICIENT-UNASSESSED")
        elif "P4-TP-OBSERVED-HOST-WITH-RESTRICTIVE-CLAIM" in rule_ids:
            # This is a review signal only. Metadata does not prove a policy
            # contradiction, payload contents, tracking, or personal-data transfer.
            priority = ReviewPriority.MEDIUM
            rule_ids.append("P4-RISK-MEDIUM-MANUAL-REVIEW")
        elif status == FindingStatus.AVAILABLE and "P4-POLICY-CATEGORY-STATEMENT" in rule_ids:
            priority = ReviewPriority.LOW
            rule_ids.append("P4-RISK-LOW-POLICY-STATEMENT-ONLY")
        else:
            priority = ReviewPriority.UNASSESSED
            rule_ids.append("P4-RISK-NO-DEFENSIBLE-RULE")
        item["review_priority"] = priority
        item["rule_set_version"] = RULE_SET_VERSION
        item["rule_ids"] = rule_ids
        prioritized.append(item)
    return prioritized
