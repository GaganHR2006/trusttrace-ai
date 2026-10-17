"""Bounded, strict request/response models for Phase 4 evidence analysis."""

from __future__ import annotations

import ipaddress
import re
from enum import StrEnum
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=False)


class PolicyState(StrEnum):
    NOT_PROVIDED = "not_provided"
    FETCH_FAILED = "fetch_failed"
    EMPTY = "empty_extraction"
    REVIEWED = "reviewed"


class Party(StrEnum):
    FIRST = "first-party"
    THIRD = "third-party"


class Category(StrEnum):
    THIRD_PARTY_DISCLOSURE = "third_party_disclosure"
    TRACKING = "tracking_related_activity"
    RETENTION = "data_retention"
    DELETION = "deletion_rights"
    CHILDREN = "childrens_data"


class FindingStatus(StrEnum):
    AVAILABLE = "available"
    CONFLICTING = "conflicting"
    AMBIGUOUS = "ambiguous"
    INSUFFICIENT = "insufficient_evidence"


class ReviewPriority(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    UNASSESSED = "unassessed"


class ObservedDomain(StrictModel):
    host: str = Field(min_length=1, max_length=253, description="Observed hostname or IP literal only; no URL, path, or port.")
    party: Party
    count: int = Field(ge=1, le=1_000_000)

    @field_validator("host")
    @classmethod
    def validate_host(cls, value: str) -> str:
        candidate = value[1:-1] if value.startswith("[") and value.endswith("]") else value
        try:
            ipaddress.ip_address(candidate)
            return value
        except ValueError:
            pass
        labels = candidate.rstrip(".").split(".")
        if ":" in candidate or not labels or any(
            not re.fullmatch(r"(?i)(?!-)[a-z0-9-]{1,63}(?<!-)", label) for label in labels
        ):
            raise ValueError("host must be a hostname or IP literal without a port")
        return value


class Observation(StrictModel):
    page_origin: str = Field(min_length=1, max_length=2048)
    total_requests: int = Field(ge=0, le=1_000_000)
    domains: list[ObservedDomain] = Field(max_length=500)

    @model_validator(mode="after")
    def check_page_origin_and_counts(self) -> "Observation":
        parsed = urlsplit(self.page_origin)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password or parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            raise ValueError("page_origin must be an HTTP/HTTPS origin without path, query, or fragment")
        parsed.port  # force validation of malformed port syntax
        if len({item.host.lower().rstrip(".") for item in self.domains}) != len(self.domains):
            raise ValueError("observed domains must be unique")
        if sum(item.count for item in self.domains) > self.total_requests:
            raise ValueError("domain request counts cannot exceed total_requests")
        return self


class PolicyExcerptInput(StrictModel):
    source_url: str = Field(min_length=1, max_length=2048)
    start: int = Field(ge=0, le=200_000)
    end: int = Field(ge=1, le=200_000)
    text: str = Field(min_length=1, max_length=12_000)


class PolicyEvidence(StrictModel):
    state: PolicyState
    source_url: str | None = Field(default=None, max_length=2048)
    text: str | None = Field(default=None, max_length=200_000)
    excerpts: list[PolicyExcerptInput] = Field(default_factory=list, max_length=40)

    @model_validator(mode="after")
    def check_state_and_offsets(self) -> "PolicyEvidence":
        if self.state == PolicyState.REVIEWED:
            if not self.source_url or not self.text:
                raise ValueError("reviewed policy requires non-empty source_url and text")
        elif self.text not in (None, "") or self.excerpts:
            raise ValueError("policy text and excerpts are allowed only for reviewed evidence")
        if self.state == PolicyState.NOT_PROVIDED and self.source_url is not None:
            raise ValueError("not_provided policy state cannot contain a source_url")
        if self.state in {PolicyState.FETCH_FAILED, PolicyState.EMPTY} and not self.source_url:
            raise ValueError("fetch_failed and empty_extraction states require the attempted source_url")
        if self.source_url:
            parsed_source = urlsplit(self.source_url)
            if parsed_source.scheme not in {"http", "https"} or not parsed_source.hostname or parsed_source.username or parsed_source.password:
                raise ValueError("policy source_url must be an HTTP/HTTPS URL without credentials")
            parsed_source.port
        if self.state == PolicyState.EMPTY and self.text not in (None, ""):
            raise ValueError("empty_extraction cannot contain policy text")
        for excerpt in self.excerpts:
            if excerpt.source_url != self.source_url:
                raise ValueError("excerpt source_url must match the policy source_url")
            if excerpt.end <= excerpt.start or excerpt.end > len(self.text or ""):
                raise ValueError("excerpt offsets are outside the returned policy text")
            if (self.text or "")[excerpt.start:excerpt.end] != excerpt.text:
                raise ValueError("excerpt text must exactly equal the referenced policy text slice")
        if self.state == PolicyState.REVIEWED:
            ordered = sorted(self.excerpts, key=lambda item: item.start)
            cursor = 0
            for excerpt in ordered:
                if excerpt.start != cursor:
                    raise ValueError("reviewed policy excerpts must cover the exact returned text without gaps or overlaps")
                cursor = excerpt.end
            if cursor != len(self.text or ""):
                raise ValueError("reviewed policy excerpts must cover the exact returned text")
        return self


class LegalReference(StrictModel):
    passage_id: str = Field(min_length=1, max_length=300)
    corpus_version: str = Field(pattern=r"^[a-f0-9]{64}$")
    source_id: str = Field(min_length=1, max_length=200)
    title: str = Field(min_length=1, max_length=500)
    source_url: str = Field(min_length=1, max_length=2048)
    issuer: str = Field(min_length=1, max_length=500)
    instrument_number: str | None = Field(max_length=200)
    published_date: str = Field(min_length=1, max_length=40)
    version: str = Field(min_length=1, max_length=500)
    effective_date: str = Field(min_length=1, max_length=500)
    provision_id: str = Field(min_length=1, max_length=100)
    heading: str = Field(min_length=1, max_length=500)
    start: int = Field(ge=0, le=200_000)
    end: int = Field(ge=1, le=200_000)
    quote: str = Field(min_length=1, max_length=100_000)
    offset_unit: str = Field(min_length=1, max_length=100)
    sha256: str = Field(pattern=r"^[a-fA-F0-9]{64}$")


class EvidenceBundle(StrictModel):
    observation: Observation
    policy: PolicyEvidence
    legal_query: str | None = Field(default=None, min_length=3, max_length=500)
    legal_references: list[LegalReference] = Field(default_factory=list, max_length=10)

    @model_validator(mode="after")
    def require_query_for_references(self) -> "EvidenceBundle":
        if self.legal_references and not self.legal_query:
            raise ValueError("legal_query is required when legal references are supplied")
        return self


class Finding(StrictModel):
    category: Category
    status: FindingStatus
    review_priority: ReviewPriority
    rule_set_version: str
    rule_ids: list[str]
    inputs_relied_on: list[str]
    policy_excerpt_refs: list[int]
    policy_excerpts: list[PolicyExcerptInput]
    legal_reference_ids: list[str]
    rationale: str


class AnalysisResponse(StrictModel):
    rule_set_version: str
    corpus_status: str
    corpus_version: str | None
    legal_evidence_status: str
    verified_legal_references: list[LegalReference]
    findings: list[Finding]
    limitations: list[str]
