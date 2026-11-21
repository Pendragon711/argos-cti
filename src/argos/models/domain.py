"""Validated domain models for ARGOS investigations."""

from datetime import UTC, datetime
from enum import Enum
from hashlib import sha256
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


def utc_now() -> datetime:
    return datetime.now(UTC)


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex[:12]}"


class ArtifactType(str, Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    URI = "uri"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    EMAIL = "email"
    ASN = "asn"
    FILE = "file"
    UNKNOWN = "unknown"


class EpistemicStatus(str, Enum):
    OBSERVED = "observed"
    REPORTED = "reported"
    INFERRED = "inferred"
    UNVERIFIED = "unverified"


class RelationType(str, Enum):
    RESOLVES_TO = "resolves_to"
    HOSTED_ON = "hosted_on"
    PART_OF = "part_of"
    CONTAINS = "contains"
    ASSOCIATED_WITH = "associated_with"


class InvestigationStatus(str, Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    ARCHIVED = "archived"


class Artifact(BaseModel):
    id: str = Field(default_factory=lambda: new_id("art"))
    investigation_id: str
    artifact_type: ArtifactType
    value: str
    original_value: str
    source: str
    first_seen: datetime = Field(default_factory=utc_now)
    last_seen: datetime = Field(default_factory=utc_now)
    metadata: dict[str, Any] = Field(default_factory=dict)


class Evidence(BaseModel):
    id: str = Field(default_factory=lambda: new_id("evd"))
    investigation_id: str
    artifact_id: str | None = None
    source: str
    collection_method: str
    epistemic_status: EpistemicStatus = EpistemicStatus.OBSERVED
    content: str
    content_hash: str = ""
    observed_at: datetime = Field(default_factory=utc_now)
    collected_at: datetime = Field(default_factory=utc_now)
    metadata: dict[str, Any] = Field(default_factory=dict)

    def model_post_init(self, __context: Any, /) -> None:
        if not self.content_hash:
            self.content_hash = sha256(self.content.encode("utf-8")).hexdigest()


class Relation(BaseModel):
    id: str = Field(default_factory=lambda: new_id("rel"))
    investigation_id: str
    source_artifact_id: str
    target_artifact_id: str
    relation_type: RelationType
    epistemic_status: EpistemicStatus = EpistemicStatus.INFERRED
    source: str
    evidence_id: str | None = None
    context: str = ""
    created_at: datetime = Field(default_factory=utc_now)


class Investigation(BaseModel):
    id: str = Field(default_factory=lambda: new_id("inv"))
    title: str
    objective: str = ""
    scope: str = ""
    status: InvestigationStatus = InvestigationStatus.OPEN
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    notes: list[str] = Field(default_factory=list)
    conclusion: str = ""
    limitations: list[str] = Field(default_factory=list)
