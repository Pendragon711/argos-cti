"""Deterministic normalization and type classification for threat intelligence indicators."""

import ipaddress
import re
from dataclasses import dataclass, field
from hashlib import sha256
from urllib.parse import urlparse

from argos.models import ArtifactType

MAX_INDICATOR_LENGTH = 4096

_MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
_SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
_ASN_RE = re.compile(r"^(?:AS)?(\d{1,10})$", re.IGNORECASE)
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_URI_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]{1,31}$")
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


@dataclass(frozen=True)
class NormalizedIndicator:
    artifact_type: ArtifactType
    value: str
    original_value: str
    content_hash: str = ""
    parse_error: str | None = None
    warnings: tuple[str, ...] = field(default_factory=tuple)


def _defang_strip(raw: str) -> tuple[str, list[str]]:
    warnings: list[str] = []
    cleaned = raw.strip()
    defanged = re.sub(r"hxxp(s?)://", r"http\1://", cleaned, flags=re.IGNORECASE)
    if defanged != cleaned:
        warnings.append("defanged_http_scheme")
        cleaned = defanged

    dot_cleaned = re.sub(r"\[\.\]|\(\.\)|\{\.\}", ".", cleaned)
    if dot_cleaned != cleaned:
        warnings.append("defanged_dots")
        cleaned = dot_cleaned

    colon_cleaned = re.sub(r"\[:\]|\(:\)|\{:\}", ":", cleaned)
    if colon_cleaned != cleaned:
        warnings.append("defanged_colons")
        cleaned = colon_cleaned

    at_cleaned = re.sub(r"\[@\]|\(@\)|\{@\}", "@", cleaned)
    if at_cleaned != cleaned:
        warnings.append("defanged_at_sign")
        cleaned = at_cleaned

    return cleaned.strip(), warnings


def normalize_indicator(raw_value: str) -> NormalizedIndicator:
    original_value = raw_value
    digest = sha256(original_value.encode("utf-8", errors="replace")).hexdigest()

    if len(original_value) > MAX_INDICATOR_LENGTH:
        return NormalizedIndicator(
            artifact_type=ArtifactType.UNKNOWN,
            value="",
            original_value=original_value,
            content_hash=digest,
            parse_error=f"indicator_exceeds_max_length:{MAX_INDICATOR_LENGTH}",
        )

    if _CONTROL_CHARS_RE.search(original_value):
        sanitized = _CONTROL_CHARS_RE.sub("", original_value).strip()
        warnings = ["stripped_control_characters"]
    else:
        sanitized = original_value
        warnings = []

    candidate, defang_warnings = _defang_strip(sanitized)
    warnings.extend(defang_warnings)

    if not candidate:
        return NormalizedIndicator(
            artifact_type=ArtifactType.UNKNOWN,
            value="",
            original_value=original_value,
            content_hash=digest,
            parse_error="empty_or_whitespace_indicator",
            warnings=tuple(warnings),
        )

    if "://" in candidate:
        parsed = urlparse(candidate)
        scheme = parsed.scheme.lower()
        if scheme in {"http", "https"} and parsed.netloc:
            host = parsed.netloc.lower()
            path = parsed.path or "/"
            query = f"?{parsed.query}" if parsed.query else ""
            normalized_url = f"{scheme}://{host}{path}{query}"
            return NormalizedIndicator(
                artifact_type=ArtifactType.URL,
                value=normalized_url,
                original_value=original_value,
                content_hash=digest,
                warnings=tuple(warnings),
            )
        if _URI_SCHEME_RE.match(scheme) and (parsed.netloc or parsed.path):
            return NormalizedIndicator(
                artifact_type=ArtifactType.URI,
                value=candidate,
                original_value=original_value,
                content_hash=digest,
                warnings=tuple(warnings),
            )

    try:
        ip_obj = ipaddress.ip_address(candidate)
        art_type = ArtifactType.IPV4 if ip_obj.version == 4 else ArtifactType.IPV6
        return NormalizedIndicator(
            artifact_type=art_type,
            value=str(ip_obj),
            original_value=original_value,
            content_hash=digest,
            warnings=tuple(warnings),
        )
    except ValueError:
        pass

    if _MD5_RE.match(candidate):
        return NormalizedIndicator(
            artifact_type=ArtifactType.HASH_MD5,
            value=candidate.lower(),
            original_value=original_value,
            content_hash=digest,
            warnings=tuple(warnings),
        )

    if _SHA1_RE.match(candidate):
        return NormalizedIndicator(
            artifact_type=ArtifactType.HASH_SHA1,
            value=candidate.lower(),
            original_value=original_value,
            content_hash=digest,
            warnings=tuple(warnings),
        )

    if _SHA256_RE.match(candidate):
        return NormalizedIndicator(
            artifact_type=ArtifactType.HASH_SHA256,
            value=candidate.lower(),
            original_value=original_value,
            content_hash=digest,
            warnings=tuple(warnings),
        )

    if _EMAIL_RE.match(candidate):
        local, domain = candidate.rsplit("@", 1)
        return NormalizedIndicator(
            artifact_type=ArtifactType.EMAIL,
            value=f"{local}@{domain.lower()}",
            original_value=original_value,
            content_hash=digest,
            warnings=tuple(warnings),
        )

    asn_match = _ASN_RE.match(candidate)
    if asn_match:
        return NormalizedIndicator(
            artifact_type=ArtifactType.ASN,
            value=f"AS{asn_match.group(1)}",
            original_value=original_value,
            content_hash=digest,
            warnings=tuple(warnings),
        )

    domain_candidate = candidate.lower().rstrip(".")
    if _DOMAIN_RE.match(domain_candidate):
        return NormalizedIndicator(
            artifact_type=ArtifactType.DOMAIN,
            value=domain_candidate,
            original_value=original_value,
            content_hash=digest,
            warnings=tuple(warnings),
        )

    if ":" in candidate and not candidate.startswith("["):
        scheme_prefix = candidate.split(":", 1)[0].lower()
        if _URI_SCHEME_RE.match(scheme_prefix) and len(candidate) > len(scheme_prefix) + 1:
            return NormalizedIndicator(
                artifact_type=ArtifactType.URI,
                value=candidate,
                original_value=original_value,
                content_hash=digest,
                warnings=tuple(warnings),
            )

    return NormalizedIndicator(
        artifact_type=ArtifactType.UNKNOWN,
        value=candidate,
        original_value=original_value,
        content_hash=digest,
        warnings=tuple(warnings),
    )
