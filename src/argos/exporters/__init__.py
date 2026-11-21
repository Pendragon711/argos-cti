"""Interoperable exporters for ARGOS investigations (CSV and STIX 2.1)."""

import csv
import io
import json
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from argos.models import Artifact, ArtifactType, Evidence, Investigation, Relation

_STIX_NS = uuid5(NAMESPACE_URL, "https://argos.local/stix")


def _stix_id(stix_type: str, seed: str) -> str:
    return f"{stix_type}--{uuid5(_STIX_NS, seed)}"


def _stix_pattern_for_artifact(artifact: Artifact) -> str | None:
    val = artifact.value.replace("\\", "\\\\").replace("'", "\'")
    if artifact.artifact_type == ArtifactType.IPV4:
        return f"[ipv4-addr:value = '{val}']"
    if artifact.artifact_type == ArtifactType.IPV6:
        return f"[ipv6-addr:value = '{val}']"
    if artifact.artifact_type == ArtifactType.DOMAIN:
        return f"[domain-name:value = '{val}']"
    if artifact.artifact_type == ArtifactType.URL:
        return f"[url:value = '{val}']"
    if artifact.artifact_type == ArtifactType.EMAIL:
        return f"[email-addr:value = '{val}']"
    if artifact.artifact_type == ArtifactType.HASH_MD5:
        return f"[file:hashes.'MD5' = '{val}']"
    if artifact.artifact_type == ArtifactType.HASH_SHA1:
        return f"[file:hashes.'SHA-1' = '{val}']"
    if artifact.artifact_type == ArtifactType.HASH_SHA256:
        return f"[file:hashes.'SHA-256' = '{val}']"
    return None


def export_artifacts_csv(artifacts: list[Artifact]) -> str:
    """Export normalized investigation artifacts to UTF-8 CSV."""
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["id", "investigation_id", "artifact_type", "value", "original_value", "source", "first_seen", "last_seen"])
    for art in artifacts:
        writer.writerow([
            art.id,
            art.investigation_id,
            art.artifact_type.value,
            art.value,
            art.original_value,
            art.source,
            art.first_seen.isoformat(),
            art.last_seen.isoformat(),
        ])
    return buffer.getvalue()


def export_stix_bundle(
    investigation: Investigation,
    artifacts: list[Artifact],
    evidences: list[Evidence],
    relations: list[Relation],
) -> str:
    """Export investigation artifacts and relations as a STIX 2.1 bundle JSON string."""
    objects: list[dict[str, Any]] = []
    artifact_stix_map: dict[str, str] = {}

    for art in artifacts:
        pattern = _stix_pattern_for_artifact(art)
        if not pattern:
            continue
        ind_id = _stix_id("indicator", f"{investigation.id}:{art.id}")
        artifact_stix_map[art.id] = ind_id
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": ind_id,
            "created": art.first_seen.isoformat(),
            "modified": art.last_seen.isoformat(),
            "name": art.value,
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": art.first_seen.isoformat(),
        })

    for ev in evidences:
        obs_id = _stix_id("observed-data", f"{investigation.id}:{ev.id}")
        objects.append({
            "type": "observed-data",
            "spec_version": "2.1",
            "id": obs_id,
            "created": ev.collected_at.isoformat(),
            "modified": ev.observed_at.isoformat(),
            "first_observed": ev.observed_at.isoformat(),
            "last_observed": ev.observed_at.isoformat(),
            "number_observed": 1,
        })

    for rel in relations:
        src_id = artifact_stix_map.get(rel.source_artifact_id)
        dst_id = artifact_stix_map.get(rel.target_artifact_id)
        if src_id and dst_id:
            rel_id = _stix_id("relationship", f"{investigation.id}:{rel.id}")
            objects.append({
                "type": "relationship",
                "spec_version": "2.1",
                "id": rel_id,
                "created": rel.created_at.isoformat(),
                "modified": rel.created_at.isoformat(),
                "relationship_type": rel.relation_type.value.replace("_", "-"),
                "source_ref": src_id,
                "target_ref": dst_id,
            })

    bundle: dict[str, Any] = {
        "type": "bundle",
        "id": _stix_id("bundle", investigation.id),
        "objects": objects,
    }
    return json.dumps(bundle, indent=2, ensure_ascii=False)


__all__ = ["export_artifacts_csv", "export_stix_bundle"]
