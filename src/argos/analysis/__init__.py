"""Transparent analytical assessment and evidence-backed context helpers."""

from dataclasses import dataclass, field

from argos.models import Artifact, EpistemicStatus, Evidence, Relation


@dataclass(frozen=True)
class AnalyticalAssessment:
    investigation_id: str
    source_reliability: str
    evidence_quality: str
    confidence: str
    indicator_validity: str
    operational_relevance: str
    risk: str
    gaps: tuple[str, ...] = field(default_factory=tuple)
    inconsistencies: tuple[str, ...] = field(default_factory=tuple)
    mitre_mappings: tuple[dict[str, str], ...] = field(default_factory=tuple)
    methodology_note: str = (
        "Independent analytical dimensions without arbitrary threat scores or automated attribution."
    )


def evaluate_investigation(
    investigation_id: str,
    artifacts: list[Artifact],
    evidences: list[Evidence],
    relations: list[Relation],
    mitre_evidence: list[dict[str, str]] | None = None,
) -> AnalyticalAssessment:
    """Summarize independent analytical dimensions and evidence-backed ATT&CK references."""
    gaps: list[str] = []
    if not artifacts:
        gaps.append("no_artifacts_recorded")
    if not evidences:
        gaps.append("no_evidence_preserved")
    if not relations:
        gaps.append("no_artifact_relations_mapped")

    observed_count = sum(1 for e in evidences if e.epistemic_status == EpistemicStatus.OBSERVED)
    has_hashes = bool(evidences) and all(bool(e.content_hash) for e in evidences)

    source_reliability = "unassessed_requires_source_review" if evidences else "no_sources"
    evidence_quality = (
        "hash_verified_with_observations"
        if (evidences and has_hashes and observed_count > 0)
        else ("partial_or_unverified" if evidences else "none")
    )
    confidence = "low_to_moderate_pending_corroboration" if evidences else "none"
    indicator_validity = "contextual_time_bound" if artifacts else "none"
    operational_relevance = "requires_environment_context" if artifacts else "none"
    risk = "unscored_requires_analyst_judgment"

    validated_mitre: list[dict[str, str]] = []
    known_evidence_ids = {e.id for e in evidences}
    for item in mitre_evidence or []:
        ev_id = item.get("evidence_id", "").strip()
        tech_id = item.get("technique_id", "").strip()
        rationale = item.get("rationale", "").strip()
        if ev_id and ev_id in known_evidence_ids and tech_id and rationale:
            validated_mitre.append(
                {
                    "technique_id": tech_id,
                    "tactic": item.get("tactic", "").strip(),
                    "evidence_id": ev_id,
                    "rationale": rationale,
                    "status": EpistemicStatus.REPORTED.value,
                }
            )

    return AnalyticalAssessment(
        investigation_id=investigation_id,
        source_reliability=source_reliability,
        evidence_quality=evidence_quality,
        confidence=confidence,
        indicator_validity=indicator_validity,
        operational_relevance=operational_relevance,
        risk=risk,
        gaps=tuple(gaps),
        mitre_mappings=tuple(validated_mitre),
    )


__all__ = ["AnalyticalAssessment", "evaluate_investigation"]
