"""Traceable correlation helpers for linking related investigation artifacts."""

from dataclasses import dataclass

from argos.models import Artifact, ArtifactType, EpistemicStatus, Relation, RelationType


@dataclass(frozen=True)
class CorrelationCandidate:
    source_artifact_id: str
    target_artifact_id: str
    relation_type: RelationType
    epistemic_status: EpistemicStatus
    source: str
    context: str


def correlate_artifacts(
    artifacts: list[Artifact],
    investigation_id: str,
    source_label: str = "argos.correlation",
) -> list[Relation]:
    """Derive transparent, non-attributive candidate relations between artifacts."""
    relations: list[Relation] = []
    seen_pairs: set[tuple[str, str, RelationType]] = set()

    domains_by_name: dict[str, list[Artifact]] = {}
    for art in artifacts:
        if art.artifact_type == ArtifactType.DOMAIN:
            domains_by_name.setdefault(art.value.lower(), []).append(art)

    for art in artifacts:
        if art.artifact_type == ArtifactType.URL:
            for dom, dom_arts in domains_by_name.items():
                if f"://{dom}" in art.value.lower() or f"/{dom}" in art.value.lower():
                    for dom_art in dom_arts:
                        if dom_art.id != art.id:
                            key = (art.id, dom_art.id, RelationType.PART_OF)
                            if key not in seen_pairs:
                                seen_pairs.add(key)
                                relations.append(
                                    Relation(
                                        investigation_id=investigation_id,
                                        source_artifact_id=art.id,
                                        target_artifact_id=dom_art.id,
                                        relation_type=RelationType.PART_OF,
                                        epistemic_status=EpistemicStatus.INFERRED,
                                        source=source_label,
                                        context=f"URL {art.value} references domain {dom} (non-attributive structural link).",
                                    )
                                )
        elif art.artifact_type == ArtifactType.EMAIL and "@" in art.value:
            email_domain = art.value.rsplit("@", 1)[1].lower()
            for dom_art in domains_by_name.get(email_domain, []):
                if dom_art.id != art.id:
                    key = (art.id, dom_art.id, RelationType.ASSOCIATED_WITH)
                    if key not in seen_pairs:
                        seen_pairs.add(key)
                        relations.append(
                            Relation(
                                investigation_id=investigation_id,
                                source_artifact_id=art.id,
                                target_artifact_id=dom_art.id,
                                relation_type=RelationType.ASSOCIATED_WITH,
                                epistemic_status=EpistemicStatus.INFERRED,
                                source=source_label,
                                context=f"Email {art.value} shares domain suffix {email_domain} (requires independent verification).",
                            )
                        )

    return relations


__all__ = ["CorrelationCandidate", "correlate_artifacts"]
