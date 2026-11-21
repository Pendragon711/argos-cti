"""Bounded, deduplicated pivoting across investigation artifacts and relations."""

from dataclasses import dataclass, field

from argos.models import Artifact, Relation


@dataclass(frozen=True)
class PivotConfig:
    max_depth: int = 2
    max_steps: int = 50


@dataclass(frozen=True)
class PivotHop:
    depth: int
    from_artifact_id: str
    to_artifact_id: str
    relation_id: str
    relation_type: str


@dataclass(frozen=True)
class PivotSummary:
    seed_artifact_ids: tuple[str, ...]
    visited_artifact_ids: tuple[str, ...] = field(default_factory=tuple)
    hops: tuple[PivotHop, ...] = field(default_factory=tuple)
    stopped_by_limit: bool = False


def run_bounded_pivot(
    seed_ids: list[str],
    artifacts: list[Artifact],
    relations: list[Relation],
    config: PivotConfig | None = None,
) -> PivotSummary:
    """Traverse known artifact relations with depth and step bounds without duplicates."""
    cfg = config or PivotConfig()
    known_ids = {a.id for a in artifacts}
    valid_seeds = [sid for sid in seed_ids if sid in known_ids]

    visited: set[str] = set(valid_seeds)
    seen_relations: set[str] = set()
    hops: list[PivotHop] = []
    frontier: list[tuple[str, int]] = [(sid, 0) for sid in valid_seeds]
    stopped_by_limit = False

    while frontier:
        current_id, depth = frontier.pop(0)
        if depth >= cfg.max_depth:
            stopped_by_limit = True
            continue

        for rel in relations:
            if len(hops) >= cfg.max_steps:
                stopped_by_limit = True
                frontier.clear()
                break

            next_id: str | None = None
            if rel.source_artifact_id == current_id and rel.target_artifact_id in known_ids:
                next_id = rel.target_artifact_id
            elif rel.target_artifact_id == current_id and rel.source_artifact_id in known_ids:
                next_id = rel.source_artifact_id

            if next_id is None or rel.id in seen_relations:
                continue

            seen_relations.add(rel.id)
            hops.append(
                PivotHop(
                    depth=depth + 1,
                    from_artifact_id=current_id,
                    to_artifact_id=next_id,
                    relation_id=rel.id,
                    relation_type=rel.relation_type.value,
                )
            )
            if next_id not in visited:
                visited.add(next_id)
                frontier.append((next_id, depth + 1))

    return PivotSummary(
        seed_artifact_ids=tuple(valid_seeds),
        visited_artifact_ids=tuple(visited),
        hops=tuple(hops),
        stopped_by_limit=stopped_by_limit,
    )


__all__ = ["PivotConfig", "PivotHop", "PivotSummary", "run_bounded_pivot"]
