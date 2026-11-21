"""Core investigation orchestration connecting collectors, normalizers, storage, analysis, and exporters."""

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from argos.analysis import AnalyticalAssessment, evaluate_investigation
from argos.collectors import CollectedRecord, CollectionResult
from argos.collectors.local_file import LocalFileCollector
from argos.collectors.public_feed import PublicFeedCollector
from argos.core.storage import SQLiteStorage
from argos.correlation import correlate_artifacts
from argos.exporters import export_artifacts_csv, export_stix_bundle
from argos.models import (
    Artifact,
    ArtifactType,
    EpistemicStatus,
    Evidence,
    Investigation,
    InvestigationStatus,
    Relation,
)
from argos.normalizers.ioc import NormalizedIndicator, normalize_indicator
from argos.pivot import PivotConfig, PivotSummary, run_bounded_pivot
from argos.reporting import render_json_report, render_markdown_report


@dataclass(frozen=True)
class IngestionSummary:
    """Result of ingesting records into an investigation."""

    investigation_id: str
    sources: tuple[str, ...]
    errors: tuple[str, ...]
    created_artifacts: tuple[Artifact, ...]
    created_evidences: tuple[Evidence, ...]
    created_relations: tuple[Relation, ...]
    skipped_indicators: tuple[NormalizedIndicator, ...]


class InvestigationWorkflow:
    """Orchestrates local-first CTI investigation operations over SQLiteStorage."""

    def __init__(self, storage: SQLiteStorage) -> None:
        self.storage = storage

    def create_investigation(
        self,
        title: str,
        objective: str = "",
        scope: str = "",
    ) -> Investigation:
        investigation = Investigation(
            title=title,
            objective=objective,
            scope=scope,
            status=InvestigationStatus.OPEN,
        )
        self.storage.save_investigation(investigation)
        return investigation

    def ingest_records(
        self,
        investigation_id: str,
        records: Sequence[CollectedRecord],
        epistemic_status: EpistemicStatus = EpistemicStatus.OBSERVED,
        source_override: str | None = None,
        errors: Sequence[str] = (),
        auto_correlate: bool = True,
    ) -> IngestionSummary:
        existing_artifacts = self.storage.list_artifacts(investigation_id)
        by_key: dict[tuple[ArtifactType, str], Artifact] = {
            (art.artifact_type, art.value): art for art in existing_artifacts
        }

        created_artifacts: list[Artifact] = []
        created_evidences: list[Evidence] = []
        skipped_indicators: list[NormalizedIndicator] = []
        sources: set[str] = set()

        for rec in records:
            source = source_override or rec.source
            if source:
                sources.add(source)

            normalized = normalize_indicator(rec.raw_value)
            if normalized.parse_error or normalized.artifact_type == ArtifactType.UNKNOWN or not normalized.value:
                skipped_indicators.append(normalized)
                continue

            dedup_key = (normalized.artifact_type, normalized.value)
            artifact = by_key.get(dedup_key)
            if artifact is None:
                artifact = Artifact(
                    investigation_id=investigation_id,
                    artifact_type=normalized.artifact_type,
                    value=normalized.value,
                    original_value=normalized.original_value,
                    source=source or "unknown",
                    metadata={
                        **rec.metadata,
                        "normalization_warnings": list(normalized.warnings),
                    },
                )
                self.storage.save_artifact(artifact)
                by_key[dedup_key] = artifact
                created_artifacts.append(artifact)

            evidence = Evidence(
                investigation_id=investigation_id,
                artifact_id=artifact.id,
                source=source or "unknown",
                collection_method=rec.collection_method,
                epistemic_status=epistemic_status,
                content=rec.raw_value,
                metadata={
                    **rec.metadata,
                    "indicator_hash": normalized.content_hash,
                },
            )
            self.storage.save_evidence(evidence)
            created_evidences.append(evidence)

        created_relations: list[Relation] = []
        if auto_correlate:
            all_artifacts = list(by_key.values())
            existing_relations = self.storage.list_relations(investigation_id)
            existing_edges = {
                (rel.source_artifact_id, rel.target_artifact_id, rel.relation_type)
                for rel in existing_relations
            }
            for candidate in correlate_artifacts(
                all_artifacts,
                investigation_id=investigation_id,
                source_label="argos.correlation",
            ):
                edge = (
                    candidate.source_artifact_id,
                    candidate.target_artifact_id,
                    candidate.relation_type,
                )
                if edge not in existing_edges:
                    self.storage.save_relation(candidate)
                    existing_edges.add(edge)
                    created_relations.append(candidate)

        return IngestionSummary(
            investigation_id=investigation_id,
            sources=tuple(sorted(sources)),
            errors=tuple(errors),
            created_artifacts=tuple(created_artifacts),
            created_evidences=tuple(created_evidences),
            created_relations=tuple(created_relations),
            skipped_indicators=tuple(skipped_indicators),
        )

    def collect_from_local_file(
        self,
        investigation_id: str,
        file_path: Path,
        target: str | None = None,
        epistemic_status: EpistemicStatus = EpistemicStatus.OBSERVED,
    ) -> IngestionSummary:
        result: CollectionResult = LocalFileCollector(file_path=file_path).collect(target=target)
        return self.ingest_records(
            investigation_id=investigation_id,
            records=result.records,
            epistemic_status=epistemic_status,
            source_override=result.source,
            errors=result.errors,
        )

    def collect_from_public_feed(
        self,
        investigation_id: str,
        feed_name: str,
        feed_url: str,
        target: str | None = None,
        epistemic_status: EpistemicStatus = EpistemicStatus.REPORTED,
    ) -> IngestionSummary:
        result: CollectionResult = PublicFeedCollector(name=feed_name, feed_url=feed_url).collect(
            target=target
        )
        return self.ingest_records(
            investigation_id=investigation_id,
            records=result.records,
            epistemic_status=epistemic_status,
            source_override=result.source,
            errors=result.errors,
        )

    def pivot(
        self,
        investigation_id: str,
        seed_artifact_ids: list[str],
        config: PivotConfig | None = None,
    ) -> PivotSummary:
        artifacts = self.storage.list_artifacts(investigation_id)
        relations = self.storage.list_relations(investigation_id)
        return run_bounded_pivot(
            seed_ids=seed_artifact_ids,
            artifacts=artifacts,
            relations=relations,
            config=config,
        )

    def assess(
        self,
        investigation_id: str,
        mitre_evidence: list[dict[str, str]] | None = None,
    ) -> AnalyticalAssessment:
        artifacts = self.storage.list_artifacts(investigation_id)
        evidences = self.storage.list_evidences(investigation_id)
        relations = self.storage.list_relations(investigation_id)
        return evaluate_investigation(
            investigation_id=investigation_id,
            artifacts=artifacts,
            evidences=evidences,
            relations=relations,
            mitre_evidence=mitre_evidence,
        )

    def generate_report(
        self,
        investigation_id: str,
        fmt: str = "markdown",
        mitre_evidence: list[dict[str, str]] | None = None,
    ) -> str:
        investigation = self.storage.get_investigation(investigation_id)
        if investigation is None:
            msg = f"Investigation not found: {investigation_id}"
            raise ValueError(msg)
        artifacts = self.storage.list_artifacts(investigation_id)
        evidences = self.storage.list_evidences(investigation_id)
        relations = self.storage.list_relations(investigation_id)
        assessment = evaluate_investigation(
            investigation_id=investigation_id,
            artifacts=artifacts,
            evidences=evidences,
            relations=relations,
            mitre_evidence=mitre_evidence,
        )
        if fmt.lower() == "json":
            return render_json_report(investigation, artifacts, evidences, relations, assessment)
        if fmt.lower() == "markdown":
            return render_markdown_report(investigation, artifacts, evidences, relations, assessment)
        msg = f"Unsupported report format: {fmt}"
        raise ValueError(msg)

    def export_investigation(self, investigation_id: str, fmt: str = "csv") -> str:
        investigation = self.storage.get_investigation(investigation_id)
        if investigation is None:
            msg = f"Investigation not found: {investigation_id}"
            raise ValueError(msg)
        artifacts = self.storage.list_artifacts(investigation_id)
        if fmt.lower() == "csv":
            return export_artifacts_csv(artifacts)
        if fmt.lower() == "stix":
            evidences = self.storage.list_evidences(investigation_id)
            relations = self.storage.list_relations(investigation_id)
            return export_stix_bundle(investigation, artifacts, evidences, relations)
        msg = f"Unsupported export format: {fmt}"
        raise ValueError(msg)
