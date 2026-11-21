"""Reproducible Markdown and JSON reporting helpers for ARGOS investigations."""

import json
from typing import Any

from argos.analysis import AnalyticalAssessment
from argos.models import Artifact, Evidence, Investigation, Relation


def build_report_payload(
    investigation: Investigation,
    artifacts: list[Artifact],
    evidences: list[Evidence],
    relations: list[Relation],
    assessment: AnalyticalAssessment,
) -> dict[str, Any]:
    """Build a structured, reproducible dictionary payload for an investigation."""
    sources = sorted(
        {
            *(a.source for a in artifacts if a.source),
            *(e.source for e in evidences if e.source),
            *(r.source for r in relations if r.source),
        }
    )
    return {
        "investigation_id": investigation.id,
        "title": investigation.title,
        "status": investigation.status.value,
        "created_at": investigation.created_at.isoformat(),
        "updated_at": investigation.updated_at.isoformat(),
        "objective": investigation.objective,
        "scope": investigation.scope,
        "sources_consulted": sources,
        "artifacts": [a.model_dump(mode="json") for a in artifacts],
        "evidences": [e.model_dump(mode="json") for e in evidences],
        "relations": [r.model_dump(mode="json") for r in relations],
        "observations_and_notes": list(investigation.notes),
        "limitations": list(investigation.limitations),
        "conclusion": investigation.conclusion,
        "analytical_assessment": {
            "source_reliability": assessment.source_reliability,
            "evidence_quality": assessment.evidence_quality,
            "confidence": assessment.confidence,
            "indicator_validity": assessment.indicator_validity,
            "operational_relevance": assessment.operational_relevance,
            "risk": assessment.risk,
            "gaps": list(assessment.gaps),
            "inconsistencies": list(assessment.inconsistencies),
            "mitre_mappings": list(assessment.mitre_mappings),
            "methodology_note": assessment.methodology_note,
        },
        "methodology": "ARGOS local-first evidence-driven investigation workflow.",
    }


def render_markdown_report(
    investigation: Investigation,
    artifacts: list[Artifact],
    evidences: list[Evidence],
    relations: list[Relation],
    assessment: AnalyticalAssessment,
) -> str:
    """Render a human-readable Markdown investigation report."""
    payload = build_report_payload(investigation, artifacts, evidences, relations, assessment)
    lines = [
        f"# ARGOS Investigation Report: {investigation.title}",
        "",
        f"- **Investigation ID:** `{investigation.id}`",
        f"- **Status:** `{investigation.status.value}`",
        f"- **Created At:** `{investigation.created_at.isoformat()}`",
        f"- **Objective:** {investigation.objective or "Not specified"}",
        f"- **Scope:** {investigation.scope or "Not specified"}",
        "",
        "## Sources Consulted",
        "",
    ]
    if payload["sources_consulted"]:
        lines.extend(f"- {src}" for src in payload["sources_consulted"])
    else:
        lines.append("- None recorded")

    lines.extend(["", "## Artifacts", ""])
    if artifacts:
        lines.extend(f"- `{a.artifact_type.value}`: `{a.value}` (source: `{a.source}`)" for a in artifacts)
    else:
        lines.append("- None recorded")

    lines.extend(["", "## Evidences", ""])
    if evidences:
        lines.extend(
            f"- `{e.id}` [{e.epistemic_status.value}] source=`{e.source}` sha256=`{e.content_hash[:12]}...`"
            for e in evidences
        )
    else:
        lines.append("- None recorded")

    lines.extend(["", "## Relations", ""])
    if relations:
        lines.extend(
            f"- `{r.source_artifact_id}` --`{r.relation_type.value}`[{r.epistemic_status.value}]--> `{r.target_artifact_id}`"
            for r in relations
        )
    else:
        lines.append("- None recorded")

    lines.extend(
        [
            "",
            "## Analytical Assessment",
            "",
            f"- **Source Reliability:** {assessment.source_reliability}",
            f"- **Evidence Quality:** {assessment.evidence_quality}",
            f"- **Confidence:** {assessment.confidence}",
            f"- **Indicator Validity:** {assessment.indicator_validity}",
            f"- **Operational Relevance:** {assessment.operational_relevance}",
            f"- **Risk:** {assessment.risk}",
            "",
            "## Limitations & Conclusion",
            "",
            f"- **Conclusion:** {investigation.conclusion or "Pending analyst conclusion"}",
        ]
    )
    if investigation.limitations:
        lines.extend(f"- **Limitation:** {lim}" for lim in investigation.limitations)
    lines.append("")
    return "\n".join(lines)


def render_json_report(
    investigation: Investigation,
    artifacts: list[Artifact],
    evidences: list[Evidence],
    relations: list[Relation],
    assessment: AnalyticalAssessment,
) -> str:
    """Render a deterministic JSON report string."""
    payload = build_report_payload(investigation, artifacts, evidences, relations, assessment)
    return json.dumps(payload, indent=2, ensure_ascii=False)


__all__ = ["build_report_payload", "render_json_report", "render_markdown_report"]
