"""Command-line interface for ARGOS."""

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from argos.core import ArgosConfig, SQLiteStorage
from argos.models import (
    Artifact,
    ArtifactType,
    EpistemicStatus,
    Evidence,
    InvestigationStatus,
    Relation,
    RelationType,
)
from argos.normalizers import normalize_indicator
from argos.pivot import PivotConfig
from argos.ui.server import run_ui_server
from argos.workflow import InvestigationWorkflow

app = typer.Typer(help="ARGOS — Open Source Threat Intelligence Investigation Framework.")
inv_app = typer.Typer(help="Manage local threat intelligence investigations.")
art_app = typer.Typer(help="Normalize and manage investigation artifacts.")
evd_app = typer.Typer(help="Inspect collected evidence for investigations.")
rel_app = typer.Typer(help="Link and inspect relationships between artifacts.")

app.add_typer(inv_app, name="investigation")
app.add_typer(art_app, name="artifact")
app.add_typer(evd_app, name="evidence")
app.add_typer(rel_app, name="relation")

console = Console(width=200)


def _get_storage(db_path: Path | None) -> SQLiteStorage:
    config = ArgosConfig()
    config.ensure_dirs()
    target = db_path if db_path is not None else config.db_path
    return SQLiteStorage(target)


def _get_workflow(db_path: Path | None) -> InvestigationWorkflow:
    return InvestigationWorkflow(_get_storage(db_path))


def _resolve_artifact(
    storage: SQLiteStorage,
    investigation_id: str,
    ref: str,
    source: str,
) -> Artifact | None:
    for art in storage.list_artifacts(investigation_id):
        if art.id == ref:
            return art

    norm = normalize_indicator(ref)
    existing = storage.find_artifact_by_value(investigation_id, norm.value)
    if existing is not None:
        return existing

    artifact = Artifact(
        investigation_id=investigation_id,
        artifact_type=norm.artifact_type,
        value=norm.value,
        original_value=norm.original_value,
        source=source,
    )
    storage.save_artifact(artifact)
    return artifact


def _load_import_records(
    file_path: Path,
    default_source: str,
    default_status: EpistemicStatus,
) -> list[dict[str, Any]]:
    suffix = file_path.suffix.lower()
    raw_text = file_path.read_text(encoding="utf-8")

    if suffix == ".json":
        payload = json.loads(raw_text)
        if isinstance(payload, dict) and isinstance(payload.get("items"), list):
            items_list = payload["items"]
        elif isinstance(payload, list):
            items_list = payload
        else:
            raise ValueError(
                "JSON import file must contain a list of indicator objects or an 'items' list."
            )
        records: list[dict[str, Any]] = []
        for entry in items_list:
            if not isinstance(entry, dict) or "value" not in entry:
                raise ValueError("Each JSON entry must be an object containing a 'value' field.")
            status_val = entry.get("status", default_status)
            parsed_status = (
                status_val
                if isinstance(status_val, EpistemicStatus)
                else EpistemicStatus(str(status_val))
            )
            meta_val = entry.get("metadata", {})
            records.append(
                {
                    "value": str(entry["value"]),
                    "source": str(entry.get("source", default_source)),
                    "status": parsed_status,
                    "metadata": meta_val if isinstance(meta_val, dict) else {},
                }
            )
        return records

    records = []
    for line in raw_text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        records.append(
            {
                "value": stripped,
                "source": default_source,
                "status": default_status,
                "metadata": {},
            }
        )
    return records


@app.command()
def init(
    db_path: Annotated[Path | None, typer.Option(help="Custom SQLite database path.")] = None,
) -> None:
    """Initialize ARGOS local directories and SQLite database."""
    storage = _get_storage(db_path)
    console.print(f"[green]ARGOS initialized[/green] at [bold]{storage.db_path}[/bold]")


@inv_app.command("create")
def create_investigation(
    title: Annotated[str, typer.Option("--title", "-t", help="Investigation title.")],
    objective: Annotated[str, typer.Option("--objective", "-o", help="Investigation objective.")] = "",
    scope: Annotated[str, typer.Option("--scope", "-s", help="Investigation scope.")] = "",
    db_path: Annotated[Path | None, typer.Option(help="Custom SQLite database path.")] = None,
) -> None:
    """Create a new local investigation."""
    workflow = _get_workflow(db_path)
    inv = workflow.create_investigation(title=title, objective=objective, scope=scope)
    console.print(f"[green]Created investigation[/green] [bold]{inv.id}[/bold] — {inv.title}")


@inv_app.command("list")
def list_investigations(
    db_path: Annotated[Path | None, typer.Option(help="Custom SQLite database path.")] = None,
) -> None:
    """List saved investigations."""
    storage = _get_storage(db_path)
    items = storage.list_investigations()
    if not items:
        console.print("[yellow]No investigations found.[/yellow]")
        return

    table = Table(title="ARGOS Investigations")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Title", style="bold", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    table.add_column("Objective", no_wrap=True)

    for item in items:
        table.add_row(item.id, item.title, item.status.value, item.objective)

    console.print(table)


@inv_app.command("update")
def update_investigation(
    investigation_id: Annotated[str, typer.Option("--investigation", "-i", help="Investigation ID.")],
    status: Annotated[
        InvestigationStatus | None, typer.Option("--status", "-s", help="New investigation status.")
    ] = None,
    conclusion: Annotated[
        str | None, typer.Option("--conclusion", "-c", help="Investigation conclusion.")
    ] = None,
    limitation: Annotated[
        list[str] | None,
        typer.Option("--limitation", "-l", help="Add an analytical limitation (repeatable)."),
    ] = None,
    note: Annotated[
        list[str] | None,
        typer.Option("--note", "-n", help="Append an analyst note (repeatable)."),
    ] = None,
    db_path: Annotated[Path | None, typer.Option(help="Custom SQLite database path.")] = None,
) -> None:
    """Update status, conclusion, limitations, or notes for an investigation."""
    storage = _get_storage(db_path)
    inv = storage.get_investigation(investigation_id)
    if inv is None:
        console.print(f"[red]Investigation not found:[/red] {investigation_id}")
        raise typer.Exit(code=1)

    if status is not None:
        inv.status = status
    if conclusion is not None:
        inv.conclusion = conclusion
    if limitation:
        inv.limitations.extend(item.strip() for item in limitation if item.strip())
    if note:
        inv.notes.extend(item.strip() for item in note if item.strip())

    inv.updated_at = datetime.now(UTC)
    storage.save_investigation(inv)
    console.print(
        f"[green]Updated investigation[/green] [bold]{inv.id}[/bold] (status: {inv.status.value})"
    )


@inv_app.command("show")
def show_investigation(
    investigation_id: Annotated[str, typer.Option("--investigation", "-i", help="Investigation ID.")],
    db_path: Annotated[Path | None, typer.Option(help="Custom SQLite database path.")] = None,
) -> None:
    """Show detailed summary and record counts for an investigation."""
    storage = _get_storage(db_path)
    inv = storage.get_investigation(investigation_id)
    if inv is None:
        console.print(f"[red]Investigation not found:[/red] {investigation_id}")
        raise typer.Exit(code=1)

    artifacts_count = len(storage.list_artifacts(inv.id))
    evidences_count = len(storage.list_evidences(inv.id))
    relations_count = len(storage.list_relations(inv.id))

    lines = [
        f"[bold]ID:[/bold] {inv.id}",
        f"[bold]Title:[/bold] {inv.title}",
        f"[bold]Status:[/bold] {inv.status.value}",
        f"[bold]Objective:[/bold] {inv.objective or '-'}",
        f"[bold]Scope:[/bold] {inv.scope or '-'}",
        f"[bold]Artifacts:[/bold] {artifacts_count} | {evidences_count} evidence | {relations_count} relations",
        f"[bold]Conclusion:[/bold] {inv.conclusion or '-'}",
        f"[bold]Limitations:[/bold] {', '.join(inv.limitations) if inv.limitations else '-'}",
        f"[bold]Notes:[/bold] {', '.join(inv.notes) if inv.notes else '-'}",
    ]
    console.print(Panel("\n".join(lines), title=f"Investigation — {inv.id}", expand=False))


@inv_app.command("collect")
def collect_investigation(
    investigation_id: Annotated[str, typer.Option("--investigation", "-i", help="Investigation ID.")],
    file_path: Annotated[
        Path | None, typer.Option("--file", "-f", help="Local indicator file (.txt, .csv, .json).")
    ] = None,
    feed_url: Annotated[
        str | None, typer.Option("--feed-url", help="Public feed URL for indicator collection.")
    ] = None,
    feed_name: Annotated[
        str, typer.Option("--feed-name", help="Label for public feed source.")
    ] = "public_feed",
    target: Annotated[
        str | None, typer.Option("--target", help="Optional filter target passed to collector.")
    ] = None,
    status: Annotated[
        EpistemicStatus,
        typer.Option("--status", help="Epistemic status assigned to collected evidence."),
    ] = EpistemicStatus.OBSERVED,
    db_path: Annotated[Path | None, typer.Option(help="Custom SQLite database path.")] = None,
) -> None:
    """Collect and normalize indicators from a local file or public feed into an investigation."""
    storage = _get_storage(db_path)
    inv = storage.get_investigation(investigation_id)
    if inv is None:
        console.print(f"[red]Investigation not found:[/red] {investigation_id}")
        raise typer.Exit(code=1)

    if (file_path is None) == (feed_url is None):
        console.print("[red]Provide either --file or --feed-url (mutually exclusive).[/red]")
        raise typer.Exit(code=1)

    workflow = InvestigationWorkflow(storage)
    if file_path is not None:
        if not file_path.exists():
            console.print(f"[red]Collector file not found:[/red] {file_path}")
            raise typer.Exit(code=1)
        summary = workflow.collect_from_local_file(
            investigation_id=inv.id,
            file_path=file_path,
            target=target,
            epistemic_status=status,
        )
    else:
        assert feed_url is not None
        summary = workflow.collect_from_public_feed(
            investigation_id=inv.id,
            feed_name=feed_name,
            feed_url=feed_url,
            target=target,
            epistemic_status=status,
        )

    for err in summary.errors:
        console.print(f"[yellow]Collector warning/error:[/yellow] {err}")

    console.print(
        f"[green]Collection complete[/green] for [bold]{inv.id}[/bold] "
        f"(artifacts: {len(summary.created_artifacts)}, evidence: {len(summary.created_evidences)}, "
        f"relations: {len(summary.created_relations)}, skipped: {len(summary.skipped_indicators)})"
    )


@inv_app.command("pivot")
def pivot_investigation(
    investigation_id: Annotated[str, typer.Option("--investigation", "-i", help="Investigation ID.")],
    seed: Annotated[
        list[str], typer.Option("--seed", "-s", help="Seed artifact ID or indicator value (repeatable).")
    ],
    max_depth: Annotated[
        int, typer.Option("--max-depth", help="Maximum traversal depth.")
    ] = 2,
    max_steps: Annotated[
        int, typer.Option("--max-steps", help="Maximum traversal steps.")
    ] = 50,
    as_json: Annotated[bool, typer.Option("--json", help="Output pivot summary as JSON.")] = False,
    db_path: Annotated[Path | None, typer.Option(help="Custom SQLite database path.")] = None,
) -> None:
    """Run bounded relationship traversal starting from seed artifacts."""
    storage = _get_storage(db_path)
    inv = storage.get_investigation(investigation_id)
    if inv is None:
        console.print(f"[red]Investigation not found:[/red] {investigation_id}")
        raise typer.Exit(code=1)

    artifacts = storage.list_artifacts(inv.id)
    seed_ids: list[str] = []
    for ref in seed:
        matched = next(
            (a.id for a in artifacts if a.id == ref or a.value == ref or a.original_value == ref),
            None,
        )
        if matched:
            seed_ids.append(matched)

    if not seed_ids:
        console.print("[red]No matching seed artifacts found in investigation.[/red]")
        raise typer.Exit(code=1)

    workflow = InvestigationWorkflow(storage)
    summary = workflow.pivot(
        investigation_id=inv.id,
        seed_artifact_ids=seed_ids,
        config=PivotConfig(max_depth=max_depth, max_steps=max_steps),
    )

    if as_json:
        typer.echo(
            json.dumps(
                {
                    "seed_artifact_ids": list(summary.seed_artifact_ids),
                    "visited_artifact_ids": list(summary.visited_artifact_ids),
                    "traversed_relation_ids": [h.relation_id for h in summary.hops],
                    "hops": [h.__dict__ for h in summary.hops],
                    "stopped_by_limit": summary.stopped_by_limit,
                },
                indent=2,
            )
        )
        return

    stop_reason = "limit_reached" if summary.stopped_by_limit else "completed"
    console.print(
        f"[green]Pivot finished[/green] (stop_reason: {stop_reason}, "
        f"visited: {len(summary.visited_artifact_ids)}, relations: {len(summary.hops)})"
    )


@inv_app.command("assess")
def assess_investigation(
    investigation_id: Annotated[str, typer.Option("--investigation", "-i", help="Investigation ID.")],
    as_json: Annotated[bool, typer.Option("--json", help="Output analytical assessment as JSON.")] = False,
    db_path: Annotated[Path | None, typer.Option(help="Custom SQLite database path.")] = None,
) -> None:
    """Evaluate independent analytical dimensions for an investigation."""
    storage = _get_storage(db_path)
    inv = storage.get_investigation(investigation_id)
    if inv is None:
        console.print(f"[red]Investigation not found:[/red] {investigation_id}")
        raise typer.Exit(code=1)

    workflow = InvestigationWorkflow(storage)
    assessment = workflow.assess(inv.id)

    if as_json:
        typer.echo(json.dumps(assessment.__dict__, indent=2, default=list))
        return

    lines = [
        f"[bold]Source Reliability:[/bold] {assessment.source_reliability}",
        f"[bold]Evidence Quality:[/bold] {assessment.evidence_quality}",
        f"[bold]Confidence:[/bold] {assessment.confidence}",
        f"[bold]Indicator Validity:[/bold] {assessment.indicator_validity}",
        f"[bold]Operational Relevance:[/bold] {assessment.operational_relevance}",
        f"[bold]Risk:[/bold] {assessment.risk}",
        f"[bold]Gaps:[/bold] {', '.join(assessment.gaps) if assessment.gaps else 'none'}",
        f"[bold]Methodology:[/bold] {assessment.methodology_note}",
    ]
    console.print(Panel("\n".join(lines), title=f"Analytical Assessment — {inv.id}", expand=False))


@inv_app.command("report")
def report_investigation(
    investigation_id: Annotated[str, typer.Option("--investigation", "-i", help="Investigation ID.")],
    output_format: Annotated[
        str, typer.Option("--format", "-f", help="Report format: markdown or json.")
    ] = "markdown",
    output_file: Annotated[
        Path | None, typer.Option("--output", "-o", help="Write report to file path.")
    ] = None,
    db_path: Annotated[Path | None, typer.Option(help="Custom SQLite database path.")] = None,
) -> None:
    """Generate a structured investigation report in Markdown or JSON."""
    workflow = _get_workflow(db_path)
    try:
        rendered = workflow.generate_report(investigation_id=investigation_id, fmt=output_format)
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc

    if output_file is not None:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(rendered, encoding="utf-8")
        console.print(f"[green]Wrote report[/green] for [bold]{investigation_id}[/bold] to {output_file}")
    else:
        typer.echo(rendered)


@inv_app.command("export")
def export_investigation(
    investigation_id: Annotated[str, typer.Option("--investigation", "-i", help="Investigation ID.")],
    output_format: Annotated[
        str, typer.Option("--format", "-f", help="Export format: json, markdown, csv, or stix.")
    ] = "json",
    output_file: Annotated[
        Path | None, typer.Option("--output", "-o", help="Write output to file path.")
    ] = None,
    db_path: Annotated[Path | None, typer.Option(help="Custom SQLite database path.")] = None,
) -> None:
    """Export an investigation in JSON, Markdown, CSV, or STIX 2.1 format."""
    storage = _get_storage(db_path)
    inv = storage.get_investigation(investigation_id)
    if inv is None:
        console.print(f"[red]Investigation not found:[/red] {investigation_id}")
        raise typer.Exit(code=1)

    fmt = output_format.lower()
    artifacts = storage.list_artifacts(inv.id)
    evidences = storage.list_evidences(inv.id)
    relations = storage.list_relations(inv.id)

    if fmt == "json":
        payload = {
            "investigation": inv.model_dump(mode="json"),
            "artifacts": [a.model_dump(mode="json") for a in artifacts],
            "evidences": [e.model_dump(mode="json") for e in evidences],
            "relations": [r.model_dump(mode="json") for r in relations],
        }
        rendered = json.dumps(payload, indent=2, ensure_ascii=False)
    elif fmt == "markdown":
        art_map = {a.id: a.value for a in artifacts}
        md_lines = [
            f"# Investigation: {inv.title} ({inv.id})",
            "",
            f"- **Status:** {inv.status.value}",
            f"- **Objective:** {inv.objective or '-'}",
            f"- **Scope:** {inv.scope or '-'}",
            f"- **Artifacts:** {len(artifacts)} | **Evidence:** {len(evidences)} | **Relations:** {len(relations)}",
            "",
            "## Artifacts",
        ]
        if artifacts:
            for art in artifacts:
                md_lines.append(
                    f"- `{art.artifact_type.value}`: **{art.value}** (original: `{art.original_value}`, source: `{art.source}`)"
                )
        else:
            md_lines.append("- None")

        md_lines.extend(["", "## Relations"])
        if relations:
            for rel in relations:
                src_val = art_map.get(rel.source_artifact_id, rel.source_artifact_id)
                tgt_val = art_map.get(rel.target_artifact_id, rel.target_artifact_id)
                evd_suffix = f" [evidence: `{rel.evidence_id}`]" if rel.evidence_id else ""
                ctx_suffix = f" — {rel.context}" if rel.context.strip() else ""
                md_lines.append(
                    f"- `{src_val}` --[{rel.relation_type.value} ({rel.epistemic_status.value})]--> `{tgt_val}`{evd_suffix}{ctx_suffix}"
                )
        else:
            md_lines.append("- None")

        md_lines.extend(["", "## Evidence"])
        if evidences:
            for evd in evidences:
                compact_content = " ".join(evd.content.split())
                if len(compact_content) > 120:
                    compact_content = f"{compact_content[:117]}..."
                content_suffix = f" — `{compact_content}`" if compact_content else ""
                md_lines.append(
                    f"- `{evd.id}` ({evd.epistemic_status.value}) — source: `{evd.source}`, "
                    f"method: `{evd.collection_method}`, sha256: `{evd.content_hash[:16]}`{content_suffix}"
                )
        else:
            md_lines.append("- None")

        md_lines.extend(["", "## Notes"])
        if inv.notes:
            for note_item in inv.notes:
                md_lines.append(f"- {note_item}")
        else:
            md_lines.append("- None")

        md_lines.extend(
            [
                "",
                "## Conclusion & Limitations",
                f"- **Conclusion:** {inv.conclusion or '-'}",
                f"- **Limitations:** {', '.join(inv.limitations) if inv.limitations else '-'}",
            ]
        )
        rendered = "\n".join(md_lines)
    elif fmt in {"csv", "stix"}:
        workflow = InvestigationWorkflow(storage)
        rendered = workflow.export_investigation(investigation_id=inv.id, fmt=fmt)
    else:
        console.print(f"[red]Unsupported export format:[/red] {output_format}")
        raise typer.Exit(code=1)

    if output_file is not None:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(rendered, encoding="utf-8")
        console.print(f"[green]Exported investigation[/green] [bold]{inv.id}[/bold] to {output_file}")
    else:
        typer.echo(rendered)


@art_app.command("add")
def add_artifact(
    investigation_id: Annotated[str, typer.Option("--investigation", "-i", help="Investigation ID.")],
    raw_value: Annotated[str, typer.Option("--value", "-v", help="Raw or defanged indicator.")],
    source: Annotated[str, typer.Option("--source", "-s", help="Indicator source.")] = "cli_input",
    status: Annotated[
        EpistemicStatus,
        typer.Option("--status", help="Epistemic status for initial evidence."),
    ] = EpistemicStatus.OBSERVED,
    db_path: Annotated[Path | None, typer.Option(help="Custom SQLite database path.")] = None,
) -> None:
    """Normalize an indicator and save it as an artifact with initial evidence."""
    storage = _get_storage(db_path)
    inv = storage.get_investigation(investigation_id)
    if inv is None:
        console.print(f"[red]Investigation not found:[/red] {investigation_id}")
        raise typer.Exit(code=1)

    norm = normalize_indicator(raw_value)
    artifact = Artifact(
        investigation_id=inv.id,
        artifact_type=norm.artifact_type,
        value=norm.value,
        original_value=norm.original_value,
        source=source,
    )
    evidence = Evidence(
        investigation_id=inv.id,
        artifact_id=artifact.id,
        source=source,
        collection_method="cli_ingest",
        epistemic_status=status,
        content=norm.original_value,
        metadata={
            "normalized_value": norm.value,
            "artifact_type": norm.artifact_type.value,
        },
    )

    storage.save_artifact(artifact)
    storage.save_evidence(evidence)
    console.print(
        f"[green]Added artifact[/green] [bold]{artifact.id}[/bold] "
        f"({artifact.artifact_type.value}: {artifact.value})"
    )


@art_app.command("import")
def import_artifacts(
    investigation_id: Annotated[str, typer.Option("--investigation", "-i", help="Investigation ID.")],
    file_path: Annotated[
        Path, typer.Option("--file", "-f", help="Path to .txt or .json indicator file.")
    ],
    source: Annotated[str, typer.Option("--source", "-s", help="Default indicator source.")] = (
        "batch_import"
    ),
    status: Annotated[
        EpistemicStatus,
        typer.Option("--status", help="Default epistemic status for evidence."),
    ] = EpistemicStatus.OBSERVED,
    db_path: Annotated[Path | None, typer.Option(help="Custom SQLite database path.")] = None,
) -> None:
    """Import indicators in bulk from a .txt or .json file into an investigation."""
    storage = _get_storage(db_path)
    inv = storage.get_investigation(investigation_id)
    if inv is None:
        console.print(f"[red]Investigation not found:[/red] {investigation_id}")
        raise typer.Exit(code=1)

    if not file_path.exists():
        console.print(f"[red]Import file not found:[/red] {file_path}")
        raise typer.Exit(code=1)

    try:
        records = _load_import_records(file_path, source, status)
    except (ValueError, json.JSONDecodeError) as exc:
        console.print(f"[red]Invalid import file:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    created_count = 0
    reused_count = 0

    for rec in records:
        norm = normalize_indicator(rec["value"])
        existing = storage.find_artifact_by_value(inv.id, norm.value)
        if existing is not None:
            artifact = existing
            reused_count += 1
        else:
            artifact = Artifact(
                investigation_id=inv.id,
                artifact_type=norm.artifact_type,
                value=norm.value,
                original_value=norm.original_value,
                source=rec["source"],
                metadata=rec["metadata"],
            )
            storage.save_artifact(artifact)
            created_count += 1

        evidence = Evidence(
            investigation_id=inv.id,
            artifact_id=artifact.id,
            source=rec["source"],
            collection_method="file_import",
            epistemic_status=rec["status"],
            content=norm.original_value,
            metadata={
                "import_file": str(file_path),
                "normalized_value": norm.value,
                "artifact_type": norm.artifact_type.value,
                **rec["metadata"],
            },
        )
        storage.save_evidence(evidence)

    console.print(
        f"[green]Imported {len(records)} indicator(s)[/green] "
        f"(new: {created_count}, deduplicated: {reused_count})"
    )


@art_app.command("list")
def list_artifacts(
    investigation_id: Annotated[str, typer.Option("--investigation", "-i", help="Investigation ID.")],
    artifact_type: Annotated[
        ArtifactType | None,
        typer.Option("--type", "-t", help="Filter artifacts by indicator type."),
    ] = None,
    status: Annotated[
        EpistemicStatus | None,
        typer.Option("--status", help="Filter artifacts by linked evidence epistemic status."),
    ] = None,
    source: Annotated[
        str | None,
        typer.Option("--source", "-s", help="Filter artifacts by source."),
    ] = None,
    search: Annotated[
        str | None,
        typer.Option("--search", "-q", help="Filter artifacts matching normalized or raw value."),
    ] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Output results as JSON.")] = False,
    db_path: Annotated[Path | None, typer.Option(help="Custom SQLite database path.")] = None,
) -> None:
    """List normalized artifacts for an investigation."""
    storage = _get_storage(db_path)
    artifacts = storage.list_artifacts(investigation_id)

    if artifact_type is not None:
        artifacts = [art for art in artifacts if art.artifact_type == artifact_type]

    if status is not None:
        evidences = storage.list_evidences(investigation_id)
        matching_artifact_ids = {
            evd.artifact_id
            for evd in evidences
            if evd.artifact_id is not None and evd.epistemic_status == status
        }
        artifacts = [art for art in artifacts if art.id in matching_artifact_ids]

    if source and source.strip():
        source_needle = source.strip().lower()
        artifacts = [art for art in artifacts if art.source.lower() == source_needle]

    if search and search.strip():
        needle = search.strip().lower()
        artifacts = [
            art
            for art in artifacts
            if needle in art.value.lower() or needle in art.original_value.lower()
        ]

    if as_json:
        typer.echo(
            json.dumps(
                [art.model_dump(mode="json") for art in artifacts],
                indent=2,
            )
        )
        return

    if not artifacts:
        console.print("[yellow]No artifacts found matching criteria.[/yellow]")
        return

    table = Table(title=f"Artifacts — {investigation_id}")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Type", no_wrap=True)
    table.add_column("Normalized Value", style="bold", no_wrap=True)
    table.add_column("Original Value", no_wrap=True)
    table.add_column("Source", no_wrap=True)

    for art in artifacts:
        table.add_row(art.id, art.artifact_type.value, art.value, art.original_value, art.source)

    console.print(table)


@evd_app.command("list")
def list_evidences(
    investigation_id: Annotated[str, typer.Option("--investigation", "-i", help="Investigation ID.")],
    status: Annotated[
        EpistemicStatus | None, typer.Option("--status", help="Filter by epistemic status.")
    ] = None,
    source: Annotated[
        str | None, typer.Option("--source", "-s", help="Filter by evidence source.")
    ] = None,
    artifact_ref: Annotated[
        str | None,
        typer.Option("--artifact", "-a", help="Filter by linked artifact ID or value."),
    ] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Output results as JSON.")] = False,
    db_path: Annotated[Path | None, typer.Option(help="Custom SQLite database path.")] = None,
) -> None:
    """List recorded evidence items for an investigation."""
    storage = _get_storage(db_path)
    evidences = storage.list_evidences(investigation_id)
    if status is not None:
        evidences = [evd for evd in evidences if evd.epistemic_status == status]
    if source is not None:
        source_needle = source.strip().lower()
        evidences = [evd for evd in evidences if evd.source.lower() == source_needle]
    if artifact_ref and artifact_ref.strip():
        needle = artifact_ref.strip().lower()
        artifacts_for_inv = storage.list_artifacts(investigation_id)
        matched_ids = {
            art.id
            for art in artifacts_for_inv
            if art.id.lower() == needle
            or art.value.lower() == needle
            or needle in art.value.lower()
        }
        evidences = [
            evd
            for evd in evidences
            if evd.artifact_id is not None
            and (evd.artifact_id in matched_ids or evd.artifact_id.lower() == needle)
        ]
    if as_json:
        typer.echo(
            json.dumps(
                [evd.model_dump(mode="json") for evd in evidences],
                indent=2,
            )
        )
        return
    if not evidences:
        console.print("[yellow]No evidence found for investigation.[/yellow]")
        return

    table = Table(title=f"Evidence — {investigation_id}")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Artifact ID", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    table.add_column("Source", no_wrap=True)
    table.add_column("SHA-256", max_width=16, no_wrap=True)

    for evd in evidences:
        table.add_row(
            evd.id,
            evd.artifact_id or "-",
            evd.epistemic_status.value,
            evd.source,
            evd.content_hash[:16],
        )

    console.print(table)


@rel_app.command("add")
def add_relation(
    investigation_id: Annotated[str, typer.Option("--investigation", "-i", help="Investigation ID.")],
    source_ref: Annotated[
        str, typer.Option("--source-ref", help="Source artifact ID or indicator value.")
    ],
    target_ref: Annotated[
        str, typer.Option("--target-ref", help="Target artifact ID or indicator value.")
    ],
    relation_type: Annotated[
        RelationType, typer.Option("--type", "-t", help="Relationship type.")
    ] = RelationType.ASSOCIATED_WITH,
    status: Annotated[
        EpistemicStatus, typer.Option("--status", help="Epistemic status of the relation.")
    ] = EpistemicStatus.INFERRED,
    source: Annotated[str, typer.Option("--source", "-s", help="Relationship source.")] = "cli_link",
    context: Annotated[str, typer.Option("--context", "-c", help="Analyst context.")] = "",
    evidence_id: Annotated[
        str | None, typer.Option("--evidence-id", "-e", help="Supporting evidence ID.")
    ] = None,
    db_path: Annotated[Path | None, typer.Option(help="Custom SQLite database path.")] = None,
) -> None:
    """Create a directed relationship between two artifacts in an investigation."""
    storage = _get_storage(db_path)
    inv = storage.get_investigation(investigation_id)
    if inv is None:
        console.print(f"[red]Investigation not found:[/red] {investigation_id}")
        raise typer.Exit(code=1)

    resolved_evidence_id: str | None = None
    if evidence_id is not None:
        matching_evidences = [
            item for item in storage.list_evidences(inv.id) if item.id == evidence_id
        ]
        if not matching_evidences:
            console.print(
                f"[red]Evidence not found in investigation:[/red] {evidence_id}"
            )
            raise typer.Exit(code=1)
        resolved_evidence_id = matching_evidences[0].id

    src_art = _resolve_artifact(storage, inv.id, source_ref, source)
    tgt_art = _resolve_artifact(storage, inv.id, target_ref, source)
    if src_art is None or tgt_art is None:
        console.print("[red]Unable to resolve source or target artifact.[/red]")
        raise typer.Exit(code=1)

    rel = Relation(
        investigation_id=inv.id,
        source_artifact_id=src_art.id,
        target_artifact_id=tgt_art.id,
        relation_type=relation_type,
        epistemic_status=status,
        source=source,
        context=context,
        evidence_id=resolved_evidence_id,
    )
    storage.save_relation(rel)
    console.print(
        f"[green]Added relation[/green] [bold]{rel.id}[/bold] "
        f"({src_art.value} --[{rel.relation_type.value}]--> {tgt_art.value})"
    )


@rel_app.command("list")
def list_relations(
    investigation_id: Annotated[str, typer.Option("--investigation", "-i", help="Investigation ID.")],
    relation_type: Annotated[
        RelationType | None, typer.Option("--type", "-t", help="Filter by relationship type.")
    ] = None,
    status: Annotated[
        EpistemicStatus | None, typer.Option("--status", help="Filter by epistemic status.")
    ] = None,
    artifact_ref: Annotated[
        str | None,
        typer.Option("--artifact", "-a", help="Filter by source or target artifact ID or value."),
    ] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Output results as JSON.")] = False,
    db_path: Annotated[Path | None, typer.Option(help="Custom SQLite database path.")] = None,
) -> None:
    """List relationships recorded for an investigation."""
    storage = _get_storage(db_path)
    relations = storage.list_relations(investigation_id)
    if relation_type is not None:
        relations = [rel for rel in relations if rel.relation_type == relation_type]
    if status is not None:
        relations = [rel for rel in relations if rel.epistemic_status == status]
    if artifact_ref and artifact_ref.strip():
        needle = artifact_ref.strip().lower()
        artifacts_for_inv = storage.list_artifacts(investigation_id)
        matched_ids = {
            art.id
            for art in artifacts_for_inv
            if art.id.lower() == needle
            or art.value.lower() == needle
            or needle in art.value.lower()
        }
        relations = [
            rel
            for rel in relations
            if rel.source_artifact_id in matched_ids
            or rel.target_artifact_id in matched_ids
            or rel.source_artifact_id.lower() == needle
            or rel.target_artifact_id.lower() == needle
        ]
    if as_json:
        typer.echo(
            json.dumps(
                [rel.model_dump(mode="json") for rel in relations],
                indent=2,
            )
        )
        return
    if not relations:
        console.print("[yellow]No relations found for investigation.[/yellow]")
        return

    artifacts_by_id = {a.id: a.value for a in storage.list_artifacts(investigation_id)}

    table = Table(title=f"Relations — {investigation_id}")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Source Artifact", style="bold", no_wrap=True)
    table.add_column("Relation", no_wrap=True)
    table.add_column("Target Artifact", style="bold", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    table.add_column("Evidence", no_wrap=True)
    table.add_column("Context", no_wrap=True)

    for rel in relations:
        src_label = artifacts_by_id.get(rel.source_artifact_id, rel.source_artifact_id)
        tgt_label = artifacts_by_id.get(rel.target_artifact_id, rel.target_artifact_id)
        table.add_row(
            rel.id,
            src_label,
            rel.relation_type.value,
            tgt_label,
            rel.epistemic_status.value,
            rel.evidence_id or "-",
            rel.context,
        )

    console.print(table)


@app.command("ui")
def start_ui(
    db_path: Annotated[Path | None, typer.Option(help="Custom SQLite database path.")] = None,
    port: Annotated[
        int,
        typer.Option(min=0, max=65535, help="Preferred local port on 127.0.0.1."),
    ] = 8765,
    no_browser: Annotated[
        bool,
        typer.Option("--no-browser", help="Do not open the default browser automatically."),
    ] = False,
) -> None:
    """Launch the local-first ARGOS web UI bound to 127.0.0.1."""
    storage = _get_storage(db_path)

    def _on_ready(url: str) -> None:
        console.print(f"[green]ARGOS local UI listening at[/green] [bold]{url}[/bold]")
        console.print(f"[dim]SQLite database:[/dim] {storage.db_path}")

    run_ui_server(
        db_path=storage.db_path,
        port=port,
        open_browser=not no_browser,
        on_ready=_on_ready,
    )
