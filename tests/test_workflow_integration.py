"""Integration tests for end-to-end ARGOS investigation workflows and CLI commands."""

import csv
import io
import json
from pathlib import Path

from typer.testing import CliRunner

from argos.cli.app import app
from argos.core.storage import SQLiteStorage
from argos.models import EpistemicStatus, Relation, RelationType
from argos.workflow import InvestigationWorkflow

runner = CliRunner()


def test_end_to_end_local_collection_pivot_assessment_and_exports(tmp_path: Path) -> None:
    db_path = tmp_path / "argos_test.sqlite3"
    ioc_file = tmp_path / "indicators.txt"
    ioc_file.write_text(
        "# Sample indicators\nhxxp://malicious[.]example[.]com/payload\n198.51.100.42\ninvalid-not-an-ioc\n",
        encoding="utf-8",
    )

    storage = SQLiteStorage(db_path)
    workflow = InvestigationWorkflow(storage)

    inv = workflow.create_investigation(
        title="Suspicious Infra Campaign",
        objective="Correlate observed domain and IP indicators",
        scope="External infrastructure",
    )
    summary = workflow.collect_from_local_file(
        investigation_id=inv.id,
        file_path=ioc_file,
        epistemic_status=EpistemicStatus.OBSERVED,
    )

    assert len(summary.created_artifacts) == 2
    assert len(summary.created_evidences) == 2
    assert len(summary.skipped_indicators) == 1

    artifacts = storage.list_artifacts(inv.id)
    by_val = {a.value: a for a in artifacts}
    url_art = by_val["http://malicious.example.com/payload"]
    ip_art = by_val["198.51.100.42"]

    rel = Relation(
        investigation_id=inv.id,
        source_artifact_id=url_art.id,
        target_artifact_id=ip_art.id,
        relation_type=RelationType.ASSOCIATED_WITH,
        epistemic_status=EpistemicStatus.OBSERVED,
        source="dns_log",
        context="Observed infrastructure link",
    )
    storage.save_relation(rel)

    pivot_res = workflow.pivot(investigation_id=inv.id, seed_artifact_ids=[url_art.id])
    assert url_art.id in pivot_res.visited_artifact_ids
    assert ip_art.id in pivot_res.visited_artifact_ids
    assert rel.id in [h.relation_id for h in pivot_res.hops]

    assessment = workflow.assess(investigation_id=inv.id)
    assert assessment.source_reliability
    assert assessment.evidence_quality
    assert assessment.confidence
    assert assessment.indicator_validity
    assert assessment.operational_relevance
    assert assessment.risk

    md_report = workflow.generate_report(investigation_id=inv.id, fmt="markdown")
    assert "Suspicious Infra Campaign" in md_report
    assert "malicious.example.com" in md_report

    json_report = json.loads(workflow.generate_report(investigation_id=inv.id, fmt="json"))
    assert json_report["investigation_id"] == inv.id
    assert len(json_report["artifacts"]) == 2

    csv_rows = list(csv.reader(io.StringIO(workflow.export_investigation(investigation_id=inv.id, fmt="csv"))))
    assert csv_rows[0] == [
        "id",
        "investigation_id",
        "artifact_type",
        "value",
        "original_value",
        "source",
        "first_seen",
        "last_seen",
    ]
    assert len(csv_rows) == 3

    stix_bundle = json.loads(workflow.export_investigation(investigation_id=inv.id, fmt="stix"))
    assert stix_bundle["type"] == "bundle"
    object_types = {obj["type"] for obj in stix_bundle["objects"]}
    assert "indicator" in object_types
    assert "observed-data" in object_types
    assert "relationship" in object_types


def test_cli_collect_pivot_assess_report_and_export_commands(tmp_path: Path) -> None:
    db_path = tmp_path / "cli_workflow.sqlite3"
    ioc_file = tmp_path / "cli_iocs.txt"
    ioc_file.write_text("203.0.113.10\nexample-c2[.]org\n", encoding="utf-8")

    create_res = runner.invoke(
        app,
        [
            "investigation",
            "create",
            "--title",
            "CLI End-to-End Check",
            "--db-path",
            str(db_path),
        ],
    )
    assert create_res.exit_code == 0
    inv_id = next(tok for tok in create_res.stdout.split() if tok.startswith("inv_"))

    collect_res = runner.invoke(
        app,
        [
            "investigation",
            "collect",
            "--investigation",
            inv_id,
            "--file",
            str(ioc_file),
            "--db-path",
            str(db_path),
        ],
    )
    assert collect_res.exit_code == 0
    assert "Collection complete" in collect_res.stdout

    art_list_res = runner.invoke(
        app,
        [
            "artifact",
            "list",
            "--investigation",
            inv_id,
            "--json",
            "--db-path",
            str(db_path),
        ],
    )
    assert art_list_res.exit_code == 0
    arts = json.loads(art_list_res.stdout)
    assert len(arts) == 2

    pivot_res = runner.invoke(
        app,
        [
            "investigation",
            "pivot",
            "--investigation",
            inv_id,
            "--seed",
            arts[0]["id"],
            "--json",
            "--db-path",
            str(db_path),
        ],
    )
    assert pivot_res.exit_code == 0
    assert arts[0]["id"] in json.loads(pivot_res.stdout)["visited_artifact_ids"]

    assess_res = runner.invoke(
        app,
        [
            "investigation",
            "assess",
            "--investigation",
            inv_id,
            "--json",
            "--db-path",
            str(db_path),
        ],
    )
    assert assess_res.exit_code == 0
    assert "confidence" in json.loads(assess_res.stdout)

    report_out = tmp_path / "report.md"
    report_res = runner.invoke(
        app,
        [
            "investigation",
            "report",
            "--investigation",
            inv_id,
            "--format",
            "markdown",
            "--output",
            str(report_out),
            "--db-path",
            str(db_path),
        ],
    )
    assert report_res.exit_code == 0
    assert report_out.exists()
    assert "CLI End-to-End Check" in report_out.read_text(encoding="utf-8")

    stix_out = tmp_path / "bundle.stix.json"
    export_res = runner.invoke(
        app,
        [
            "investigation",
            "export",
            "--investigation",
            inv_id,
            "--format",
            "stix",
            "--output",
            str(stix_out),
            "--db-path",
            str(db_path),
        ],
    )
    assert export_res.exit_code == 0
    assert stix_out.exists()
    assert json.loads(stix_out.read_text(encoding="utf-8"))["type"] == "bundle"
