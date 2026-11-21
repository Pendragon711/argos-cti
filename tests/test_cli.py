import json
import re
from pathlib import Path

from typer.testing import CliRunner

from argos.cli import app
from argos.models import RelationType

runner = CliRunner()


def test_cli_init_and_investigation_lifecycle(tmp_path: Path) -> None:
    db_file = tmp_path / "cli_argos.sqlite3"

    res_init = runner.invoke(app, ["init", "--db-path", str(db_file)])
    assert res_init.exit_code == 0
    assert db_file.exists()

    res_create = runner.invoke(
        app,
        [
            "investigation",
            "create",
            "--title",
            "Suspicious Outbound IP",
            "--objective",
            "Triage indicator observed in logs",
            "--db-path",
            str(db_file),
        ],
    )
    assert res_create.exit_code == 0
    assert "Created investigation" in res_create.stdout

    res_list = runner.invoke(app, ["investigation", "list", "--db-path", str(db_file)])
    assert res_list.exit_code == 0
    assert "Suspicious Outbound IP" in res_list.stdout


def test_cli_artifact_normalization_and_evidence_listing(tmp_path: Path) -> None:
    db_file = tmp_path / "cli_artifacts.sqlite3"

    res_create = runner.invoke(
        app,
        [
            "investigation",
            "create",
            "--title",
            "Honeypot Triage",
            "--db-path",
            str(db_file),
        ],
    )
    assert res_create.exit_code == 0
    match = re.search(r"\binv_[a-f0-9]{12}\b", res_create.stdout)
    assert match is not None
    inv_id = match.group(0)

    res_add = runner.invoke(
        app,
        [
            "artifact",
            "add",
            "--investigation",
            inv_id,
            "--value",
            "hxxps://evil[.]example/stage1",
            "--source",
            "loki_honeypot",
            "--db-path",
            str(db_file),
        ],
    )
    assert res_add.exit_code == 0
    assert "Added artifact" in res_add.stdout
    assert "https://evil.example/stage1" in res_add.stdout

    res_art_list = runner.invoke(
        app,
        ["artifact", "list", "--investigation", inv_id, "--db-path", str(db_file)],
    )
    assert res_art_list.exit_code == 0
    assert "hxxps://evil[.]example/stage1" in res_art_list.stdout

    res_evd_list = runner.invoke(
        app,
        ["evidence", "list", "--investigation", inv_id, "--db-path", str(db_file)],
    )
    assert res_evd_list.exit_code == 0
    assert "observed" in res_evd_list.stdout
    assert "loki_honeypot" in res_evd_list.stdout

    res_missing = runner.invoke(
        app,
        [
            "artifact",
            "add",
            "--investigation",
            "inv_doesnotexist",
            "--value",
            "198.51.100.10",
            "--db-path",
            str(db_file),
        ],
    )
    assert res_missing.exit_code == 1
    assert "Investigation not found" in res_missing.stdout


def test_cli_relation_add_and_list(tmp_path: Path) -> None:
    db_file = tmp_path / "cli_relations.sqlite3"

    res_create = runner.invoke(
        app,
        [
            "investigation",
            "create",
            "--title",
            "Domain Resolution Chain",
            "--db-path",
            str(db_file),
        ],
    )
    assert res_create.exit_code == 0
    match = re.search(r"\binv_[a-f0-9]{12}\b", res_create.stdout)
    assert match is not None
    inv_id = match.group(0)

    res_rel_add = runner.invoke(
        app,
        [
            "relation",
            "add",
            "--investigation",
            inv_id,
            "--source-ref",
            "c2[.]example[.]com",
            "--target-ref",
            "198[.]51[.]100[.]77",
            "--type",
            "resolves_to",
            "--status",
            "observed",
            "--context",
            "DNS resolution observed during scan",
            "--db-path",
            str(db_file),
        ],
    )
    assert res_rel_add.exit_code == 0
    assert "Added relation" in res_rel_add.stdout
    assert "c2.example.com" in res_rel_add.stdout
    assert "198.51.100.77" in res_rel_add.stdout

    res_rel_list = runner.invoke(
        app,
        ["relation", "list", "--investigation", inv_id, "--db-path", str(db_file)],
    )
    assert res_rel_list.exit_code == 0
    assert "resolves_to" in res_rel_list.stdout
    assert "observed" in res_rel_list.stdout


def test_cli_artifact_import_txt_and_json_with_dedup(tmp_path: Path) -> None:
    db_file = tmp_path / "cli_import.sqlite3"
    txt_file = tmp_path / "iocs.txt"
    json_file = tmp_path / "iocs.json"

    txt_file.write_text(
        "# Honeypot offending IPs\n\n203[.]0[.]113[.]50\nmalicious[.]domain[.]org\n",
        encoding="utf-8",
    )
    json_file.write_text(
        json.dumps(
            [
                {
                    "value": "203.0.113.50",
                    "source": "abuseipdb",
                    "status": "reported",
                    "metadata": {"confidence": 95},
                },
                {
                    "value": "as15169",
                    "source": "asn_lookup",
                    "status": "observed",
                },
            ]
        ),
        encoding="utf-8",
    )

    res_create = runner.invoke(
        app,
        [
            "investigation",
            "create",
            "--title",
            "Batch IoC Triage",
            "--db-path",
            str(db_file),
        ],
    )
    assert res_create.exit_code == 0
    match = re.search(r"\binv_[a-f0-9]{12}\b", res_create.stdout)
    assert match is not None
    inv_id = match.group(0)

    res_txt = runner.invoke(
        app,
        [
            "artifact",
            "import",
            "--investigation",
            inv_id,
            "--file",
            str(txt_file),
            "--source",
            "loki_unmatched",
            "--db-path",
            str(db_file),
        ],
    )
    assert res_txt.exit_code == 0
    assert "Imported 2 indicator(s) (new: 2, deduplicated: 0)" in res_txt.stdout

    res_json = runner.invoke(
        app,
        [
            "artifact",
            "import",
            "--investigation",
            inv_id,
            "--file",
            str(json_file),
            "--db-path",
            str(db_file),
        ],
    )
    assert res_json.exit_code == 0
    assert "Imported 2 indicator(s) (new: 1, deduplicated: 1)" in res_json.stdout


def test_cli_investigation_show_and_not_found(tmp_path: Path) -> None:
    db_file = tmp_path / "cli_show.sqlite3"

    res_create = runner.invoke(
        app,
        [
            "investigation",
            "create",
            "--title",
            "Outbound C2 Beacon",
            "--objective",
            "Correlate honeypot IPs and domains",
            "--scope",
            "enois-prod-backend",
            "--db-path",
            str(db_file),
        ],
    )
    assert res_create.exit_code == 0
    match = re.search(r"\binv_[a-f0-9]{12}\b", res_create.stdout)
    assert match is not None
    inv_id = match.group(0)

    runner.invoke(
        app,
        [
            "relation",
            "add",
            "--investigation",
            inv_id,
            "--source-ref",
            "beacon[.]example[.]net",
            "--target-ref",
            "198[.]51[.]100[.]25",
            "--type",
            "resolves_to",
            "--db-path",
            str(db_file),
        ],
    )

    res_show = runner.invoke(
        app,
        ["investigation", "show", "--investigation", inv_id, "--db-path", str(db_file)],
    )
    assert res_show.exit_code == 0
    assert "Outbound C2 Beacon" in res_show.stdout
    assert "Artifacts: 2" in res_show.stdout
    assert "1 relations" in res_show.stdout

    res_missing = runner.invoke(
        app,
        ["investigation", "show", "--investigation", "inv_missing", "--db-path", str(db_file)],
    )
    assert res_missing.exit_code == 1
    assert "Investigation not found" in res_missing.stdout


def test_cli_investigation_export_json_and_markdown(tmp_path: Path) -> None:
    db_file = tmp_path / "cli_export.sqlite3"
    md_out = tmp_path / "report.md"

    res_create = runner.invoke(
        app,
        [
            "investigation",
            "create",
            "--title",
            "Honeypot Infra Correlation",
            "--objective",
            "Map scanner IPs and domains",
            "--scope",
            "loki-honeypot",
            "--db-path",
            str(db_file),
        ],
    )
    assert res_create.exit_code == 0
    match = re.search(r"\binv_[a-f0-9]{12}\b", res_create.stdout)
    assert match is not None
    inv_id = match.group(0)

    runner.invoke(
        app,
        [
            "relation",
            "add",
            "--investigation",
            inv_id,
            "--source-ref",
            "dropper[.]example[.]org",
            "--target-ref",
            "192[.]0[.]2[.]99",
            "--type",
            "resolves_to",
            "--db-path",
            str(db_file),
        ],
    )

    res_json = runner.invoke(
        app,
        [
            "investigation",
            "export",
            "--investigation",
            inv_id,
            "--format",
            "json",
            "--db-path",
            str(db_file),
        ],
    )
    assert res_json.exit_code == 0
    parsed = json.loads(res_json.stdout)
    assert parsed["investigation"]["id"] == inv_id
    assert len(parsed["artifacts"]) == 2
    assert len(parsed["relations"]) == 1

    res_md = runner.invoke(
        app,
        [
            "investigation",
            "export",
            "--investigation",
            inv_id,
            "--format",
            "markdown",
            "--output",
            str(md_out),
            "--db-path",
            str(db_file),
        ],
    )
    assert res_md.exit_code == 0
    assert md_out.exists()
    md_content = md_out.read_text(encoding="utf-8")
    assert f"# Investigation: Honeypot Infra Correlation ({inv_id})" in md_content
    res_upd = runner.invoke(
        app,
        [
            "investigation",
            "update",
            "--investigation",
            inv_id,
            "--note",
            "Matched against honeypot probe logs",
            "--db-path",
            str(db_file),
        ],
    )
    assert res_upd.exit_code == 0

    res_md_enriched = runner.invoke(
        app,
        [
            "investigation",
            "export",
            "--investigation",
            inv_id,
            "--format",
            "markdown",
            "--db-path",
            str(db_file),
        ],
    )
    assert res_md_enriched.exit_code == 0
    assert "dropper.example.org" in res_md_enriched.stdout
    assert "## Evidence" in res_md_enriched.stdout
    assert "cli_link" in res_md_enriched.stdout
    assert "## Notes" in res_md_enriched.stdout
    assert "Matched against honeypot probe logs" in res_md_enriched.stdout


def test_cli_investigation_update_and_reflection(tmp_path: Path) -> None:
    db_file = tmp_path / "cli_update.sqlite3"

    res_create = runner.invoke(
        app,
        [
            "investigation",
            "create",
            "--title",
            "Scanner Triage",
            "--db-path",
            str(db_file),
        ],
    )
    assert res_create.exit_code == 0
    match = re.search(r"\binv_[a-f0-9]{12}\b", res_create.stdout)
    assert match is not None
    inv_id = match.group(0)

    res_upd = runner.invoke(
        app,
        [
            "investigation",
            "update",
            "--investigation",
            inv_id,
            "--status",
            "completed",
            "--conclusion",
            "Automated recon traffic without lateral movement",
            "--limitation",
            "Loki retention window limited to 14 days",
            "--note",
            "Correlated with UNMATCHED HTTP probe spike",
            "--db-path",
            str(db_file),
        ],
    )
    assert res_upd.exit_code == 0
    assert "Updated investigation" in res_upd.stdout
    assert "completed" in res_upd.stdout

    res_show = runner.invoke(
        app,
        ["investigation", "show", "--investigation", inv_id, "--db-path", str(db_file)],
    )
    assert res_show.exit_code == 0
    assert "Automated recon traffic without lateral movement" in res_show.stdout
    assert "Loki retention window limited to 14 days" in res_show.stdout


def test_cli_artifact_list_filters(tmp_path: Path) -> None:
    db_file = tmp_path / "cli_filters.sqlite3"

    res_create = runner.invoke(
        app,
        [
            "investigation",
            "create",
            "--title",
            "Filtered Triage",
            "--db-path",
            str(db_file),
        ],
    )
    assert res_create.exit_code == 0
    match = re.search(r"\binv_[a-f0-9]{12}\b", res_create.stdout)
    assert match is not None
    inv_id = match.group(0)

    for raw_val in ["198.51.100.44", "c2[.]badactor[.]io", "203.0.113.88"]:
        res_add = runner.invoke(
            app,
            [
                "artifact",
                "add",
                "--investigation",
                inv_id,
                "--value",
                raw_val,
                "--db-path",
                str(db_file),
            ],
        )
        assert res_add.exit_code == 0

    res_type = runner.invoke(
        app,
        [
            "artifact",
            "list",
            "--investigation",
            inv_id,
            "--type",
            "ipv4",
            "--db-path",
            str(db_file),
        ],
    )
    assert res_type.exit_code == 0
    assert "198.51.100.44" in res_type.stdout
    assert "203.0.113.88" in res_type.stdout
    assert "c2.badactor.io" not in res_type.stdout

    res_search = runner.invoke(
        app,
        [
            "artifact",
            "list",
            "--investigation",
            inv_id,
            "--search",
            "badactor",
            "--db-path",
            str(db_file),
        ],
    )
    assert res_search.exit_code == 0
    assert "c2.badactor.io" in res_search.stdout
    assert "198.51.100.44" not in res_search.stdout

    res_empty = runner.invoke(
        app,
        [
            "artifact",
            "list",
            "--investigation",
            inv_id,
            "--search",
            "nonexistent-indicator",
            "--db-path",
            str(db_file),
        ],
    )
    assert res_empty.exit_code == 0
    assert "No artifacts found matching criteria." in res_empty.stdout


def test_cli_relation_with_evidence_id_and_validation(tmp_path: Path) -> None:
    db_file = tmp_path / "cli_rel_evd.sqlite3"

    res_create = runner.invoke(
        app,
        [
            "investigation",
            "create",
            "--title",
            "Evidence-Backed Resolution",
            "--db-path",
            str(db_file),
        ],
    )
    assert res_create.exit_code == 0
    match = re.search(r"\binv_[a-f0-9]{12}\b", res_create.stdout)
    assert match is not None
    inv_id = match.group(0)

    res_art = runner.invoke(
        app,
        [
            "artifact",
            "add",
            "--investigation",
            inv_id,
            "--value",
            "pivot[.]example[.]net",
            "--source",
            "loki_honeypot",
            "--db-path",
            str(db_file),
        ],
    )
    assert res_art.exit_code == 0

    res_evd = runner.invoke(
        app,
        ["evidence", "list", "--investigation", inv_id, "--db-path", str(db_file)],
    )
    assert res_evd.exit_code == 0
    evd_match = re.search(r"\bevd_[a-f0-9]{12}\b", res_evd.stdout)
    assert evd_match is not None
    evd_id = evd_match.group(0)

    res_bad_evd = runner.invoke(
        app,
        [
            "relation",
            "add",
            "--investigation",
            inv_id,
            "--source-ref",
            "pivot[.]example[.]net",
            "--target-ref",
            "198[.]51[.]100[.]120",
            "--evidence-id",
            "evd_doesnotexist",
            "--db-path",
            str(db_file),
        ],
    )
    assert res_bad_evd.exit_code == 1
    assert "Evidence not found in investigation" in res_bad_evd.stdout

    res_rel = runner.invoke(
        app,
        [
            "relation",
            "add",
            "--investigation",
            inv_id,
            "--source-ref",
            "pivot[.]example[.]net",
            "--target-ref",
            "198[.]51[.]100[.]120",
            "--type",
            "resolves_to",
            "--evidence-id",
            evd_id,
            "--db-path",
            str(db_file),
        ],
    )
    assert res_rel.exit_code == 0

    res_rel_list = runner.invoke(
        app,
        ["relation", "list", "--investigation", inv_id, "--db-path", str(db_file)],
    )
    assert res_rel_list.exit_code == 0
    assert evd_id in res_rel_list.stdout

    res_md = runner.invoke(
        app,
        [
            "investigation",
            "export",
            "--investigation",
            inv_id,
            "--format",
            "markdown",
            "--db-path",
            str(db_file),
        ],
    )
    assert res_md.exit_code == 0
    assert f"[evidence: `{evd_id}`]" in res_md.stdout
    assert "pivot[.]example[.]net" in res_md.stdout or "pivot.example.net" in res_md.stdout


def test_cli_artifact_import_json_items_envelope(tmp_path: Path) -> None:
    db_file = tmp_path / "cli_import_items.sqlite3"
    json_file = tmp_path / "enrichment_items.json"

    res_create = runner.invoke(
        app,
        [
            "investigation",
            "create",
            "--title",
            "Enrichment Envelope Triage",
            "--db-path",
            str(db_file),
        ],
    )
    assert res_create.exit_code == 0
    match = re.search(r"\binv_[a-f0-9]{12}\b", res_create.stdout)
    assert match is not None
    inv_id = match.group(0)

    payload = {
        "items": [
            {
                "value": "198[.]51[.]100[.]200",
                "source": "abuseipdb",
                "status": "observed",
                "metadata": {"confidence_score": 95},
            },
            {
                "value": "stage2[.]badactor[.]org",
                "source": "otx",
                "status": "inferred",
                "metadata": {"pulse_count": 3},
            },
        ]
    }
    json_file.write_text(json.dumps(payload), encoding="utf-8")

    res_imp = runner.invoke(
        app,
        [
            "artifact",
            "import",
            "--investigation",
            inv_id,
            "--file",
            str(json_file),
            "--db-path",
            str(db_file),
        ],
    )
    assert res_imp.exit_code == 0

    res_list = runner.invoke(
        app,
        ["artifact", "list", "--investigation", inv_id, "--db-path", str(db_file)],
    )
    assert res_list.exit_code == 0
    assert "198.51.100.200" in res_list.stdout
    assert "stage2.badactor.org" in res_list.stdout


def test_cli_artifact_import_deduplication_summary(tmp_path: Path) -> None:
    db_file = tmp_path / "cli_import_dedup.sqlite3"
    txt_file = tmp_path / "indicators.txt"
    txt_file.write_text("198.51.100.55\n198[.]51[.]100[.]55\n", encoding="utf-8")

    res_create = runner.invoke(
        app,
        [
            "investigation",
            "create",
            "--title",
            "Import Dedup Check",
            "--db-path",
            str(db_file),
        ],
    )
    assert res_create.exit_code == 0
    match = re.search(r"\binv_[a-f0-9]{12}\b", res_create.stdout)
    assert match is not None
    inv_id = match.group(0)

    res_imp = runner.invoke(
        app,
        [
            "artifact",
            "import",
            "--investigation",
            inv_id,
            "--file",
            str(txt_file),
            "--db-path",
            str(db_file),
        ],
    )
    assert res_imp.exit_code == 0
    assert "Imported 2 indicator(s)" in res_imp.stdout
    assert "new: 1" in res_imp.stdout
    assert "deduplicated: 1" in res_imp.stdout


def test_cli_relation_list_type_filter(tmp_path: Path) -> None:
    db_file = tmp_path / "cli_rel_filter.sqlite3"
    rel_types = list(RelationType)
    assert len(rel_types) >= 2
    t1 = rel_types[0].value
    t2 = rel_types[1].value
    t_unused = rel_types[2].value if len(rel_types) > 2 else t2

    res_create = runner.invoke(
        app,
        [
            "investigation",
            "create",
            "--title",
            "Relation Type Filter",
            "--db-path",
            str(db_file),
        ],
    )
    assert res_create.exit_code == 0
    match = re.search(r"\binv_[a-f0-9]{12}\b", res_create.stdout)
    assert match is not None
    inv_id = match.group(0)

    res_r1 = runner.invoke(
        app,
        [
            "relation",
            "add",
            "--investigation",
            inv_id,
            "--source-ref",
            "pivot[.]example[.]net",
            "--target-ref",
            "198[.]51[.]100[.]120",
            "--type",
            t1,
            "--db-path",
            str(db_file),
        ],
    )
    assert res_r1.exit_code == 0

    res_r2 = runner.invoke(
        app,
        [
            "relation",
            "add",
            "--investigation",
            inv_id,
            "--source-ref",
            "198[.]51[.]100[.]120",
            "--target-ref",
            "c2[.]badactor[.]io",
            "--type",
            t2,
            "--db-path",
            str(db_file),
        ],
    )
    assert res_r2.exit_code == 0

    res_filtered = runner.invoke(
        app,
        [
            "relation",
            "list",
            "--investigation",
            inv_id,
            "--type",
            t1,
            "--db-path",
            str(db_file),
        ],
    )
    assert res_filtered.exit_code == 0
    assert t1 in res_filtered.stdout
    if t2 != t1:
        assert t2 not in res_filtered.stdout

    if t_unused not in {t1, t2}:
        res_empty = runner.invoke(
            app,
            [
                "relation",
                "list",
                "--investigation",
                inv_id,
                "--type",
                t_unused,
                "--db-path",
                str(db_file),
            ],
        )
        assert res_empty.exit_code == 0
        assert "No relations found" in res_empty.stdout


def test_cli_relation_list_status_filter(tmp_path: Path) -> None:
    db_file = tmp_path / "cli_rel_status_filter.sqlite3"
    rel_type = next(iter(RelationType)).value

    res_create = runner.invoke(
        app,
        [
            "investigation",
            "create",
            "--title",
            "Relation Status Filter",
            "--db-path",
            str(db_file),
        ],
    )
    assert res_create.exit_code == 0
    match = re.search(r"\binv_[a-f0-9]{12}\b", res_create.stdout)
    assert match is not None
    inv_id = match.group(0)

    res_obs = runner.invoke(
        app,
        [
            "relation",
            "add",
            "--investigation",
            inv_id,
            "--source-ref",
            "pivot[.]example[.]net",
            "--target-ref",
            "198[.]51[.]100[.]120",
            "--type",
            rel_type,
            "--status",
            "observed",
            "--db-path",
            str(db_file),
        ],
    )
    assert res_obs.exit_code == 0

    res_inf = runner.invoke(
        app,
        [
            "relation",
            "add",
            "--investigation",
            inv_id,
            "--source-ref",
            "198[.]51[.]100[.]120",
            "--target-ref",
            "c2[.]badactor[.]io",
            "--type",
            rel_type,
            "--status",
            "inferred",
            "--db-path",
            str(db_file),
        ],
    )
    assert res_inf.exit_code == 0

    res_filtered = runner.invoke(
        app,
        [
            "relation",
            "list",
            "--investigation",
            inv_id,
            "--status",
            "observed",
            "--db-path",
            str(db_file),
        ],
    )
    assert res_filtered.exit_code == 0
    assert "observed" in res_filtered.stdout
    assert "inferred" not in res_filtered.stdout


def test_cli_evidence_list_status_filter(tmp_path: Path) -> None:
    db_file = tmp_path / "cli_evd_status_filter.sqlite3"

    res_create = runner.invoke(
        app,
        [
            "investigation",
            "create",
            "--title",
            "Evidence Status Filter",
            "--db-path",
            str(db_file),
        ],
    )
    assert res_create.exit_code == 0
    match = re.search(r"\binv_[a-f0-9]{12}\b", res_create.stdout)
    assert match is not None
    inv_id = match.group(0)

    res_a1 = runner.invoke(
        app,
        [
            "artifact",
            "add",
            "--investigation",
            inv_id,
            "--value",
            "198[.]51[.]100[.]77",
            "--status",
            "observed",
            "--source",
            "loki",
            "--db-path",
            str(db_file),
        ],
    )
    assert res_a1.exit_code == 0

    res_a2 = runner.invoke(
        app,
        [
            "artifact",
            "add",
            "--investigation",
            inv_id,
            "--value",
            "c2-rep[.]example[.]org",
            "--status",
            "reported",
            "--source",
            "otx-feed",
            "--db-path",
            str(db_file),
        ],
    )
    assert res_a2.exit_code == 0

    res_obs = runner.invoke(
        app,
        [
            "evidence",
            "list",
            "--investigation",
            inv_id,
            "--status",
            "observed",
            "--db-path",
            str(db_file),
        ],
    )
    assert res_obs.exit_code == 0
    assert "observed" in res_obs.stdout
    assert "reported" not in res_obs.stdout

    res_inf = runner.invoke(
        app,
        [
            "evidence",
            "list",
            "--investigation",
            inv_id,
            "--status",
            "unverified",
            "--db-path",
            str(db_file),
        ],
    )
    assert res_inf.exit_code == 0
    assert "No evidence" in res_inf.stdout


def test_cli_evidence_list_source_filter(tmp_path: Path) -> None:
    db_file = tmp_path / "cli_evd_source_filter.sqlite3"

    res_create = runner.invoke(
        app,
        [
            "investigation",
            "create",
            "--title",
            "Evidence Source Filter",
            "--db-path",
            str(db_file),
        ],
    )
    assert res_create.exit_code == 0
    match = re.search(r"\binv_[a-f0-9]{12}\b", res_create.stdout)
    assert match is not None
    inv_id = match.group(0)

    res_a1 = runner.invoke(
        app,
        [
            "artifact",
            "add",
            "--investigation",
            inv_id,
            "--value",
            "198[.]51[.]100[.]88",
            "--source",
            "loki",
            "--db-path",
            str(db_file),
        ],
    )
    assert res_a1.exit_code == 0

    res_a2 = runner.invoke(
        app,
        [
            "artifact",
            "add",
            "--investigation",
            inv_id,
            "--value",
            "c2-src[.]example[.]net",
            "--source",
            "otx",
            "--db-path",
            str(db_file),
        ],
    )
    assert res_a2.exit_code == 0

    res_loki = runner.invoke(
        app,
        [
            "evidence",
            "list",
            "--investigation",
            inv_id,
            "--source",
            "LOKI",
            "--db-path",
            str(db_file),
        ],
    )
    assert res_loki.exit_code == 0
    assert "loki" in res_loki.stdout.lower()
    assert "otx" not in res_loki.stdout.lower()

    res_missing = runner.invoke(
        app,
        [
            "evidence",
            "list",
            "--investigation",
            inv_id,
            "--source",
            "crowdsec",
            "--db-path",
            str(db_file),
        ],
    )
    assert res_missing.exit_code == 0
    assert "No evidence" in res_missing.stdout


def test_cli_list_commands_json_output(tmp_path: Path) -> None:
    db_file = tmp_path / "cli_json_output.sqlite3"
    rel_type = next(iter(RelationType)).value

    res_create = runner.invoke(
        app,
        [
            "investigation",
            "create",
            "--title",
            "JSON Output Check",
            "--db-path",
            str(db_file),
        ],
    )
    assert res_create.exit_code == 0
    match = re.search(r"\binv_[a-f0-9]{12}\b", res_create.stdout)
    assert match is not None
    inv_id = match.group(0)

    res_a1 = runner.invoke(
        app,
        [
            "artifact",
            "add",
            "--investigation",
            inv_id,
            "--value",
            "198[.]51[.]100[.]99",
            "--source",
            "loki",
            "--db-path",
            str(db_file),
        ],
    )
    assert res_a1.exit_code == 0

    res_a2 = runner.invoke(
        app,
        [
            "artifact",
            "add",
            "--investigation",
            inv_id,
            "--value",
            "c2-json[.]example[.]org",
            "--source",
            "otx",
            "--db-path",
            str(db_file),
        ],
    )
    assert res_a2.exit_code == 0

    res_rel = runner.invoke(
        app,
        [
            "relation",
            "add",
            "--investigation",
            inv_id,
            "--source-ref",
            "198[.]51[.]100[.]99",
            "--target-ref",
            "c2-json[.]example[.]org",
            "--type",
            rel_type,
            "--db-path",
            str(db_file),
        ],
    )
    assert res_rel.exit_code == 0

    art_json = runner.invoke(
        app,
        ["artifact", "list", "--investigation", inv_id, "--json", "--db-path", str(db_file)],
    )
    assert art_json.exit_code == 0
    parsed_art = json.loads(art_json.stdout)
    assert isinstance(parsed_art, list)
    assert len(parsed_art) == 2

    evd_json = runner.invoke(
        app,
        ["evidence", "list", "--investigation", inv_id, "--json", "--db-path", str(db_file)],
    )
    assert evd_json.exit_code == 0
    parsed_evd = json.loads(evd_json.stdout)
    assert isinstance(parsed_evd, list)
    assert len(parsed_evd) == 2

    rel_json = runner.invoke(
        app,
        ["relation", "list", "--investigation", inv_id, "--json", "--db-path", str(db_file)],
    )
    assert rel_json.exit_code == 0
    parsed_rel = json.loads(rel_json.stdout)
    assert isinstance(parsed_rel, list)
    assert len(parsed_rel) == 1

    empty_rel_json = runner.invoke(
        app,
        [
            "relation",
            "list",
            "--investigation",
            inv_id,
            "--status",
            "unverified",
            "--json",
            "--db-path",
            str(db_file),
        ],
    )
    assert empty_rel_json.exit_code == 0
    assert json.loads(empty_rel_json.stdout) == []


def test_cli_relation_list_artifact_filter(tmp_path: Path) -> None:
    db_file = tmp_path / "cli_rel_artifact_filter.sqlite3"
    rel_type = next(iter(RelationType)).value

    res_create = runner.invoke(
        app,
        [
            "investigation",
            "create",
            "--title",
            "Relation Artifact Filter",
            "--db-path",
            str(db_file),
        ],
    )
    assert res_create.exit_code == 0
    match = re.search(r"\binv_[a-f0-9]{12}\b", res_create.stdout)
    assert match is not None
    inv_id = match.group(0)

    res_r1 = runner.invoke(
        app,
        [
            "relation",
            "add",
            "--investigation",
            inv_id,
            "--source-ref",
            "pivot-a[.]example[.]net",
            "--target-ref",
            "198[.]51[.]100[.]50",
            "--type",
            rel_type,
            "--db-path",
            str(db_file),
        ],
    )
    assert res_r1.exit_code == 0

    res_r2 = runner.invoke(
        app,
        [
            "relation",
            "add",
            "--investigation",
            inv_id,
            "--source-ref",
            "198[.]51[.]100[.]50",
            "--target-ref",
            "c2-b[.]example[.]org",
            "--type",
            rel_type,
            "--db-path",
            str(db_file),
        ],
    )
    assert res_r2.exit_code == 0

    res_r3 = runner.invoke(
        app,
        [
            "relation",
            "add",
            "--investigation",
            inv_id,
            "--source-ref",
            "unrelated-src[.]example[.]com",
            "--target-ref",
            "unrelated-dst[.]example[.]com",
            "--type",
            rel_type,
            "--db-path",
            str(db_file),
        ],
    )
    assert res_r3.exit_code == 0

    res_pivot = runner.invoke(
        app,
        [
            "relation",
            "list",
            "--investigation",
            inv_id,
            "--artifact",
            "198.51.100.50",
            "--db-path",
            str(db_file),
        ],
    )
    assert res_pivot.exit_code == 0
    assert "pivot-a.example.net" in res_pivot.stdout
    assert "c2-b.example.org" in res_pivot.stdout
    assert "unrelated-src.example.com" not in res_pivot.stdout

    res_none = runner.invoke(
        app,
        [
            "relation",
            "list",
            "--investigation",
            inv_id,
            "--artifact",
            "nonexistent[.]example[.]invalid",
            "--db-path",
            str(db_file),
        ],
    )
    assert res_none.exit_code == 0
    assert "No relations" in res_none.stdout


def test_cli_artifact_list_source_filter(tmp_path: Path) -> None:
    db_file = tmp_path / "cli_art_source_filter.sqlite3"

    res_create = runner.invoke(
        app,
        [
            "investigation",
            "create",
            "--title",
            "Artifact Source Filter",
            "--db-path",
            str(db_file),
        ],
    )
    assert res_create.exit_code == 0
    match = re.search(r"\binv_[a-f0-9]{12}\b", res_create.stdout)
    assert match is not None
    inv_id = match.group(0)

    res_a1 = runner.invoke(
        app,
        [
            "artifact",
            "add",
            "--investigation",
            inv_id,
            "--value",
            "198[.]51[.]100[.]120",
            "--source",
            "loki",
            "--db-path",
            str(db_file),
        ],
    )
    assert res_a1.exit_code == 0

    res_a2 = runner.invoke(
        app,
        [
            "artifact",
            "add",
            "--investigation",
            inv_id,
            "--value",
            "c2-art[.]example[.]org",
            "--source",
            "otx",
            "--db-path",
            str(db_file),
        ],
    )
    assert res_a2.exit_code == 0

    res_loki = runner.invoke(
        app,
        [
            "artifact",
            "list",
            "--investigation",
            inv_id,
            "--source",
            "LOKI",
            "--db-path",
            str(db_file),
        ],
    )
    assert res_loki.exit_code == 0
    assert "198.51.100.120" in res_loki.stdout
    assert "c2-art.example.org" not in res_loki.stdout

    res_missing = runner.invoke(
        app,
        [
            "artifact",
            "list",
            "--investigation",
            inv_id,
            "--source",
            "crowdsec",
            "--db-path",
            str(db_file),
        ],
    )
    assert res_missing.exit_code == 0
    assert "No artifacts found matching criteria" in res_missing.stdout


def test_cli_artifact_list_status_filter(tmp_path: Path) -> None:
    db_file = tmp_path / "cli_art_status_filter.sqlite3"

    res_create = runner.invoke(
        app,
        [
            "investigation",
            "create",
            "--title",
            "Artifact Status Filter",
            "--db-path",
            str(db_file),
        ],
    )
    assert res_create.exit_code == 0
    match = re.search(r"\binv_[a-f0-9]{12}\b", res_create.stdout)
    assert match is not None
    inv_id = match.group(0)

    res_a1 = runner.invoke(
        app,
        [
            "artifact",
            "add",
            "--investigation",
            inv_id,
            "--value",
            "198[.]51[.]100[.]140",
            "--status",
            "observed",
            "--source",
            "loki",
            "--db-path",
            str(db_file),
        ],
    )
    assert res_a1.exit_code == 0

    res_a2 = runner.invoke(
        app,
        [
            "artifact",
            "add",
            "--investigation",
            inv_id,
            "--value",
            "c2-status[.]example[.]org",
            "--status",
            "reported",
            "--source",
            "otx",
            "--db-path",
            str(db_file),
        ],
    )
    assert res_a2.exit_code == 0

    res_obs = runner.invoke(
        app,
        [
            "artifact",
            "list",
            "--investigation",
            inv_id,
            "--status",
            "observed",
            "--db-path",
            str(db_file),
        ],
    )
    assert res_obs.exit_code == 0
    assert "198.51.100.140" in res_obs.stdout
    assert "c2-status.example.org" not in res_obs.stdout

    res_unv = runner.invoke(
        app,
        [
            "artifact",
            "list",
            "--investigation",
            inv_id,
            "--status",
            "unverified",
            "--db-path",
            str(db_file),
        ],
    )
    assert res_unv.exit_code == 0
    assert "No artifacts found matching criteria" in res_unv.stdout


def test_cli_evidence_list_artifact_filter(tmp_path: Path) -> None:
    db_file = tmp_path / "cli_evd_artifact_filter.sqlite3"

    res_create = runner.invoke(
        app,
        [
            "investigation",
            "create",
            "--title",
            "Evidence Artifact Filter",
            "--db-path",
            str(db_file),
        ],
    )
    assert res_create.exit_code == 0
    match = re.search(r"\binv_[a-f0-9]{12}\b", res_create.stdout)
    assert match is not None
    inv_id = match.group(0)

    res_a1 = runner.invoke(
        app,
        [
            "artifact",
            "add",
            "--investigation",
            inv_id,
            "--value",
            "198[.]51[.]100[.]160",
            "--source",
            "loki",
            "--db-path",
            str(db_file),
        ],
    )
    assert res_a1.exit_code == 0

    res_a2 = runner.invoke(
        app,
        [
            "artifact",
            "add",
            "--investigation",
            inv_id,
            "--value",
            "c2-evd[.]example[.]org",
            "--source",
            "otx",
            "--db-path",
            str(db_file),
        ],
    )
    assert res_a2.exit_code == 0

    res_filtered = runner.invoke(
        app,
        [
            "evidence",
            "list",
            "--investigation",
            inv_id,
            "--artifact",
            "198.51.100.160",
            "--db-path",
            str(db_file),
        ],
    )
    assert res_filtered.exit_code == 0
    assert "loki" in res_filtered.stdout.lower()
    assert "otx" not in res_filtered.stdout.lower()

    res_none = runner.invoke(
        app,
        [
            "evidence",
            "list",
            "--investigation",
            inv_id,
            "--artifact",
            "nonexistent[.]example[.]invalid",
            "--db-path",
            str(db_file),
        ],
    )
    assert res_none.exit_code == 0
    assert "No evidence" in res_none.stdout
