"""Tests for ARGOS local web UI server and CLI command."""

from __future__ import annotations

import json
import threading
import time
import urllib.request
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from argos.cli.app import app
from argos.ui.server import create_ui_server, run_ui_server


def _http_json(
    base_url: str,
    path: str,
    method: str = "GET",
    payload: dict | None = None,
) -> tuple[int, dict]:
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {"Content-Type": "application/json"} if body is not None else {}
    req = urllib.request.Request(f"{base_url}{path}", data=body, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=5) as resp:
        return resp.status, json.loads(resp.read().decode("utf-8"))


@pytest.fixture()
def running_ui(tmp_path: Path):
    db_file = tmp_path / "test_argos.sqlite3"
    httpd, url = create_ui_server(db_path=db_file, port=0)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield url.rstrip("/"), db_file
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=2)


def test_ui_full_investigation_workflow(running_ui: tuple[str, Path]) -> None:
    base_url, _ = running_ui

    status, health = _http_json(base_url, "/api/health")
    assert status == 200
    assert health["status"] == "ok"

    with urllib.request.urlopen(f"{base_url}/", timeout=5) as html_resp:
        html = html_resp.read().decode("utf-8")
        assert "ARGOS" in html

    status, created = _http_json(
        base_url,
        "/api/investigations",
        method="POST",
        payload={
            "title": "Campanha Phishing Local",
            "objective": "Mapear infraestrutura inicial",
            "scope": "Domínios e IPs observados",
        },
    )
    assert status == 201
    inv_id = created["investigation"]["id"]

    status, updated = _http_json(
        base_url,
        f"/api/investigations/{inv_id}",
        method="PATCH",
        payload={
            "status": "in_progress",
            "notes": ["Triagem inicial concluída."],
            "limitations": ["Sem telemetria interna de endpoint."],
        },
    )
    assert status == 200
    assert updated["investigation"]["status"] == "in_progress"

    status, collected = _http_json(
        base_url,
        f"/api/investigations/{inv_id}/collect-text",
        method="POST",
        payload={
            "text": "hxxps://c2[.]malicious[.]example/beacon\n203.0.113.10\n",
            "source": "analyst_notes",
            "epistemic_status": "reported",
        },
    )
    assert status == 200
    assert "result" in collected

    status, detail = _http_json(base_url, f"/api/investigations/{inv_id}")
    assert status == 200
    artifacts = detail["artifacts"]
    assert len(artifacts) >= 2

    src_id = artifacts[0]["id"]
    dst_id = artifacts[1]["id"]
    status, rel_resp = _http_json(
        base_url,
        f"/api/investigations/{inv_id}/relations",
        method="POST",
        payload={
            "source_artifact_id": src_id,
            "target_artifact_id": dst_id,
            "relation_type": "associated_with",
            "epistemic_status": "inferred",
            "context": "Coletados no mesmo boletim",
        },
    )
    assert status == 201
    assert rel_resp["relation"]["relation_type"] == "associated_with"

    status, pivot_resp = _http_json(
        base_url,
        f"/api/investigations/{inv_id}/pivot",
        method="POST",
        payload={"artifact_id": src_id, "max_depth": 2, "max_steps": 10},
    )
    assert status == 200
    assert "pivot" in pivot_resp

    status, assess_resp = _http_json(base_url, f"/api/investigations/{inv_id}/assess")
    assert status == 200
    assert "assessment" in assess_resp

    status, md_rep = _http_json(base_url, f"/api/investigations/{inv_id}/report?format=markdown")
    assert status == 200
    assert "Campanha Phishing Local" in md_rep["content"]

    status, csv_exp = _http_json(base_url, f"/api/investigations/{inv_id}/export?format=csv")
    assert status == 200
    assert len(csv_exp["content"]) > 0

    status, stix_exp = _http_json(base_url, f"/api/investigations/{inv_id}/export?format=stix")
    assert status == 200
    stix_bundle = json.loads(stix_exp["content"])
    assert stix_bundle.get("type") == "bundle"


def test_ui_no_browser_flag_skips_webbrowser_open(tmp_path: Path) -> None:
    db_file = tmp_path / "nobrowser.sqlite3"
    runner = CliRunner()

    with (
        patch("argos.ui.server.webbrowser.open") as mock_browser,
        patch("argos.ui.server.ArgosHTTPServer.serve_forever", return_value=None),
    ):
        result = runner.invoke(
            app,
            ["ui", "--db-path", str(db_file), "--port", "0", "--no-browser"],
        )
        assert result.exit_code == 0
        mock_browser.assert_not_called()


def test_run_ui_server_opens_browser_when_enabled(tmp_path: Path) -> None:
    db_file = tmp_path / "openbrowser.sqlite3"
    opened_urls: list[str] = []

    def fake_open(url: str) -> bool:
        opened_urls.append(url)
        return True

    with (
        patch("argos.ui.server.webbrowser.open", side_effect=fake_open),
        patch("argos.ui.server.ArgosHTTPServer.serve_forever", side_effect=lambda: time.sleep(0.25)),
    ):
        run_ui_server(db_path=db_file, port=0, open_browser=True)

    assert len(opened_urls) == 1
    assert opened_urls[0].startswith("http://127.0.0.1:")

def test_ui_reset_database(running_ui: tuple[str, Path]) -> None:
    base_url, _ = running_ui

    status, created = _http_json(
        base_url,
        "/api/investigations",
        method="POST",
        payload={"title": "Caso Temporário", "objective": "Testar reset"},
    )
    assert status == 201
    assert created["investigation"]["id"]

    status, reset_res = _http_json(base_url, "/api/reset", method="POST", payload={})
    assert status == 200
    assert reset_res["status"] == "reset"

    status, listed = _http_json(base_url, "/api/investigations")
    assert status == 200
    assert listed["investigations"] == []
