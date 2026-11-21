"""Local-first HTTP server and JSON API for ARGOS."""

from __future__ import annotations

import dataclasses
import enum
import json
import mimetypes
import socket
import tempfile
import threading
import urllib.parse
import webbrowser
from datetime import UTC, datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from argos.collectors import CollectedRecord
from argos.core import ArgosConfig, SQLiteStorage
from argos.models import (
    EpistemicStatus,
    InvestigationStatus,
    Relation,
    RelationType,
)
from argos.pivot import PivotConfig
from argos.workflow import InvestigationWorkflow

STATIC_DIR = Path(__file__).resolve().parent / "static"


def _serialize(obj: Any) -> Any:
    """Recursively serialize Pydantic models, dataclasses, enums, and datetimes."""
    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, enum.Enum):
        return obj.value
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, Path):
        return str(obj)
    if hasattr(obj, "model_dump"):
        return _serialize(obj.model_dump())
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {k: _serialize(v) for k, v in dataclasses.asdict(obj).items()}
    if isinstance(obj, dict):
        return {str(k): _serialize(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [_serialize(item) for item in obj]
    if hasattr(obj, "__dict__"):
        return {
            k: _serialize(v)
            for k, v in vars(obj).items()
            if not k.startswith("_")
        }
    return str(obj)


def _parse_epistemic(raw: Any, default: EpistemicStatus) -> EpistemicStatus:
    if not raw:
        return default
    return EpistemicStatus(str(raw).strip().lower())


def _parse_status(raw: Any, default: InvestigationStatus) -> InvestigationStatus:
    if not raw:
        return default
    val = str(raw).strip().lower()
    if val == "closed":
        return InvestigationStatus.COMPLETED
    return InvestigationStatus(val)


def _normalize_str_list(raw: Any) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, list):
        return [str(x).strip() for x in raw if str(x).strip()]
    if isinstance(raw, str):
        return [line.strip() for line in raw.splitlines() if line.strip()]
    return [str(raw).strip()]


class ArgosUIState:
    """Thread-safe wrapper around SQLiteStorage and InvestigationWorkflow."""

    def __init__(self, db_path: Path | str | None = None) -> None:
        cfg = ArgosConfig()
        cfg.ensure_dirs()
        self.db_path = Path(db_path) if db_path is not None else cfg.db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.storage = SQLiteStorage(self.db_path)
        self.workflow = InvestigationWorkflow(self.storage)

    def list_investigations(self) -> list[dict[str, Any]]:
        with self.lock:
            return _serialize(self.storage.list_investigations())

    def create_investigation(self, payload: dict[str, Any]) -> dict[str, Any]:
        title = (payload.get("title") or "").strip()
        if not title:
            raise ValueError("Investigation 'title' is required.")
        objective = (payload.get("objective") or "").strip()
        scope = (payload.get("scope") or "").strip()
        with self.lock:
            inv = self.workflow.create_investigation(
                title=title,
                objective=objective,
                scope=scope,
            )
            return _serialize(inv)

    def get_investigation_detail(self, inv_id: str) -> dict[str, Any]:
        with self.lock:
            inv = self.storage.get_investigation(inv_id)
            if inv is None:
                raise KeyError(f"Investigation '{inv_id}' not found.")
            return {
                "investigation": _serialize(inv),
                "artifacts": _serialize(self.storage.list_artifacts(inv_id)),
                "evidences": _serialize(self.storage.list_evidences(inv_id)),
                "relations": _serialize(self.storage.list_relations(inv_id)),
            }

    def update_investigation(self, inv_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        with self.lock:
            inv = self.storage.get_investigation(inv_id)
            if inv is None:
                raise KeyError(f"Investigation '{inv_id}' not found.")

            if "title" in payload and str(payload["title"]).strip():
                inv.title = str(payload["title"]).strip()
            if "objective" in payload:
                inv.objective = str(payload["objective"] or "").strip()
            if "scope" in payload:
                inv.scope = str(payload["scope"] or "").strip()
            if "status" in payload and payload["status"] is not None:
                inv.status = _parse_status(payload["status"], inv.status)
            if "notes" in payload:
                inv.notes = _normalize_str_list(payload["notes"])
            if "conclusion" in payload:
                inv.conclusion = str(payload["conclusion"] or "").strip()
            if "limitations" in payload:
                inv.limitations = _normalize_str_list(payload["limitations"])

            inv.updated_at = datetime.now(UTC)
            self.storage.save_investigation(inv)
            return _serialize(inv)

    def collect_text(self, inv_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        raw_text = (payload.get("text") or "").strip()
        if not raw_text:
            raise ValueError("Field 'text' cannot be empty.")
        source = (payload.get("source") or "manual_paste").strip()
        ep_status = _parse_epistemic(payload.get("epistemic_status"), EpistemicStatus.OBSERVED)

        records = [
            CollectedRecord(
                raw_value=line.strip(),
                source=source,
                collection_method="manual_text",
                metadata={"input_mode": "text"},
            )
            for line in raw_text.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        if not records:
            raise ValueError("No non-comment indicator lines found in 'text'.")

        with self.lock:
            if self.storage.get_investigation(inv_id) is None:
                raise KeyError(f"Investigation '{inv_id}' not found.")
            summary = self.workflow.ingest_records(
                investigation_id=inv_id,
                records=records,
                epistemic_status=ep_status,
                source_override=source,
            )
            return _serialize(summary)

    def collect_file(self, inv_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        file_path_str = (payload.get("file_path") or "").strip()
        file_content = payload.get("content")
        file_name = (payload.get("file_name") or "uploaded_iocs.txt").strip()
        ep_status = _parse_epistemic(payload.get("epistemic_status"), EpistemicStatus.OBSERVED)

        with self.lock:
            if self.storage.get_investigation(inv_id) is None:
                raise KeyError(f"Investigation '{inv_id}' not found.")

            if file_content is not None:
                suffix = Path(file_name).suffix or ".txt"
                with tempfile.NamedTemporaryFile(
                    mode="w",
                    encoding="utf-8",
                    prefix="argos_upload_",
                    suffix=suffix,
                    delete=True,
                ) as tmp:
                    tmp.write(str(file_content))
                    tmp.flush()
                    summary = self.workflow.collect_from_local_file(
                        investigation_id=inv_id,
                        file_path=Path(tmp.name),
                        epistemic_status=ep_status,
                    )
                return _serialize(summary)

            if not file_path_str:
                raise ValueError("Provide either 'file_path' or 'content'.")
            target = Path(file_path_str).expanduser()
            if not target.is_file():
                raise FileNotFoundError(f"Local file not found: {target}")

            summary = self.workflow.collect_from_local_file(
                investigation_id=inv_id,
                file_path=target,
                epistemic_status=ep_status,
            )
            return _serialize(summary)

    def collect_feed(self, inv_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        url = (payload.get("url") or "").strip()
        if not url:
            raise ValueError("Feed 'url' is required.")
        feed_name = (payload.get("source") or payload.get("feed_name") or "public_feed").strip()
        ep_status = _parse_epistemic(payload.get("epistemic_status"), EpistemicStatus.REPORTED)

        with self.lock:
            if self.storage.get_investigation(inv_id) is None:
                raise KeyError(f"Investigation '{inv_id}' not found.")
            summary = self.workflow.collect_from_public_feed(
                investigation_id=inv_id,
                feed_name=feed_name,
                feed_url=url,
                epistemic_status=ep_status,
            )
            return _serialize(summary)

    def create_relation(self, inv_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        source_id = (payload.get("source_artifact_id") or "").strip()
        target_id = (payload.get("target_artifact_id") or "").strip()
        raw_rel_type = (payload.get("relation_type") or "").strip().lower()
        context = (payload.get("context") or "").strip()
        evidence_id = payload.get("evidence_id") or None
        ep_status = _parse_epistemic(payload.get("epistemic_status"), EpistemicStatus.INFERRED)

        if not source_id or not target_id or not raw_rel_type:
            raise ValueError(
                "'source_artifact_id', 'target_artifact_id', and 'relation_type' are required."
            )

        rel_type = RelationType(raw_rel_type)
        with self.lock:
            if self.storage.get_investigation(inv_id) is None:
                raise KeyError(f"Investigation '{inv_id}' not found.")
            rel = Relation(
                investigation_id=inv_id,
                source_artifact_id=source_id,
                target_artifact_id=target_id,
                relation_type=rel_type,
                epistemic_status=ep_status,
                source="argos.ui",
                evidence_id=evidence_id,
                context=context,
            )
            self.storage.save_relation(rel)
            return _serialize(rel)

    def run_pivot(self, inv_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        artifact_id = (payload.get("artifact_id") or "").strip()
        if not artifact_id:
            raise ValueError("Seed 'artifact_id' is required for pivot.")
        max_depth = int(payload.get("max_depth", 2))
        max_steps = int(payload.get("max_steps", 25))
        if max_depth < 1 or max_steps < 1:
            raise ValueError("'max_depth' and 'max_steps' must be positive integers.")

        config = PivotConfig(max_depth=max_depth, max_steps=max_steps)
        with self.lock:
            if self.storage.get_investigation(inv_id) is None:
                raise KeyError(f"Investigation '{inv_id}' not found.")
            summary = self.workflow.pivot(
                investigation_id=inv_id,
                seed_artifact_ids=[artifact_id],
                config=config,
            )
            return _serialize(summary)

    def run_assessment(self, inv_id: str) -> dict[str, Any]:
        with self.lock:
            if self.storage.get_investigation(inv_id) is None:
                raise KeyError(f"Investigation '{inv_id}' not found.")
            assessment = self.workflow.assess(investigation_id=inv_id)
            return _serialize(assessment)

    def generate_report(self, inv_id: str, fmt: str) -> str:
        fmt_norm = fmt.lower().strip()
        if fmt_norm in {"md", "markdown"}:
            target = "markdown"
        elif fmt_norm == "json":
            target = "json"
        else:
            raise ValueError("Report format must be 'markdown' or 'json'.")

        with self.lock:
            return self.workflow.generate_report(investigation_id=inv_id, fmt=target)

    def export_data(self, inv_id: str, fmt: str) -> str:
        fmt_norm = fmt.lower().strip()
        if fmt_norm not in {"csv", "stix"}:
            raise ValueError("Export format must be 'csv' or 'stix'.")

        with self.lock:
            return self.workflow.export_investigation(investigation_id=inv_id, fmt=fmt_norm)


    def reset_database(self) -> dict[str, Any]:
        with self.lock:
            close_fn = getattr(self.storage, "close", None)
            if callable(close_fn):
                close_fn()
            for suffix in ("", "-wal", "-shm", "-journal"):
                candidate = Path(f"{self.db_path}{suffix}")
                if candidate.exists():
                    candidate.unlink()
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self.storage = SQLiteStorage(self.db_path)
            self.workflow = InvestigationWorkflow(self.storage)
            return {"status": "reset", "db_path": str(self.db_path)}


class ArgosHTTPServer(ThreadingHTTPServer):
    """Local-only HTTP server holding shared ArgosUIState."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address: tuple[str, int], state: ArgosUIState) -> None:
        self.state = state
        super().__init__(server_address, ArgosRequestHandler)


class ArgosRequestHandler(BaseHTTPRequestHandler):
    """HTTP handler serving local static assets and JSON REST routes."""

    server: ArgosHTTPServer

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _send_json(self, status: int, data: Any) -> None:
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_text(
        self,
        status: int,
        text: str,
        content_type: str,
        filename: str | None = None,
    ) -> None:
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if filename:
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length == 0:
            return {}
        raw = self.rfile.read(length).decode("utf-8")
        parsed = json.loads(raw)
        if not isinstance(parsed, dict):
            raise TypeError("JSON request body must be an object.")
        return parsed

    def _serve_static(self, rel_path: str) -> None:
        clean = rel_path.lstrip("/") or "index.html"
        target = (STATIC_DIR / clean).resolve()
        if not str(target).startswith(str(STATIC_DIR.resolve())) or not target.is_file():
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "Static asset not found."})
            return
        mime, _ = mimetypes.guess_type(str(target))
        content = target.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", f"{mime or 'application/octet-stream'}; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(content)

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        try:
            if path == "/api/health":
                self._send_json(
                    HTTPStatus.OK,
                    {"status": "ok", "db_path": str(self.server.state.db_path)},
                )
                return

            if path == "/api/investigations":
                items = self.server.state.list_investigations()
                self._send_json(HTTPStatus.OK, {"investigations": items})
                return

            parts = [p for p in path.split("/") if p]
            if len(parts) >= 3 and parts[0] == "api" and parts[1] == "investigations":
                inv_id = urllib.parse.unquote(parts[2])
                if len(parts) == 3:
                    detail = self.server.state.get_investigation_detail(inv_id)
                    self._send_json(HTTPStatus.OK, detail)
                    return
                action = parts[3]
                if action == "assess":
                    assessment = self.server.state.run_assessment(inv_id)
                    self._send_json(HTTPStatus.OK, {"assessment": assessment})
                    return
                if action == "report":
                    fmt = (query.get("format") or ["markdown"])[0]
                    content = self.server.state.generate_report(inv_id, fmt)
                    if (query.get("download") or ["0"])[0] == "1":
                        ext = "json" if fmt.lower() == "json" else "md"
                        ctype = "application/json" if ext == "json" else "text/markdown"
                        self._send_text(
                            HTTPStatus.OK,
                            content,
                            ctype,
                            filename=f"argos-report-{inv_id[:12]}.{ext}",
                        )
                    else:
                        self._send_json(HTTPStatus.OK, {"format": fmt, "content": content})
                    return
                if action == "export":
                    fmt = (query.get("format") or ["csv"])[0]
                    content = self.server.state.export_data(inv_id, fmt)
                    if (query.get("download") or ["0"])[0] == "1":
                        ext = "json" if fmt.lower() == "stix" else "csv"
                        ctype = "application/stix+json" if ext == "json" else "text/csv"
                        self._send_text(
                            HTTPStatus.OK,
                            content,
                            ctype,
                            filename=f"argos-export-{inv_id[:12]}.{ext}",
                        )
                    else:
                        self._send_json(HTTPStatus.OK, {"format": fmt, "content": content})
                    return

            if not path.startswith("/api/"):
                self._serve_static(path)
                return

            self._send_json(HTTPStatus.NOT_FOUND, {"error": f"Unknown endpoint: {path}"})
        except KeyError as exc:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": str(exc)})
        except ValueError as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
        except Exception as exc:  # noqa: BLE001
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": str(exc)})

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        parts = [p for p in path.split("/") if p]

        try:
            payload = self._read_json_body()

            if path == "/api/reset":
                result = self.server.state.reset_database()
                self._send_json(HTTPStatus.OK, result)
                return

            if path == "/api/investigations":
                created = self.server.state.create_investigation(payload)
                self._send_json(HTTPStatus.CREATED, {"investigation": created})
                return

            if len(parts) == 4 and parts[0] == "api" and parts[1] == "investigations":
                inv_id = urllib.parse.unquote(parts[2])
                action = parts[3]

                if action == "collect-text":
                    result = self.server.state.collect_text(inv_id, payload)
                    self._send_json(HTTPStatus.OK, {"result": result})
                    return
                if action == "collect-file":
                    result = self.server.state.collect_file(inv_id, payload)
                    self._send_json(HTTPStatus.OK, {"result": result})
                    return
                if action == "collect-feed":
                    result = self.server.state.collect_feed(inv_id, payload)
                    self._send_json(HTTPStatus.OK, {"result": result})
                    return
                if action == "relations":
                    relation = self.server.state.create_relation(inv_id, payload)
                    self._send_json(HTTPStatus.CREATED, {"relation": relation})
                    return
                if action == "pivot":
                    pivot_res = self.server.state.run_pivot(inv_id, payload)
                    self._send_json(HTTPStatus.OK, {"pivot": pivot_res})
                    return

            self._send_json(HTTPStatus.NOT_FOUND, {"error": f"Unknown endpoint: {path}"})
        except KeyError as exc:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": str(exc)})
        except (ValueError, FileNotFoundError, json.JSONDecodeError) as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
        except Exception as exc:  # noqa: BLE001
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": str(exc)})

    def do_PATCH(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        parts = [p for p in parsed.path.split("/") if p]
        try:
            payload = self._read_json_body()
            if len(parts) == 3 and parts[0] == "api" and parts[1] == "investigations":
                inv_id = urllib.parse.unquote(parts[2])
                updated = self.server.state.update_investigation(inv_id, payload)
                self._send_json(HTTPStatus.OK, {"investigation": updated})
                return
            self._send_json(HTTPStatus.NOT_FOUND, {"error": f"Unknown endpoint: {parsed.path}"})
        except KeyError as exc:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": str(exc)})
        except (ValueError, json.JSONDecodeError) as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
        except Exception as exc:  # noqa: BLE001
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": str(exc)})


def _bind_local_server(state: ArgosUIState, preferred_port: int) -> ArgosHTTPServer:
    """Bind strictly to 127.0.0.1, falling back to subsequent ports if busy."""
    if preferred_port == 0:
        return ArgosHTTPServer(("127.0.0.1", 0), state)

    for offset in range(25):
        candidate = preferred_port + offset
        if candidate > 65535:
            break
        try:
            return ArgosHTTPServer(("127.0.0.1", candidate), state)
        except OSError:
            continue

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        ephemeral = s.getsockname()[1]
    return ArgosHTTPServer(("127.0.0.1", ephemeral), state)


def create_ui_server(
    db_path: Path | str | None = None,
    port: int = 8765,
) -> tuple[ArgosHTTPServer, str]:
    """Initialize state and bind local HTTP server without blocking."""
    state = ArgosUIState(db_path=db_path)
    httpd = _bind_local_server(state, preferred_port=port)
    bound_port = httpd.server_address[1]
    url = f"http://127.0.0.1:{bound_port}/"
    return httpd, url


def run_ui_server(
    db_path: Path | str | None = None,
    port: int = 8765,
    open_browser: bool = True,
    on_ready: Any = None,
) -> None:
    """Start the local web UI server and optionally open the default browser."""
    httpd, url = create_ui_server(db_path=db_path, port=port)
    if callable(on_ready):
        on_ready(url)
    if open_browser:
        threading.Timer(0.15, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
