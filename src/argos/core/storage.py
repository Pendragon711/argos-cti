"""SQLite persistence layer for ARGOS local investigations."""

import json
import sqlite3
from pathlib import Path

from argos.models import Artifact, Evidence, Investigation, Relation


class SQLiteStorage:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        return conn

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS investigations (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    objective TEXT NOT NULL,
                    scope TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    notes_json TEXT NOT NULL,
                    conclusion TEXT NOT NULL,
                    limitations_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS artifacts (
                    id TEXT PRIMARY KEY,
                    investigation_id TEXT NOT NULL,
                    artifact_type TEXT NOT NULL,
                    value TEXT NOT NULL,
                    original_value TEXT NOT NULL,
                    source TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS evidences (
                    id TEXT PRIMARY KEY,
                    investigation_id TEXT NOT NULL,
                    artifact_id TEXT,
                    source TEXT NOT NULL,
                    collection_method TEXT NOT NULL,
                    epistemic_status TEXT NOT NULL,
                    content TEXT NOT NULL,
                    content_hash TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    collected_at TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE,
                    FOREIGN KEY (artifact_id) REFERENCES artifacts(id) ON DELETE SET NULL
                );

                CREATE TABLE IF NOT EXISTS relations (
                    id TEXT PRIMARY KEY,
                    investigation_id TEXT NOT NULL,
                    source_artifact_id TEXT NOT NULL,
                    target_artifact_id TEXT NOT NULL,
                    relation_type TEXT NOT NULL,
                    epistemic_status TEXT NOT NULL,
                    source TEXT NOT NULL,
                    evidence_id TEXT,
                    context TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
                );
                """
            )

    def save_investigation(self, inv: Investigation) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO investigations (
                    id, title, objective, scope, status, created_at, updated_at,
                    notes_json, conclusion, limitations_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    title = excluded.title,
                    objective = excluded.objective,
                    scope = excluded.scope,
                    status = excluded.status,
                    updated_at = excluded.updated_at,
                    notes_json = excluded.notes_json,
                    conclusion = excluded.conclusion,
                    limitations_json = excluded.limitations_json
                """,
                (
                    inv.id,
                    inv.title,
                    inv.objective,
                    inv.scope,
                    inv.status.value,
                    inv.created_at.isoformat(),
                    inv.updated_at.isoformat(),
                    json.dumps(inv.notes),
                    inv.conclusion,
                    json.dumps(inv.limitations),
                ),
            )

    def get_investigation(self, inv_id: str) -> Investigation | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM investigations WHERE id = ?", (inv_id,)
            ).fetchone()
            if not row:
                return None
            return Investigation(
                id=row["id"],
                title=row["title"],
                objective=row["objective"],
                scope=row["scope"],
                status=row["status"],
                created_at=row["created_at"],
                updated_at=row["updated_at"],
                notes=json.loads(row["notes_json"]),
                conclusion=row["conclusion"],
                limitations=json.loads(row["limitations_json"]),
            )

    def list_investigations(self) -> list[Investigation]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM investigations ORDER BY created_at DESC"
            ).fetchall()
            return [
                Investigation(
                    id=r["id"],
                    title=r["title"],
                    objective=r["objective"],
                    scope=r["scope"],
                    status=r["status"],
                    created_at=r["created_at"],
                    updated_at=r["updated_at"],
                    notes=json.loads(r["notes_json"]),
                    conclusion=r["conclusion"],
                    limitations=json.loads(r["limitations_json"]),
                )
                for r in rows
            ]

    def save_artifact(self, art: Artifact) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO artifacts (
                    id, investigation_id, artifact_type, value, original_value,
                    source, first_seen, last_seen, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    last_seen = excluded.last_seen,
                    metadata_json = excluded.metadata_json
                """,
                (
                    art.id,
                    art.investigation_id,
                    art.artifact_type.value,
                    art.value,
                    art.original_value,
                    art.source,
                    art.first_seen.isoformat(),
                    art.last_seen.isoformat(),
                    json.dumps(art.metadata),
                ),
            )

    def find_artifact_by_value(self, investigation_id: str, value: str) -> Artifact | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM artifacts WHERE investigation_id = ? AND value = ?",
                (investigation_id, value),
            ).fetchone()
            if not row:
                return None
            return Artifact(
                id=row["id"],
                investigation_id=row["investigation_id"],
                artifact_type=row["artifact_type"],
                value=row["value"],
                original_value=row["original_value"],
                source=row["source"],
                first_seen=row["first_seen"],
                last_seen=row["last_seen"],
                metadata=json.loads(row["metadata_json"]),
            )

    def list_artifacts(self, investigation_id: str) -> list[Artifact]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM artifacts WHERE investigation_id = ? ORDER BY first_seen DESC",
                (investigation_id,),
            ).fetchall()
            return [
                Artifact(
                    id=r["id"],
                    investigation_id=r["investigation_id"],
                    artifact_type=r["artifact_type"],
                    value=r["value"],
                    original_value=r["original_value"],
                    source=r["source"],
                    first_seen=r["first_seen"],
                    last_seen=r["last_seen"],
                    metadata=json.loads(r["metadata_json"]),
                )
                for r in rows
            ]

    def save_evidence(self, evd: Evidence) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO evidences (
                    id, investigation_id, artifact_id, source, collection_method,
                    epistemic_status, content, content_hash, observed_at,
                    collected_at, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    evd.id,
                    evd.investigation_id,
                    evd.artifact_id,
                    evd.source,
                    evd.collection_method,
                    evd.epistemic_status.value,
                    evd.content,
                    evd.content_hash,
                    evd.observed_at.isoformat(),
                    evd.collected_at.isoformat(),
                    json.dumps(evd.metadata),
                ),
            )

    def list_evidences(self, investigation_id: str) -> list[Evidence]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM evidences WHERE investigation_id = ? ORDER BY collected_at DESC",
                (investigation_id,),
            ).fetchall()
            return [
                Evidence(
                    id=r["id"],
                    investigation_id=r["investigation_id"],
                    artifact_id=r["artifact_id"],
                    source=r["source"],
                    collection_method=r["collection_method"],
                    epistemic_status=r["epistemic_status"],
                    content=r["content"],
                    content_hash=r["content_hash"],
                    observed_at=r["observed_at"],
                    collected_at=r["collected_at"],
                    metadata=json.loads(r["metadata_json"]),
                )
                for r in rows
            ]

    def save_relation(self, rel: Relation) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO relations (
                    id, investigation_id, source_artifact_id, target_artifact_id,
                    relation_type, epistemic_status, source, evidence_id,
                    context, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    rel.id,
                    rel.investigation_id,
                    rel.source_artifact_id,
                    rel.target_artifact_id,
                    rel.relation_type.value,
                    rel.epistemic_status.value,
                    rel.source,
                    rel.evidence_id,
                    rel.context,
                    rel.created_at.isoformat(),
                ),
            )

    def list_relations(self, investigation_id: str) -> list[Relation]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM relations WHERE investigation_id = ? ORDER BY created_at DESC",
                (investigation_id,),
            ).fetchall()
            return [
                Relation(
                    id=r["id"],
                    investigation_id=r["investigation_id"],
                    source_artifact_id=r["source_artifact_id"],
                    target_artifact_id=r["target_artifact_id"],
                    relation_type=r["relation_type"],
                    epistemic_status=r["epistemic_status"],
                    source=r["source"],
                    evidence_id=r["evidence_id"],
                    context=r["context"],
                    created_at=r["created_at"],
                )
                for r in rows
            ]
