"""Local file and dataset collector supporting TXT, CSV, and JSON inputs safely."""

import csv
import json
from pathlib import Path

from argos.collectors import CollectedRecord, CollectionResult

MAX_LOCAL_FILE_BYTES = 5 * 1024 * 1024
SUPPORTED_EXTENSIONS = {".txt", ".csv", ".json"}


class LocalFileCollector:
    name = "local_file"
    requires_network = False

    def __init__(self, file_path: Path, max_bytes: int = MAX_LOCAL_FILE_BYTES) -> None:
        self.file_path = file_path
        self.max_bytes = max_bytes

    def collect(self, target: str | None = None) -> CollectionResult:
        source_name = f"file:{self.file_path.name}"
        if not self.file_path.exists() or not self.file_path.is_file():
            return CollectionResult(source=source_name, errors=("file_not_found",))

        ext = self.file_path.suffix.lower()
        if ext not in SUPPORTED_EXTENSIONS:
            return CollectionResult(source=source_name, errors=(f"unsupported_extension:{ext}",))

        size = self.file_path.stat().st_size
        if size > self.max_bytes:
            return CollectionResult(source=source_name, errors=(f"file_exceeds_max_bytes:{self.max_bytes}",))

        try:
            if ext == ".txt":
                return self._collect_txt(source_name, target)
            if ext == ".csv":
                return self._collect_csv(source_name, target)
            return self._collect_json(source_name, target)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, csv.Error) as exc:
            return CollectionResult(source=source_name, errors=(f"parse_error:{type(exc).__name__}",))

    def _matches_target(self, value: str, target: str | None) -> bool:
        if not target:
            return True
        return target.lower() in value.lower()

    def _collect_txt(self, source_name: str, target: str | None) -> CollectionResult:
        records: list[CollectedRecord] = []
        raw_text = self.file_path.read_text(encoding="utf-8")
        for line_no, line in enumerate(raw_text.splitlines(), start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if self._matches_target(stripped, target):
                records.append(
                    CollectedRecord(
                        raw_value=stripped,
                        source=source_name,
                        collection_method="local_txt",
                        metadata={"line": line_no},
                    )
                )
        return CollectionResult(source=source_name, records=tuple(records))

    def _collect_csv(self, source_name: str, target: str | None) -> CollectionResult:
        records: list[CollectedRecord] = []
        with self.file_path.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.reader(handle)
            for row_idx, row in enumerate(reader, start=1):
                for col_idx, cell in enumerate(row, start=1):
                    val = cell.strip()
                    if val and self._matches_target(val, target):
                        records.append(
                            CollectedRecord(
                                raw_value=val,
                                source=source_name,
                                collection_method="local_csv",
                                metadata={"row": row_idx, "column": col_idx},
                            )
                        )
        return CollectionResult(source=source_name, records=tuple(records))

    def _collect_json(self, source_name: str, target: str | None) -> CollectionResult:
        records: list[CollectedRecord] = []
        payload = json.loads(self.file_path.read_text(encoding="utf-8"))
        self._walk_json(payload, source_name, target, "root", records)
        return CollectionResult(source=source_name, records=tuple(records))

    def _walk_json(
        self,
        node: object,
        source_name: str,
        target: str | None,
        path_label: str,
        out: list[CollectedRecord],
    ) -> None:
        if isinstance(node, str):
            val = node.strip()
            if val and self._matches_target(val, target):
                out.append(
                    CollectedRecord(
                        raw_value=val,
                        source=source_name,
                        collection_method="local_json",
                        metadata={"path": path_label},
                    )
                )
        elif isinstance(node, list):
            for idx, item in enumerate(node):
                self._walk_json(item, source_name, target, f"{path_label}[{idx}]", out)
        elif isinstance(node, dict):
            for key, value in node.items():
                self._walk_json(value, source_name, target, f"{path_label}.{key}", out)
