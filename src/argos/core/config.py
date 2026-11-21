"""Local-first configuration for ARGOS."""

from pathlib import Path

from pydantic import BaseModel, Field


def default_data_dir() -> Path:
    return Path.home() / ".local" / "share" / "argos"


class ArgosConfig(BaseModel):
    data_dir: Path = Field(default_factory=default_data_dir)
    db_filename: str = "argos.sqlite3"
    request_timeout_seconds: float = Field(default=10.0, ge=1.0, le=120.0)
    max_pivot_depth: int = Field(default=2, ge=1, le=5)

    @property
    def db_path(self) -> Path:
        return self.data_dir / self.db_filename

    def ensure_dirs(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
