"""Collectors for local datasets and optional public threat intelligence sources."""

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable


@dataclass(frozen=True)
class CollectedRecord:
    raw_value: str
    source: str
    collection_method: str
    metadata: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class CollectionResult:
    source: str
    records: tuple[CollectedRecord, ...] = field(default_factory=tuple)
    errors: tuple[str, ...] = field(default_factory=tuple)


@runtime_checkable
class Collector(Protocol):
    name: str
    requires_network: bool

    def collect(self, target: str | None = None) -> CollectionResult:
        ...


__all__ = ["CollectedRecord", "CollectionResult", "Collector"]
