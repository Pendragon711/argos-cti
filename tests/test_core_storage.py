from pathlib import Path

from argos.core import SQLiteStorage
from argos.models import ArtifactType, EpistemicStatus, Evidence, Investigation


def test_investigation_evidence_and_storage_roundtrip(tmp_path: Path) -> None:
    db_path = tmp_path / "argos_test.sqlite3"
    storage = SQLiteStorage(db_path)

    inv = Investigation(title="IP Investigation", objective="Check indicator context")
    storage.save_investigation(inv)

    loaded = storage.get_investigation(inv.id)
    assert loaded is not None
    assert loaded.title == "IP Investigation"

    evd = Evidence(
        investigation_id=inv.id,
        source="local_input",
        collection_method="manual",
        epistemic_status=EpistemicStatus.OBSERVED,
        content="198.51.100.23",
        metadata={"artifact_type": ArtifactType.IPV4.value},
    )
    assert len(evd.content_hash) == 64
    storage.save_evidence(evd)
    assert len(storage.list_investigations()) == 1
