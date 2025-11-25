from __future__ import annotations

from datetime import datetime, timedelta, timezone
from io import BytesIO
from typing import Iterator
from unittest.mock import MagicMock

import pytest

from onyx.configs.constants import DocumentSource
from onyx.connectors.network_file_system.connector import (
    NetworkFileSystemConnector,
    SMBRemoteFile,
)
from onyx.connectors.models import Document
from onyx.connectors.models import TextSection


def _build_connector(*, share_path: str | None = None, **kwargs: object) -> NetworkFileSystemConnector:
    connector = NetworkFileSystemConnector(
        share_path=share_path or "\\\\fileserver\\engineering",
        **kwargs,
    )
    connector.load_credentials({"smb_username": "svc", "smb_password": "secret"})
    return connector


def test_parse_share_path_handles_unc() -> None:
    server, share, base = NetworkFileSystemConnector._parse_share_path(
        "\\\\server01\\Finance\\Quarterly"
    )
    assert server == "server01"
    assert share == "Finance"
    assert base == "Quarterly"


def test_strip_base_path_trims_prefix() -> None:
    connector = _build_connector(share_path="\\\\fileserver\\engineering\\design")
    assert connector._strip_base_path("design/spec.md") == "spec.md"


def test_should_exclude_patterns() -> None:
    connector = _build_connector(exclude_patterns=["secret/*", "*.tmp"])

    assert connector._should_include("design/overview.pdf") is True
    assert connector._should_include("design/readme.tmp") is False
    assert connector._should_include("secret/plan.pdf") is False


def test_iter_remote_files_filters_hidden_and_depth() -> None:
    connector = _build_connector(ignore_hidden_entries=True, max_depth=2)

    now = datetime.now(timezone.utc)
    files = [
        SMBRemoteFile(
            path="spec.txt",
            filename="spec.txt",
            file_size=100,
            last_modified=now,
        ),
        SMBRemoteFile(
            path=".shadow/confidential.txt",
            filename="confidential.txt",
            file_size=10,
            last_modified=now,
        ),
        SMBRemoteFile(
            path="deep/nested/file.txt",
            filename="file.txt",
            file_size=10,
            last_modified=now,
        ),
    ]

    class DummyClient:
        def iter_files(self, base_path: str) -> Iterator[SMBRemoteFile]:  # noqa: D401
            return iter(files)

    results = list(
        connector._iter_remote_files(
            DummyClient(),
            modified_after=None,
            modified_before=None,
        )
    )

    # Only the first file should survive (hidden + depth filters remove others)
    assert len(results) == 1
    assert results[0][0].filename == "spec.txt"


def test_process_remote_file_builds_documents(monkeypatch: pytest.MonkeyPatch) -> None:
    connector = _build_connector()

    text_section = TextSection(text="example", link=None)
    dummy_document = Document(
        id="FILE_CONNECTOR__placeholder",
        source=DocumentSource.FILE,
        sections=[text_section],
        semantic_identifier="placeholder",
        metadata={},
    )

    def _fake_process_file(*args, **kwargs):  # type: ignore[no-untyped-def]
        return [dummy_document]

    monkeypatch.setattr(
        "onyx.connectors.network_file_system.connector._process_file",
        _fake_process_file,
    )

    client = MagicMock()
    client.download_file.return_value = BytesIO(b"hello world")

    remote_file = SMBRemoteFile(
        path="engineering/specs/plan.md",
        filename="plan.md",
        file_size=512,
        last_modified=datetime.now(timezone.utc),
    )

    documents = connector._process_remote_file(client, remote_file, "specs/plan.md")
    assert documents is not None
    assert len(documents) == 1

    document = documents[0]
    assert document.source == DocumentSource.NETWORK_FILE_SYSTEM
    assert document.id.startswith(NetworkFileSystemConnector.DOCUMENT_ID_PREFIX)
    assert document.semantic_identifier.startswith("\\\\fileserver\\engineering")
    assert document.metadata.get("network_path").endswith("specs\\plan.md")
    client.download_file.assert_called_once_with("engineering/specs/plan.md")