from __future__ import annotations

import fnmatch
import hashlib
import mimetypes
import os
import socket
from dataclasses import dataclass
from datetime import datetime, timezone
from io import BytesIO
from typing import Any, Iterator

from onyx.configs.app_configs import BLOB_STORAGE_SIZE_THRESHOLD
from onyx.configs.app_configs import INDEX_BATCH_SIZE
from onyx.configs.constants import DocumentSource
from onyx.connectors.exceptions import ConnectorValidationError
from onyx.connectors.file.connector import _process_file
from onyx.connectors.interfaces import GenerateDocumentsOutput
from onyx.connectors.interfaces import LoadConnector
from onyx.connectors.interfaces import PollConnector
from onyx.connectors.interfaces import SecondsSinceUnixEpoch
from onyx.connectors.models import ConnectorMissingCredentialError
from onyx.connectors.models import Document
from onyx.utils.logger import setup_logger
from smb.SMBConnection import SMBConnection  # type: ignore[import-untyped]


@dataclass
class SMBRemoteFile:
    """Lightweight container describing a file stored on the SMB share."""

    path: str
    filename: str
    file_size: int
    last_modified: datetime


class _SMBClient:
    """Thin wrapper around pysmb that provides a friendlier interface."""

    def __init__(
        self,
        *,
        server: str,
        share: str,
        username: str,
        password: str,
        client_machine_name: str,
        server_name: str,
        domain: str | None = None,
        port: int = 445,
    ) -> None:
        self.server = server
        self.share = share
        self.username = username
        self.password = password
        self.client_machine_name = client_machine_name
        self.server_name = server_name
        self.domain = domain
        self.port = port

        self._connection: SMBConnection | None = None

    def __enter__(self) -> "_SMBClient":
        self._connection = SMBConnection(
            username=self.username,
            password=self.password,
            my_name=self.client_machine_name,
            remote_name=self.server_name,
            domain=self.domain or "",
            use_ntlm_v2=True,
            is_direct_tcp=True,
        )

        connected = self._connection.connect(self.server, self.port, timeout=30)
        if not connected:
            raise ConnectionError(
                f"Unable to connect to SMB share {self.server_name}:{self.port}"
            )

        return self

    def __exit__(self, exc_type, exc, exc_tb) -> None:  # type: ignore[override]
        if self._connection is not None:
            self._connection.close()
            self._connection = None

    def iter_files(self, base_path: str) -> Iterator[SMBRemoteFile]:
        """Depth-first traversal that yields file descriptors for the provided base path."""

        if self._connection is None:
            raise RuntimeError("SMB connection has not been established")

        stack: list[str] = [base_path]

        while stack:
            current_path = stack.pop()
            for entry in self._connection.listPath(self.share, self._to_smb_path(current_path)):
                if entry.filename in {".", ".."}:
                    continue

                relative_path = "/".join(
                    component for component in (current_path, entry.filename) if component
                )

                if entry.isDirectory:
                    stack.append(relative_path)
                    continue

                yield SMBRemoteFile(
                    path=relative_path,
                    filename=entry.filename,
                    file_size=entry.file_size,
                    last_modified=self._to_datetime(entry.last_write_time),
                )

    def download_file(self, remote_path: str) -> BytesIO:
        """Download a remote file into memory and return a BytesIO handle."""

        if self._connection is None:
            raise RuntimeError("SMB connection has not been established")

        buffer = BytesIO()
        self._connection.retrieveFile(self.share, self._to_smb_path(remote_path), buffer)
        buffer.seek(0)
        return buffer

    @staticmethod
    def _to_smb_path(path: str) -> str:
        normalized = path.replace("\\", "/").strip("/")
        return f"/{normalized}" if normalized else "/"

    @staticmethod
    def _to_datetime(value: datetime | float | int) -> datetime:
        if isinstance(value, datetime):
            if value.tzinfo is None:
                return value.replace(tzinfo=timezone.utc)
            return value.astimezone(timezone.utc)
        return datetime.fromtimestamp(float(value), tz=timezone.utc)


logger = setup_logger()


class NetworkFileSystemConnector(LoadConnector, PollConnector):
    """Connector for indexing on-prem or VPC SMB (Windows) network file systems."""

    DOCUMENT_ID_PREFIX = "NETWORK_FILE_SYSTEM__"

    def __init__(
        self,
        *,
        share_path: str,
        exclude_patterns: list[str] | None = None,
        ignore_hidden_entries: bool = True,
        max_depth: int | None = None,
        port: int | None = None,
        batch_size: int = INDEX_BATCH_SIZE,
        size_threshold_mb: int | None = None,
    ) -> None:
        if not share_path:
            raise ValueError("share_path is required for the network file system connector")

        self.server, self.share, base_path = self._parse_share_path(share_path)
        self._start_path = self._normalize_path(base_path)

        self.exclude_patterns = [self._normalize_pattern(p) for p in exclude_patterns or []]
        self.ignore_hidden_entries = ignore_hidden_entries
        self.max_depth = max_depth if max_depth and max_depth > 0 else None
        self.port = port or 445
        self.batch_size = batch_size
        self.size_threshold_bytes = (
            size_threshold_mb * 1024 * 1024
            if size_threshold_mb is not None
            else BLOB_STORAGE_SIZE_THRESHOLD
        )

        self._allow_images: bool | None = None
        self._username: str | None = None
        self._password: str | None = None
        self._domain: str | None = None
        self._client_name: str = socket.gethostname().split(".")[0] or "onyx"

    def load_credentials(self, credentials: dict[str, Any]) -> dict[str, Any] | None:  # noqa: PLR0912
        username = credentials.get("smb_username")
        password = credentials.get("smb_password")

        if not username or not password:
            raise ConnectorMissingCredentialError("Network file system")

        self._username = username
        self._password = password
        self._domain = credentials.get("smb_domain")

        return None

    def set_allow_images(self, value: bool) -> None:  # noqa: D401
        self._allow_images = value

    def validate_connector_settings(self) -> None:
        try:
            with self._connect() as client:
                for _remote_file, _relative_path in self._iter_remote_files(
                    client,
                    modified_after=None,
                    modified_before=None,
                    limit=1,
                ):
                    # Successfully accessed the share and found at least one entry, so we can return.
                    return
        except Exception as exc:  # pragma: no cover - defensive, logged below
            raise ConnectorValidationError(str(exc)) from exc

    def load_from_state(self) -> GenerateDocumentsOutput:
        return self._generate_documents()

    def poll_source(
        self, start: SecondsSinceUnixEpoch, end: SecondsSinceUnixEpoch
    ) -> GenerateDocumentsOutput:
        start_dt = datetime.fromtimestamp(start, tz=timezone.utc)
        end_dt = datetime.fromtimestamp(end, tz=timezone.utc)
        return self._generate_documents(modified_after=start_dt, modified_before=end_dt)

    def _generate_documents(
        self,
        *,
        modified_after: datetime | None = None,
        modified_before: datetime | None = None,
    ) -> GenerateDocumentsOutput:
        def iterator() -> Iterator[list[Document]]:
            documents: list[Document] = []

            with self._connect() as client:
                for remote_file, relative_path in self._iter_remote_files(
                    client,
                    modified_after=modified_after,
                    modified_before=modified_before,
                ):
                    processed_docs = self._process_remote_file(
                        client,
                        remote_file,
                        relative_path,
                    )
                    if not processed_docs:
                        continue

                    documents.extend(processed_docs)
                    if len(documents) >= self.batch_size:
                        yield documents
                        documents = []

            if documents:
                yield documents

        return iterator()

    def _connect(self) -> _SMBClient:
        if not self._username or not self._password:
            raise ConnectorMissingCredentialError("Network file system")

        return _SMBClient(
            server=self.server,
            share=self.share,
            username=self._username,
            password=self._password,
            client_machine_name=self._client_name,
            server_name=self.server,
            domain=self._domain,
            port=self.port,
        )

    def _iter_remote_files(
        self,
        client: _SMBClient,
        *,
        modified_after: datetime | None,
        modified_before: datetime | None,
        limit: int | None = None,
    ) -> Iterator[tuple[SMBRemoteFile, str]]:
        yielded = 0

        for remote_file in client.iter_files(self._start_path):
            relative_path = self._strip_base_path(remote_file.path)

            if self.ignore_hidden_entries and self._is_hidden(relative_path):
                continue

            if self.max_depth is not None and self._path_depth(relative_path) > self.max_depth:
                continue

            if not self._should_include(relative_path):
                continue

            if modified_after is not None and remote_file.last_modified < modified_after:
                continue

            if modified_before is not None and remote_file.last_modified > modified_before:
                continue

            if (
                self.size_threshold_bytes is not None
                and remote_file.file_size > self.size_threshold_bytes
            ):
                logger.warning(
                    "Skipping %s because it exceeds the size threshold (%s bytes)",
                    remote_file.path,
                    self.size_threshold_bytes,
                )
                continue

            if (self._allow_images is False) and self._is_image(relative_path):
                continue

            yield remote_file, relative_path
            yielded += 1
            if limit is not None and yielded >= limit:
                break

    def _process_remote_file(
        self,
        client: _SMBClient,
        remote_file: SMBRemoteFile,
        relative_path: str,
    ) -> list[Document] | None:
        try:
            file_stream = client.download_file(remote_file.path)
        except Exception as exc:  # pragma: no cover - network errors
            logger.warning(
                "Failed to download %s from %s: %s",
                remote_file.path,
                self.share,
                exc,
            )
            return None

        file_type, _ = mimetypes.guess_type(remote_file.filename)
        relative_to_share = remote_file.path.replace("/", "\\")
        relative_to_base = relative_path.replace("/", "\\")

        metadata = {
            "link": self._build_unc_path(remote_file.path),
            "file_display_name": remote_file.filename,
            "doc_updated_at": remote_file.last_modified.isoformat(),
            "connector_type": DocumentSource.NETWORK_FILE_SYSTEM.value,
            "network_path": self._build_unc_path(remote_file.path),
            "relative_path": relative_to_share,
            "relative_to_base": relative_to_base,
            "share": self.share,
            "server": self.server,
        }

        documents = _process_file(
            file_id=self._build_file_id(remote_file.path),
            file_name=remote_file.filename,
            file=file_stream,
            metadata=metadata,
            pdf_pass=None,
            file_type=file_type,
        )

        if not documents:
            return None

        semantic_identifier = self._build_semantic_identifier(remote_file.path)
        doc_updated_at = remote_file.last_modified

        for document in documents:
            document.id = (
                f"{self.DOCUMENT_ID_PREFIX}{self._build_file_id(remote_file.path)}"
            )
            document.source = DocumentSource.NETWORK_FILE_SYSTEM
            document.semantic_identifier = semantic_identifier
            document.doc_updated_at = doc_updated_at
            document.metadata = document.metadata or {}
            document.metadata.setdefault("network_path", metadata["network_path"])
            document.metadata.setdefault("relative_path", relative_to_share)
            if relative_to_base:
                document.metadata.setdefault("relative_to_base", relative_to_base)

        return documents

    @staticmethod
    def _parse_share_path(path: str) -> tuple[str, str, str]:
        normalized = path.strip()
        if normalized.startswith("\\\\"):
            normalized = normalized[2:]
        normalized = normalized.replace("/", "\\").strip("\\")
        segments = [segment for segment in normalized.split("\\") if segment]

        if len(segments) < 2:
            raise ValueError(
                "share_path must include both the server and share name, e.g. \\server\\share\\folder"
            )

        server = segments[0]
        share = segments[1]
        remainder = "\\".join(segments[2:]) if len(segments) > 2 else ""
        return server, share, remainder

    @staticmethod
    def _normalize_path(path: str) -> str:
        return path.replace("\\", "/").strip("/")

    @staticmethod
    def _normalize_pattern(pattern: str) -> str:
        return pattern.replace("\\", "/").lower()

    def _strip_base_path(self, path: str) -> str:
        normalized = path.replace("\\", "/").strip("/")
        if self._start_path and normalized.startswith(self._start_path):
            trimmed = normalized[len(self._start_path) :].lstrip("/")
            return trimmed or os.path.basename(normalized)
        return normalized

    @staticmethod
    def _path_depth(path: str) -> int:
        if not path:
            return 0
        return len([segment for segment in path.split("/") if segment])

    @staticmethod
    def _is_hidden(path: str) -> bool:
        return any(segment.startswith(".") for segment in path.split("/") if segment)

    def _is_image(self, path: str) -> bool:
        _, ext = os.path.splitext(path.lower())
        return ext in self.IMAGE_EXTENSIONS

    def _should_include(self, relative_path: str) -> bool:
        normalized = relative_path.replace("\\", "/").lower()

        if any(fnmatch.fnmatch(normalized, pattern) for pattern in self.exclude_patterns):
            return False

        return True

    @staticmethod
    def _build_file_id(path: str) -> str:
        normalized = path.replace("\\", "/").lower()
        return hashlib.sha256(normalized.encode("utf-8")).hexdigest()

    def _build_unc_path(self, path: str) -> str:
        normalized = path.replace("/", "\\").strip("\\")
        return f"\\\\{self.server}\\{self.share}\\{normalized}" if normalized else f"\\\\{self.server}\\{self.share}"

    def _build_semantic_identifier(self, relative_path: str) -> str:
        relative = relative_path.replace("/", "\\").strip("\\")
        if relative:
            return f"\\\\{self.server}\\{self.share}\\{relative}"
        return f"\\\\{self.server}\\{self.share}"
