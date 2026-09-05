"""Synthetic test fixtures and mock containers for graphworx32-gdf-parser."""

from __future__ import annotations

import io
import struct
from pathlib import Path

import pytest

from graphworx32_gdf_parser.models import ParseLimits


def make_mfc_cstring_bytes(text: str) -> bytes:
    """Create a synthetic MFC CString UTF-16LE byte sequence."""
    raw = text.encode("utf-16le")
    length = len(raw) // 2
    if length < 0xFF:
        return b"\xff\xfe\xff" + bytes([length]) + raw
    else:
        return b"\xff\xfe\xff\xff" + struct.pack("<H", length) + raw


def make_synthetic_alias_map(entries: list[tuple[str, str]]) -> bytes:
    """Create a synthetic MFC string map of key-value pairs."""
    count = len(entries)
    payload = struct.pack("<H", count)
    for key, val in entries:
        payload += make_mfc_cstring_bytes(key)
        payload += make_mfc_cstring_bytes(val)
    return payload


class MockMetadata:
    SUMMARY_ATTRIBS = ("title", "author")
    DOCSUM_ATTRIBS = ()

    def __init__(self, title: str = "Synthetic Display", author: str = "Test Suite") -> None:
        self.title = title
        self.author = author


class MockOleContainer:
    """In-memory synthetic OLE container implementing olefile's interface."""

    def __init__(
        self,
        paths: list[list[str]] | None = None,
        *,
        contents: bytes = b"",
        issues: list[str] | None = None,
        title: str = "Synthetic Display",
    ) -> None:
        self.paths = paths if paths is not None else [["Contents"]]
        self.contents = contents
        self.parsing_issues = [(RuntimeError, issue) for issue in issues or []]
        self.metadata = MockMetadata(title=title)

    def __enter__(self) -> "MockOleContainer":
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def exists(self, path: str) -> bool:
        return path == "Contents" or any(p == [path] for p in self.paths)

    def get_type(self, path: str | list[str]) -> int:
        return 2  # olefile.STGTY_STREAM

    def listdir(self, *, streams: bool, storages: bool) -> list[list[str]]:
        return self.paths

    def get_size(self, path: str | list[str]) -> int:
        target = [path] if isinstance(path, str) else path
        if target == ["Contents"]:
            return len(self.contents)
        return 16

    def get_metadata(self) -> MockMetadata:
        return self.metadata

    def openstream(self, path: str | list[str]) -> io.BytesIO:
        target = [path] if isinstance(path, str) else path
        if target == ["Contents"]:
            return io.BytesIO(self.contents)
        return io.BytesIO(b"dummy")


class MockOleModule:
    """Mock for olefile module."""

    DEFECT_INCORRECT = 1
    STGTY_STREAM = 2
    STGTY_STORAGE = 1

    def __init__(self, container: MockOleContainer | None = None) -> None:
        self._container = container or MockOleContainer()

    def isOleFile(self, _: object) -> bool:
        return True

    def OleFileIO(self, *_: object, **__: object) -> MockOleContainer:
        return self._container
