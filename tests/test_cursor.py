"""Tests for ArchiveCursor bounded byte handling."""

from __future__ import annotations

import struct
import pytest

from graphworx32_gdf_parser.cursor import ArchiveCursor
from graphworx32_gdf_parser.errors import GdfParserError
from graphworx32_gdf_parser.models import ParseLimits, Span


def test_cursor_require_and_read_primitives() -> None:
    data = struct.pack("<HIi", 1234, 567890, -42) + b"hello world"
    cursor = ArchiveCursor(data, ParseLimits())

    val_u16, span_u16 = cursor.read_u16()
    assert val_u16 == 1234
    assert span_u16 == Span(0, 2)

    val_u32, span_u32 = cursor.read_u32()
    assert val_u32 == 567890
    assert span_u32 == Span(2, 6)

    val_i32, span_i32 = cursor.read_i32()
    assert val_i32 == -42
    assert span_i32 == Span(6, 10)

    raw, span_raw = cursor.read_bytes(11)
    assert raw == b"hello world"
    assert span_raw == Span(10, 21)
    assert cursor.offset == len(data)
    cursor.require_exhausted()


def test_cursor_read_string_utf8() -> None:
    text = "GDF Test String"
    encoded = text.encode("utf-8")
    data = struct.pack("<H", len(encoded)) + encoded
    cursor = ArchiveCursor(data, ParseLimits())

    s, span = cursor.read_string()
    assert s == text
    assert span.start == 0
    assert span.end == len(data)


def test_cursor_boundary_violations() -> None:
    cursor = ArchiveCursor(b"1234", ParseLimits())
    with pytest.raises(GdfParserError) as exc:
        cursor.require(10, "overflow")
    assert exc.value.code == "ARCHIVE_TRUNCATED"

    with pytest.raises(GdfParserError) as exc2:
        cursor.require(-1, "negative")
    assert exc2.value.code == "ARCHIVE_LENGTH_INVALID"


def test_cursor_subregion_and_nesting() -> None:
    data = b"abcdefghij"
    limits = ParseLimits(max_depth=2)
    c0 = ArchiveCursor(data, limits)
    c1 = c0.subregion(8)
    assert c1.depth == 1
    assert c1.end == 8

    c2 = c1.subregion(4)
    assert c2.depth == 2

    with pytest.raises(GdfParserError) as exc:
        c2.subregion(2)
    assert exc.value.code == "ARCHIVE_NESTING_LIMIT"
