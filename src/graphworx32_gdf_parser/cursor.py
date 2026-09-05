"""Bounded cursor and stream reading primitives for binary archives."""

from __future__ import annotations

import struct

from graphworx32_gdf_parser.errors import GdfParserError
from graphworx32_gdf_parser.models import ParseLimits, Span, TrustedSpan


class ArchiveCursor:
    """Bounded, cursor-driven reader with explicit little-endian unpacking and lineage."""

    def __init__(
        self,
        data: bytes,
        limits: ParseLimits,
        start: int = 0,
        end: int | None = None,
        depth: int = 0,
        lineage: object | None = None,
    ) -> None:
        self.data = data
        self.limits = limits
        self.start = start
        self.end = len(data) if end is None else end
        self.offset = start
        self.last_proven_offset = start
        self.depth = depth
        self._lineage = object() if lineage is None else lineage
        if start < 0 or self.end < start or self.end > len(data):
            raise GdfParserError("ARCHIVE_BOUNDARY_UNKNOWN", "archive region is not bounded")

    def require(self, width: int, label: str = "value") -> TrustedSpan:
        if width < 0:
            raise GdfParserError("ARCHIVE_LENGTH_INVALID", f"archive {label} length is invalid")
        if width > self.end - self.offset:
            raise GdfParserError("ARCHIVE_TRUNCATED", f"archive {label} exceeds its proven boundary")
        start = self.offset
        self.offset += width
        self.last_proven_offset = self.offset
        return TrustedSpan(start, self.offset, self._lineage)

    def read_bytes(self, width: int) -> tuple[bytes, Span]:
        span = self.require(width, "bytes")
        return self.data[span.start : span.end], span

    def read_u16(self) -> tuple[int, Span]:
        span = self.require(2, "u16")
        return struct.unpack_from("<H", self.data, span.start)[0], span

    def read_u32(self) -> tuple[int, Span]:
        span = self.require(4, "u32")
        return struct.unpack_from("<I", self.data, span.start)[0], span

    def read_i32(self) -> tuple[int, Span]:
        span = self.require(4, "i32")
        return struct.unpack_from("<i", self.data, span.start)[0], span

    def read_count(self) -> tuple[int, Span]:
        value, span = self.read_u32()
        if value > self.limits.max_entries:
            raise GdfParserError("ARCHIVE_COUNT_INVALID", "archive count exceeds the approved limit")
        return value, span

    def read_string(self) -> tuple[str, TrustedSpan]:
        length, length_span = self.read_u16()
        if length > self.limits.max_metadata_value_chars:
            raise GdfParserError("ARCHIVE_LENGTH_INVALID", "archive string length exceeds the approved limit")
        raw, value_span = self.read_bytes(length)
        try:
            value = raw.decode("utf-8")
        except UnicodeDecodeError as error:
            raise GdfParserError("ARCHIVE_LENGTH_INVALID", "archive string is not valid UTF-8") from error
        return value, TrustedSpan(length_span.start, value_span.end, self._lineage)

    def subregion(self, width: int) -> "ArchiveCursor":
        span = self.require(width, "region")
        if self.depth + 1 > self.limits.max_depth:
            raise GdfParserError("ARCHIVE_NESTING_LIMIT", "archive nesting exceeds the approved limit")
        return ArchiveCursor(self.data, self.limits, span.start, span.end, self.depth + 1, self._lineage)

    def require_exhausted(self) -> None:
        if self.offset != self.end:
            raise GdfParserError("ARCHIVE_BOUNDARY_UNKNOWN", "archive region has unconsumed bytes")

    def trusted_region(self) -> TrustedSpan:
        self.require_exhausted()
        return TrustedSpan(self.start, self.end, self._lineage)
