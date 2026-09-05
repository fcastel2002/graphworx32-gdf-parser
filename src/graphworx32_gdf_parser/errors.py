"""Common exceptions and status codes for GraphWorX32 GDF Parser."""

from __future__ import annotations

from enum import IntEnum


class ExitStatus(IntEnum):
    CLEAN = 0
    WARNINGS = 1
    UNSUPPORTED = 2
    FATAL = 3


class GdfParserError(Exception):
    """Base exception for parsing and validation failures."""

    def __init__(self, code: str, message: str, status: ExitStatus = ExitStatus.FATAL) -> None:
        super().__init__(message)
        self.code = code
        self.status = status


# Compatibility alias for gdf-inventory migration
InventoryFailure = GdfParserError
