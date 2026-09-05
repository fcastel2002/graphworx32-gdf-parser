"""Tests for ParseLimits validation and resource enforcement."""

from __future__ import annotations

import io
import pytest

from graphworx32_gdf_parser.cfbf import OleFileAdapter, _bounded_text, _validate_path
from graphworx32_gdf_parser.errors import GdfParserError
from graphworx32_gdf_parser.models import ParseLimits
from .conftest import MockOleContainer, MockOleModule


def test_bounded_text_limit() -> None:
    assert _bounded_text("short", 10, "field") == "short"
    with pytest.raises(GdfParserError) as exc:
        _bounded_text("very long text exceeding limit", 5, "test_field")
    assert exc.value.code == "RESOURCE_LIMIT_EXCEEDED"


def test_validate_path_limits() -> None:
    limits = ParseLimits(max_depth=3, max_component_chars=10, max_path_chars=20)
    assert _validate_path(["a", "b", "c"], limits) == ("a", "b", "c")

    with pytest.raises(GdfParserError):
        _validate_path(["a", "b", "c", "d"], limits)

    with pytest.raises(GdfParserError):
        _validate_path(["verylongcomponentname"], limits)


def test_adapter_max_entries_enforcement() -> None:
    limits = ParseLimits(max_entries=2)
    # 3 paths exceeds limit of 2
    container = MockOleContainer(paths=[["Contents"], ["Stream1"], ["Stream2"]])
    adapter = OleFileAdapter(ole_module=MockOleModule(container))

    with pytest.raises(GdfParserError) as exc:
        adapter.inventory(io.BytesIO(b"fake"), limits)
    assert exc.value.code == "RESOURCE_LIMIT_EXCEEDED"
