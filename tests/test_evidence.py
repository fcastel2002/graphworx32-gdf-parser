"""Tests for evidence record loading, promotion predicates, and decoder registry."""

from __future__ import annotations

import pytest

from graphworx32_gdf_parser.errors import GdfParserError
from graphworx32_gdf_parser.evidence import (
    load_evidence_record,
    parse_evidence_record,
    production_registry,
    inspect_contents,
)
from graphworx32_gdf_parser.models import ParseLimits


def test_bundled_default_evidence_record_loads_safely() -> None:
    record = load_evidence_record()
    assert record.disposition == "BLOCKED_EVIDENCE_REQUIRED"
    assert not record.approved
    assert "runtime_class_schema_observed" in record.failed_criterion_ids
    assert len(record.fixtures) == 8


def test_production_registry_blocked_fails_closed() -> None:
    registry = production_registry()
    assert len(registry.layouts) == 0

    result = inspect_contents(b"some contents", ParseLimits(), registry=registry, runtime_class="TestClass", schema=1)
    assert result.diagnostic_code == "ARCHIVE_EVIDENCE_REQUIRED"
    assert result.last_proven_offset == 0


def test_parse_evidence_record_rejects_confidential_bytes() -> None:
    bad_payload = {"record_version": 1, "data": b"confidential"}
    with pytest.raises(GdfParserError) as exc:
        parse_evidence_record(bad_payload)
    assert exc.value.code == "ARCHIVE_EVIDENCE_REQUIRED"
