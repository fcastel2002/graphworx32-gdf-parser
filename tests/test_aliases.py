"""Tests for alias recovery profile and CString reading."""

from __future__ import annotations

import struct
import pytest

from graphworx32_gdf_parser.aliases import (
    decode_experimental_local_aliases,
    read_experimental_cstring,
    read_mfc_cstring,
)
from graphworx32_gdf_parser.models import ParseLimits
from .conftest import make_mfc_cstring_bytes, make_synthetic_alias_map


def test_read_mfc_cstring_short_and_extended() -> None:
    short_text = "Short String"
    short_bytes = make_mfc_cstring_bytes(short_text)
    val, end = read_mfc_cstring(short_bytes, 0)
    assert val == short_text
    assert end == len(short_bytes)

    long_text = "A" * 300
    long_bytes = make_mfc_cstring_bytes(long_text)
    val_long, end_long = read_mfc_cstring(long_bytes, 0)
    assert val_long == long_text
    assert end_long == len(long_bytes)



def test_read_mfc_cstring_surrogate_pairs_and_unicode() -> None:
    unicode_text = "Válvula_Presión_Tanque_🌍_№1"
    raw_bytes = make_mfc_cstring_bytes(unicode_text)
    val, end = read_mfc_cstring(raw_bytes, 0)
    assert val == unicode_text
    assert end == len(raw_bytes)

def test_decode_experimental_local_aliases_happy_path() -> None:
    # Build synthetic operational map with Channel and Device plus a custom alias
    op_entries = [
        ("Channel", "MODBUS_TCP"),
        ("Device", "PLC_01"),
        ("PressureTag", "PIT_101"),
        ("Description", "Header Pressure"),
    ]
    alias_map_bytes = make_synthetic_alias_map(op_entries)
    # Prefix with 2 padding bytes because string map search starts at index 2
    contents = b"\x00\x00" + alias_map_bytes + b"\x00\x00"

    result = decode_experimental_local_aliases(contents, ParseLimits())
    assert result.diagnostic_code is None
    assert len(result.objects) == 1
    assert 1 in result.object_local_sets

    local_evidence = result.object_local_sets[1].evidence
    aliases_by_name = {ev.alias_name: ev.raw_evidence for ev in local_evidence}

    assert aliases_by_name["Channel"] == "MODBUS_TCP"
    assert aliases_by_name["Device"] == "PLC_01"
    assert aliases_by_name["PressureTag"] == "PIT_101"
    assert aliases_by_name["Description"] == "Header Pressure"


def test_decode_experimental_local_aliases_no_operational_map() -> None:
    # Map with only description entries should not produce operational objects
    entries = [
        ("Description", "Only description without operational aliases"),
    ]
    contents = b"\x00\x00" + make_synthetic_alias_map(entries)
    result = decode_experimental_local_aliases(contents, ParseLimits())
    assert result.diagnostic_code == "ARCHIVE_EXPERIMENTAL_NO_ALIAS_MAP"
