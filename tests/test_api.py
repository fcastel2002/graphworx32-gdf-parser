"""Tests for the high-level public API functions."""

from __future__ import annotations

import tempfile
from pathlib import Path
import pytest

from graphworx32_gdf_parser.api import inventory_file, parse_gdf
from graphworx32_gdf_parser.cfbf import OleFileAdapter
from graphworx32_gdf_parser.errors import ExitStatus
from .conftest import MockOleContainer, MockOleModule, make_mfc_cstring_bytes, make_synthetic_alias_map
from graphworx32_gdf_parser.models import ParseLimits


def test_parse_gdf_with_adapter_mock(tmp_path: Path) -> None:
    test_file = tmp_path / "test.gdf"
    test_file.write_bytes(b"synthetic gdf container file")

    op_entries = [
        ("OPCChannel", "MODBUS_TCP"),
        ("TypeOfPlc", "PLC_01"),
        ("Tag1", "VAL1"),
    ]
    contents_bytes = b"\x00\x00" + make_synthetic_alias_map(op_entries) + b"\x00\x00"
    container = MockOleContainer(contents=contents_bytes, title="My Synthetic Test")
    mock_module = MockOleModule(container)
    adapter = OleFileAdapter(ole_module=mock_module)

    result = parse_gdf(test_file, adapter=adapter, profiles=("aliases",))
    assert result.status == ExitStatus.CLEAN
    assert result.document is not None
    assert result.document.source_size == len(b"synthetic gdf container file")
    assert result.document.archive is not None
    assert len(result.document.archive.objects) == 1

    # Check inventory compatibility wrapper
    inv_result = inventory_file(test_file, adapter=adapter)
    assert inv_result.status == ExitStatus.CLEAN
    assert inv_result.inventory is not None


def test_parse_gdf_with_screen_profile_and_mock_adapter(tmp_path: Path) -> None:
    import struct

    test_file = tmp_path / "screen_test.gdf"
    test_file.write_bytes(b"synthetic screen container")

    layer_cstring = make_mfc_cstring_bytes("1-PROCESS")
    child_ids = [101]
    arr_chunk = b"\x83\x44\x00\x00\x00" + struct.pack("<H", len(child_ids)) + struct.pack("<I", *child_ids)
    om_section = b"ObjectManager" + layer_cstring + arr_chunk + b"\x00" * 32

    dm_prefix = struct.pack("<I", 501) + struct.pack("<I", 101) + b"\x00\x00\x00\x00\x00"
    obj_cstring = make_mfc_cstring_bytes("Widget1")
    dm_section = b"ODynamicManager" + b"\x00" * 16 + dm_prefix + obj_cstring + b"\x00" * 32

    opm_chunk = struct.pack("<I", 501) + b"\x98\xf0\x98\xf0" + struct.pack("<H", 0) + make_mfc_cstring_bytes('$"Tag1"$')
    opm_section = b"OPointManager" + b"\x00" * 8 + opm_chunk + b"\x00" * 16

    contents_bytes = om_section + dm_section + opm_section

    container = MockOleContainer(contents=contents_bytes, title="Screen Test")
    mock_module = MockOleModule(container)
    adapter = OleFileAdapter(ole_module=mock_module)

    result = parse_gdf(test_file, adapter=adapter, profiles=("screen",), layer_target="1")
    assert result.status == ExitStatus.CLEAN
    assert result.document is not None
    assert result.document.archive is None
    assert result.document.screen is not None
    assert result.document.screen.selected_layer == "1-PROCESS"
    assert len(result.document.screen.objects) == 1
    assert result.document.screen.objects[0].object_name == "Widget1"


def test_parse_gdf_screen_profile_reads_contents_once_and_skips_alias_decoding(tmp_path: Path) -> None:
    from unittest.mock import patch
    import struct
    import graphworx32_gdf_parser.api as api_mod

    test_file = tmp_path / "screen_single_read.gdf"
    test_file.write_bytes(b"synthetic single read screen")

    layer_cstring = make_mfc_cstring_bytes("1-PROCESS")
    arr_chunk = b"\x83\x44\x00\x00\x00" + struct.pack("<H", 1) + struct.pack("<I", 101)
    om_section = b"ObjectManager" + layer_cstring + arr_chunk + b"\x00" * 32
    dm_prefix = struct.pack("<I", 501) + struct.pack("<I", 101) + b"\x00\x00\x00\x00\x00"
    obj_cstring = make_mfc_cstring_bytes("PumpWidget")
    dm_section = b"ODynamicManager" + b"\x00" * 16 + dm_prefix + obj_cstring + b"\x00" * 32
    opm_chunk = struct.pack("<I", 501) + b"\x98\xf0\x98\xf0" + struct.pack("<H", 0) + make_mfc_cstring_bytes('$"Tag1"$')
    opm_section = b"OPointManager" + b"\x00" * 8 + opm_chunk + b"\x00" * 16
    contents_bytes = om_section + dm_section + opm_section

    class _TrackedContainer(MockOleContainer):
        contents_reads = 0

        def openstream(self, path: str | list[str]):
            target = [path] if isinstance(path, str) else path
            if target == ["Contents"]:
                self.contents_reads += 1
            return super().openstream(path)

    container = _TrackedContainer(contents=contents_bytes)
    adapter = OleFileAdapter(ole_module=MockOleModule(container))

    with patch.object(api_mod, "decode_experimental_local_aliases", wraps=api_mod.decode_experimental_local_aliases) as alias_decoder:
        result = parse_gdf(test_file, adapter=adapter, profiles=("screen",), layer_target="1")

    assert result.status == ExitStatus.CLEAN
    assert result.document is not None
    assert result.document.archive is None
    assert result.document.screen is not None
    assert len(result.document.screen.objects) == 1
    assert result.document.screen.objects[0].object_name == "PumpWidget"

    # Contents was read exactly ONCE, and alias decoder was called ZERO times!
    assert container.contents_reads == 1
    assert alias_decoder.call_count == 0


def test_parse_gdf_screen_profile_exceeds_max_stream_bytes(tmp_path: Path) -> None:
    test_file = tmp_path / "limit_test.gdf"
    test_file.write_bytes(b"synthetic stream limit container")

    class _GuardedContainer(MockOleContainer):
        def get_size(self, path: str | list[str]) -> int:
            return 500

        def openstream(self, path: str | list[str]) -> None:
            raise AssertionError("openstream() must not be called when Contents size exceeds max_stream_bytes!")

    container = _GuardedContainer()
    adapter = OleFileAdapter(ole_module=MockOleModule(container))

    # Limit max_stream_bytes to 100 bytes while container reports 500
    result = parse_gdf(
        test_file,
        adapter=adapter,
        profiles=("screen",),
        limits=ParseLimits(max_stream_bytes=100),
    )
    assert result.status == ExitStatus.FATAL
    assert result.document is None
    assert len(result.diagnostics) == 1
    assert result.diagnostics[0].code == "RESOURCE_LIMIT_EXCEEDED"
    assert "exceeds the approved limit" in result.diagnostics[0].message
