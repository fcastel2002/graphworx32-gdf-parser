"""Tests for screen profile recovery: layers, dynamic objects, and OPoint mapping."""

from __future__ import annotations

import struct
import pytest

from graphworx32_gdf_parser.screen import (
    clean_expression,
    discover_layers,
    extract_screen_profile,
    select_target_layer,
)
from .conftest import make_mfc_cstring_bytes


def test_clean_expression() -> None:
    assert clean_expression('$"ICONICS.Simulator.1\\SimulatedTags.Ramp"$') == "ICONICS.Simulator.1\\SimulatedTags.Ramp"
    assert clean_expression("Plain.Tag.Reference") == "Plain.Tag.Reference"


def test_select_target_layer() -> None:
    layers = {"1-MAIN": [10, 11], "2-ALARM": [20, 21]}
    assert select_target_layer(layers, "1") == "1-MAIN"
    assert select_target_layer(layers, "2") == "2-ALARM"
    assert select_target_layer(layers, "3") is None


def test_extract_screen_profile_empty_or_missing_managers() -> None:
    result = extract_screen_profile(b"Empty contents without managers")
    assert result.layers == {}
    assert result.objects == ()
    assert result.selected_layer is None


def test_extract_screen_profile_synthetic() -> None:
    # Build synthetic Contents with ObjectManager, ODynamicManager, OPointManager
    layer_name = "1-PROCESS"
    layer_cstring = make_mfc_cstring_bytes(layer_name)
    # Array pattern: b"\x83\x44\x00\x00\x00" + count (u16) + IDs (u32 each)
    child_ids = [101, 102]
    arr_chunk = b"\x83\x44\x00\x00\x00" + struct.pack("<H", len(child_ids)) + struct.pack("<2I", *child_ids)
    om_section = b"ObjectManager" + layer_cstring + arr_chunk + b"\x00" * 32

    # ODynamicManager: contains object 101 with dynamic_id 501
    obj_name = "PumpWidget"
    obj_cstring = make_mfc_cstring_bytes(obj_name)
    # Before obj_name: dynamic_id at -13 (u32), object_id at -9 (u32)
    # Total prefix before cstring: 13 bytes
    dm_prefix = struct.pack("<I", 501) + struct.pack("<I", 101) + b"\x00\x00\x00\x00\x00"
    dm_section = b"ODynamicManager" + b"\x00" * 16 + dm_prefix + obj_cstring + b"\x00" * 32

    # OPointManager: marker b"\x98\xf0\x98\xf0", dyn_id 501 at -4, count 1 at +4
    expr = 'ICONICS.Simulator.1\\Ramp'
    expr_cstring = make_mfc_cstring_bytes(expr)
    opm_chunk = struct.pack("<I", 501) + b"\x98\xf0\x98\xf0" + struct.pack("<H", 0) + expr_cstring
    opm_section = b"OPointManager" + b"\x00" * 8 + opm_chunk + b"\x00" * 16

    contents = om_section + dm_section + opm_section

    profile = extract_screen_profile(contents, layer_target="1")
    assert "1-PROCESS" in profile.layers
    assert profile.layers["1-PROCESS"] == [101, 102]
    assert profile.selected_layer == "1-PROCESS"
    assert len(profile.objects) == 1

    obj = profile.objects[0]
    assert obj.object_id == 101
    assert obj.dynamic_id == 501
    assert obj.object_name == "PumpWidget"
    assert obj.data_source == expr


def test_extract_screen_profile_empty_layer_returns_zero_objects() -> None:
    layer_name = "1-EMPTY"
    layer_cstring = make_mfc_cstring_bytes(layer_name)
    # Array pattern with count = 0
    arr_chunk = b"\x83\x44\x00\x00\x00" + struct.pack("<H", 0)
    om_section = b"ObjectManager" + layer_cstring + arr_chunk + b"\x00" * 32

    dm_prefix = struct.pack("<I", 501) + struct.pack("<I", 101) + b"\x00\x00\x00\x00\x00"
    obj_cstring = make_mfc_cstring_bytes("PumpWidget")
    dm_section = b"ODynamicManager" + b"\x00" * 16 + dm_prefix + obj_cstring + b"\x00" * 32

    expr_cstring = make_mfc_cstring_bytes('$"Tag1"$')
    opm_chunk = struct.pack("<I", 501) + b"\x98\xf0\x98\xf0" + struct.pack("<H", 0) + expr_cstring
    opm_section = b"OPointManager" + b"\x00" * 8 + opm_chunk + b"\x00" * 16

    contents = om_section + dm_section + opm_section

    # Layer "1" exists but is empty -> should return 0 objects, not all objects!
    profile = extract_screen_profile(contents, layer_target="1")
    assert profile.selected_layer == "1-EMPTY"
    assert len(profile.objects) == 0


def test_extract_screen_profile_object_with_description_and_custom_data() -> None:
    layer_name = "1-PROCESS"
    layer_cstring = make_mfc_cstring_bytes(layer_name)
    arr_chunk = b"\x83\x44\x00\x00\x00" + struct.pack("<H", 1) + struct.pack("<I", 101)
    om_section = b"ObjectManager" + layer_cstring + arr_chunk + b"\x00" * 32

    dm_prefix = struct.pack("<I", 501) + struct.pack("<I", 101) + b"\x00\x00\x00\x00\x00"
    obj_cstring = make_mfc_cstring_bytes("PumpWidget")
    desc_cstring = make_mfc_cstring_bytes("Pump Description")
    custom_cstring = make_mfc_cstring_bytes("CustomDataPayload")
    dm_section = b"ODynamicManager" + b"\x00" * 16 + dm_prefix + obj_cstring + desc_cstring + custom_cstring + b"\x00" * 32

    expr_cstring = make_mfc_cstring_bytes('$"Tag1"$')
    opm_chunk = struct.pack("<I", 501) + b"\x98\xf0\x98\xf0" + struct.pack("<H", 0) + expr_cstring
    opm_section = b"OPointManager" + b"\x00" * 8 + opm_chunk + b"\x00" * 16

    contents = om_section + dm_section + opm_section

    # Without layer filtering (layer_target=None): should return exactly 1 object, not 3!
    profile = extract_screen_profile(contents, layer_target=None)
    assert len(profile.objects) == 1
    assert profile.objects[0].object_name == "PumpWidget"
    assert profile.objects[0].description == "Pump Description"
    assert profile.objects[0].custom_data == "CustomDataPayload"
