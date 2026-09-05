"""Screen, layer, dynamic object, and OPoint recovery profile for GraphWorX32 GDF."""

from __future__ import annotations

import re
import struct

from graphworx32_gdf_parser.aliases import read_mfc_cstring
from graphworx32_gdf_parser.models import RawDynamicObject, ScreenProfileResult


def clean_expression(raw: str) -> str:
    """Extract inner content if enclosed in $"..."$."""
    match = re.search(r'\$"([^"]+)"\$', raw)
    return match.group(1) if match else raw


def discover_layers(contents: bytes, om_start: int, dm_start: int) -> dict[str, list[int]]:
    """Locate layer symbols and their child object IDs in ObjectManager."""
    layer_symbols: dict[str, list[int]] = {}
    pos = om_start
    while pos < dm_start:
        if contents[pos : pos + 3] == b"\xff\xfe\xff":
            name, end = read_mfc_cstring(contents, pos)
            if name and re.match(r"^\d+-", name):
                post_chunk = contents[end : end + 80]
                idx_arr = post_chunk.find(b"\x83\x44\x00\x00\x00")
                if idx_arr != -1:
                    arr_start = end + idx_arr + 5
                    if arr_start + 2 <= len(contents):
                        cnt = struct.unpack_from("<H", contents, arr_start)[0]
                        c_start = arr_start + 2
                        if c_start + cnt * 4 <= len(contents):
                            cids = [
                                struct.unpack_from("<I", contents, c_start + i * 4)[0]
                                for i in range(cnt)
                            ]
                            layer_symbols[name] = cids
            pos = end if name else pos + 1
        else:
            pos += 1
    return layer_symbols


def select_target_layer(layer_symbols: dict[str, list[int]], layer_target: str) -> str | None:
    """Resolve layer target ('1', '1-ALM', etc.) to the exact layer symbol name."""
    clean_target = layer_target.strip()
    if clean_target in layer_symbols:
        return clean_target
    for name in layer_symbols:
        if re.match(rf"^{re.escape(clean_target)}[^\d]", name):
            return name
    for name in layer_symbols:
        if clean_target.lower() in name.lower():
            return name
    return None


def build_opoint_map(contents: bytes, opm_start: int) -> dict[int, str]:
    """Map every dynamic_id to its Data Source expression in OPointManager."""
    pos = opm_start
    # Detect the file-specific OPoint marker (repeated 2-byte tag ending in \xf0)
    match = re.search(rb"(.\xf0)\1", contents[opm_start : opm_start + 8000])
    marker = match.group(0) if match else b"\x98\xf0\x98\xf0"

    opoint_map: dict[int, str] = {}

    while pos < len(contents) - 10:
        idx = contents.find(marker, pos)
        if idx == -1:
            break
        if idx >= opm_start + 4:
            dyn_id = struct.unpack_from("<I", contents, idx - 4)[0]
            if idx + 6 <= len(contents):
                cnt = struct.unpack_from("<H", contents, idx + 4)[0]
                str_offset = idx + 6 + cnt * 4
                expr: str | None = None
                for p in range(str_offset, min(len(contents) - 4, str_offset + 16)):
                    if contents[p : p + 3] == b"\xff\xfe\xff":
                        expr, _ = read_mfc_cstring(contents, p)
                        if expr:
                            break
                if expr:
                    opoint_map[dyn_id] = expr
        pos = idx + 4

    return opoint_map


def extract_screen_profile(
    contents: bytes,
    layer_target: str | None = "1",
) -> ScreenProfileResult:
    """Extract layers, dynamic objects, and points from Contents stream."""
    om_start = contents.find(b"ObjectManager")
    dm_start = contents.find(b"ODynamicManager")
    opm_start = contents.find(b"OPointManager")

    if om_start == -1 or dm_start == -1 or opm_start == -1 or not (om_start < dm_start < opm_start):
        return ScreenProfileResult(layers={}, opoints={}, objects=(), selected_layer=None)

    layer_symbols = discover_layers(contents, om_start, dm_start)
    selected_layer = select_target_layer(layer_symbols, layer_target) if layer_target else None
    layer_children: set[int] | None = None
    if layer_target is not None:
        layer_children = set(layer_symbols.get(selected_layer, [])) if selected_layer else set()

    opoint_map = build_opoint_map(contents, opm_start)

    objects: list[RawDynamicObject] = []
    pos = dm_start
    obj_counter = 1

    while pos < opm_start:
        if contents[pos : pos + 3] == b"\xff\xfe\xff":
            name, end_name = read_mfc_cstring(contents, pos)
            end_record = end_name
            if name and pos >= dm_start + 13:
                object_id = struct.unpack_from("<I", contents, pos - 9)[0]
                dynamic_id = struct.unpack_from("<I", contents, pos - 13)[0]

                next_cs_idx = contents.find(b"\xff\xfe\xff", end_name, end_name + 24)
                desc = ""
                custom_data = ""
                if next_cs_idx != -1:
                    d_val, end_desc = read_mfc_cstring(contents, next_cs_idx)
                    if d_val is not None:
                        desc = d_val
                        end_record = end_desc
                        c_val, end_custom = read_mfc_cstring(contents, end_desc)
                        if c_val is not None:
                            custom_data = c_val
                            end_record = end_custom

                if layer_children is None or object_id in layer_children:
                    dyn_type = "Size"
                    pre_win = contents[max(dm_start, pos - 30) : pos]
                    if b"OHide" in pre_win or "hide" in name.lower():
                        dyn_type = "Hide"

                    expr = opoint_map.get(dynamic_id, "")
                    rec = RawDynamicObject(
                        index=obj_counter,
                        object_id=object_id,
                        dynamic_id=dynamic_id,
                        object_name=name,
                        dynamic_type=dyn_type,
                        custom_data=custom_data,
                        data_source=expr,
                        layer_name=selected_layer or "",
                        description=desc,
                    )
                    objects.append(rec)
                    obj_counter += 1
            pos = end_record if name else pos + 1
        else:
            pos += 1
    return ScreenProfileResult(
        layers=layer_symbols,
        opoints=opoint_map,
        objects=tuple(objects),
        selected_layer=selected_layer,
    )
