"""Experimental GraphWorX32 local alias and description map recovery."""

from __future__ import annotations

import struct
from dataclasses import dataclass

from graphworx32_gdf_parser.models import (
    ArchiveClass,
    ArchiveEvent,
    ArchiveEventKind,
    ArchiveObject,
    ArchiveResult,
    ObjectLocalEvidence,
    ObjectLocalSet,
    ParseLimits,
    Span,
    TrustedSpan,
)


@dataclass(frozen=True)
class _ExperimentalMap:
    entries: tuple[tuple[str, TrustedSpan, str, TrustedSpan], ...]
    start: int
    end: int


_EXPERIMENTAL_DESCRIPTION_NAMES = frozenset({"Description", "Desc"})


def read_experimental_cstring(
    data: bytes,
    offset: int,
    limits: ParseLimits,
    lineage: object,
) -> tuple[str, TrustedSpan, int] | None:
    """Read the short Unicode CString form observed in GraphWorX32 fixtures."""
    if offset + 4 > len(data) or data[offset : offset + 3] != b"\xff\xfe\xff":
        return None
    units = data[offset + 3]
    end = offset + 4 + units * 2
    if units > limits.max_metadata_value_chars or end > len(data):
        return None
    try:
        value = data[offset + 4 : end].decode("utf-16le")
    except UnicodeDecodeError:
        return None
    return value, TrustedSpan(offset, end, lineage), end


def read_mfc_cstring(
    contents: bytes,
    offset: int,
    max_chars: int = 8192,
) -> tuple[str | None, int]:
    """Read a UTF-16LE CString from MFC CArchive bytes at offset.

    Supports both short (< 0xFF characters) and extended (0xFF prefix + u16 length) forms.
    """
    if offset + 4 > len(contents) or contents[offset : offset + 3] != b"\xff\xfe\xff":
        return None, offset
    l_byte = contents[offset + 3]
    if l_byte == 0xFF:
        if offset + 6 > len(contents):
            return None, offset
        length = struct.unpack_from("<H", contents, offset + 4)[0]
        start = offset + 6
    else:
        length = l_byte
        start = offset + 4
    if length > max_chars:
        return None, offset
    end = start + length * 2
    if end > len(contents):
        return None, offset
    try:
        val = contents[start:end].decode("utf-16le")
        return val, end
    except UnicodeDecodeError:
        return None, offset


def _experimental_string_maps(contents: bytes, limits: ParseLimits) -> tuple[_ExperimentalMap, ...]:
    maps: list[_ExperimentalMap] = []
    lineage = object()
    for start in range(2, len(contents) - 4):
        if contents[start : start + 3] != b"\xff\xfe\xff":
            continue
        count = struct.unpack_from("<H", contents, start - 2)[0]
        if count < 1 or count > 64 or count > limits.max_entries:
            continue
        offset = start
        entries: list[tuple[str, TrustedSpan, str, TrustedSpan]] = []
        for _ in range(count):
            key = read_experimental_cstring(contents, offset, limits, lineage)
            if key is None or not key[0]:
                break
            value = read_experimental_cstring(contents, key[2], limits, lineage)
            if value is None:
                break
            entries.append((key[0], key[1], value[0], value[1]))
            offset = value[2]
        if len(entries) == count:
            maps.append(_ExperimentalMap(tuple(entries), start, offset))
    return tuple(maps)


def _description_match_key(value: str) -> str:
    return "".join(character for character in value.upper() if character.isalnum())


def decode_experimental_local_aliases(contents: bytes, limits: ParseLimits) -> ArchiveResult:
    """Recover useful object-local aliases from evidenced GraphWorX string maps.

    Ownership is an experimental ordinal association. Every value retains its exact
    source span and repeated serialized copies are deduplicated only within a file.
    """
    maps = _experimental_string_maps(contents, limits)
    operational: list[_ExperimentalMap] = []
    description_maps: list[_ExperimentalMap] = []
    seen_operational: set[tuple[tuple[str, str], ...]] = set()
    for map_ in maps:
        has_operational_entries = any(
            key and key not in _EXPERIMENTAL_DESCRIPTION_NAMES for key, _, _, _ in map_.entries
        )
        if has_operational_entries:
            identity = tuple((key, value) for key, _, value, _ in map_.entries)
            if identity not in seen_operational:
                seen_operational.add(identity)
                operational.append(map_)
        elif any(key in _EXPERIMENTAL_DESCRIPTION_NAMES for key, _, _, _ in map_.entries):
            description_maps.append(map_)

    if not operational:
        return ArchiveResult(last_proven_offset=0, diagnostic_code="ARCHIVE_EXPERIMENTAL_NO_ALIAS_MAP")

    object_count = max(len(operational), 1)
    classes = {1: ArchiveClass(1, "ExperimentalGraphWorXAliasObject", 0, Span(0, 0))}
    objects: dict[int, ArchiveObject] = {}
    object_sets: dict[int, ObjectLocalSet] = {}
    events: list[ArchiveEvent] = []
    for index in range(object_count):
        parser_id = index + 1
        map_ = operational[min(index, len(operational) - 1)]
        objects[parser_id] = ArchiveObject(parser_id, parser_id, 1, Span(map_.start, map_.end))
        evidence: list[ObjectLocalEvidence] = []
        primary_entry = next(
            (
                entry
                for entry in map_.entries
                if entry[0] and entry[0] not in _EXPERIMENTAL_DESCRIPTION_NAMES
            ),
            None,
        )
        primary_value = primary_entry[2] if primary_entry is not None else None
        primary_match_key = _description_match_key(primary_value) if primary_value else ""
        description_candidates: list[tuple[str, str, TrustedSpan, str]] = []
        for key, _, value, value_span in map_.entries:
            if key in _EXPERIMENTAL_DESCRIPTION_NAMES:
                description_candidates.append((key, value, value_span, primary_value or ""))
            else:
                kind = "facility" if key in {"Channel", "Facility"} else "device" if key in {"Device", "PLC", "Controller"} else "local-alias"
                record = ObjectLocalEvidence(
                    parser_id,
                    classes[1].runtime_class,
                    0,
                    kind,
                    value,
                    value_span,
                    alias_name=key,
                )
                evidence.append(record)

        # Match description records against the first real alias value
        if primary_match_key:
            for description_map in description_maps:
                identifiers = tuple(
                    (key, value)
                    for key, _, value, _ in description_map.entries
                    if key and key not in _EXPERIMENTAL_DESCRIPTION_NAMES
                )
                matched = next(
                    ((key, value) for key, value in identifiers if _description_match_key(value) == primary_match_key),
                    None,
                )
                if matched is None:
                    continue
                for key, _, value, value_span in description_map.entries:
                    if key in _EXPERIMENTAL_DESCRIPTION_NAMES:
                        description_candidates.append((key, value, value_span, matched[1]))

        seen_descriptions: set[tuple[str, str, int, int, str]] = set()
        for alias_name, value, value_span, match_key in description_candidates:
            identity = (alias_name, value, value_span.start, value_span.end, match_key)
            if identity in seen_descriptions:
                continue
            seen_descriptions.add(identity)
            record = ObjectLocalEvidence(
                parser_id,
                classes[1].runtime_class,
                0,
                "description",
                value,
                value_span,
                alias_name=alias_name,
                match_key=match_key,
            )
            evidence.append(record)
        evidence.sort(key=lambda item: (item.span.start, item.span.end, item.field_kind))
        for item in evidence:
            events.append(
                ArchiveEvent(
                    len(events) + 1,
                    ArchiveEventKind.OBJECT_LOCAL_EVIDENCE,
                    item.span.start,
                    item.span.end,
                    parser_object_id=parser_id,
                    archive_class_id=1,
                    archive_object_id=parser_id,
                    runtime_class=classes[1].runtime_class,
                    schema=0,
                    owner_object_id=parser_id,
                    evidence_kind=item.field_kind,
                    evidence=item.raw_evidence,
                )
            )
        object_sets[parser_id] = ObjectLocalSet(parser_id, tuple(evidence))
    last_offset = max((event.end for event in events), default=0)
    return ArchiveResult(tuple(events), classes, objects, object_sets, (), last_offset)
