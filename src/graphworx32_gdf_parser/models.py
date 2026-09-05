"""Data models and structures for GraphWorX32 GDF parsing and extraction."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Sequence

from graphworx32_gdf_parser.errors import ExitStatus, GdfParserError


@dataclass(frozen=True, eq=False)
class Span:
    """A half-open [start, end) byte range in an archive or stream."""

    start: int
    end: int

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Span) and (self.start, self.end) == (other.start, other.end)

    def __hash__(self) -> int:
        return hash((self.start, self.end))


@dataclass(frozen=True)
class TrustedSpan(Span):
    """A consumed range capability bound to one cursor lineage."""

    _lineage: object = field(repr=False, compare=False)


@dataclass(frozen=True)
class ParseLimits:
    """Configurable resource and recursion limits for bounded parsing."""

    max_input_bytes: int = 67_108_864
    max_entries: int = 4096
    max_depth: int = 32
    max_component_chars: int = 255
    max_path_chars: int = 4096
    max_stream_bytes: int = 67_108_864
    max_diagnostics: int = 1000
    max_diagnostic_chars: int = 2048
    max_metadata_value_chars: int = 8192
    max_xml_bytes: int = 16_777_216


Limits = ParseLimits
DEFAULT_LIMITS = ParseLimits()


class EntryType(str, Enum):
    ROOT = "root"
    STORAGE = "storage"
    STREAM = "stream"


@dataclass(frozen=True)
class Diagnostic:
    severity: str
    code: str
    message: str
    entry_path: str | None = None


@dataclass(frozen=True)
class MetadataProperty:
    name: str
    value: str


@dataclass(frozen=True)
class CfbfEntry:
    path: tuple[str, ...]
    entry_type: EntryType
    byte_size: int | None
    opaque: bool = True

    @property
    def display_path(self) -> str:
        return "/" if not self.path else "/".join(self.path)


class ArchiveEventKind(str, Enum):
    NULL = "null"
    CLASS_DECLARATION = "class_declaration"
    CLASS_REFERENCE = "class_reference"
    NEW_OBJECT = "new_object"
    EXISTING_OBJECT_REFERENCE = "existing_object_reference"
    OPAQUE = "opaque"
    OBJECT_LOCAL_EVIDENCE = "object_local_evidence"


@dataclass(frozen=True)
class ArchiveEvent:
    encounter_index: int
    event: ArchiveEventKind
    start: int
    end: int
    parser_object_id: int | None = None
    archive_class_id: int | None = None
    archive_object_id: int | None = None
    runtime_class: str | None = None
    schema: int | None = None
    owner_object_id: int | None = None
    symbol_object_id: int | None = None
    collection_owner_id: int | None = None
    evidence_kind: str | None = None
    evidence: str | None = None
    diagnostic_code: str | None = None


@dataclass(frozen=True)
class ArchiveClass:
    archive_class_id: int
    runtime_class: str
    schema: int
    span: Span


@dataclass(frozen=True)
class ArchiveObject:
    archive_object_id: int
    parser_object_id: int
    archive_class_id: int
    span: Span


@dataclass(frozen=True)
class ObjectLocalEvidence:
    """Raw structural evidence bound solely to one parser-owned object."""

    owner_object_id: int
    runtime_class: str
    schema: int
    field_kind: str
    raw_evidence: str
    span: Span
    symbol_object_id: int | None = None
    collection_owner_id: int | None = None
    alias_name: str | None = None
    match_key: str | None = None


@dataclass(frozen=True)
class GlobalAliasEvidence:
    """Raw Global Alias evidence intentionally outside object-local ownership."""

    runtime_class: str
    schema: int
    field_kind: str
    raw_evidence: str
    span: Span


@dataclass(frozen=True)
class ObjectLocalSet:
    owner_object_id: int
    evidence: tuple[ObjectLocalEvidence, ...] = ()


@dataclass(frozen=True)
class ArchiveResult:
    events: tuple[ArchiveEvent, ...] = ()
    classes: dict[int, ArchiveClass] = field(default_factory=dict)
    objects: dict[int, ArchiveObject] = field(default_factory=dict)
    object_local_sets: dict[int, ObjectLocalSet] = field(default_factory=dict)
    global_alias_evidence: tuple[GlobalAliasEvidence, ...] = ()
    last_proven_offset: int = 0
    diagnostic_code: str | None = None


@dataclass(frozen=True)
class EvidenceBasis:
    """Redacted proof required before a class/schema layout can be used."""

    fixture_id: str
    runtime_class: str
    schema: int
    proven_field_start: int
    proven_field_end: int
    proven_end: int
    baseline_change_isolated: bool
    runtime_observed: bool
    repeated: bool
    negative_control: bool
    decoder_statement: str
    evidence_ids: frozenset[str] = frozenset()
    predicate_results: tuple[tuple[str, bool], ...] = ()

    def missing_predicates(self) -> tuple[str, ...]:
        predicates = (
            ("baseline-change isolation", self.baseline_change_isolated),
            ("runtime class/schema observation", self.runtime_observed),
            ("independent field boundary", self.proven_field_start < self.proven_field_end <= self.proven_end),
            ("repeatability", self.repeated),
            ("negative control", self.negative_control),
            ("decoder statement", bool(self.decoder_statement)),
            ("complete evidence basis", not self.predicate_results or all(result for _, result in self.predicate_results)),
        )
        return tuple(name for name, satisfied in predicates if not satisfied)


@dataclass(frozen=True)
class ApprovedLayout:
    basis: EvidenceBasis
    decoder: object  # ArchiveGrammar


@dataclass(frozen=True)
class EvidenceFixture:
    role: str
    evidence_id: str
    runtime_class_id: str
    schema: int | None
    decoder_id: str
    field_boundary: Span
    payload_boundary: Span


@dataclass(frozen=True)
class EvidenceRecord:
    disposition: str
    failed_criterion_ids: frozenset[str]
    predicate_results: tuple[tuple[str, bool], ...]
    fixtures: tuple[EvidenceFixture, ...]

    @property
    def approved(self) -> bool:
        return self.disposition == "PROMOTION_APPROVED"


# --- Screen / Display models ---

@dataclass(frozen=True)
class RawDynamicObject:
    """Extracted dynamic screen object before domain-specific interpretation."""

    index: int
    object_id: int
    dynamic_id: int
    object_name: str
    dynamic_type: str
    custom_data: str
    data_source: str
    layer_name: str
    description: str = ""


@dataclass(frozen=True)
class ScreenProfileResult:
    """Result of screen profile recovery (layers, dynamic objects, and points)."""

    layers: dict[str, list[int]] = field(default_factory=dict)
    opoints: dict[int, str] = field(default_factory=dict)
    objects: tuple[RawDynamicObject, ...] = ()
    selected_layer: str | None = None


# --- Overall Document / Result models ---

@dataclass(frozen=True)
class GdfDocument:
    source_path: Path
    source_size: int
    source_sha256: str
    entries: tuple[CfbfEntry, ...]
    metadata: tuple[MetadataProperty, ...] = ()
    archive: ArchiveResult | None = None
    screen: ScreenProfileResult | None = None


Inventory = GdfDocument


@dataclass(frozen=True)
class ParseResult:
    status: ExitStatus
    document: GdfDocument | None
    diagnostics: tuple[Diagnostic, ...] = ()

    @property
    def inventory(self) -> GdfDocument | None:
        """Compatibility property for gdf-inventory."""
        return self.document


InventoryResult = ParseResult
