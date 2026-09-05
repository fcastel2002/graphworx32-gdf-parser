"""Evidence validation, schema promotion, and grammar-driven decoders for GDF."""

from __future__ import annotations

import importlib.resources
import json
import re
from pathlib import Path
from typing import Protocol

from graphworx32_gdf_parser.cursor import ArchiveCursor
from graphworx32_gdf_parser.errors import GdfParserError
from graphworx32_gdf_parser.models import (
    ApprovedLayout,
    ArchiveClass,
    ArchiveEvent,
    ArchiveEventKind,
    ArchiveObject,
    ArchiveResult,
    EvidenceBasis,
    EvidenceFixture,
    EvidenceRecord,
    GlobalAliasEvidence,
    ObjectLocalEvidence,
    ObjectLocalSet,
    ParseLimits,
    Span,
    TrustedSpan,
)

_EVIDENCE_ROOT_FIELDS = frozenset({"record_version", "disposition", "failed_criterion_ids", "promotion_predicates", "fixtures"})
_EVIDENCE_FIXTURE_FIELDS = frozenset({"role", "evidence_id", "recipe_id", "runtime_class_id", "schema", "contents_sha256", "byte_size", "changed_spans", "unchanged_regions", "field_boundary", "payload_boundary", "repeatability_outcome", "control_outcome", "conclusion_outcome", "decoder_id"})
_EVIDENCE_ROLES = frozenset({"one_object_baseline", "opcchannel_variant", "typeofplc_variant", "same_owner_description_variant", "unrelated_local_alias_variant", "two_object_collision", "global_alias_control", "repeated_saves"})
_PROMOTION_PREDICATES = frozenset({"baseline_change_isolated", "runtime_class_schema_observed", "independent_boundaries_proven", "repeatability_confirmed", "negative_control_confirmed", "evidence_basis_complete"})
_STRUCTURAL_ID = re.compile(r"^[A-Z][A-Z0-9_]{2,63}$")
_EVIDENCE_BLOCK = re.compile(r"```json\n(.*?)\n```", re.DOTALL)
_UNOBSERVED = "UNOBSERVED"
_UNAVAILABLE = "UNAVAILABLE"
_REPEATABILITY_OUTCOMES = frozenset({"CONFIRMED_BYTE_IDENTICAL", _UNOBSERVED})
_CONTROL_OUTCOMES = frozenset({"BASELINE_OBSERVED", "LOCALIZED_ALIGNMENT_OBSERVED", "ISOLATED_CHANGED_SPANS_OBSERVED", _UNOBSERVED})
_CONCLUSION_OUTCOMES = frozenset({"STRUCTURAL_OBSERVATION_RECORDED", "PROMOTION_PENDING", _UNOBSERVED})


def _validate_span(value: object, label: str) -> tuple[int, int]:
    if not isinstance(value, list) or len(value) != 2 or not all(isinstance(item, int) and item >= 0 for item in value) or value[0] > value[1]:
        raise GdfParserError("ARCHIVE_EVIDENCE_REQUIRED", f"invalid evidence {label}")
    return value[0], value[1]


def _reject_confidential_evidence(value: object) -> None:
    if isinstance(value, (bytes, bytearray, memoryview)):
        raise GdfParserError("ARCHIVE_EVIDENCE_REQUIRED", "byte-like evidence is forbidden")
    if isinstance(value, (dict, list)):
        for nested in (value.values() if isinstance(value, dict) else value):
            _reject_confidential_evidence(nested)


def parse_evidence_record(record: object) -> EvidenceRecord:
    """Validate the committed redacted evidence schema before registry construction."""
    _reject_confidential_evidence(record)
    if not isinstance(record, dict) or set(record) != _EVIDENCE_ROOT_FIELDS or record.get("record_version") != 1:
        raise GdfParserError("ARCHIVE_EVIDENCE_REQUIRED", "invalid evidence record envelope")
    disposition = record.get("disposition")
    if disposition not in {"BLOCKED_EVIDENCE_REQUIRED", "PROMOTION_APPROVED"}:
        raise GdfParserError("ARCHIVE_EVIDENCE_REQUIRED", "invalid evidence disposition")
    predicates = record["promotion_predicates"]
    if not isinstance(predicates, list) or len(predicates) != len(_PROMOTION_PREDICATES):
        raise GdfParserError("ARCHIVE_EVIDENCE_REQUIRED", "promotion predicates are incomplete")
    if any(not isinstance(item, dict) or set(item) != {"id", "result"} or item["id"] not in _PROMOTION_PREDICATES or not isinstance(item["result"], bool) for item in predicates):
        raise GdfParserError("ARCHIVE_EVIDENCE_REQUIRED", "invalid promotion predicate")
    predicate_results = tuple((item["id"], item["result"]) for item in predicates)
    if {identifier for identifier, _ in predicate_results} != _PROMOTION_PREDICATES:
        raise GdfParserError("ARCHIVE_EVIDENCE_REQUIRED", "promotion predicates are incomplete")
    failed = record["failed_criterion_ids"]
    if not isinstance(failed, list) or set(failed) - _PROMOTION_PREDICATES or len(failed) != len(set(failed)):
        raise GdfParserError("ARCHIVE_EVIDENCE_REQUIRED", "invalid failed criterion IDs")
    failed_ids = frozenset(failed)
    failures = frozenset(identifier for identifier, result in predicate_results if not result)
    if (disposition == "PROMOTION_APPROVED" and (failures or failed_ids)) or (disposition == "BLOCKED_EVIDENCE_REQUIRED" and (not failures or failed_ids != failures)):
        raise GdfParserError("ARCHIVE_EVIDENCE_REQUIRED", "evidence disposition does not match its predicates")
    fixtures = record["fixtures"]
    if not isinstance(fixtures, list) or len(fixtures) != len(_EVIDENCE_ROLES):
        raise GdfParserError("ARCHIVE_EVIDENCE_REQUIRED", "fixture roles are incomplete")
    parsed_fixtures: list[EvidenceFixture] = []
    for fixture in fixtures:
        if not isinstance(fixture, dict) or set(fixture) != _EVIDENCE_FIXTURE_FIELDS or not isinstance(fixture.get("role"), str):
            raise GdfParserError("ARCHIVE_EVIDENCE_REQUIRED", "fixture fields are incomplete")
        if not isinstance(fixture["evidence_id"], str) or not re.fullmatch(r"E-02-[A-Z]+", fixture["evidence_id"]):
            raise GdfParserError("ARCHIVE_EVIDENCE_REQUIRED", "invalid evidence ID")
        field_start, field_end = _validate_span(fixture["field_boundary"], "field boundary")
        payload_start, payload_end = _validate_span(fixture["payload_boundary"], "payload boundary")
        if not all(isinstance(fixture[name], str) and _STRUCTURAL_ID.fullmatch(fixture[name]) for name in ("recipe_id", "runtime_class_id", "decoder_id")):
            raise GdfParserError("ARCHIVE_EVIDENCE_REQUIRED", "invalid structural evidence descriptor")
        if fixture["repeatability_outcome"] not in _REPEATABILITY_OUTCOMES or fixture["control_outcome"] not in _CONTROL_OUTCOMES or fixture["conclusion_outcome"] not in _CONCLUSION_OUTCOMES:
            raise GdfParserError("ARCHIVE_EVIDENCE_REQUIRED", "invalid evidence outcome descriptor")
        schema = fixture["schema"]
        if disposition == "PROMOTION_APPROVED":
            if not isinstance(schema, int) or schema < 0 or fixture["runtime_class_id"] == _UNOBSERVED or fixture["decoder_id"] == _UNAVAILABLE:
                raise GdfParserError("ARCHIVE_EVIDENCE_REQUIRED", "approved evidence requires an exact layout identity")
        elif schema is not None or fixture["runtime_class_id"] != _UNOBSERVED or fixture["decoder_id"] != _UNAVAILABLE:
            raise GdfParserError("ARCHIVE_EVIDENCE_REQUIRED", "blocked evidence must leave layout identity unavailable")
        parsed_fixtures.append(EvidenceFixture(fixture["role"], fixture["evidence_id"], fixture["runtime_class_id"], schema, fixture["decoder_id"], Span(field_start, field_end), Span(payload_start, payload_end)))
    if {fixture.role for fixture in parsed_fixtures} != _EVIDENCE_ROLES or len({fixture.evidence_id for fixture in parsed_fixtures}) != len(parsed_fixtures):
        raise GdfParserError("ARCHIVE_EVIDENCE_REQUIRED", "fixture roles or evidence IDs are incomplete")
    return EvidenceRecord(disposition, failed_ids, predicate_results, tuple(parsed_fixtures))


def load_evidence_record(path: Path | str | None = None) -> EvidenceRecord:
    """Load and parse the committed redacted evidence record.

    If path is omitted, loads the bundled default evidence record.
    """
    if path is None:
        try:
            ref = importlib.resources.files("graphworx32_gdf_parser.data").joinpath("default_evidence_record.json")
            content = ref.read_text(encoding="utf-8")
        except Exception:
            local = Path(__file__).parent / "data" / "default_evidence_record.json"
            content = local.read_text(encoding="utf-8")
        return parse_evidence_record(json.loads(content))

    target = Path(path)
    text = target.read_text(encoding="utf-8")
    blocks = _EVIDENCE_BLOCK.findall(text)
    raw_json = blocks[0] if len(blocks) == 1 else text
    try:
        return parse_evidence_record(json.loads(raw_json))
    except json.JSONDecodeError as error:
        raise GdfParserError("ARCHIVE_EVIDENCE_REQUIRED", "evidence record JSON is invalid") from error


class EvidenceRegistry:
    """Exact class/schema registry; production code supplies no entries until promotion."""

    def __init__(self) -> None:
        self.layouts: dict[tuple[str, int], ApprovedLayout] = {}

    def register(self, basis: EvidenceBasis, decoder: "ArchiveGrammar | None" = None) -> "EvidenceRegistry":
        missing = basis.missing_predicates()
        if missing:
            raise GdfParserError("ARCHIVE_EVIDENCE_REQUIRED", f"layout evidence missing: {', '.join(missing)}")
        if decoder is None:
            raise GdfParserError("ARCHIVE_EVIDENCE_REQUIRED", "layout decoder is unavailable")
        key = (basis.runtime_class, basis.schema)
        if key in self.layouts:
            raise GdfParserError("ARCHIVE_EVIDENCE_REQUIRED", "layout evidence is already registered")
        self.layouts[key] = ApprovedLayout(basis, decoder)
        return self

    def require(self, runtime_class: str, schema: int) -> ApprovedLayout:
        layout = self.layouts.get((runtime_class, schema))
        if layout is None:
            raise GdfParserError("ARCHIVE_LAYOUT_UNEVIDENCED", f"layout is not evidenced for {runtime_class!r} schema {schema}")
        return layout


def production_registry(path: Path | str | None = None, decoder_resolver: dict[str, ArchiveGrammar] | None = None) -> EvidenceRegistry:
    """Construct production layouts only from a validated approved evidence record."""
    record = load_evidence_record(path)
    registry = EvidenceRegistry()
    if not record.approved:
        return registry
    resolver = {} if decoder_resolver is None else decoder_resolver
    classes = {(fixture.runtime_class_id, fixture.schema, fixture.decoder_id) for fixture in record.fixtures}
    if len(classes) != 1:
        raise GdfParserError("ARCHIVE_EVIDENCE_REQUIRED", "approved evidence must identify one exact class/schema")
    runtime_class, schema, decoder_id = classes.pop()
    if schema is None or decoder_id not in resolver:
        raise GdfParserError("ARCHIVE_EVIDENCE_REQUIRED", "approved evidence decoder is unavailable")
    field_start = min(fixture.field_boundary.start for fixture in record.fixtures)
    field_end = max(fixture.field_boundary.end for fixture in record.fixtures)
    payload_end = max(fixture.payload_boundary.end for fixture in record.fixtures)
    registry.register(
        EvidenceBasis(
            next(iter(record.fixtures)).evidence_id,
            runtime_class,
            schema,
            field_start,
            field_end,
            payload_end,
            True,
            True,
            True,
            True,
            "validated_redacted_evidence_record",
            frozenset(fixture.evidence_id for fixture in record.fixtures),
            record.predicate_results,
        ),
        resolver[decoder_id],
    )
    return registry


class ArchiveGrammar(Protocol):
    """Test or evidence-promoted grammar supplied outside generic infrastructure."""

    def decode(self, cursor: ArchiveCursor, decoder: "ArchiveDecoder") -> None: ...


class ArchiveDecoder:
    def __init__(self, cursor: ArchiveCursor) -> None:
        self.cursor = cursor
        self.events: list[ArchiveEvent] = []
        self.classes: dict[int, ArchiveClass] = {}
        self.objects: dict[int, ArchiveObject] = {}
        self.object_local_sets: dict[int, ObjectLocalSet] = {}
        self.global_alias_evidence: list[GlobalAliasEvidence] = []
        self._next_parser_object_id = 1

    def _event(self, kind: ArchiveEventKind, span: Span, **details: object) -> None:
        self.events.append(ArchiveEvent(len(self.events) + 1, kind, span.start, span.end, **details))

    def declare_class(self, archive_class_id: int, runtime_class: str, schema: int, span: Span) -> None:
        if archive_class_id in self.classes:
            raise GdfParserError("ARCHIVE_REFERENCE_INVALID", "archive class is already declared")
        record = ArchiveClass(archive_class_id, runtime_class, schema, span)
        self.classes[archive_class_id] = record
        self._event(ArchiveEventKind.CLASS_DECLARATION, span, archive_class_id=archive_class_id, runtime_class=runtime_class, schema=schema)

    def reference_class(self, archive_class_id: int, span: Span) -> ArchiveClass:
        record = self.classes.get(archive_class_id)
        if record is None:
            raise GdfParserError("ARCHIVE_REFERENCE_INVALID", "archive class reference is invalid or forward")
        self._event(ArchiveEventKind.CLASS_REFERENCE, span, archive_class_id=archive_class_id, runtime_class=record.runtime_class, schema=record.schema)
        return record

    def new_object(self, archive_object_id: int, archive_class_id: int, span: Span) -> ArchiveObject:
        class_record = self.classes.get(archive_class_id)
        if class_record is None or archive_object_id in self.objects:
            raise GdfParserError("ARCHIVE_REFERENCE_INVALID", "archive object declaration is invalid")
        record = ArchiveObject(archive_object_id, self._next_parser_object_id, archive_class_id, span)
        self._next_parser_object_id += 1
        self.objects[archive_object_id] = record
        self._event(ArchiveEventKind.NEW_OBJECT, span, parser_object_id=record.parser_object_id, archive_class_id=archive_class_id, archive_object_id=archive_object_id, runtime_class=class_record.runtime_class, schema=class_record.schema)
        return record

    def reference_object(self, archive_object_id: int, span: Span) -> ArchiveObject:
        record = self.objects.get(archive_object_id)
        if record is None:
            raise GdfParserError("ARCHIVE_REFERENCE_INVALID", "archive object reference is invalid or forward")
        class_record = self.classes[record.archive_class_id]
        self._event(ArchiveEventKind.EXISTING_OBJECT_REFERENCE, span, parser_object_id=record.parser_object_id, archive_class_id=record.archive_class_id, archive_object_id=archive_object_id, runtime_class=class_record.runtime_class, schema=class_record.schema)
        return record

    def null(self, span: Span) -> None:
        self._event(ArchiveEventKind.NULL, span)

    def opaque(self, archive_class_id: int, span: TrustedSpan, reason: str) -> None:
        class_record = self.classes.get(archive_class_id)
        if class_record is None:
            raise GdfParserError("ARCHIVE_BOUNDARY_UNKNOWN", "unsupported payload lacks a proven enclosing range")
        self._event(
            ArchiveEventKind.OPAQUE,
            span,
            archive_class_id=archive_class_id,
            runtime_class=class_record.runtime_class,
            schema=class_record.schema,
            evidence=reason,
        )

    def object_local_evidence(
        self,
        parser_object_id: int,
        field_kind: str,
        evidence: str,
        span: TrustedSpan,
        alias_name: str | None = None,
        match_key: str | None = None,
    ) -> None:
        target_object = next((obj for obj in self.objects.values() if obj.parser_object_id == parser_object_id), None)
        if target_object is None:
            raise GdfParserError("ARCHIVE_REFERENCE_INVALID", "evidence cannot attach to an unrecorded object")
        class_record = self.classes[target_object.archive_class_id]
        record = ObjectLocalEvidence(
            parser_object_id,
            class_record.runtime_class,
            class_record.schema,
            field_kind,
            evidence,
            span,
            alias_name=alias_name,
            match_key=match_key,
        )
        current_set = self.object_local_sets.get(parser_object_id, ObjectLocalSet(parser_object_id))
        self.object_local_sets[parser_object_id] = ObjectLocalSet(parser_object_id, current_set.evidence + (record,))
        self._event(
            ArchiveEventKind.OBJECT_LOCAL_EVIDENCE,
            span,
            parser_object_id=parser_object_id,
            archive_class_id=target_object.archive_class_id,
            archive_object_id=target_object.archive_object_id,
            runtime_class=class_record.runtime_class,
            schema=class_record.schema,
            owner_object_id=parser_object_id,
            evidence_kind=field_kind,
            evidence=evidence,
        )

    def result(self) -> ArchiveResult:
        last_offset = max((event.end for event in self.events), default=0)
        return ArchiveResult(
            tuple(self.events),
            self.classes,
            self.objects,
            self.object_local_sets,
            tuple(self.global_alias_evidence),
            last_offset,
        )


def decode_archive(contents: bytes, limits: ParseLimits, grammar: ArchiveGrammar | None = None) -> ArchiveResult:
    """Decode only a supplied synthetic or evidence-promoted grammar; otherwise fail closed."""
    cursor = ArchiveCursor(contents, limits)
    if grammar is None:
        return ArchiveResult(last_proven_offset=0, diagnostic_code="ARCHIVE_EVIDENCE_REQUIRED")
    decoder = ArchiveDecoder(cursor)
    grammar.decode(cursor, decoder)
    return decoder.result()


def inspect_contents(
    contents: bytes,
    limits: ParseLimits,
    registry: EvidenceRegistry | None = None,
    runtime_class: str | None = None,
    schema: int | None = None,
) -> ArchiveResult:
    """Inspect only a supplied evidence-promoted registry; blocked evidence reads nothing."""
    registry = production_registry() if registry is None else registry
    if not registry.layouts or runtime_class is None or schema is None:
        return ArchiveResult(last_proven_offset=0, diagnostic_code="ARCHIVE_EVIDENCE_REQUIRED")
    try:
        layout = registry.require(runtime_class, schema)
    except GdfParserError:
        return ArchiveResult(last_proven_offset=0, diagnostic_code="ARCHIVE_EVIDENCE_REQUIRED")
    return decode_archive(contents, limits, layout.decoder)
