"""OLE/CFBF container traversal and metadata extraction."""

from __future__ import annotations

import hashlib
import os
import stat
from datetime import datetime
from pathlib import Path
from typing import BinaryIO, Iterable, Sequence

from graphworx32_gdf_parser.aliases import decode_experimental_local_aliases
from graphworx32_gdf_parser.errors import ExitStatus, GdfParserError
from graphworx32_gdf_parser.evidence import ArchiveGrammar, decode_archive
from graphworx32_gdf_parser.models import (
    ArchiveResult,
    CfbfEntry,
    Diagnostic,
    EntryType,
    MetadataProperty,
    ParseLimits,
)


def _bounded_text(value: object, limit: int, field_name: str) -> str:
    if isinstance(value, datetime):
        text = value.isoformat()
    elif isinstance(value, bytes):
        text = f"sha256:{hashlib.sha256(value).hexdigest()};bytes:{len(value)}"
    elif isinstance(value, (list, tuple)):
        text = ", ".join(_bounded_text(item, limit, field_name) for item in value)
    else:
        text = str(value)
    if len(text) > limit:
        raise GdfParserError("RESOURCE_LIMIT_EXCEEDED", f"{field_name} exceeds its approved limit")
    return text


def _validate_path(path: Sequence[str], limits: ParseLimits) -> tuple[str, ...]:
    components = tuple(path)
    if len(components) > limits.max_depth:
        raise GdfParserError("RESOURCE_LIMIT_EXCEEDED", "entry depth exceeds the approved limit")
    for component in components:
        if not component or len(component) > limits.max_component_chars:
            raise GdfParserError("RESOURCE_LIMIT_EXCEEDED", "entry component exceeds the approved limit")
    if len("/".join(components)) > limits.max_path_chars:
        raise GdfParserError("RESOURCE_LIMIT_EXCEEDED", "entry path exceeds the approved limit")
    return components


class OleFileAdapter:
    """Read-only adapter for OLE/CFBF containers and metadata."""

    def __init__(self, ole_module: object | None = None, archive_grammar: ArchiveGrammar | None = None) -> None:
        self._ole_module = ole_module
        self._archive_grammar = archive_grammar

    def inspect(
        self, source: BinaryIO, limits: ParseLimits, read_contents: bool = False
    ) -> tuple[tuple[CfbfEntry, ...], tuple[MetadataProperty, ...], tuple[Diagnostic, ...], bytes | None]:
        """Inspect CFBF container structure, entries, metadata, and optionally read Contents stream."""
        if self._ole_module is None:
            import olefile
        else:
            olefile = self._ole_module

        source.seek(0)
        if not olefile.isOleFile(source):
            raise GdfParserError("UNSUPPORTED_CFBF", "input is not an OLE/CFBF container", ExitStatus.UNSUPPORTED)
        try:
            source.seek(0)
            with olefile.OleFileIO(source, raise_defects=olefile.DEFECT_INCORRECT) as container:
                if not container.exists("Contents") or container.get_type("Contents") != olefile.STGTY_STREAM:
                    raise GdfParserError(
                        "CONTENTS_REQUIRED_STREAM",
                        "CFBF input does not contain a root Contents stream",
                        ExitStatus.UNSUPPORTED,
                    )
                paths = container.listdir(streams=True, storages=True)
                if len(paths) > limits.max_entries:
                    raise GdfParserError("RESOURCE_LIMIT_EXCEEDED", "entry count exceeds the approved limit")
                entries = [CfbfEntry((), EntryType.ROOT, None)]
                seen_paths = {()}
                for raw_path in paths:
                    path = _validate_path(raw_path, limits)
                    if path in seen_paths:
                        raise GdfParserError("DUPLICATE_ENTRY_PATH", "duplicate CFBF entry path")
                    seen_paths.add(path)
                    raw_type = container.get_type(list(path))
                    if raw_type == olefile.STGTY_STREAM:
                        size = container.get_size(list(path))
                        if size < 0 or size > limits.max_stream_bytes:
                            raise GdfParserError("RESOURCE_LIMIT_EXCEEDED", "declared stream size exceeds the approved limit")
                        entry_type = EntryType.STREAM
                    elif raw_type == olefile.STGTY_STORAGE:
                        size = None
                        entry_type = EntryType.STORAGE
                    else:
                        continue
                    entries.append(CfbfEntry(path, entry_type, size))
                metadata = self._metadata(container.get_metadata(), limits)
                diagnostics = self._diagnostics(container.parsing_issues, limits)
                contents: bytes | None = None
                if read_contents:
                    contents_size = container.get_size("Contents")
                    if contents_size < 0 or contents_size > limits.max_stream_bytes:
                        raise GdfParserError("RESOURCE_LIMIT_EXCEEDED", "declared Contents size exceeds the approved limit")
                    contents = container.openstream("Contents").read(contents_size)
                    if len(contents) != contents_size:
                        raise GdfParserError("ARCHIVE_TRUNCATED", "Contents stream is shorter than its declared size")
        except GdfParserError:
            raise
        except Exception as error:
            raise GdfParserError("CFBF_TRAVERSAL_FAILED", "CFBF traversal failed") from error
        ordered_entries = tuple(sorted(entries, key=lambda entry: (not not entry.path, entry.path)))
        return ordered_entries, metadata, diagnostics, contents

    def inventory(
        self, source: BinaryIO, limits: ParseLimits
    ) -> tuple[tuple[CfbfEntry, ...], tuple[MetadataProperty, ...], tuple[Diagnostic, ...], ArchiveResult]:
        """Inspect CFBF container and decode aliases archive (backward compatible)."""
        entries, metadata, diagnostics, contents = self.inspect(source, limits, read_contents=True)
        assert contents is not None
        archive = (
            decode_archive(contents, limits, self._archive_grammar)
            if self._archive_grammar is not None
            else decode_experimental_local_aliases(contents, limits)
        )
        return entries, metadata, diagnostics, archive

    @staticmethod
    def _metadata(metadata: object, limits: ParseLimits) -> tuple[MetadataProperty, ...]:
        properties: list[MetadataProperty] = []
        for name in sorted(getattr(metadata, "SUMMARY_ATTRIBS", ()) + getattr(metadata, "DOCSUM_ATTRIBS", ())):
            value = getattr(metadata, name, None)
            if value is not None:
                properties.append(MetadataProperty(name, _bounded_text(value, limits.max_metadata_value_chars, "metadata value")))
        return tuple(properties)

    @staticmethod
    def _diagnostics(issues: Iterable[object], limits: ParseLimits) -> tuple[Diagnostic, ...]:
        diagnostics: list[Diagnostic] = []
        for issue in issues:
            if len(diagnostics) >= limits.max_diagnostics:
                if diagnostics:
                    diagnostics[-1] = Diagnostic(
                        "warning",
                        "DIAGNOSTICS_TRUNCATED",
                        "diagnostics exceed the approved limit",
                    )
                break
            message = str(issue[1] if isinstance(issue, tuple) and len(issue) > 1 else issue)[: limits.max_diagnostic_chars]
            diagnostics.append(Diagnostic("warning", "CFBF_NONFATAL_DEFECT", message))
        return tuple(diagnostics)


def source_snapshot(source: BinaryIO) -> os.stat_result:
    return os.fstat(source.fileno())


def path_snapshot(source_path: Path) -> os.stat_result:
    try:
        return os.stat(source_path)
    except OSError as error:
        raise GdfParserError("SOURCE_IDENTITY_CHANGED", "source identity or size changed during inspection") from error


def require_stable_source(initial: os.stat_result, current: os.stat_result) -> None:
    if (initial.st_dev, initial.st_ino, initial.st_size) != (current.st_dev, current.st_ino, current.st_size):
        raise GdfParserError("SOURCE_IDENTITY_CHANGED", "source identity or size changed during inspection")


def sha256_handle(source: BinaryIO) -> str:
    digest = hashlib.sha256()
    source.seek(0)
    for chunk in iter(lambda: source.read(1024 * 1024), b""):
        digest.update(chunk)
    return digest.hexdigest()
