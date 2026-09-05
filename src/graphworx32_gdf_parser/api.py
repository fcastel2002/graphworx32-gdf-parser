"""High-level public API for GraphWorX32 GDF parsing and extraction."""

from __future__ import annotations

import stat
from pathlib import Path

from graphworx32_gdf_parser.aliases import decode_experimental_local_aliases
from graphworx32_gdf_parser.cfbf import (
    OleFileAdapter,
    path_snapshot,
    require_stable_source,
    sha256_handle,
    source_snapshot,
)
from graphworx32_gdf_parser.errors import ExitStatus, GdfParserError
from graphworx32_gdf_parser.evidence import decode_archive
from graphworx32_gdf_parser.models import (
    DEFAULT_LIMITS,
    ArchiveResult,
    Diagnostic,
    GdfDocument,
    ParseLimits,
    ParseResult,
    ScreenProfileResult,
)
from graphworx32_gdf_parser.screen import extract_screen_profile

def parse_gdf(
    input_path: str | Path,
    *,
    limits: ParseLimits = DEFAULT_LIMITS,
    profiles: tuple[str, ...] = ("aliases",),
    layer_target: str | None = None,
    adapter: OleFileAdapter | None = None,
) -> ParseResult:
    """Parse a GraphWorX32 .gdf file using specified extraction profiles."""
    source_path = Path(input_path)
    try:
        source_path = source_path.resolve(strict=True)
        with source_path.open("rb") as source:
            initial_snapshot = source_snapshot(source)
            if not stat.S_ISREG(initial_snapshot.st_mode):
                raise GdfParserError("INPUT_NOT_REGULAR_FILE", "input must be an existing regular file")
            if initial_snapshot.st_size > limits.max_input_bytes:
                raise GdfParserError("RESOURCE_LIMIT_EXCEEDED", "input size exceeds the approved limit")
            active_adapter = adapter or OleFileAdapter()
            needs_contents = bool({"aliases", "screen"} & set(profiles))
            if hasattr(active_adapter, "inspect"):
                entries, metadata, diagnostics, contents = active_adapter.inspect(
                    source, limits, read_contents=needs_contents
                )
                archive = None
            else:
                inspected = active_adapter.inventory(source, limits)
                if len(inspected) == 3:
                    entries, metadata, diagnostics = inspected
                    archive = None
                else:
                    entries, metadata, diagnostics, archive = inspected
                contents = getattr(active_adapter, "_last_contents", None)

            archive_result: ArchiveResult | None = None
            if "aliases" in profiles:
                if archive is not None:
                    archive_result = archive
                elif contents is not None:
                    archive_grammar = getattr(active_adapter, "_archive_grammar", None)
                    archive_result = (
                        decode_archive(contents, limits, archive_grammar)
                        if archive_grammar is not None
                        else decode_experimental_local_aliases(contents, limits)
                    )

            screen: ScreenProfileResult | None = None
            if "screen" in profiles:
                if contents is None:
                    source.seek(0)
                    ole_mod = getattr(active_adapter, "_ole_module", None)
                    if ole_mod is None:
                        import olefile as ole_mod
                    with ole_mod.OleFileIO(source) as container:
                        if container.exists("Contents"):
                            contents_size = container.get_size("Contents")
                            if contents_size < 0 or contents_size > limits.max_stream_bytes:
                                raise GdfParserError("RESOURCE_LIMIT_EXCEEDED", "declared Contents size exceeds the approved limit")
                            contents = container.openstream("Contents").read(contents_size)
                            if len(contents) != contents_size:
                                raise GdfParserError("ARCHIVE_TRUNCATED", "Contents stream is shorter than its declared size")
                if contents is not None:
                    screen = extract_screen_profile(contents, layer_target=layer_target)

            require_stable_source(initial_snapshot, source_snapshot(source))
            source_sha256 = sha256_handle(source)
            require_stable_source(initial_snapshot, source_snapshot(source))
            require_stable_source(initial_snapshot, path_snapshot(source_path))
            doc = GdfDocument(
                source_path=source_path,
                source_size=initial_snapshot.st_size,
                source_sha256=source_sha256,
                entries=entries,
                metadata=metadata,
                archive=archive_result,
                screen=screen,
            )
        return ParseResult(ExitStatus.WARNINGS if diagnostics else ExitStatus.CLEAN, doc, diagnostics)
    except GdfParserError as failure:
        return ParseResult(failure.status, None, (Diagnostic("error", failure.code, str(failure)),))
    except OSError:
        return ParseResult(ExitStatus.FATAL, None, (Diagnostic("error", "INPUT_ACCESS_FAILED", "input could not be inspected"),))


def inventory_file(
    input_path: str | Path,
    output_path: str | Path | None = None,
    limits: ParseLimits = DEFAULT_LIMITS,
    adapter: OleFileAdapter | None = None,
) -> ParseResult:
    """Inspect and inventory a GDF container.

    Maintains full compatibility with gdf-inventory inspection semantics.
    """
    source_path = Path(input_path)
    if output_path is not None:
        destination = Path(output_path)
        if destination.exists() and source_path.resolve(strict=False) == destination.resolve(strict=False):
            return ParseResult(
                ExitStatus.FATAL,
                None,
                (Diagnostic("error", "SOURCE_OUTPUT_IDENTITY", "input and output must not identify the same file"),),
            )
    return parse_gdf(source_path, limits=limits, profiles=("aliases",), adapter=adapter)


def read_contents(path: str | Path, limits: ParseLimits = DEFAULT_LIMITS) -> bytes:
    """Read raw Contents stream from a GDF file with boundary checks."""
    import olefile

    source_path = Path(path).resolve(strict=True)
    with olefile.OleFileIO(source_path) as container:
        if not container.exists("Contents"):
            raise GdfParserError("CONTENTS_REQUIRED_STREAM", "GDF file does not contain a Contents stream")
        size = container.get_size("Contents")
        if size > limits.max_stream_bytes:
            raise GdfParserError("RESOURCE_LIMIT_EXCEEDED", "Contents stream size exceeds limit")
        return container.openstream("Contents").read(size)
