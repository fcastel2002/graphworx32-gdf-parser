# graphworx32-gdf-parser

Neutral, read-only reverse-engineering parser and data recovery library for proprietary GraphWorX32 `.gdf` display files (OLE/CFBF container with MFC `CArchive` serialization).

## Features

- **Standalone runtime**: Does not require GraphWorX32, COM interfaces, or Windows-specific runtime libraries to read files.
- **OLE/CFBF traversal**: Bounded inspection of streams, storages, summary metadata, and defect reporting via `olefile`.
- **Dual extraction profiles**:
  - **Alias recovery profile**: Identifies Local Alias mappings (`OPCChannel`, `TypeOfPlc`, and custom aliases) and associated descriptions.
  - **Screen display profile**: Recovers ObjectManager layers, dynamic objects (Hide/Size), and OPointManager data source expressions.
- **Fail-safe boundaries**: Strict input size, recursion depth, string length, and entry limits to prevent unbounded memory allocation or denial-of-service on malformed files.
- **Zero domain bias**: Does not generate Ignition tags, UDT instances, or plant-specific classifications. Emits neutral data structures suitable for any downstream migration pipeline.

## Installation

```bash
pip install .
```

## Quick Example

```python
from pathlib import Path
from graphworx32_gdf_parser import parse_gdf, ParseLimits

result = parse_gdf(
    "path/to/display.gdf",
    profiles=("aliases", "screen"),
)

if result.document:
    print(f"File size: {result.document.source_size} bytes")
    print(f"SHA-256: {result.document.source_sha256}")
    
    # Aliases
    if result.document.archive:
        for obj_id, local_set in result.document.archive.object_local_sets.items():
            print(f"Object {obj_id}: {len(local_set.evidence)} alias records")
            
    # Screen objects
    if result.document.screen:
        for dyn_obj in result.document.screen.objects:
            print(f"Layer '{dyn_obj.layer_name}': {dyn_obj.object_name} -> {dyn_obj.data_source}")
```

## License and Status

**Notice**: License selection is currently pending project author confirmation. All rights reserved. Do not redistribute without explicit permission.
