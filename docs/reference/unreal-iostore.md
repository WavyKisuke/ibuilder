# Unreal Engine IoStore support: implementation notes

This page tracks the incremental Unreal reader in `ibuilder-shadersplit`.

## Layer 1: TOC metadata reader

`src/unreal.rs` adds a bounds-checked, safe-Rust parser for the fixed 144-byte IoStore TOC header and the chunk ID, chunk range, compression-block, and compression-method tables.

It exposes:
- Container version, ID, flags, partition count and partition size.
- Chunk IDs and their uncompressed-stream ranges.
- Compression-block offsets, stored/raw sizes, and method indices.
- Shader-library / shader-code and export-bundle chunk counts.

The parser has synthetic tests for shader chunk metadata and malformed/truncated TOCs. It is deliberately metadata-only at this stage.

## Not implemented yet

This first layer does **not**:
- Read or decompress `.ucas` data or multi-partition containers.
- Decode Oodle (Kraken, Mermaid, Leviathan) or other Unreal compression payloads.
- Decrypt encrypted containers or parse their directory indexes.
- Read Unreal `.pak` archives.
- Decode Unreal shader-code libraries and inline shader records.
- Convert Unreal shader bytecode into the SPIR-V / Metal pipeline's input format.
- Connect Unreal inputs to the normal game build flow.

The main splitter still rejects `.utoc` and Unreal `.pak` inputs until the complete extraction path is implemented. A TOC that can be parsed is not yet a game that can be built.

## Next implementation layers

1. Read chunk ranges from the matching `.ucas` partition(s), with bounded streaming reads.
2. Implement supported block decoders and a pluggable Oodle backend where licensing and iOS compatibility permit.
3. Parse shader-library chunks and UE4.27 / UE5 inline shader layouts separately.
4. Feed validated shader records into the existing split output contract, with game/update/DLC mount order and resumable memo support.
5. Add synthetic fixtures and compare output against known-good Unreal shader extraction results before enabling detection in the app.