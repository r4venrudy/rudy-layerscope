Rudy LayerScope 0.1.0-preview introduces an offline Go OCI image forensics engine.

- Verify SHA-256 manifest/config/layer descriptors, uncompressed DiffIDs and ordered ChainIDs.
- Model explicit/opaque whiteouts, directory replacements and earlier-target hardlinks without extracting image payloads.
- Review final files and all file revisions, including hidden credential-like paths and selected private-key headers.
- Compare filesystem releases and rule fingerprints; produce text, JSON, SARIF 2.1.0 and self-contained HTML investigations.
- Enforce parsing budgets, explicit unsupported-input errors and new-file-only report writes.
- Include two synthetic OCI layouts and an example HTML investigation in every native package.

Native Linux amd64, Windows amd64 and macOS arm64 packages are built and smoke-tested on their respective runners. Each archive contains a standard-library-only binary, documentation and synthetic examples. Verify downloads with SHA256SUMS.

Preview boundary: Linux OCI layouts with SHA-256 and tar/gzip layers. No registry client, extraction, payload execution, signatures, CVE database, zstd, sparse entries, forward hardlinks or symlink-ancestor writes. Heuristics do not prove real secrets, runtime privilege or exploitability. Digests verify local content consistency, not publisher identity. See docs/CONTRACT.md and docs/RULES.md for exact semantics and limits.
