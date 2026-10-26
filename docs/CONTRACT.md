# Input, model and output contract

LayerScope 0.1.0-preview analyzes a stable Linux OCI image layout directory with `oci-layout` version 1.0.0 and an OCI schemaVersion 2 index. It is intentionally a documented subset of [OCI Image Spec v1.1.1](https://github.com/opencontainers/image-spec/tree/v1.1.1).

## Selection and integrity

- `--ref` filters the top-level descriptor's `org.opencontainers.image.ref.name`. A selected nested index is then traversed to image manifests.
- `--platform` matches config `os/architecture[/variant]` exactly. There is no host-platform default or variant alias inference. Descriptor platform fields must agree with verified config fields.
- Exactly one distinct Linux image manifest must remain. Repeated references to the same digest are deduplicated. Other artifact media types are skipped, not analyzed. Recognized image metadata in selected index branches is verified even if another platform is requested.
- SHA-256 descriptor digest and size are verified for each consumed manifest/config/layer. JSON metadata is snapshotted into bounded memory. Layer blobs are hashed before decoding, then rehashed over the parsed stream. Root `index.json` is independently hashed and reported.
- Uncompressed layer DiffIDs are verified over the entire stream, including tar padding. ChainID is the first DiffID, then SHA256(previous ChainID + space + next DiffID). Nonzero bytes after a tar end marker fail analysis.
- The untrusted root index is not externally authenticated. Modifying all blobs and descriptors consistently passes integrity verification. There is no signature/provenance verification.
- Only local `blobs/sha256/` files are used. Descriptor URLs, embedded `data` and network fetching are not used. Docker v2 manifests and Docker `save` archives are outside this preview.
- JSON must have valid UTF-8, no duplicate object keys, no trailing documents and at most 64 nesting levels. Unknown object fields are allowed for OCI extensibility. This is not full JSON-schema validation of every OCI field.

## Filesystem semantics

- Linux paths are case-sensitive and relative to the image root. Leading `./`, repeated slashes and trailing slashes normalize; absolute paths, dot-dot components, backslashes, controls, names over 4096 UTF-8 bytes and depth over 128 are rejected. A `.` directory root entry is accepted but not modeled as a final entry.
- Duplicate normalized names within a layer fail. Sparse formats fail. Regular payloads are streamed into hashes/header checks; no payload bytes are stored in reports or extracted to disk.
- All explicit and opaque whiteouts are applied to the lower state before additions, irrespective of archive order. Whiteout markers never appear in final files. Opaque whiteouts remove descendants, retaining their containing directory. Root opacity is supported.
- Directory-to-directory updates replace metadata and retain children. Other replacements remove the prior path/subtree and create a fresh entry. Missing parents become implicit 0755 root-owned directories, explicitly labeled `implicit`; their actual runtime attributes are unknown.
- A path's ancestors must be directories when it is added. Image symlinks are retained verbatim but never traversed. Thus some otherwise usable runtime images with symlink-ancestor writes are rejected instead of approximated.
- Hardlinks must target an earlier regular file in the current virtual state. They copy its inode metadata/content identity at link creation; subsequent unlink/recreate of the original path does not change the alias. Forward links, directory links, symlink links and missing targets fail. Hardlink header mode/owner fields are ignored in favor of the target's inode metadata.
- Symlink targets are metadata, may be absolute or escape-looking, and are never opened. Device major/minor and FIFO type are recorded; nothing is created on the host.
- Selected `SCHILY.xattr.security.capability` presence is reported, not interpreted. ACLs, SELinux labels, arbitrary xattrs, timestamps, uname/gname and Windows security descriptors are outside the model. This is not a runtime emulator.

## Resource and host boundaries

Defaults: 512 MiB per stored layer blob, 4 GiB total expanded layer bytes, 32 MiB total metadata, 4 MiB per JSON document, 200,000 archive entries and final entries, 256 layers, 4,096 consumed metadata descriptors, index depth eight. Payload processing is streamed; memory scales with bounded metadata and file revisions. There is no silent truncation. Exceeding a budget is exit 2 with no success report.

CLI overrides: `--max-blob-mib` (up to 8192), `--max-expanded-mib` (up to 65536), `--max-entries` (up to 1,000,000). Library callers may supply all Limits fields, within enforced ceilings. Reducing budgets is recommended for untrusted inputs. The archive reader also has Go standard-library header limits.

Layout reads use Go `os.Root` containment and require regular leaf files. Payload extraction is never performed. A trusted stable copy on a regular local filesystem is required: mount points, special filesystem behavior and concurrent mutation are not a sandboxed input channel. Avoid hostile bind mounts or procfs trees. Do not rely on hashes alone to make a concurrently changing directory safe to open.

## Reports and differences

Layer numbers are zero-based. `history` has every explicit non-whiteout entry revision. `files` has final entries including implicit directories. Each revision records origin layer, content layer, content digest, replacement/removal reason and optional removal layer. `history --path` selects an exact normalized relative path.

Summary payload sizes count regular-file tar payloads, excluding hardlink aliases. Hidden payload size is the sum of retired payload revision sizes. It is **not** compressed waste, unique content size, or reclaimable size; aliases or duplicate content may retain the same bytes.

LS001/LS002 are deduplicated by rule/path/payload digest. `hidden` means no final file at that same path has the same digest. Finding layer points to the first matching content revision. An alias at another path does not change that path-specific state. Other rules evaluate final entries or image config.

Reports contain no file bodies, raw xattr values, environment values, build commands, annotations or arbitrary config arrays. Paths, link targets, owners, selected config User and environment key names are metadata and can themselves contain sensitive information. Redaction is omission of selected fields, not a guarantee against secrets deliberately placed in metadata.

`diff` requires the same exact platform. It compares final entry path/type/mode/uid/gid/size/content hash/link target/device IDs/capability presence. It ignores timestamps, layer order/origins, implicit-directory status, all unmodeled attributes, and non-rule config changes. Rule findings compare stable rule/path/evidence fingerprints; identical fingerprints may have changed layer numbers or hidden states. `finding` gate means new fingerprints, not all changes in finding metadata.

Output is deterministic for an identical input snapshot and options. JSON schema identities are `rudy.layerscope/v1` and `rudy.layerscope.delta/v1`; consumers should reject unknown schemas. SARIF 2.1.0 uses logical image paths, not fabricated source locations. HTML escapes metadata and uses no external resources. Output files require exclusive creation; write failures may leave a partial new file, never a replaced existing file.

References: [layout](https://github.com/opencontainers/image-spec/blob/v1.1.1/image-layout.md), [descriptors](https://github.com/opencontainers/image-spec/blob/v1.1.1/descriptor.md), [layers and whiteouts](https://github.com/opencontainers/image-spec/blob/v1.1.1/layer.md), [DiffID/ChainID](https://github.com/opencontainers/image-spec/blob/v1.1.1/config.md).
