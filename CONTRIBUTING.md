# Contributing

Start with a reproducible issue and the documented model boundary. Good changes include additional supported OCI semantics, adversarial parser cases, better evidence attribution and narrower false-positive behavior. Do not submit real credentials or private images.

Run `gofmt -w .`, `go vet ./...`, and `go test ./...`. On a supported native toolchain, also run `go test -race ./...` and the affected fuzz target. Explain before/after behavior and add a meaningful regression case for a correctness change. Keep deterministic reports, bounded parsing, no target execution, no extraction and new-file-only output behavior.

Packaging: `go run scripts/package.go --out artifacts/release`. The destination package files must not already exist. Preserve the shared navy/teal RUDY visual identity and accurate preview labels.
