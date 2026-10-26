# Security policy

Do not upload real keys, private images or sensitive reports to public issues. Use GitHub's private vulnerability reporting on this repository when available; otherwise open a public request for a private contact without exploit details or sensitive data.

This preview treats image JSON, tar headers and payloads as untrusted, bounded data. It never executes or extracts target contents and never contacts registries. Input layout directories must be stable local copies on a normal filesystem. `os.Root` contains layout reads; it does not isolate hostile mount points or concurrent filesystem replacement.

Report paths and selected metadata can be sensitive despite content omission. Store reports appropriately. A matching SHA-256 descriptor is not a signature or statement of trust. The included synthetic examples contain no real secrets and no executable target payloads.

See [the exact input and model contract](docs/CONTRACT.md) for limits and unsupported formats. Do not use a clean report as a blanket safety verdict.
