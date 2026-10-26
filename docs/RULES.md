# Review rules

These are deterministic indicators for source review. They do not use a vulnerability database, reputation service or ML classifier. Findings can be false positives. A clean result only means these configured rules did not match the supported model.

| ID | Level | Evidence and scope |
| --- | --- | --- |
| LS001 | error | Selected PEM private-key header anywhere in any regular-file revision, including hidden revisions and hardlink aliases |
| LS002 | warning | Credential-like file path in any regular-file revision, including hidden revisions |
| LS003 | warning | Final regular file with at least one execute bit and a setuid/setgid bit |
| LS004 | warning | Final world-writable regular file or non-sticky world-writable directory; implicit parents excluded |
| LS005 | warning | Config User omitted/empty, `root`, or numeric zero, before optional group suffix |
| LS006 | warning | Credential-like config environment key; values always omitted |
| LS007 | warning | Nonempty `SCHILY.xattr.security.capability` value on a final regular file; no bit decoding |
| LS008 | warning | Final block/character device metadata |

LS001 recognizes `BEGIN PRIVATE KEY`, `RSA PRIVATE KEY`, `EC PRIVATE KEY`, `DSA PRIVATE KEY`, `OPENSSH PRIVATE KEY`, and `ENCRYPTED PRIVATE KEY` PEM delimiters. It checks the complete payload stream, across chunk boundaries. It does not parse/validate key bodies, find binary keys or decode archives/encodings. Public certificate headers do not match.

LS002 covers `.env`, `.env.*` except `.env.example`/`.env.sample`/`.env.template`, private SSH key basenames, `.npmrc`, `.pypirc`, `.netrc`, and paths ending in `.aws/credentials`, `.docker/config.json`, `.kube/config`. Matching is case-insensitive as a heuristic, although the filesystem model is case-sensitive. Empty/example files and runtime-inert material can match. Extensions like arbitrary `.pem` alone do not match.

LS006 matches names containing PASSWORD, PASSWD, SECRET, TOKEN, PRIVATE_KEY, API_KEY, ACCESS_KEY, case-insensitively. Names such as TOKENIZERS_PARALLELISM can therefore be false positives. Move actual secrets to runtime secret injection and rebuild images without secret-bearing layers; a later deletion does not remove referenced lower-layer bytes.

An image's default User may be overridden at runtime; a named user may resolve to UID 0, which this tool does not infer. Privilege bits/capability metadata may be disabled by runtime mount and security settings. LS001 `error` is a configurable review severity, not a validated exploit severity.
