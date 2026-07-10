# Launch posts (paste-ready)

## Show HN
**Title:** Show HN: I audited my own crypto library, found it was theater, and rebuilt it

**Text:**
I published surframe 0.1.5 on PyPI — a "signed, auditable" dataset container. Then I did a deep audit of my own package and found the value proposition didn't exist: the Ed25519 signing wasn't implemented anywhere, the "signature" was an unkeyed SHA-256 chain anyone with write access could rewrite, and there was a data-loss bug where encrypting columns in two calls silently orphaned the first call's ciphertext.

0.2.0 is the rebuild: real Ed25519 signatures with per-entry diff reporting ("this exact parquet chunk changed"), audit chain anchored under the signature (the test suite includes a full chain-rewrite attack that the bare chain misses and the signature catches), column-level AES-GCM bound to the container so sidecars can't be spliced between files, and a CLI whose `verify` exits 0/1 for CI.

The pitch: cosign for datasets. Training sets and data deliverables still ship as naked files with no provenance; this is a single-file container that's queryable (Parquet + bloom/minmax pruning inside a zip) and tamper-evident.

Threat model with explicit non-goals is in the repo — including why self-attested signatures prove consistency, not identity, and why rollback detection needs the transparency log I'm building next.

Repo: https://github.com/Christ10-8/surframe

## r/Python
**Title:** surframe 0.2.0 — signed, encrypted, tamper-evident dataset containers (Ed25519 + AES-GCM + Parquet)

**Text:**
`pip install surframe` gives you a single-file `.surx` container: Parquet chunks with predicate-pushdown indexes, column-level AES-GCM encryption (ship PII encrypted, query the rest without the key), an append-only audit log, and Ed25519 signing where `verify` names the exact entry that changed.

Honest origin story: 0.1.5 claimed signing and didn't have it. I audited my own package, wrote up every hole, and 0.2.0 fixes them with a 38-check test battery that attacks each fix — including an audit-chain rewrite attack and a sidecar-splice attack. Threat model with explicit non-goals in the repo.

CLI included (`surx sign/verify/encrypt/read`, CI-friendly exit codes) plus a GitHub Action. Feedback on the format design very welcome.

## r/dataengineering
**Title:** Your datasets have no supply chain. I built signed containers to fix that (open source)

**Text:**
We sign binaries, verify checksums, and keep transparency logs for software — then ship training data and client deliverables as naked Parquet with zero provenance. surframe is a single-file container (`.surx`) that's queryable like a mini lakehouse table (Parquet chunks, bloom/minmax pruning, snapshots, partition by any column) but signed with Ed25519: `surx verify` in CI tells you the exact chunk that was modified, whether the audit log was rewritten, and exits 1 so the pipeline stops.

Column-level encryption means PII columns travel encrypted while consumers query everything else. Threat model (including what it does NOT protect against) is in the repo — key compromise, rollback and availability are explicitly out of scope, and rollback detection is why a hosted transparency log is next on the roadmap.

Apache-2.0, `pip install surframe`.
