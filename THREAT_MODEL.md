# Threat Model

Security tools earn trust by stating limits. Here are SURFRAME's.

## What SURFRAME protects against

| Threat | Mechanism | Verified by |
|---|---|---|
| Silent modification of any container entry | Ed25519 signature over per-entry SHA-256 digests | `verify_container` reports the exact modified/missing/added entry (test T3) |
| Audit-log editing, including a full chain rewrite by an attacker with write access | Chain heads are anchored under the signature; post-signing appends stay valid, rewrites don't | Test T5: recomputed chain passes the internal check, signature still catches it |
| Reading encrypted columns without the passphrase | AES-GCM per column, Scrypt N=2^17 key derivation | Tests T1/T2 |
| Transplanting an encrypted sidecar into another container (same passphrase) | GCM associated data binds `container_id`, partition and column | Test T6 |
| Wrong-passphrase confusion / accidental key mixing across encrypt calls | Stored passphrase verifier; multi-call encryption reuses the container key | Tests T1/T2 (this was a data-loss bug in 0.1.5) |
| Torn writes on power loss | fsync of temp file and directory around every atomic rewrite | Code-reviewed; not fault-injection tested |
| Lost audit events under concurrent writers | Inter-process file lock around read-modify-write | Test T9 (2 processes × 10 appends, 0 lost) |

## What SURFRAME does NOT protect against

- **Key compromise.** Anyone holding the private key produces valid signatures. Store it encrypted (`keygen` supports a passphrase; the PEM is written 0600) and rotate if leaked. There is no revocation mechanism in the container itself.
- **Self-attested trust.** `verify` without an external public key only proves the container is *internally consistent* with its embedded key — it does not prove *who* signed it. Identity requires distributing the public key out-of-band, or (roadmap) a transparency log.
- **Rollback.** A signed container can be replaced wholesale by an older signed container. Detecting rollback needs an external registry of latest-known signatures — that is exactly the hosted service on the roadmap, and why it exists.
- **Availability.** Deleting the file is always possible. Tamper-*evidence*, not tamper-*proofing*.
- **Confidentiality of unencrypted columns and metadata.** Schema, column names, row counts, chunk structure and the audit log are visible to anyone with the file.
- **Side channels.** Chunk sizes and sidecar sizes leak information about the data.
- **Malicious writer at creation time.** Signing attests to state, not truthfulness. Garbage in, signed garbage out.

## Zip structure hardening (0.3.0)

Containers with duplicate entry names are rejected at both `sign` and `verify` time. Duplicate
entries are a classic parser-differential attack: Python's ZipFile reads the last copy while other
extractors may read the first, so a signature could validate content a different reader never sees.
Absolute paths, `..` components and backslashes in entry names are rejected for the same reason.

## Cryptographic choices

Ed25519 (via `cryptography`) for signatures; AES-256-GCM with 12-byte random nonces per sidecar; Scrypt (N=2^17, r=8, p=1) for passphrase-derived keys — legacy 0.1.5 containers (N=2^14) remain readable and are upgraded in place on the next encrypt call. Random 96-bit GCM nonces are safe far beyond the per-container sidecar counts here (NIST bounds
apply from ~2^32 encryptions under one key; a container has one sidecar per column per partition).
The audit chain is an *unkeyed* SHA-256 chain by design: it provides ordering and internal consistency; authenticity comes from anchoring its head under the Ed25519 signature. We say this explicitly because 0.1.5 marketed the bare chain as a signature, and it wasn't.

## Disclosure

Found a hole? Open a GitHub issue with the `security` label. Reproductions in the style of `tests/test_v020.py` are the fastest path to a fix.
