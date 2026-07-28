# Threat Model

Security tools earn trust by stating limits. Here are SURFRAME's.

## What SURFRAME protects against

| Threat | Mechanism | Verified by |
|---|---|---|
| Silent modification of any container entry | Ed25519 signature over per-entry SHA-256 digests | `verify_container` reports the exact modified/missing/added entry (test T3) |
| Audit-log editing, including a full chain rewrite by an attacker with write access | Chain heads are anchored under the signature; rewrites break it. Since 0.4.0, appends *after* signing are reported and invalidate by default | Test T5: recomputed chain passes the internal check, signature still catches it |
| Reading encrypted columns without the passphrase | AES-GCM per column, Scrypt N=2^17 key derivation | Tests T1/T2 |
| Transplanting an encrypted sidecar into another container (same passphrase) | GCM associated data binds `container_id`, partition and column | Test T6 |
| Wrong-passphrase confusion / accidental key mixing across encrypt calls | Stored passphrase verifier; multi-call encryption reuses the container key | Tests T1/T2 (this was a data-loss bug in 0.1.5) |
| Torn writes on power loss | fsync of temp file and directory around every atomic rewrite | Code-reviewed; not fault-injection tested |
| Lost audit events under concurrent writers | Inter-process file lock around read-modify-write | Test T9 (2 processes × 10 appends, 0 lost) |

## What SURFRAME does NOT protect against

- **Key compromise.** Anyone holding the private key produces valid signatures. Store it encrypted (`keygen` supports a passphrase; the PEM is written 0600) and rotate if leaked. There is no revocation mechanism in the container itself.
- **Self-attested trust.** `verify` without `--pubkey` only proves the container is *internally consistent* with its embedded key — it does not prove *who* signed it. An attacker who tampers the content and re-signs with their own key, keeping the same `signer` string, exits 0. Identity requires the public key out-of-band. In CI, use `--pubkey`, or set `fail-on-self-attested: true` in the Action.
- **Unauthenticated audit appends.** The audit log is excluded from the signed digest so it can grow after signing, and its chain is an *unkeyed* SHA-256 — continuing it requires no key. So an event appended after the signature proves only "somebody with write access wrote this"; it is not evidence of who did what. Since 0.4.0 `verify` counts these in `audit.unattested_appends` and returns invalid unless you pass `--allow-appends`. Events present *at signing time* are attested and are the ones you can rely on. Authenticating later appends would require handing the signing key to every process that reads the container, which is worse; the intended workflow is to re-sign.
- **Seal replay.** Proof of possession (0.4.0) stops someone claiming authorship they cannot prove, but it is possession, not freshness: whoever has a copy of a public `.surx` can replay its signature document and obtain a second seal for a root that genuinely belongs to that signer. Closing this needs a server nonce signed at seal time, i.e. the private key at `surx seal` time. Deliberately not done.
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

## Trust anchor for registry seals (0.4.0)

`check-seal` verifies the issuer signature against a **pinned** key
(`surframe.registry_client.PINNED_ISSUER_KEYS`), overridable with `--issuer-key`
or `SURX_ISSUER_KEY` for a self-hosted registry.

Until 0.3.5 it verified the signature against `receipt["issuer_public_key"]` — a
key carried inside the artifact under audit. That check was decorative: generate
a keypair, tamper the content, recompute the root, sign your own receipt, and all
three indicators read green offline. The same class of bug as CVE-2026-22703 in
Cosign, where a bundle verified although the embedded log entry did not bind the
artifact's digest, signature or key. Two related holes closed at the same time:
`urllib.error.HTTPError` is a subclass of `URLError`, so a registry answering
`404 seal_id not found` was being reported as `unreachable` and left the result
valid; and the receipt was never bound to the container's own signature, so a
seal issued for someone else's key was accepted. A reachable registry that
answers now fails closed; only a genuine network failure degrades to
`unreachable`, and in that case the local, content and issuer bindings still hold.

## Signer identity in seals: proof of possession (0.4.0)

`subject.signer` used to be free text. Any key holder — including a free-tier key
— could seal a root claiming `signer: "data-team@openai"` with an arbitrary
`public_key`, and the public page and badge said **verified**. The seal proved
that a root existed at a time, never who produced it.

`surx seal` now sends the container's `signatures/ed25519.json`, and the registry
checks that it is a valid Ed25519 signature by `subject.public_key` over a payload
committing to *this* `entries_root` — something only the private key holder can
produce. The outcome is recorded inside the signed seal payload as
`subject.verified`, so it cannot be edited afterwards, and the public page and
badge distinguish **VERIFIED** (possession proved) from **SEALED** (identity
declared by the submitter, not verified). Clients ≤0.3.5 omit the proof and get
`verified: false` rather than an error.

## Verifier resource limits (0.4.0)

A verifier runs attacker-controlled input in CI and in a hosted service, so it is
itself an attack surface. Entries are hashed in 1 MiB chunks instead of read whole
into memory, and are refused above `SURX_MAX_ENTRY_BYTES` (2 GiB),
`SURX_MAX_TOTAL_BYTES` (8 GiB) or `SURX_MAX_RATIO` (200x) — checked both on the
declared header sizes and on the bytes actually decompressed, since the header is
attacker-controlled. Before this, a 260 KB container with a 1000x ratio made the
verifier allocate 256 MB.

## Byte-exactness of the container (0.4.0)

The digest covers entry *content*, not the raw file, which left three unsigned
channels that changed `sha256(file)` while `verify` still said valid: bytes
prepended before the first local header, bytes appended after the
end-of-central-directory record, and the zip archive comment. All three are now
rejected at `sign` and `verify` time. A signed artifact must be exactly one zip,
starting at offset 0, ending at the EOCD, with no comment — anything else is
parser ambiguity (polyglot files) and is refused rather than blessed.

## Operator compromise of the transparency log

For a transparency log the threat model *is* the operator, so this needs saying
plainly. `verify_seal` used to verify each seal's issuer signature against the
`issuer_public_key` stored in the same database row it was auditing; whoever can
write the database can write both. It now compares against the live signer key,
which is loaded from the encrypted PEM, and `audit_full_chain` validates every
issuer signature rather than only the hash links (links are unkeyed SHA-256 and
trivially recomputed by an operator).

What remains **not** solved: the log lives on a single Fly volume with no mirror,
and `/v1/checkpoint` exists but no client consumes it, so signed checkpoints are
not yet compared over time — meaning a rollback of the whole log by the operator
would not currently be detected by any automated check. Anchoring roots in an
independent public log such as Rekor is the real fix and is not implemented.

## Local PRO feature gate is not a security boundary

`surframe/license.py` gates optional local features. It is not enforcement:
revenue lives in server-side quotas on the registry. Until 0.3.5 it accepted any
unsigned JSON, which unlocked PRO features locally — harmless, but misleading to
anyone reading the code. It now validates an Ed25519 signature when
`SURFRAME_LICENSE_PUBKEY` is set, and otherwise reports `reason="unverified"`
instead of implying enforcement it does not perform.

## Cryptographic choices

Ed25519 (via `cryptography`) for signatures; AES-256-GCM with 12-byte random nonces per sidecar; Scrypt (N=2^17, r=8, p=1) for passphrase-derived keys — legacy 0.1.5 containers (N=2^14) remain readable and are upgraded in place on the next encrypt call. Random 96-bit GCM nonces are safe far beyond the per-container sidecar counts here (NIST bounds
apply from ~2^32 encryptions under one key; a container has one sidecar per column per partition).
The audit chain is an *unkeyed* SHA-256 chain by design: it provides ordering and internal consistency; authenticity comes from anchoring its head under the Ed25519 signature. We say this explicitly because 0.1.5 marketed the bare chain as a signature, and it wasn't.

## Disclosure

Found a hole? Open a GitHub issue with the `security` label. Reproductions in the style of `tests/test_v020.py` are the fastest path to a fix.
