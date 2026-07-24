# SURFRAME

**Cosign for datasets.** Prove where your data came from and that nobody touched it — offline, in one command, without trusting anyone's server.

```
pip install surframe
surx demo          # the whole story in 15 seconds: sign → verify → poison → catch
```

![SURFRAME demo: sign a dataset, flip one byte, verification names the exact file](https://raw.githubusercontent.com/Christ10-8/surframe/main/docs/demo.png)

[![CI](https://github.com/Christ10-8/surframe/actions/workflows/ci.yml/badge.svg)](https://github.com/Christ10-8/surframe/actions)
[![PyPI](https://img.shields.io/pypi/v/surframe.svg)](https://pypi.org/project/surframe/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

## The problem, concretely

You trained a model on a dataset a vendor sent you in March. In May, someone edited
three rows and re-sent the "same" file. Nothing in your pipeline noticed: the checksum
you kept was for the old version, and even if it had failed, it would only have told you
*something* changed — not what, not when, not who.

Which dataset actually trained your model? And can you prove it to an auditor who has no
reason to trust your infrastructure?

## Why

Software has a supply chain: we sign artifacts, verify checksums, keep transparency logs. **Data has none of that.** Training sets, eval benchmarks, telemetry dumps and client deliverables travel as naked CSVs and Parquet files — no provenance, no integrity, no way to prove the dataset you audited is the dataset that trained the model.

SURFRAME is a single-file container (`.surx`) that fixes this:

- **Ed25519 signatures** over every entry — `verify` tells you the *exact* file that changed, and whether the audit log was rewritten.
- **Column-level AES-GCM encryption** — ship PII columns encrypted; recipients query everything else without the passphrase. Sidecars are cryptographically bound to their container (no splicing between files).
- **Append-only audit chain** — every read/write logged inside the container, hash-chained, and *anchored under the signature*: an attacker who rewrites the whole chain still gets caught.
- **Queryable without unpacking** — Parquet chunks + bloom/minmax indexes inside a zip. `read(where=...)` prunes chunks before touching data.
- **Offline, third-party verification** — one open-source command, exit codes. No account, no server, no vendor lock-in.

Think *cosign for datasets*, in one `pip install`.

## Why not just a SHA-256?

A checksum answers one question: *are these exact bytes unchanged?* That is genuinely
useful, and if it is all you need, use it — it ships with your OS.

It stops being enough the moment a dataset is a bundle rather than a single blob:

- A checksum says *something* changed. `surx verify` names the **exact file inside** the
  container that changed, and tells you whether the audit log was rewritten.
- A detached `.sha256` gets separated from its data in real pipelines. Here the signature,
  the manifest and the audit trail live **inside** the artifact and travel with it.
- A checksum proves nothing about **who** produced the data. An Ed25519 signature ties the
  container to a key you chose to trust.
- A checksum can't leave part of the data readable and part encrypted. Column-level AES-GCM
  can: ship PII encrypted, let recipients query everything else.

If your threat model is "detect accidental corruption of one file", a checksum wins on
simplicity. If it is "prove provenance to someone who doesn't trust me", it doesn't cover it.

## How it compares

These tools solve different problems and compose well. Versioning tools answer *which
version is this?* inside infrastructure you control. SURFRAME answers *can a third party who
doesn't trust your infrastructure verify where this came from?*

| | Versioning | Large-file storage | Signed by author | Offline third-party verify | Column-level encryption | Evidence travels inside the artifact |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| SHA-256 checksum | — | — | — | bytes only | — | — |
| Git LFS | ✅ | ✅ | — | — | — | — |
| DVC | ✅ | ✅ | — | — | — | — |
| LakeFS | ✅ | ✅ | — | — | — | — |
| Parquet / Iceberg / Delta | — | ✅ | — | — | — | — |
| **SURFRAME** | — | — | ✅ | ✅ | ✅ | ✅ |

Read the table honestly: SURFRAME is **not** a versioning or storage layer, and it is not
trying to be. You can version a `.surx` container in DVC and store it in LakeFS. What it adds
is attestation — the part none of the others do.

## EU AI Act: evidence, not documentation

The AI Act asks high-risk systems to document data governance (Art. 10), keep technical documentation (Art. 11) and traceable records (Art. 12). A README or a warehouse export is *documentation* — editable, and only as trustworthy as the system it came from. SURFRAME produces **evidence**: a signed pack an auditor can verify offline, without trusting you.

```bash
surx export trainset.surx --format ai-act
```

...emits an evidence pack (`EVIDENCE.json`, `REPORT.md`, an explicit map onto Art. 10/11/12, the audit chain, checksums) and **refuses to generate it for a tampered or corrupt container**. It attests integrity and traceability — not conformity.

→ Full write-up: **[surframe.dev/blog/ai-act-evidence](https://surframe.dev/blog/ai-act-evidence)** · the deadline landscape post-Omnibus: **[surframe.dev/ai-act](https://surframe.dev/ai-act)**

## 60-second demo: catch a tampered dataset

```python
import pandas as pd, surframe

# 1. Build and sign a dataset
df = pd.DataFrame({"prompt": ["..."]*1000, "label": [1,0]*500,
                   "annotator_email": ["a@x.com"]*1000})
surframe.write(df, "trainset.surx")
surframe.encrypt_columns_in_surx("trainset.surx", ["annotator_email"], "s3cret")

kp = surframe.generate_keypair()
surframe.sign_container("trainset.surx", kp.private_hex, signer="data-team")

# 2. Recipient verifies — no passphrase needed
report = surframe.verify_container("trainset.surx", kp.public_hex)
assert report["valid"]                      # ✓ authentic, untouched

# 3. Someone flips one byte in one chunk...
report = surframe.verify_container("trainset.surx", kp.public_hex)
print(report["reason"])    # "tampering detected: 1 modified entry"
print(report["modified"])  # ["chunks/part-000000.parquet"]  ← the exact file
```

Or from the CLI — exit codes are CI-ready:

```bash
surx keygen
surx sign trainset.surx --key surx_signing.key --signer data-team
surx verify trainset.surx --pubkey surx_signing.pub   # exit 0 = intact, 1 = tampered
```

Run the full story: `surx demo`

## What's inside a .surx

Zstd-compressed Parquet chunks, a manifest, bloom/minmax indexes for predicate pushdown, snapshots, a journal, an append-only audit log (`profiles/audit/*.jsonl`), encrypted column sidecars (`enc/`), and a detached Ed25519 signature (`signatures/ed25519.json`). It's a zip — you can open it with anything, but you can't *alter* it without detection.

Partitioning is optional and generic: `surframe.write(df, path, partition_by=["model"])` gives you partition pruning on any column; no `partition_by` writes a single flat chunk set.

## CLI

`write · read · plan · inspect · validate · optimize · snapshot · log · encrypt · decrypt · keygen · sign · verify · audit-verify · export · seal · check-seal`

`verify`, `audit-verify`, `export` and `check-seal` return exit code 0/1, so a dataset check
is one line in any pipeline. A ready-made GitHub Action lives in
[`surx-verify-action/`](surx-verify-action/).

**Keys: `--key` vs `--pubkey`.** `sign` takes `--key` (your *private* key — never share it).
`verify` takes `--pubkey` (the *public* key of whoever signed, which you're meant to
distribute). Different flags on purpose: mixing them up should be a syntax error, not a
silent leak.

```bash
surx keygen                                        # -> surx_signing.key (private, 0600)
                                                   #    surx_signing.pub (public, share this)
surx sign   trainset.surx --key    surx_signing.key --signer data-team
surx verify trainset.surx --pubkey surx_signing.pub
```

Set `SURX_PASSPHRASE` to avoid the interactive prompt when encrypting or reading encrypted
columns in CI. Set `SURX_REGISTRY` only if you run your own registry; it defaults to the
hosted one.

## Performance

Measured on a 62 MB container (1.5M rows, incompressible data): `verify` in 0.32 s (~195 MB/s — effectively SHA-256 + zip read speed), `sign` in 2.5 s (it atomically rewrites the container to embed the signature). Try it yourself: `surx demo` runs the full sign→tamper→catch story in seconds.

## Security, honestly

Read [THREAT_MODEL.md](THREAT_MODEL.md) before trusting this with anything serious. Short version: signatures prove integrity and authorship *relative to a public key you trust*; a self-attested container proves consistency, not identity. Key compromise, availability and side channels are out of scope. Version 0.3.x exists because we audited 0.1.5, found it didn't deliver what it promised, and rebuilt it — the [CHANGELOG](CHANGELOG_0.2.0.md) documents every hole and its fix, and `tests/test_v020.py` (42 checks) attacks each one, including a full audit-chain-rewrite attack that the unkeyed chain misses and the signature catches.

## Roadmap

- **Hosted transparency log** — *live*. A Rekor-style public registry for dataset
  signatures: notarized seals, public verification pages, signed anti-rollback checkpoints.
  `surx seal` notarizes a signed container; `surx check-seal` verifies it against the log.
  A free tier needs no account beyond a key request; paid tiers exist at
  [surframe.dev](https://surframe.dev). **Verification is free and offline forever** —
  you never need the registry, or an account, to verify a container.
- Streaming/append writes, row-group chunking for large partitions.
- Keyless signing via OIDC (Sigstore-style) — exploring.

## License

Apache-2.0. The container format and this library are open and will stay open.
