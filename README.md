# SURFRAME

**Signed, encrypted, tamper-evident data containers.** Ship a dataset the way you'd ship a signed binary: anyone can verify *who* produced it and *that not a single byte changed* — down to the exact file inside.

```
pip install surframe
```

[![CI](https://github.com/Christ10-8/surframe/actions/workflows/ci.yml/badge.svg)](https://github.com/Christ10-8/surframe/actions)
[![PyPI](https://img.shields.io/pypi/v/surframe.svg)](https://pypi.org/project/surframe/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

## Why

Software has a supply chain: we sign artifacts, verify checksums, keep transparency logs. **Data has none of that.** Training sets, eval benchmarks, telemetry dumps and client deliverables travel as naked CSVs and Parquet files — no provenance, no integrity, no way to prove the dataset you audited is the dataset that trained the model.

SURFRAME is a single-file container (`.surx`) that fixes this:

- **Ed25519 signatures** over every entry — `verify` tells you the *exact* file that changed, and whether the audit log was rewritten.
- **Column-level AES-GCM encryption** — ship PII columns encrypted; recipients query everything else without the passphrase. Sidecars are cryptographically bound to their container (no splicing between files).
- **Append-only audit chain** — every read/write logged inside the container, hash-chained, and *anchored under the signature*: an attacker who rewrites the whole chain still gets caught.
- **Queryable without unpacking** — Parquet chunks + bloom/minmax indexes inside a zip. `read(where=...)` prunes chunks before touching data.

Think *cosign for datasets*, in one `pip install`.

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
print(report["reason"])    # "tampering detectado: 1 entrada(s) modificada(s)"
print(report["modified"])  # ["chunks/part-000000.parquet"]  ← the exact file
```

Or from the CLI — exit codes are CI-ready:

```bash
surx keygen
surx sign trainset.surx --key surx_signing.key --signer data-team
surx verify trainset.surx --pubkey surx_signing.pub   # exit 0 = intact, 1 = tampered
```

Run the full story: `python examples/provenance_demo.py`

## What's inside a .surx

Zstd-compressed Parquet chunks, a manifest, bloom/minmax indexes for predicate pushdown, snapshots, a journal, an append-only audit log (`profiles/audit/*.jsonl`), encrypted column sidecars (`enc/`), and a detached Ed25519 signature (`signatures/ed25519.json`). It's a zip — you can open it with anything, but you can't *alter* it without detection.

Partitioning is optional and generic: `surframe.write(df, path, partition_by=["model"])` gives you partition pruning on any column; no `partition_by` writes a single flat chunk set.

## CLI

`write · read · plan · inspect · validate · optimize · snapshot · log · encrypt · decrypt · keygen · sign · verify · audit-verify`

`verify` and `audit-verify` return exit code 0/1, so a dataset check is one line in any pipeline. A ready-made GitHub Action lives in [`surx-verify-action/`](surx-verify-action/).

## Performance

Measured on a 62 MB container (1.5M rows, incompressible data): `verify` in 0.32 s (~195 MB/s — 
effectively SHA-256 + zip read speed), `sign` in 2.5 s (it atomically rewrites the container to 
embed the signature). Try it yourself: `surx demo` runs the full sign→tamper→catch story in seconds.

## Security, honestly

Read [THREAT_MODEL.md](THREAT_MODEL.md) before trusting this with anything serious. Short version: signatures prove integrity and authorship *relative to a public key you trust*; a self-attested container proves consistency, not identity. Key compromise, availability and side channels are out of scope. Version 0.2.0 exists because we audited 0.1.5 and found it didn't deliver what it promised — the [CHANGELOG](CHANGELOG_0.2.0.md) documents every hole and its fix, and `tests/test_v020.py` (38 checks) attacks each one, including a full audit-chain-rewrite attack that the unkeyed chain misses and the signature catches.

## Badge your datasets

Every seal gets a live badge — green while the published root stays verified in the log:

```markdown
[![surx seal](https://YOUR-REGISTRY/badge/sf-00001042-ab12cd34.svg)](https://YOUR-REGISTRY/s/sf-00001042-ab12cd34)
```

## Roadmap

- **Hosted transparency log** (a Rekor-style public registry for dataset signatures: notarized seals, RFC 3161 timestamps, third-party verification pages). Open an issue tagged `registry-early-access` if you want in.
- Streaming/append writes, row-group chunking for large partitions.
- Keyless signing via OIDC (Sigstore-style) — exploring.

## License

Apache-2.0. The container format and this library are open and will stay open.
