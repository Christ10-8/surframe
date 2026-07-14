"""surframe.export_aiact — EU AI Act evidence pack generation.

Generates a self-contained, offline-verifiable "evidence pack" from a signed
.surx container, mapped to EU AI Act (Regulation (EU) 2024/1689) Articles
10, 11 and 12. See docs/EVIDENCE_PACK.md.

Design rule: this module REFUSES to produce evidence for a container that
fails verification. Exit path for tampered containers is an exception, not
a degraded pack.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import shutil
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional

SPEC_VERSION = "1"

DISCLAIMER = (
    "This pack attests to the cryptographic integrity, authorship and "
    "traceability of the referenced data container. It does NOT constitute "
    "legal advice nor a certification of conformity with Regulation (EU) "
    "2024/1689 (AI Act). Conformity assessment remains the responsibility "
    "of the AI system provider and the competent bodies."
)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _sha256_file(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def _utcnow() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _tool_version() -> str:
    try:
        import surframe
        return getattr(surframe, "__version__", "unknown")
    except Exception:  # pragma: no cover
        return "unknown"


def _copy_audit_chain(container: Path, dest: Path) -> List[str]:
    """Copy profiles/audit/*.jsonl verbatim into the pack."""
    dest.mkdir(parents=True, exist_ok=True)
    copied: List[str] = []
    with zipfile.ZipFile(container, "r") as zf:
        for name in zf.namelist():
            norm = name.replace("\\", "/")
            if norm.startswith("profiles/audit/") and norm.endswith(".jsonl"):
                out = dest / Path(norm).name
                out.write_bytes(zf.read(name))
                copied.append(out.name)
    return sorted(copied)


def _read_signature_doc(container: Path) -> Optional[dict]:
    with zipfile.ZipFile(container, "r") as zf:
        names = zf.namelist()
        if "signatures/ed25519.json" in names:
            try:
                return json.loads(zf.read("signatures/ed25519.json"))
            except json.JSONDecodeError:
                return None
    return None


def _audit_time_range(audit_dir: Path) -> Dict[str, Optional[str]]:
    first: Optional[str] = None
    last: Optional[str] = None
    total = 0
    for f in sorted(audit_dir.glob("*.jsonl")):
        for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            total += 1
            ts = ev.get("ts") or ev.get("timestamp") or ev.get("time")
            if ts:
                first = first or ts
                last = ts
    return {"first_event_at": first, "last_event_at": last, "events_total": total}


def _dataset_summary(container: Path) -> Optional[dict]:
    """Schema/partitions via the public API; degrade gracefully."""
    try:
        import surframe
        info = surframe.inspect(str(container))
        if isinstance(info, dict):
            return {
                "schema": info.get("schema"),
                "partitions": info.get("partitions") or info.get("partition_by"),
                "rows": info.get("rows"),
                "chunks": info.get("chunks") if isinstance(info.get("chunks"), (int, list)) else None,
                "snapshots": info.get("snapshots") if isinstance(info.get("snapshots"), (int, list)) else None,
            }
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# core
# ---------------------------------------------------------------------------

def build_evidence_pack(
    container_path: str,
    output_dir: Optional[str] = None,
    public_key_hex: Optional[str] = None,
    include_container: bool = False,
    declarations: Optional[Dict[str, Any]] = None,
    as_zip: bool = False,
) -> dict:
    """Build an AI Act evidence pack from a signed .surx container.

    Raises RuntimeError if signature or audit-chain verification fails:
    no evidence is produced for a tampered or unsigned container.
    Returns the EVIDENCE.json content as a dict, plus "_pack_path".
    """
    container = Path(container_path).resolve()
    if not container.exists():
        raise FileNotFoundError(f"Not found: {container}")

    # 1. Verification gate — Ed25519 signature + entry diff + audit chain.
    from surframe.signing import verify_container
    try:
        report = verify_container(str(container), public_key_hex)
    except Exception as exc:  # corrupted zip / truncated stream / bad entry
        raise RuntimeError(
            "Container verification FAILED — the file could not even be "
            f"read as a valid container ({type(exc).__name__}: {exc}). "
            "No evidence pack will be generated."
        ) from exc
    if not report.get("valid", False):
        raise RuntimeError(
            "Container verification FAILED — no evidence pack will be "
            f"generated. Reason: {report.get('reason')!r}. "
            f"Modified: {report.get('modified')} Missing: {report.get('missing')} "
            f"Added: {report.get('added')}"
        )
    audit_info = report.get("audit") or {}
    if audit_info.get("consistent") is False or audit_info.get("append_only") is False:
        raise RuntimeError(
            "Audit chain verification FAILED — no evidence pack will be "
            f"generated. Detail: {audit_info.get('detail')}"
        )

    generated_at = _utcnow()
    stamp = generated_at.replace("-", "").replace(":", "")[:13]  # YYYYMMDDTHHMM
    pack_name = f"evidence_pack_{container.stem}_{stamp}"
    out_root = Path(output_dir).resolve() if output_dir else container.parent
    pack_dir = out_root / pack_name
    pack_dir.mkdir(parents=True, exist_ok=False)

    # 2. Verbatim audit chain + signature document.
    audit_files = _copy_audit_chain(container, pack_dir / "audit_chain")
    sig_doc = _read_signature_doc(container)
    if sig_doc is not None:
        (pack_dir / "signature.ed25519.json").write_text(
            json.dumps(sig_doc, indent=2, ensure_ascii=False), encoding="utf-8"
        )

    # 3. Container: embed or reference by hash.
    container_sha = _sha256_file(container)
    if include_container:
        shutil.copy2(container, pack_dir / container.name)

    # 4. EVIDENCE.json — the machine-readable root document.
    chain_stats = _audit_time_range(pack_dir / "audit_chain")
    evidence: Dict[str, Any] = {
        "spec_version": SPEC_VERSION,
        "generated_at": generated_at,
        "disclaimer": DISCLAIMER,
        "tool": {"name": "surframe", "version": _tool_version()},
        "container": {
            "filename": container.name,
            "sha256": container_sha,
            "size_bytes": container.stat().st_size,
            "included": include_container,
        },
        "signature": {
            "algorithm": "ed25519",
            "signer": report.get("signer"),
            "signed_at": report.get("signed_at"),
            "trusted_key_provided": bool(report.get("trusted_key")),
            "self_attested": not bool(report.get("trusted_key")),
        },
        "verification": {
            "valid": True,
            "modified": report.get("modified", []),
            "missing": report.get("missing", []),
            "added": report.get("added", []),
            "audit_chain": {
                "consistent": audit_info.get("consistent"),
                "append_only": audit_info.get("append_only"),
            },
        },
        "audit_chain": {
            "files": audit_files,
            "chain_algorithm": "sha256-linked, anchored under Ed25519 signature",
            **chain_stats,
        },
        "dataset": _dataset_summary(container),
        "declarations": declarations or {},
    }
    (pack_dir / "EVIDENCE.json").write_text(
        json.dumps(evidence, indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )

    # 5. Human-readable documents.
    (pack_dir / "REPORT.md").write_text(_render_report(evidence), encoding="utf-8")
    (pack_dir / "VERIFY.md").write_text(_render_verify(evidence), encoding="utf-8")
    (pack_dir / "ai_act_mapping.md").write_text(_render_mapping(evidence), encoding="utf-8")

    # 6. checksums.txt over everything above.
    lines = [
        f"{_sha256_file(f)}  {f.relative_to(pack_dir)}"
        for f in sorted(pack_dir.rglob("*"))
        if f.is_file() and f.name != "checksums.txt"
    ]
    (pack_dir / "checksums.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")

    # 7. Optional zip.
    if as_zip:
        evidence["_pack_path"] = shutil.make_archive(str(pack_dir), "zip", root_dir=pack_dir)
    else:
        evidence["_pack_path"] = str(pack_dir)
    return evidence


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------

def _render_report(e: dict) -> str:
    s = e["signature"]
    a = e["audit_chain"]
    ds = e.get("dataset") or {}
    decl = e.get("declarations") or {}
    trust = ("verified against a caller-provided public key"
             if s["trusted_key_provided"]
             else "self-attested (verified against the embedded public key)")
    lines = [
        "# Evidence Report — SURFRAME Evidence Pack",
        "",
        f"- Generated: {e['generated_at']}",
        f"- Tool: surframe {e['tool']['version']} (evidence spec v{e['spec_version']})",
        f"- Container: `{e['container']['filename']}`",
        f"- SHA-256: `{e['container']['sha256']}`",
        f"- Size: {e['container']['size_bytes']:,} bytes",
        f"- Container included in pack: {'yes' if e['container']['included'] else 'no (referenced by hash)'}",
        "",
        "## Verification result",
        "",
        "**VALID — signature verified, no entries modified, added or missing.**",
        "",
        f"- Signature: Ed25519, signer `{s['signer']}`, signed at {s['signed_at']}",
        f"- Trust basis: {trust}",
        f"- Audit chain: consistent={e['verification']['audit_chain']['consistent']}, "
        f"append-only={e['verification']['audit_chain']['append_only']}",
        f"- Audit events: {a.get('events_total')} "
        f"({a.get('first_event_at') or 'n/a'} → {a.get('last_event_at') or 'n/a'})",
        "",
        "## Dataset",
        "",
    ]
    if ds.get("schema"):
        lines.append(f"- Schema: `{json.dumps(ds['schema'], ensure_ascii=False, default=str)}`")
    if ds.get("rows") is not None:
        lines.append(f"- Rows: {ds['rows']}")
    if ds.get("partitions"):
        lines.append(f"- Partitioning: `{ds['partitions']}`")
    if not any(ds.get(k) for k in ("schema", "rows", "partitions")):
        lines.append("- (dataset summary not available)")
    if decl:
        lines += ["", "## Producer declarations", ""]
        lines += [f"- **{k}**: {v}" for k, v in decl.items()]
    lines += ["", "---", "", f"> {e['disclaimer']}", ""]
    return "\n".join(lines)


def _render_verify(e: dict) -> str:
    name = e["container"]["filename"]
    sha = e["container"]["sha256"]
    self_attested = e["signature"]["self_attested"]
    steps = [
        "# How to verify this pack (auditor instructions)",
        "",
        "Verification is offline and requires no access to the producer's",
        "infrastructure. Requirements: Python 3.10+ and `pip install surframe`.",
        "",
        "## 1. Pack integrity",
        "```bash",
        "sha256sum -c checksums.txt",
        "```",
        "Every file must report OK.",
        "",
        "## 2. Container integrity and authorship",
    ]
    get_container = [] if e["container"]["included"] else [
        "The container is not embedded in this pack. Request it from the",
        "producer, then confirm its SHA-256 matches `EVIDENCE.json`:",
        "```",
        f"{sha}  {name}",
        "```",
        "",
    ]
    steps += get_container + [
        "```bash",
        f"surx verify {name}" + ("" if self_attested else "  --pubkey <producer-key.pub>"),
        "```",
        "Expected: exit code 0 (valid). Exit code 1 names the exact entry",
        "that was modified, added or removed.",
    ]
    if self_attested:
        steps += [
            "",
            "> Note: this container is self-attested (verified against the key",
            "> embedded in it). That proves internal consistency. To also prove",
            "> authorship, obtain the producer's public key through an",
            "> independent channel and pass it via `--pubkey`.",
        ]
    steps += [
        "",
        "## 3. Audit chain",
        "```bash",
        f"surx audit-verify {name}",
        "```",
        "Files under `audit_chain/` are a verbatim copy of the container's",
        "event history. Each line is SHA-256-chained to the previous one and",
        "the chain heads are anchored under the Ed25519 signature — a rewrite",
        "of the whole chain is still detected.",
        "",
        "A VALID result means: no event was modified, deleted, inserted or",
        "reordered since it was recorded, and the container content is exactly",
        "what the signer signed.",
        "",
    ]
    return "\n".join(steps)


def _render_mapping(e: dict) -> str:
    decl = e.get("declarations") or {}
    prov = ("producer declarations in `EVIDENCE.json` (purpose, sources, licensing)"
            if decl else
            "no producer declarations attached — see `EVIDENCE.json → declarations`")
    return "\n".join([
        "# Mapping: EU AI Act requirements → evidence in this pack",
        "",
        "Regulation (EU) 2024/1689. This table states **which technical",
        "evidence this pack contributes** toward each requirement; it is not",
        "a conformity assessment.",
        "",
        "| Requirement | Evidence in this pack |",
        "|---|---|",
        f"| **Art. 10(2)** — data governance: origin, collection and processing operations | {prov} + transformation events in `audit_chain/` |",
        "| **Art. 12** — automatic, traceable record-keeping over the lifecycle | `audit_chain/` (verbatim), cryptographically verified and signature-anchored (`EVIDENCE.json → verification`) |",
        "| **Art. 11 / Annex IV(2)(d)** — technical documentation of the datasets | `EVIDENCE.json` (schema, rows, partitions, hashes) + `REPORT.md` |",
        "| Third-party verifiability | `VERIFY.md` + open-source CLI (`pip install surframe`), offline, exit-code based |",
        "",
        "---",
        "",
        f"> {e['disclaimer']}",
        "",
    ])
