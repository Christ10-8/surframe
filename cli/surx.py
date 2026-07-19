# Copyright 2025 Christ10-8
# Licensed under the Apache License, Version 2.0
"""CLI de SURFRAME. En 0.1.5 el help prometia write|read|plan|inspect pero
ninguno estaba registrado (solo comandos PRO de un modulo no incluido).
0.2.0 wires the full core + Ed25519 signing/verification."""
from __future__ import annotations

import json
import sys
from typing import Optional, List

import typer

app = typer.Typer(add_completion=False, help="SURX CLI — signed, encrypted, auditable data containers")


def _echo_json(obj) -> None:
    typer.echo(json.dumps(obj, ensure_ascii=False, indent=2, default=str))


# -------------------- core --------------------

@app.command()
def write(source: str, out: str,
          partition_by: Optional[str] = typer.Option(None, help="Comma-separated columns")):
    """Convert CSV/Parquet into a .surx container."""
    import surframe
    pb = [c.strip() for c in partition_by.split(",")] if partition_by else None
    surframe.write(source, out, partition_by=pb)
    typer.echo(f"OK: {out}")


@app.command()
def read(path: str,
         columns: Optional[str] = typer.Option(None, help="Comma-separated columns"),
         where: Optional[str] = typer.Option(None),
         passphrase: Optional[str] = typer.Option(None, envvar="SURX_PASSPHRASE"),
         limit: int = typer.Option(10, help="Rows to show (0 = all)"),
         to_csv: Optional[str] = typer.Option(None, help="Export result to CSV")):
    """Read the container (with index pruning) and show/export rows."""
    import surframe
    cols = [c.strip() for c in columns.split(",")] if columns else None
    kwargs = {}
    if passphrase:
        kwargs["passphrase"] = passphrase
    df = surframe.read(path, columns=cols, where=where, **kwargs)
    if to_csv:
        df.to_csv(to_csv, index=False)
        typer.echo(f"OK: {len(df)} rows -> {to_csv}")
    else:
        typer.echo(df.head(limit).to_string() if limit else df.to_string())
        typer.echo(f"[{len(df)} rows]")


@app.command()
def plan(path: str, where: Optional[str] = typer.Option(None)):
    """Explain pruning: which chunks would be read and why."""
    import surframe
    _echo_json(surframe.plan(path, where=where))


@app.command()
def inspect(path: str):
    """Container summary: schema, chunks, indexes, snapshots."""
    import surframe
    _echo_json(surframe.inspect(path))


@app.command()
def validate(path: str):
    """Internal consistency checks on the container."""
    import surframe
    surframe.validate(path)
    typer.echo("OK: container valid")


@app.command()
def optimize(path: str):
    """Compact and reorder the container."""
    import surframe
    surframe.optimize(path)
    typer.echo("OK: optimized")


@app.command()
def snapshot(path: str, note: Optional[str] = typer.Option(None)):
    """Create a snapshot of the current state."""
    import surframe
    _echo_json(surframe.snapshot(path, note=note))


@app.command()
def log(path: str):
    """Show the operations journal."""
    import surframe
    _echo_json(surframe.log(path))


@app.command()
def demo():
    """The whole story in 15 seconds: sign, verify, poison, catch."""
    import os, tempfile, zipfile as _zf
    import pandas as pd
    import surframe
    w = tempfile.mkdtemp()
    p = os.path.join(w, "trainset.surx")
    typer.echo("1) Writing dataset (3,000 rows, PII in 'annotator_email')...")
    df = pd.DataFrame({"prompt": [f"review #{i}" for i in range(3000)],
                       "label": [i % 2 for i in range(3000)],
                       "annotator_email": [f"a{i%40}@vendor.example" for i in range(3000)]})
    surframe.write(df, p)
    surframe.encrypt_columns_in_surx(p, ["annotator_email"], "demo-pass")
    kp = surframe.generate_keypair()
    surframe.sign_container(p, kp.private_hex, signer="you@demo")
    typer.echo("   signed with Ed25519 ✓  PII column encrypted ✓")
    rep = surframe.verify_container(p, kp.public_hex)
    typer.echo(f"2) verify -> {rep['reason']} ✓")
    zin = _zf.ZipFile(p); data = {n: zin.read(n) for n in zin.namelist()}; zin.close()
    t = [n for n in data if n.endswith(".parquet")][0]
    b = bytearray(data[t]); b[100] ^= 1; data[t] = bytes(b)
    with _zf.ZipFile(p, "w") as z:
        for n, d in data.items():
            z.writestr(n, d)
    typer.echo(f"3) Attacker flips ONE byte in {t}")
    rep = surframe.verify_container(p, kp.public_hex)
    typer.echo(f"4) verify -> INVALID: {rep['reason']}")
    typer.echo(f"   exact entry: {rep['modified'][0]}")
    typer.echo("\nThat's what your CI sees. Real signing: surx keygen && surx sign. Notarize: surx seal.")


# -------------------- encryption --------------------

@app.command()
def encrypt(path: str, columns: str,
            passphrase: str = typer.Option(..., prompt=True, hide_input=True,
                                           confirmation_prompt=True,
                                           envvar="SURX_PASSPHRASE")):
    """Encrypt columns (AES-GCM) into side-cars. Safe across multiple calls."""
    from surframe import encrypt_columns_in_surx
    encrypt_columns_in_surx(path, [c.strip() for c in columns.split(",")], passphrase)
    typer.echo("OK: columns encrypted")


@app.command()
def decrypt(path: str,
            columns: Optional[str] = typer.Option(None, help="Empty = all columns"),
            passphrase: str = typer.Option(..., prompt=True, hide_input=True,
                                           envvar="SURX_PASSPHRASE")):
    """Revert encrypted columns back to plaintext."""
    from surframe import decrypt_columns_in_surx
    cols = [c.strip() for c in columns.split(",")] if columns else []
    decrypt_columns_in_surx(path, cols, passphrase)
    typer.echo("OK: columns decrypted")


# -------------------- Ed25519 signing --------------------

@app.command()
def keygen(private_out: str = typer.Option("surx_signing.key"),
           public_out: str = typer.Option("surx_signing.pub"),
           passphrase: Optional[str] = typer.Option(None, envvar="SURX_KEY_PASSPHRASE",
                                                    help="Encrypt the private key at rest")):
    """Generate an Ed25519 keypair (PEM). The private key is saved with 0600 perms."""
    from surframe import generate_keypair, save_private_key, save_public_key
    kp = generate_keypair()
    save_private_key(kp, private_out, passphrase=passphrase)
    save_public_key(kp, public_out)
    typer.echo(f"OK: private -> {private_out} (0600), public -> {public_out}")
    typer.echo(f"public_key_hex: {kp.public_hex}")


@app.command()
def sign(path: str,
         key: str = typer.Option(..., help="Ed25519 private key PEM"),
         signer: Optional[str] = typer.Option(None),
         passphrase: Optional[str] = typer.Option(None, envvar="SURX_KEY_PASSPHRASE")):
    """Sign the container: entries + audit heads under Ed25519."""
    from surframe import load_private_key, sign_container
    payload = sign_container(path, load_private_key(key, passphrase), signer=signer)
    typer.echo(f"OK: signed by '{payload['signer']}' @ {payload['signed_at']}")
    typer.echo(f"entries_root: {payload['entries_root']} ({payload['entry_count']} entries)")


@app.command()
def verify(path: str,
           pubkey: Optional[str] = typer.Option(None, help="Public key PEM. Without it: self-attested"),
           full: bool = typer.Option(False, help="Full JSON report")):
    """Verify signature and integrity. Exit 0 = valid, 1 = tampering/invalid."""
    from surframe import load_public_key, verify_container
    pk = load_public_key(pubkey) if pubkey else None
    rep = verify_container(path, pk)
    if full:
        _echo_json(rep)
    else:
        status = "VALID" if rep["valid"] else "INVALID"
        trust = "external key" if rep["trusted_key"] else "embedded key (self-attested)"
        typer.echo(f"{status} [{trust}] - {rep['reason']}")
        for k in ("modified", "missing", "added"):
            for name in rep[k]:
                typer.echo(f"  {k}: {name}")
    raise typer.Exit(code=0 if rep["valid"] else 1)


@app.command(name="audit-verify")
def audit_verify(path: str):
    """Validate the audit log hash chain. Exit 0/1."""
    from surframe import verify_audit_chain
    rep = verify_audit_chain(path)
    _echo_json(rep)
    raise typer.Exit(code=0 if rep["ok"] else 1)


@app.command()
def export(path: str,
           format: str = typer.Option("ai-act", "--format", help="Pack format (ai-act)"),
           output: Optional[str] = typer.Option(None, "--output", "-o", help="Output directory"),
           pubkey: Optional[str] = typer.Option(None, "--pubkey", help="Producer public key file (else self-attested)"),
           include_container: bool = typer.Option(False, "--include-container", help="Embed the .surx in the pack"),
           zip: bool = typer.Option(False, "--zip", help="Package as .zip"),
           declare: Optional[List[str]] = typer.Option(None, "--declare", "-d",
               help="Producer declaration, repeatable: -d 'purpose=training data'")):
    """Generate an offline-verifiable evidence pack (EU AI Act Art. 10/11/12). Exit 0/1."""
    if format != "ai-act":
        typer.secho(f"Unsupported format: {format}. Available: ai-act", fg=typer.colors.RED)
        raise typer.Exit(code=2)
    declarations = {}
    for item in declare or []:
        if "=" not in item:
            typer.secho(f"Invalid declaration (expected key=value): {item}", fg=typer.colors.RED)
            raise typer.Exit(code=2)
        k, _, v = item.partition("=")
        declarations[k.strip()] = v.strip()
    pub_hex = None
    if pubkey:
        from surframe.signing import load_public_key
        pub_hex = load_public_key(pubkey)
    from surframe.export_aiact import build_evidence_pack
    try:
        ev = build_evidence_pack(path, output_dir=output, public_key_hex=pub_hex,
                                 include_container=include_container,
                                 declarations=declarations, as_zip=zip)
    except RuntimeError as exc:
        typer.secho(f"\n  ✗ {exc}\n", fg=typer.colors.RED, bold=True)
        raise typer.Exit(code=1)
    s = ev["signature"]
    typer.secho("\n  ✓ Evidence pack generated", fg=typer.colors.GREEN, bold=True)
    typer.echo(f"  location : {ev['_pack_path']}")
    typer.echo(f"  container: {ev['container']['filename']} (sha256 {ev['container']['sha256'][:16]}…)")
    typer.echo(f"  signature: ed25519 · signer {s['signer']} · "
               f"{'trusted key' if s['trusted_key_provided'] else 'self-attested'}")
    typer.echo(f"  audit    : {ev['audit_chain'].get('events_total')} events · chain anchored under signature")
    typer.echo("  contents : EVIDENCE.json, REPORT.md, VERIFY.md, ai_act_mapping.md, audit_chain/, checksums.txt")
    if not include_container:
        typer.echo("  note     : container referenced by hash (use --include-container to embed)")
    typer.echo("")


@app.command()
def seal(path: str,
         api_key: str = typer.Option(..., envvar="SURX_REGISTRY_KEY"),
         registry: str = typer.Option("https://surx-registry.fly.dev", envvar="SURX_REGISTRY_URL")):
    """Seal the container in the transparency log (SURX Registry)."""
    from surframe import seal_with_registry
    r = seal_with_registry(path, api_key, registry_url=registry)
    typer.echo(f"OK: sealed at position {r['seal']['position']} in the log")
    typer.echo(f"public verification: {r['verify_url']}")


@app.command(name="verify-seal")
def verify_seal(path: str,
                registry: Optional[str] = typer.Option(None, envvar="SURX_REGISTRY_URL"),
                pubkey_hex: Optional[str] = typer.Option(None, help="Registry key pinning")):
    """Verify the notarized seal against the registry. Exit 0/1."""
    from surframe import verify_registry_seal
    rep = verify_registry_seal(path, registry_url=registry, registry_pubkey_hex=pubkey_hex)
    typer.echo(("VALID" if rep["valid"] else "INVALID") + f" - {rep['reason']}")
    if rep.get("verify_url"):
        typer.echo(f"public page: {rep['verify_url']}")
    raise typer.Exit(code=0 if rep["valid"] else 1)


# -------------------- registry (transparency log) --------------------

@app.command()
def seal(path: str,
         api_key: str = typer.Option(..., envvar="SURX_API_KEY"),
         registry: str = typer.Option("", envvar="SURX_REGISTRY",
                                      help="Registry URL (default: env or localhost)")):
    """Notarize the signed container in the transparency log (free tier)."""
    from surframe.registry_client import seal_container_remote
    r = seal_container_remote(path, api_key, registry)
    typer.echo(f"OK: seal {r['seal_id']} (log #{r['n']})")
    typer.echo(f"public verification: {r.get('verify_url','')}")


@app.command(name="check-seal")
def check_seal_cmd(path: str,
                   registry: str = typer.Option("", envvar="SURX_REGISTRY")):
    """Verify the seal: content vs sealed + issuer + registry. Exit 0/1."""
    from surframe.registry_client import check_seal
    rep = check_seal(path, registry)
    _echo_json(rep)
    raise typer.Exit(code=0 if rep["valid"] else 1)


# -------------------- PRO (gated) --------------------

def _pro_cmd(feature: str):
    from surframe import is_pro_enabled
    if not is_pro_enabled(feature):
        typer.echo(f"PRO command blocked: missing license for feature '{feature}'.", err=True)
        raise typer.Exit(code=2)


@app.command()
def learn():
    _pro_cmd("ucodec")
    from surframe.ucodec.learn import learn_ucodec
    learn_ucodec()


@app.command()
def reencode():
    _pro_cmd("ucodec")
    from surframe.ucodec.reencode import reencode_ucodec
    reencode_ucodec()


@app.command()
def zopt():
    _pro_cmd("zopt")
    from surframe.ucodec.layout import zorder_optimize
    zorder_optimize()


@app.command()
def tier():
    _pro_cmd("tier")
    from surframe.ucodec.tier import tier_plan
    tier_plan()


def main():
    app()


if __name__ == "__main__":
    main()
