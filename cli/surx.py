# Copyright 2025 Christ10-8
# Licensed under the Apache License, Version 2.0
"""CLI de SURFRAME. En 0.1.5 el help prometia write|read|plan|inspect pero
ninguno estaba registrado (solo comandos PRO de un modulo no incluido).
0.2.0 registra el nucleo completo + firma/verificacion Ed25519."""
from __future__ import annotations

import json
import sys
from typing import Optional, List

import typer

app = typer.Typer(add_completion=False, help="SURX CLI - contenedor firmado, cifrado y auditable")


def _echo_json(obj) -> None:
    typer.echo(json.dumps(obj, ensure_ascii=False, indent=2, default=str))


# -------------------- nucleo --------------------

@app.command()
def write(source: str, out: str,
          partition_by: Optional[str] = typer.Option(None, help="Columnas separadas por coma")):
    """Convierte CSV/Parquet a contenedor .surx."""
    import surframe
    pb = [c.strip() for c in partition_by.split(",")] if partition_by else None
    surframe.write(source, out, partition_by=pb)
    typer.echo(f"OK: {out}")


@app.command()
def read(path: str,
         columns: Optional[str] = typer.Option(None, help="Columnas separadas por coma"),
         where: Optional[str] = typer.Option(None),
         passphrase: Optional[str] = typer.Option(None, envvar="SURX_PASSPHRASE"),
         limit: int = typer.Option(10, help="Filas a mostrar (0 = todas)"),
         to_csv: Optional[str] = typer.Option(None, help="Exportar resultado a CSV")):
    """Lee el contenedor (con pruning por indices) y muestra/exporta filas."""
    import surframe
    cols = [c.strip() for c in columns.split(",")] if columns else None
    kwargs = {}
    if passphrase:
        kwargs["passphrase"] = passphrase
    df = surframe.read(path, columns=cols, where=where, **kwargs)
    if to_csv:
        df.to_csv(to_csv, index=False)
        typer.echo(f"OK: {len(df)} filas -> {to_csv}")
    else:
        typer.echo(df.head(limit).to_string() if limit else df.to_string())
        typer.echo(f"[{len(df)} filas]")


@app.command()
def plan(path: str, where: Optional[str] = typer.Option(None)):
    """Explica el pruning: que chunks se leerian y por que."""
    import surframe
    _echo_json(surframe.plan(path, where=where))


@app.command()
def inspect(path: str):
    """Resumen del contenedor: schema, chunks, indices, snapshots."""
    import surframe
    _echo_json(surframe.inspect(path))


@app.command()
def validate(path: str):
    """Chequeos de consistencia interna del contenedor."""
    import surframe
    surframe.validate(path)
    typer.echo("OK: contenedor valido")


@app.command()
def optimize(path: str):
    """Compacta y reordena el contenedor."""
    import surframe
    surframe.optimize(path)
    typer.echo("OK: optimizado")


@app.command()
def snapshot(path: str, note: Optional[str] = typer.Option(None)):
    """Crea un snapshot del estado actual."""
    import surframe
    _echo_json(surframe.snapshot(path, note=note))


@app.command()
def log(path: str):
    """Muestra el journal de operaciones."""
    import surframe
    _echo_json(surframe.log(path))


@app.command()
def demo():
    """La historia completa en 15 segundos: firmar, verificar, envenenar, atrapar."""
    import os, tempfile, zipfile as _zf
    import pandas as pd
    import surframe
    w = tempfile.mkdtemp()
    p = os.path.join(w, "trainset.surx")
    typer.echo("1) Escribiendo dataset (3.000 filas, PII en 'annotator_email')...")
    df = pd.DataFrame({"prompt": [f"review #{i}" for i in range(3000)],
                       "label": [i % 2 for i in range(3000)],
                       "annotator_email": [f"a{i%40}@vendor.example" for i in range(3000)]})
    surframe.write(df, p)
    surframe.encrypt_columns_in_surx(p, ["annotator_email"], "demo-pass")
    kp = surframe.generate_keypair()
    surframe.sign_container(p, kp.private_hex, signer="you@demo")
    typer.echo("   firmado con Ed25519 ✓  columna PII cifrada ✓")
    rep = surframe.verify_container(p, kp.public_hex)
    typer.echo(f"2) verify -> {rep['reason']} ✓")
    zin = _zf.ZipFile(p); data = {n: zin.read(n) for n in zin.namelist()}; zin.close()
    t = [n for n in data if n.endswith(".parquet")][0]
    b = bytearray(data[t]); b[100] ^= 1; data[t] = bytes(b)
    with _zf.ZipFile(p, "w") as z:
        for n, d in data.items():
            z.writestr(n, d)
    typer.echo(f"3) Atacante voltea UN byte en {t}")
    rep = surframe.verify_container(p, kp.public_hex)
    typer.echo(f"4) verify -> INVALIDO: {rep['reason']}")
    typer.echo(f"   entrada exacta: {rep['modified'][0]}")
    typer.echo("\nEso ve tu CI. Firma real: surx keygen && surx sign. Notariza: surx seal.")


# -------------------- cifrado --------------------

@app.command()
def encrypt(path: str, columns: str,
            passphrase: str = typer.Option(..., prompt=True, hide_input=True,
                                           confirmation_prompt=True,
                                           envvar="SURX_PASSPHRASE")):
    """Cifra columnas (AES-GCM) moviendolas a side-cars. Multi-llamada segura."""
    from surframe import encrypt_columns_in_surx
    encrypt_columns_in_surx(path, [c.strip() for c in columns.split(",")], passphrase)
    typer.echo("OK: columnas cifradas")


@app.command()
def decrypt(path: str,
            columns: Optional[str] = typer.Option(None, help="Vacio = todas"),
            passphrase: str = typer.Option(..., prompt=True, hide_input=True,
                                           envvar="SURX_PASSPHRASE")):
    """Revierte columnas cifradas a texto plano."""
    from surframe import decrypt_columns_in_surx
    cols = [c.strip() for c in columns.split(",")] if columns else []
    decrypt_columns_in_surx(path, cols, passphrase)
    typer.echo("OK: columnas descifradas")


# -------------------- firma Ed25519 --------------------

@app.command()
def keygen(private_out: str = typer.Option("surx_signing.key"),
           public_out: str = typer.Option("surx_signing.pub"),
           passphrase: Optional[str] = typer.Option(None, envvar="SURX_KEY_PASSPHRASE",
                                                    help="Cifra la clave privada at-rest")):
    """Genera un par Ed25519 (PEM). La privada se guarda con permisos 0600."""
    from surframe import generate_keypair, save_private_key, save_public_key
    kp = generate_keypair()
    save_private_key(kp, private_out, passphrase=passphrase)
    save_public_key(kp, public_out)
    typer.echo(f"OK: privada -> {private_out} (0600), publica -> {public_out}")
    typer.echo(f"public_key_hex: {kp.public_hex}")


@app.command()
def sign(path: str,
         key: str = typer.Option(..., help="PEM de clave privada Ed25519"),
         signer: Optional[str] = typer.Option(None),
         passphrase: Optional[str] = typer.Option(None, envvar="SURX_KEY_PASSPHRASE")):
    """Firma el contenedor: entradas + heads de auditoria bajo Ed25519."""
    from surframe import load_private_key, sign_container
    payload = sign_container(path, load_private_key(key, passphrase), signer=signer)
    typer.echo(f"OK: firmado por '{payload['signer']}' @ {payload['signed_at']}")
    typer.echo(f"entries_root: {payload['entries_root']} ({payload['entry_count']} entradas)")


@app.command()
def verify(path: str,
           pubkey: Optional[str] = typer.Option(None, help="PEM publico. Sin el: self-attested"),
           full: bool = typer.Option(False, help="Reporte JSON completo")):
    """Verifica firma e integridad. Exit 0 = valido, 1 = tampering/invalid."""
    from surframe import load_public_key, verify_container
    pk = load_public_key(pubkey) if pubkey else None
    rep = verify_container(path, pk)
    if full:
        _echo_json(rep)
    else:
        status = "VALIDO" if rep["valid"] else "INVALIDO"
        trust = "clave externa" if rep["trusted_key"] else "clave embebida (self-attested)"
        typer.echo(f"{status} [{trust}] - {rep['reason']}")
        for k in ("modified", "missing", "added"):
            for name in rep[k]:
                typer.echo(f"  {k}: {name}")
    raise typer.Exit(code=0 if rep["valid"] else 1)


@app.command(name="audit-verify")
def audit_verify(path: str):
    """Valida la cadena hash del log de auditoria. Exit 0/1."""
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
    """Genera un evidence pack verificable offline (EU AI Act Art. 10/11/12). Exit 0/1."""
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
    """Sella el contenedor en el transparency log (SURX Registry)."""
    from surframe import seal_with_registry
    r = seal_with_registry(path, api_key, registry_url=registry)
    typer.echo(f"OK: sellado en posicion {r['seal']['position']} del log")
    typer.echo(f"verificacion publica: {r['verify_url']}")


@app.command(name="verify-seal")
def verify_seal(path: str,
                registry: Optional[str] = typer.Option(None, envvar="SURX_REGISTRY_URL"),
                pubkey_hex: Optional[str] = typer.Option(None, help="Pinning de la clave del registro")):
    """Verifica el sello notarizado contra el registro. Exit 0/1."""
    from surframe import verify_registry_seal
    rep = verify_registry_seal(path, registry_url=registry, registry_pubkey_hex=pubkey_hex)
    typer.echo(("VALIDO" if rep["valid"] else "INVALIDO") + f" - {rep['reason']}")
    if rep.get("verify_url"):
        typer.echo(f"pagina publica: {rep['verify_url']}")
    raise typer.Exit(code=0 if rep["valid"] else 1)


# -------------------- registro (transparency log) --------------------

@app.command()
def seal(path: str,
         api_key: str = typer.Option(..., envvar="SURX_API_KEY"),
         registry: str = typer.Option("", envvar="SURX_REGISTRY",
                                      help="URL del registro (default: env o localhost)")):
    """Notariza el contenedor firmado en el transparency log (tier free: gratis)."""
    from surframe.registry_client import seal_container_remote
    r = seal_container_remote(path, api_key, registry)
    typer.echo(f"OK: sello {r['seal_id']} (log #{r['n']})")
    typer.echo(f"verificacion publica: {r.get('verify_url','')}")


@app.command(name="check-seal")
def check_seal_cmd(path: str,
                   registry: str = typer.Option("", envvar="SURX_REGISTRY")):
    """Verifica el sello: contenido vs sellado + emisor + registro. Exit 0/1."""
    from surframe.registry_client import check_seal
    rep = check_seal(path, registry)
    _echo_json(rep)
    raise typer.Exit(code=0 if rep["valid"] else 1)


# -------------------- PRO (gated) --------------------

def _pro_cmd(feature: str):
    from surframe import is_pro_enabled
    if not is_pro_enabled(feature):
        typer.echo(f"Comando PRO bloqueado: falta licencia con feature '{feature}'.", err=True)
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
