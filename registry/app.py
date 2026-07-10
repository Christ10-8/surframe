# Copyright 2025 Christ10-8 — Apache-2.0
"""SURX Registry API. Correr: uvicorn registry.app:app"""
from __future__ import annotations

import html
import os
import time
from typing import Optional

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

from . import core

app = FastAPI(title="SURX Registry", version="0.1.0",
              description="Transparency log + notarization for .surx dataset containers.")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["GET", "POST"],
                   allow_headers=["*"])

_registry: Optional[core.Registry] = None
_free_ips: dict[str, float] = {}
BASE_URL = os.environ.get("REGISTRY_BASE_URL", "http://localhost:8000")


def reg() -> core.Registry:
    global _registry
    if _registry is None:
        _registry = core.Registry()
    return _registry


class SealIn(BaseModel):
    entries_root: str = Field(min_length=64, max_length=64)
    entry_count: int = Field(ge=0)
    subject: dict = Field(default_factory=dict)


class ActivateIn(BaseModel):
    license_key: str


@app.get("/v1/health")
def health():
    return {"ok": True, "issuer_public_key": reg().signer.public_hex}


@app.post("/v1/keys/free")
def free_key(request: Request):
    ip = request.client.host if request.client else "?"
    last = _free_ips.get(ip, 0.0)
    if time.time() - last < 3600:
        raise HTTPException(429, "Una key gratis por hora por IP. Tiers pagos: /pricing")
    _free_ips[ip] = time.time()
    key = core.create_key("free", label=f"ip:{ip}")
    return {"api_key": key, "tier": "free",
            "quota": core.TIERS["free"], "note": "Guardala: no se puede recuperar."}


@app.post("/v1/keys/activate")
def activate(body: ActivateIn):
    try:
        key = core.activate_license(body.license_key)
    except PermissionError as e:
        raise HTTPException(403, str(e))
    row = core.resolve_key(key)
    return {"api_key": key, "tier": row["tier"], "quota": core.TIERS[row["tier"]]}


@app.post("/v1/seal")
def seal(body: SealIn, x_api_key: str = Header(default="")):
    if not x_api_key:
        raise HTTPException(401, "Falta header X-API-Key. Key gratis: POST /v1/keys/free")
    try:
        row = core.consume_quota(x_api_key)
    except PermissionError as e:
        raise HTTPException(401, str(e))
    except ValueError as e:
        raise HTTPException(402, str(e))
    receipt = reg().seal(entries_root=body.entries_root.lower(),
                         entry_count=body.entry_count,
                         subject=body.subject, tier=row["tier"])
    receipt["verify_url"] = f"{BASE_URL}/s/{receipt['seal_id']}"
    return receipt


@app.get("/v1/verify/{seal_id}")
def verify(seal_id: str):
    rep = reg().verify_seal(seal_id)
    if not rep["found"]:
        raise HTTPException(404, rep["reason"])
    return rep


@app.get("/v1/seals/by-root/{entries_root}")
def by_root(entries_root: str):
    return {"seals": [
        {"seal_id": s["seal_id"], "n": s["n"], "ts": s["ts"], "chain_hash": s["chain_hash"]}
        for s in reg().find_by_root(entries_root.lower())]}


@app.get("/v1/log")
def log_list(after: int = 0, limit: int = 50):
    """Log publico paginado: cualquiera puede recorrer el registro entero."""
    limit = max(1, min(int(limit), 100))
    rows = core.db.connect().execute(
        "SELECT n, seal_id, ts, entries_root, chain_hash, payload_json FROM seals "
        "WHERE n > ? ORDER BY n LIMIT ?", (int(after), limit)).fetchall()
    import json as _j
    return {"entries": [
        {"n": r["n"], "seal_id": r["seal_id"], "ts": r["ts"],
         "entries_root": r["entries_root"], "chain_hash": r["chain_hash"],
         "name": _j.loads(r["payload_json"])["subject"].get("name", "")}
        for r in rows]}


@app.get("/v1/log/audit")
def audit():
    return reg().audit_full_chain()


@app.get("/v1/checkpoint")
def checkpoint():
    return reg().checkpoint()


# -------------------- badge SVG para READMEs (loop viral) --------------------

_BADGE = """<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="20" role="img" aria-label="surx: {word}">
<rect width="42" height="20" fill="#14213D"/><rect x="42" width="{w2}" height="20" fill="{color}"/>
<g fill="#fff" font-family="Verdana,Geneva,sans-serif" font-size="11">
<text x="21" y="14" text-anchor="middle">surx</text>
<text x="{tx}" y="14" text-anchor="middle">{word}</text></g></svg>"""


@app.get("/badge/{seal_id}.svg")
def badge(seal_id: str):
    from fastapi.responses import Response
    rep = reg().verify_seal(seal_id)
    if not rep["found"]:
        word, color = "not found", "#5B6770"
    elif rep["valid"]:
        word, color = "verified", "#1B7F5C"
    else:
        word, color = "tampered", "#B3402A"
    w2 = 12 + 7 * len(word)
    svg = _BADGE.format(w=42 + w2, w2=w2, tx=42 + w2 // 2, word=word, color=color)
    return Response(svg, media_type="image/svg+xml",
                    headers={"Cache-Control": "no-cache, max-age=300"})


# -------------------- pagina publica de verificacion --------------------

_PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Seal {sid} — SURX Registry</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Newsreader:ital,opsz,wght@0,6..72,500;0,6..72,700;1,6..72,500&family=Public+Sans:wght@400;600&family=Spline+Sans+Mono:wght@400;600&display=swap" rel="stylesheet">
<style>
:root{{--paper:#F2F4F3;--ink:#14213D;--seal:#1B7F5C;--stamp:#B3402A;--line:#C9CFCB;--mut:#5B6770}}
*{{box-sizing:border-box;margin:0}}
body{{background:var(--paper);color:var(--ink);font:16px/1.55 "Public Sans",system-ui,sans-serif;
display:flex;justify-content:center;padding:48px 20px}}
.card{{max-width:640px;width:100%;background:#fff;border:1px solid var(--line);padding:36px}}
.eyebrow{{font:600 12px/1 "Spline Sans Mono",monospace;letter-spacing:.14em;color:var(--mut);
text-transform:uppercase}}
h1{{font:700 34px/1.15 "Newsreader",serif;margin:10px 0 4px}}
h1 em{{font-style:italic;color:{state_color}}}
.state{{display:inline-block;margin:14px 0 26px;padding:7px 14px;border:2px solid {state_color};
color:{state_color};font:600 13px/1 "Spline Sans Mono",monospace;letter-spacing:.12em}}
dl{{border-top:1px solid var(--line)}}
.row{{display:grid;grid-template-columns:150px 1fr;gap:12px;padding:11px 0;
border-bottom:1px solid var(--line)}}
dt{{color:var(--mut);font-size:13px;padding-top:2px}}
dd{{font:400 13px/1.5 "Spline Sans Mono",monospace;word-break:break-all}}
.ok{{color:var(--seal)}}.bad{{color:var(--stamp)}}
footer{{margin-top:26px;font-size:13px;color:var(--mut)}}
footer a{{color:var(--ink)}}
@media(max-width:520px){{.row{{grid-template-columns:1fr}}}}
</style></head><body><main class="card">
<div class="eyebrow">SURX Registry · transparency log</div>
<h1>Seal <em>{sid}</em></h1>
<div class="state">{state_word}</div>
<dl>
<div class="row"><dt>Status</dt><dd class="{cls}">{state_line}</dd></div>
<div class="row"><dt>Dataset root</dt><dd>{root}</dd></div>
<div class="row"><dt>Entries</dt><dd>{count}</dd></div>
<div class="row"><dt>Sealed at</dt><dd>{ts}</dd></div>
<div class="row"><dt>Signer</dt><dd>{signer}</dd></div>
<div class="row"><dt>Signer pubkey</dt><dd>{spk}</dd></div>
<div class="row"><dt>Log position</dt><dd>#{n} · chain {chain}</dd></div>
<div class="row"><dt>Issuer signature</dt><dd class="{sig_cls}">{sig_state}</dd></div>
<div class="row"><dt>RFC 3161</dt><dd>{tsa}</dd></div>
</dl>
<footer>Anyone can audit the full log: <a href="/v1/log/audit">/v1/log/audit</a> ·
<a href="/v1/checkpoint">signed checkpoint</a>. Verify offline with
<span style="font-family:'Spline Sans Mono',monospace">surx check-seal</span>.</footer>
</main></body></html>"""


@app.get("/s/{seal_id}", response_class=HTMLResponse)
def seal_page(seal_id: str):
    rep = reg().verify_seal(seal_id)
    if not rep["found"]:
        return HTMLResponse(_PAGE.format(
            sid=html.escape(seal_id), state_color="var(--stamp)", state_word="NOT FOUND",
            cls="bad", state_line="No seal with this id exists in the log.",
            root="—", count="—", ts="—", signer="—", spk="—", n="—", chain="—",
            sig_cls="bad", sig_state="—", tsa="—"), status_code=404)
    p = rep["payload"]
    ok = rep["valid"]
    return HTMLResponse(_PAGE.format(
        sid=html.escape(seal_id),
        state_color="var(--seal)" if ok else "var(--stamp)",
        state_word="VERIFIED" if ok else "TAMPERED / INVALID",
        cls="ok" if ok else "bad",
        state_line="Issuer signature, chain link and timestamp all check out."
                   if ok else "One or more checks failed — do not trust this artifact.",
        root=html.escape(p["entries_root"]),
        count=p["entry_count"], ts=html.escape(p["ts"]),
        signer=html.escape(p["subject"]["signer"] or "—"),
        spk=html.escape(p["subject"]["public_key"] or "—"),
        n=p["n"], chain=html.escape(rep["chain_hash"][:16]) + "…",
        sig_cls="ok" if rep["issuer_sig_ok"] else "bad",
        sig_state="valid" if rep["issuer_sig_ok"] else "INVALID",
        tsa=rep["rfc3161"]))
