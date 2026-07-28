# Copyright 2025 Christ10-8 — Apache-2.0
"""Nucleo del registro: log encadenado, sellado, keys y metering."""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import db
from .signer import IssuerSigner, canonical
from . import tsa

GENESIS = "0" * 64
TIERS = {"free": 10, "pro": 500, "business": 5000}
LS_VALIDATE_URL = "https://api.lemonsqueezy.com/v1/licenses/validate"
# Mapa variant_id de Lemon Squeezy -> tier. Se setea por env, ej: "123:pro,456:business"
LS_VARIANTS_ENV = "REGISTRY_LS_VARIANTS"
DEV_FAKE_LS = "REGISTRY_DEV_FAKE_LS"   # tests: "LICENSE:tier,..."


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def month_key() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m")


# -------------------- API keys --------------------

def _hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def create_key(tier: str, label: str = "", license_hash: Optional[str] = None) -> str:
    key = "surx_" + secrets.token_urlsafe(24)
    conn = db.connect()
    conn.execute(
        "INSERT INTO api_keys(key_hash,tier,month,used,label,created,license_hash) "
        "VALUES(?,?,?,0,?,?,?)",
        (_hash_key(key), tier, month_key(), label, now_iso(), license_hash))
    conn.commit()
    return key


def revoke_keys_for_license(license_hash: str) -> int:
    """Revoke every API key previously issued for this license. Returns how many."""
    conn = db.connect()
    with db.lock():
        cur = conn.execute("UPDATE api_keys SET revoked=1 "
                           "WHERE license_hash=? AND revoked=0", (license_hash,))
        conn.commit()
        return cur.rowcount


def resolve_key(key: str) -> Optional[dict]:
    row = db.connect().execute("SELECT * FROM api_keys WHERE key_hash=? AND revoked=0",
                               (_hash_key(key),)).fetchone()
    return dict(row) if row else None


def get_usage(key: str) -> dict:
    """Read-only view of a key's monthly quota. Does not consume anything."""
    row = db.connect().execute("SELECT * FROM api_keys WHERE key_hash=? AND revoked=0",
                               (_hash_key(key),)).fetchone()
    if not row:
        raise PermissionError("Invalid or revoked API key.")
    mk = month_key()
    used = row["used"] if row["month"] == mk else 0
    limit = TIERS.get(row["tier"], 0)
    return {"tier": row["tier"], "used": used, "limit": limit,
            "remaining": max(0, limit - used), "month": mk}


def consume_quota(key: str) -> dict:
    """Devuelve la fila de la key si tiene cupo este mes; ValueError si no."""
    conn = db.connect()
    with db.lock():
        row = conn.execute("SELECT * FROM api_keys WHERE key_hash=? AND revoked=0",
                           (_hash_key(key),)).fetchone()
        if not row:
            raise PermissionError("Invalid or revoked API key.")
        mk = month_key()
        used = row["used"] if row["month"] == mk else 0
        limit = TIERS.get(row["tier"], 0)
        if used >= limit:
            raise ValueError(f"Monthly quota exhausted for tier '{row['tier']}' ({limit} seals/month).")
        conn.execute("UPDATE api_keys SET month=?, used=? WHERE id=?", (mk, used + 1, row["id"]))
        conn.commit()
        d = dict(row)
        d["used"] = used + 1
        d["limit"] = limit
        d["remaining"] = limit - (used + 1)
        return d


def usage(key: str) -> dict:
    """Read-only quota snapshot for an API key. Does not consume anything."""
    row = resolve_key(key)
    if not row:
        raise PermissionError("Invalid or revoked API key.")
    mk = month_key()
    used = row["used"] if row["month"] == mk else 0
    limit = TIERS.get(row["tier"], 0)
    return {"tier": row["tier"], "used": used, "limit": limit,
            "remaining": max(0, limit - used), "month": mk}


def activate_license(license_key: str) -> str:
    """Validate a Lemon Squeezy license key and issue an API key for its tier.

    One license == one live API key. Re-activating the same license (e.g. the
    customer lost their key) revokes the previous one and issues a fresh key,
    so a single subscription can never accumulate extra quota.
    """
    lic_hash = _hash_key(license_key)
    fake = os.environ.get(DEV_FAKE_LS, "")
    if fake:  # test/dev path, no network
        mapping = dict(p.split(":") for p in fake.split(",") if ":" in p)
        tier = mapping.get(license_key)
        if not tier:
            raise PermissionError("Invalid license key.")
        revoke_keys_for_license(lic_hash)
        return create_key(tier, label=f"ls:{license_key[:8]}", license_hash=lic_hash)

    variants = dict(p.split(":") for p in os.environ.get(LS_VARIANTS_ENV, "").split(",") if ":" in p)
    body = urllib.parse.urlencode({"license_key": license_key}).encode()
    req = urllib.request.Request(LS_VALIDATE_URL, data=body,
                                 headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.loads(r.read())
    except urllib.error.HTTPError as e:
        # Lemon Squeezy answers with a 4xx (not 200 + valid:false) for keys it does
        # not recognise. Without this branch a customer who mistypes one character
        # gets an opaque 500 instead of a readable "invalid license key".
        detail = ""
        try:
            detail = (json.loads(e.read()) or {}).get("error") or ""
        except Exception:
            pass
        if 400 <= e.code < 500:
            raise PermissionError("Invalid or expired license key."
                                  + (f" ({detail})" if detail else ""))
        raise RuntimeError("The license server is unavailable right now. "
                           "Please try again in a few minutes.")
    except (urllib.error.URLError, TimeoutError, OSError):
        raise RuntimeError("Could not reach the license server. "
                           "Please try again in a few minutes.")
    except ValueError:
        raise RuntimeError("Unexpected response from the license server.")
    if not data.get("valid"):
        raise PermissionError("Invalid or expired license key.")
    variant_id = str(data.get("meta", {}).get("variant_id", ""))
    tier = variants.get(variant_id)
    if not tier:
        raise PermissionError(f"Variant {variant_id} is not mapped to a tier ({LS_VARIANTS_ENV}).")
    revoke_keys_for_license(lic_hash)
    return create_key(tier, label=f"ls:{license_key[:8]}", license_hash=lic_hash)


# -------------------- transparency log --------------------

def _verify_possession(signature_doc: Dict[str, Any], entries_root: str,
                       claimed_key: str) -> bool:
    """True only if `signature_doc` is a real Ed25519 signature by `claimed_key`
    over a payload that commits to `entries_root`.

    Three bindings, all required: the key must be the claimed one, the signature
    must verify under it, and the signed payload must be about THIS root. Drop any
    one and authorship becomes forgeable again.

    Note on scope: this is possession, not freshness. Someone who copies a public
    .surx can replay its signature document and obtain a second seal for a root
    that genuinely belongs to that signer — annoying, not forgery. Closing that
    needs a server nonce signed at seal time, which means handing the private key
    to `surx seal`. Deliberately out of scope; see THREAT_MODEL.md.
    """
    if not isinstance(signature_doc, dict):
        return False
    payload = signature_doc.get("payload")
    sig_hex = signature_doc.get("signature")
    if not isinstance(payload, dict) or not isinstance(sig_hex, str):
        return False
    if str(payload.get("entries_root", "")).lower() != entries_root.lower():
        return False
    key = str(payload.get("public_key", "")).lower()
    if not key or key != claimed_key:
        return False
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(key))
        pub.verify(bytes.fromhex(sig_hex),
                   json.dumps(payload, ensure_ascii=False, sort_keys=True,
                              separators=(",", ":")).encode("utf-8"))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


class Registry:
    def __init__(self) -> None:
        self.signer = IssuerSigner()
        db.connect()

    def _head(self) -> tuple[int, str]:
        row = db.connect().execute(
            "SELECT n, chain_hash FROM seals ORDER BY n DESC LIMIT 1").fetchone()
        return (row["n"], row["chain_hash"]) if row else (0, GENESIS)

    def seal(self, *, entries_root: str, entry_count: int,
             subject: Dict[str, Any], tier: str,
             signature_doc: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Crea un sello: firma del EMISOR sobre el payload canonico completo
        (metadata incluida — leccion: firmar solo el root permite forjar autoria),
        encadenado al log. Append bajo lock (leccion: race condition).

        0.4.0 — PRUEBA DE POSESION. Hasta 0.3.5 `subject` era texto libre: con
        una key free cualquiera podia mandar signer="data-team@openai" y un
        public_key inventado, y /v1/verify devolvia valid:true y el badge decia
        "verified". El sello probaba "alguien publico este root en T", nunca
        QUIEN. Ahora el cliente manda su signatures/ed25519.json y el registro
        comprueba que la firma valide contra subject.public_key sobre un payload
        que contiene ESTE entries_root. Eso solo lo puede producir quien tiene la
        privada.

        No es obligatorio, a proposito: los clientes <=0.3.5 no lo mandan y
        seguirian rompiendose. Pero el resultado queda GRABADO en el payload
        firmado (`subject.verified`), asi que la pagina publica puede decir la
        verdad sobre cada sello en vez de decir "verified" para todos.
        """
        if not (isinstance(entries_root, str) and len(entries_root) == 64
                and all(c in "0123456789abcdef" for c in entries_root)):
            raise ValueError("entries_root must be a 64-char SHA-256 hex string.")

        claimed_key = str(subject.get("public_key", ""))[:64].lower()
        verified = False
        if signature_doc is not None:
            verified = _verify_possession(signature_doc, entries_root, claimed_key)
            if not verified:
                raise ValueError(
                    "proof of possession failed: the signature document does not "
                    "verify against subject.public_key over this entries_root.")

        conn = db.connect()
        with db.lock():
            n_prev, prev_hash = self._head()
            n = n_prev + 1
            seal_id = f"sf-{n:08d}-{secrets.token_hex(4)}"
            payload = {
                "v": 1, "seal_id": seal_id, "n": n, "ts": now_iso(),
                "entries_root": entries_root, "entry_count": int(entry_count),
                "subject": {
                    "signer": str(subject.get("signer", "unknown"))[:120],
                    "public_key": claimed_key,
                    "name": str(subject.get("name", ""))[:120],
                    # True  = the sealer proved possession of the private key.
                    # False = self-declared identity, NOT verified by the registry.
                    "verified": verified,
                },
                "tier": tier, "prev_hash": prev_hash,
                "issuer_public_key": self.signer.public_hex,
            }
            issuer_sig = self.signer.sign(payload)
            chain_hash = hashlib.sha256(
                (prev_hash + hashlib.sha256(canonical(payload)).hexdigest()).encode()
            ).hexdigest()
            token = tsa.timestamp(canonical(payload))
            conn.execute(
                "INSERT INTO seals(seal_id,n,ts,entries_root,payload_json,issuer_sig,"
                "prev_hash,chain_hash,tsa_token_b64) VALUES(?,?,?,?,?,?,?,?,?)",
                (seal_id, n, payload["ts"], entries_root,
                 json.dumps(payload, ensure_ascii=False), issuer_sig,
                 prev_hash, chain_hash, token))
            conn.commit()
        return {"seal_id": seal_id, "n": n, "payload": payload,
                "issuer_sig": issuer_sig, "chain_hash": chain_hash,
                "issuer_public_key": self.signer.public_hex,
                "rfc3161": bool(token)}

    def get(self, seal_id: str) -> Optional[dict]:
        row = db.connect().execute("SELECT * FROM seals WHERE seal_id=?", (seal_id,)).fetchone()
        return dict(row) if row else None

    def find_by_root(self, entries_root: str) -> list[dict]:
        rows = db.connect().execute(
            "SELECT * FROM seals WHERE entries_root=? ORDER BY n", (entries_root,)).fetchall()
        return [dict(r) for r in rows]

    def verify_seal(self, seal_id: str) -> Dict[str, Any]:
        """Re-verifica TODO: firma del emisor, eslabon de cadena y token RFC 3161
        contra el imprint real (leccion: nunca confiar en un campo editable).

        0.4.0: `payload["issuer_public_key"]` sale de payload_json, o sea de una
        fila de la base. Verificar la firma con la clave que viene en el mismo
        registro que se esta auditando no prueba nada: quien pueda escribir la
        base pone su clave y su firma. Para un transparency log el modelo de
        amenaza ES el compromiso del operador, asi que la clave se compara
        contra la del signer vivo (que sale del PEM cifrado, no de la base).
        """
        row = self.get(seal_id)
        if not row:
            return {"found": False, "valid": False, "reason": "seal_id not found"}
        payload = json.loads(row["payload_json"])
        from .signer import verify_issuer
        row_key = str(payload.get("issuer_public_key", "")).lower()
        issuer_is_ours = row_key == self.signer.public_hex.lower()
        sig_ok = issuer_is_ours and verify_issuer(row_key, payload, row["issuer_sig"])
        expected_chain = hashlib.sha256(
            (row["prev_hash"] + hashlib.sha256(canonical(payload)).hexdigest()).encode()
        ).hexdigest()
        chain_ok = expected_chain == row["chain_hash"]
        tsa_state = "absent"
        if row["tsa_token_b64"]:
            # El timestamp RFC 3161 es un REFUERZO opcional. Si no se puede validar
            # (p.ej. falta el cert del TSA), se reporta como "unverified" pero NO
            # invalida un sello con firma de emisor + cadena correctas.
            tsa_state = "valid" if tsa.verify_token(row["tsa_token_b64"], canonical(payload)) \
                        else "unverified"
        valid = sig_ok and chain_ok
        return {"found": True, "valid": valid, "issuer_sig_ok": sig_ok,
                "issuer_is_current_key": issuer_is_ours,
                "signer_verified": bool(
                    isinstance(payload.get("subject"), dict)
                    and payload["subject"].get("verified") is True),
                "chain_link_ok": chain_ok, "rfc3161": tsa_state,
                "payload": payload, "chain_hash": row["chain_hash"]}

    def audit_full_chain(self) -> Dict[str, Any]:
        """Recorre el log entero y valida cada eslabon Y cada firma del emisor.
        Publico: cualquiera puede auditarlo.

        0.4.0: antes solo verificaba eslabones. Un operador que reescribe filas
        recalcula los eslabones sin esfuerzo — es SHA-256 sin clave. Lo que no
        puede falsificar sin la privada del emisor es la firma de cada payload.
        Sin ese chequeo, "el log es auditable" era una afirmacion vacia.
        """
        from .signer import verify_issuer
        conn = db.connect()
        prev = GENESIS
        bad = None
        bad_sig = None
        n = 0
        ours = self.signer.public_hex.lower()
        for row in conn.execute("SELECT * FROM seals ORDER BY n"):
            n += 1
            payload = json.loads(row["payload_json"])
            expected = hashlib.sha256(
                (prev + hashlib.sha256(canonical(payload)).hexdigest()).encode()).hexdigest()
            if row["prev_hash"] != prev or row["chain_hash"] != expected:
                bad = row["n"]
                break
            key = str(payload.get("issuer_public_key", "")).lower()
            if key != ours or not verify_issuer(key, payload, row["issuer_sig"]):
                bad_sig = row["n"]
                break
            prev = row["chain_hash"]
        return {"ok": bad is None and bad_sig is None, "size": n, "head": prev,
                "first_bad_n": bad, "first_bad_signature_n": bad_sig,
                "issuer_public_key": self.signer.public_hex}

    def checkpoint(self) -> Dict[str, Any]:
        """Head del log firmado por el emisor (estilo Rekor STH): permite detectar
        rollback del registro comparando checkpoints en el tiempo."""
        n, head = self._head()
        body = {"v": 1, "size": n, "head": head, "ts": now_iso(),
                "issuer_public_key": self.signer.public_hex}
        return {"checkpoint": body, "issuer_sig": self.signer.sign(body)}


import urllib.parse  # noqa: E402  (usado en activate_license)
