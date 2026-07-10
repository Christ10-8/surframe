# Copyright 2025 Christ10-8 — Apache-2.0
"""Clave del emisor del registro. Lecciones aplicadas de la auditoria del notary:
la clave privada NUNCA se guarda en texto plano; el servicio se niega a arrancar
sin REGISTRY_KEY_PASSPHRASE; la firma cubre TODO el payload canonico (metadata
incluida), no solo el hash raiz."""
from __future__ import annotations
import json, os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

KEY_PATH_ENV, PASS_ENV = "REGISTRY_KEY_PATH", "REGISTRY_KEY_PASSPHRASE"

def canonical(payload: dict) -> bytes:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()

class IssuerSigner:
    def __init__(self) -> None:
        path = os.environ.get(KEY_PATH_ENV, "issuer_key.pem")
        passphrase = os.environ.get(PASS_ENV)
        if not passphrase:
            raise RuntimeError(f"{PASS_ENV} no seteada: el registro no arranca con clave sin cifrar.")
        if not os.path.exists(path):
            raise RuntimeError(f"No existe {path}. Corre: python -m registry.bootstrap")
        with open(path, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=passphrase.encode())
        if not isinstance(key, Ed25519PrivateKey):
            raise RuntimeError("La clave del emisor debe ser Ed25519.")
        self._key = key
        self.public_hex = key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()

    def sign(self, payload: dict) -> str:
        return self._key.sign(canonical(payload)).hex()

def verify_issuer(public_hex: str, payload: dict, sig_hex: str) -> bool:
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex))
        pub.verify(bytes.fromhex(sig_hex), canonical(payload))
        return True
    except (InvalidSignature, ValueError):
        return False

def bootstrap(path: str, passphrase: str) -> str:
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.BestAvailableEncryption(passphrase.encode()))
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem); f.flush(); os.fsync(f.fileno())
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
