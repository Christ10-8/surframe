"""python -m registry.bootstrap: genera la clave Ed25519 del emisor (cifrada)."""
import os, sys
from .signer import bootstrap, KEY_PATH_ENV, PASS_ENV

if __name__ == "__main__":
    path = os.environ.get(KEY_PATH_ENV, "issuer_key.pem")
    pw = os.environ.get(PASS_ENV)
    if not pw:
        print(f"Seteá {PASS_ENV} primero."); sys.exit(1)
    if os.path.exists(path):
        print(f"{path} ya existe; no lo piso."); sys.exit(1)
    pub = bootstrap(path, pw)
    print(f"Clave del emisor creada: {path} (0600, cifrada)\npublic_key_hex: {pub}")
