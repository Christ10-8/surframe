# Self-hosting the registry

```bash
cp .env.example .env   # editá REGISTRY_KEY_PASSPHRASE
docker compose run --rm registry python -m registry.bootstrap   # una sola vez
docker compose up -d
curl localhost:8000/v1/health
```
Backups: `/data` (SQLite + issuer key PEM). The PEM is encrypted; the passphrase lives
only in your env. Losing the passphrase = losing the issuer identity — keep both safe.
Business tier includes hosted→self-hosted migration help.
