# SURX Registry — API

Base URL: your deployment (`REGISTRY_BASE_URL`). All responses JSON unless noted.

## Get a key
```bash
curl -X POST https://REG/v1/keys/free                 # 10 seals/month, 1 key/hour/IP
curl -X POST https://REG/v1/keys/activate \
     -H 'Content-Type: application/json' \
     -d '{"license_key":"<lemon-squeezy-license>"}'   # pro/business
```

## Seal a container
`surx seal file.surx` does this for you. Raw:
```bash
curl -X POST https://REG/v1/seal -H "X-API-Key: surx_..." \
     -H 'Content-Type: application/json' -d '{
  "entries_root": "<64-hex sha256 from signatures/ed25519.json>",
  "entry_count": 11,
  "subject": {"signer":"data-team","public_key":"<hex>","name":"trainset-v3.surx"}
}'
```
Returns `seal_id`, log position `n`, `chain_hash`, `issuer_sig`, `verify_url`.
Errors: 401 bad key · 402 quota exhausted · 422 malformed root.

## Verify
```bash
curl https://REG/v1/verify/sf-00000042-ab12cd34   # JSON report
open https://REG/s/sf-00000042-ab12cd34           # human page
curl https://REG/v1/seals/by-root/<entries_root>  # find seals for a dataset
```

## Audit the log (public, no key)
```bash
curl https://REG/v1/log/audit    # walks every link; reports first bad position
curl https://REG/v1/checkpoint   # issuer-signed head {size, head, ts} — store these
```
Comparing checkpoints over time detects registry rollback. That is the point of the service:
your proof does not depend on trusting the operator's database.
