# Lo único que no puedo hacer yo (todo requiere TUS cuentas) — ~60 min total

Todo lo demás ya está construido y probado: librería 0.3.0, registro (24/24 tests),
web, docs, legales, deploy configs, posts. Orden recomendado:

## 1. GitHub — 5 min
```bash
unzip surframe-business-v0.3.0.zip -d surframe && cd surframe
git init -b main && git add -A && git commit -m "surframe 0.3.0 + SURX Registry"
gh repo create Christ10-8/surframe --public --source=. --push
git tag v0.3.0 && git push --tags
```
CI corre solo (38 + 24 checks + demo). LICENSE: Add file → License template → Apache-2.0.

## 2. PyPI — 5 min
Token: pypi.org/manage/account/token/
```bash
pip install twine
TWINE_USERNAME=__token__ TWINE_PASSWORD=pypi-XXX twine upload surframe-0.3.0-py3-none-any.whl
```

## 3. Dominio — 10 min (Namecheap/Porkbun, ~US$10/año, acepta tarjeta)
Sugerencias: surframe.dev · surx.dev · getsurframe.com

## 4. Deploy del registro en Fly.io — 15 min (free tier alcanza)
```bash
curl -L https://fly.io/install.sh | sh && fly auth signup
cd surframe && fly launch --no-deploy --copy-config
fly volumes create registry_data --size 1
fly secrets set REGISTRY_KEY_PASSPHRASE='una-frase-larga-unica'
fly deploy
fly ssh console -C "python -m registry.bootstrap"   # clave del emisor, UNA vez
fly certs add api.TUDOMINIO   # y el CNAME que te indique
```
Después actualizá REGISTRY_BASE_URL en fly.toml a https://api.TUDOMINIO y `fly deploy`.

## 5. Web — 5 min
Cloudflare Pages (gratis): New project → Direct upload → carpeta `site/` → dominio raíz.
(O GitHub Pages sirviendo /site.)

## 6. Lemon Squeezy — 15 min
Cuenta en lemonsqueezy.com (merchant of record: factura él, cobrás por Payoneer/Wise).
Store → 2 productos suscripción: Pro $19, Business $99, con **License Keys activadas**.
Copiá los variant_id de cada uno y:
```bash
fly secrets set REGISTRY_LS_VARIANTS='VARIANTID_PRO:pro,VARIANTID_BIZ:business'
```
En site/index.html reemplazá los dos href="#" (data-ls) por tus links de checkout de LS.
El flujo del cliente: paga → recibe license key por mail de LS →
`curl -X POST https://api.TUDOMINIO/v1/keys/activate -d '{"license_key":"..."}'` → api_key.

## 7. Lanzamiento — 10 min
Pegá launch/POSTS.md (Show HN martes–jueves 14–16 UTC; contestá comentarios las primeras 3 h).
Antes de pegar, buscá-reemplazá el dominio en README/site si elegiste otro.

## Checkpoint día 30
≥500 descargas/mes, ≥50 stars o ≥3 señales de pago → seguimos. Si no → se estaciona.
