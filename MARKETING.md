# Marketing SURFRAME — motor completo (anónimo, US$0 de presupuesto, en inglés)

## Principios (por qué así y no de otra forma)
- **Idioma: inglés en todo lo público.** El comprador de dev-tools lee inglés aunque sea polaco,
  indio o brasileño. Español reduciría el mercado ~20x. El anonimato descarta canales de cara
  (charlas, LinkedIn personal, ventas): compensamos con producto que se promociona solo + contenido.
- **Product-led:** el marketing más barato ya está DENTRO del producto: badges en READMEs
  (cada dataset sellado = un cartel en GitHub), páginas públicas /s/{id} (cada verificación = una
  landing), la GitHub Action (aparece en Marketplace y en los workflows ajenos), y el exit code 1
  que hace que el tool se mencione en postmortems.

## Fase 1 — Launch burst (semana 1)
1. Show HN (martes–jueves, 14:00–16:00 UTC). **Tu única tarea de marketing no delegable:
   responder comentarios las primeras 3 horas.** El post ya está escrito (POSTS.md).
2. r/Python y r/dataengineering el mismo día, separados 2–3 h. Día 2–3: Lobste.rs y dev.to
   (crosspost del post técnico #1 de abajo).
3. PRs a listas awesome: awesome-mlops, awesome-data-engineering, awesome-python,
   awesome-production-machine-learning. Cada una es un backlink permanente con tráfico real.
4. GitHub topics del repo: `data-provenance`, `dataset`, `ed25519`, `supply-chain-security`,
   `mlops`, `data-integrity`, `transparency-log`.

## Fase 2 — Motor de contenido (semanas 2–8, 1 post/semana, los escribo yo)
Posts técnicos que rankean en búsquedas de dolor real (dev.to + GitHub Pages del sitio):
1. "How to sign a dataset (and why checksums aren't enough)"
2. "EU AI Act Article 10: what 'data governance' means for your training sets" ← regulación = tráfico
3. "Detecting training-data tampering in CI with one GitHub Action"
4. "DVC, LakeFS, or signed containers? Data versioning vs data provenance"
5. "I audited my own crypto library. Here's everything that was wrong" ← el post estrella
6. "Column-level encryption: shipping PII inside a queryable file"

## Fase 3 — Ecosistema (mes 2–3)
- Ejemplo oficial con HuggingFace datasets (sellar antes de subir) → PR al foro/docs de HF.
- Notebook Kaggle "verify your competition data" (tu cuenta de Kaggle ya existe y es pertinente).
- Página comparativa honesta vs DVC/lakeFS/Sigstore en el sitio (SEO de comparación = intención
  de compra alta). Interoperar > pelear: "usá DVC para versionar, SURX para probar".
- Responder (sin spamear) preguntas de StackOverflow/Reddit sobre "verify dataset integrity",
  "dataset checksum", "prove data provenance" — 2 por semana, solo donde aporta de verdad.

## Cadencia y medición
- Todo el tracking: PyPI downloads (pypistats), GitHub stars/traffic, seals emitidos (SELECT
  count(*) del registro), free keys que AGOTAN cupo (la métrica de oro: dolor real).
- Sin ads pagas hasta tener 1 cliente orgánico: las ads no arreglan un funnel que no convierte.

## Mensaje único (repetir en todos lados, no improvisar)
"Ship datasets like signed binaries. Verification names the exact file that changed."
