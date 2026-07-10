# Posibles clientes — segmentos, dónde están, y el mensaje para cada uno

## 1. Vendedores de datasets y data marketplaces  ← el mejor fit/pain
Quién: sellers en Datarade, AWS Data Exchange, Snowflake Marketplace; feeds financieros chicos;
vendedores de datos scrapeados/geo/alternativos.
Dolor: el comprador no puede verificar que lo entregado es lo prometido; disputas de integridad.
Pitch: "Your buyers verify every delivery cryptographically — a green badge on the listing."
Dónde encontrarlos: los marketplaces listan a los sellers públicamente; email de producto.

## 2. Vendors de etiquetado y proveedores de training data
Quién: agencias de labeling/anotación (los cientos de Scale-chiquitos), generadores de datos
sintéticos, empresas de RLHF/eval data.
Dolor: el cliente ML pregunta "¿cómo sé que no me cambiaron/contaminaron el batch?"
Pitch: "Deliver every batch sealed; your client's CI verifies before training."

## 3. Equipos de ML con compliance (EU AI Act, auditorías)
Quién: startups de IA vendiendo a Europa, auditores de modelos, AI red-teams, MLOps leads.
Dolor: Art. 10 exige gobernanza de datos de entrenamiento documentada y demostrable.
Pitch: "Auditable training-data provenance in one file. The audit trail is inside the container."

## 4. Consultoras de datos y agencias analytics
Quién: consultoras que entregan datasets/reportes a clientes (Upwork/Toptal top-rated data
consultants son una lista pública).
Dolor: el entregable viaja por mail/drive; meses después, disputa sobre "qué versión era".
Pitch: "Your deliverable, signed. If there's ever a dispute, the log settles it."

## 5. Investigación y open data (tier free → credibilidad, badges, citas)
Quién: publishers de datasets en HuggingFace/Zenodo/Kaggle, labs con papers de reproducibilidad.
Valor: no pagan, pero cada badge en un repo/paper es marketing permanente y SEO académico.

## Outreach (email desde hello@TUDOMINIO — pseudónimo válido, no hace falta cara)
Plantilla corta (segmentos 1–4):

Subject: verify {their product} deliveries cryptographically
---
Hi — saw {specific thing: their listing/service}. Quick question: when you deliver a dataset,
how does the buyer verify it's byte-identical to what they audited?
I built SURFRAME: containers signed with Ed25519 + a public transparency log. Sellers seal each
delivery; buyers (and their CI) verify free — it names the exact file if anything changed.
2-min demo: {link}. Free tier covers a pilot. Worth a look?
---
Cadencia: 5 emails/día máx, personalizados de verdad (una línea específica), un follow-up a los
5 días, nunca dos. 100 contactos/mes ≈ 2–5 conversaciones ≈ 0–2 clientes al principio.
