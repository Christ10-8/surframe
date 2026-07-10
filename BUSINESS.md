# SURFRAME — negocio en una página (privado, no publicar)

**Producto:** confianza para la cadena de suministro de datos. Librería Apache-2.0 (distribución)
+ registro de transparencia hosteado (revenue). Análogo: Sigstore/cosign, pero para datasets.

**Por qué el registro es el moat:** el código se forkea; un log público con historia, checkpoints
firmados y verificación de terceros, no. Autofirmarse no prueba nada ante terceros — sellar sí.

**Pricing:** Open $0 (verify ilimitado, 10 sellos/mes) · Pro $19 (500) · Business $99 (5.000,
self-hosting support). Costo marginal por sello ≈ 0; infra total ≈ $5–15/mes (Fly.io 1 máquina
+ volumen). Break-even: 1 cliente Pro.

**Canal:** PyPI + GitHub Action (la cuña en CI) + Show HN/Reddit → docs → free key en 10 segundos
→ upgrade cuando el equipo pasa 10 sellos/mes. Sin ventas, sin demos, sin cara: todo self-serve,
cobro vía merchant of record (LS/Paddle) → Payoneer/Wise en USD.

**Métricas día 30 (seguir/estacionar):** ≥500 descargas/mes o ≥50 stars o ≥3 señales de pago
reales (free keys que agotan cupo cuentan doble). Día 60: primer cliente pago o se estaciona.

**Riesgos honestos:** mercado educándose (mitiga: EU AI Act, provenance ML en agenda);
formatos son slow-burn (mitiga: la Action mete el verify en pipelines ajenos); competencia
de Sigstore expandiéndose a modelos (mitiga: nicho dataset-first + columna cifrada, que ellos
no tienen; peor caso: interoperar).
