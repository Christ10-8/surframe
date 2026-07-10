# SURFRAME 0.3.0

- **SURX Registry client**: `seal_container_remote` / `check_seal` + CLI `surx seal` /
  `surx check-seal` (triple verificación: contenido vs sellado, emisor offline, registro online;
  funciona sin red). Recibo guardado dentro del contenedor sin romper la firma local.
- **Hardening de estructura zip**: entradas duplicadas, paths absolutos, `..` y backslashes
  rechazados en sign y verify (ataque de parser-differential).
- **`surx demo`**: la historia firmar→envenenar→atrapar en 15 segundos, offline.
- Badges SVG de verificación (`/badge/{seal_id}.svg`) — verde/rojo/gris en vivo.
- Log público paginado (`GET /v1/log`).
- Performance medida: verify ~195 MB/s.
- Baterías: 40 checks (librería) + 28 (registro), todas atacando el fix que prueban.

# SURFRAME 0.2.0 — Security release

## Critico
- **Fix pérdida de datos en cifrado multi-llamada.** En 0.1.5, la segunda llamada a
  `encrypt_columns_in_surx` regeneraba el salt y pisaba `config/crypto.json`, dejando
  indescifrables las columnas de la primera llamada. Ahora reutiliza la clave existente
  (verificando la passphrase primero) y FUSIONA el meta. Idempotente si la columna ya está cifrada.
- **Firma Ed25519 real** (`surframe/signing.py`, nuevo). En 0.1.5 no existía: la "firma" era un
  hash-chain sin clave, reescribible por cualquiera con acceso de escritura.
  - `generate_keypair / save|load_private_key (PEM PKCS8, cifrable at-rest, 0600) / save|load_public_key`
  - `sign_container()`: digest determinístico sobre entradas del zip (excluye `signatures/`,
    `profiles/audit/`, `profiles/usage*`) + chain-heads de auditoría, firmado y guardado como
    `signatures/ed25519.json`.
  - `verify_container()`: reporta exactamente qué entradas cambiaron/faltan/sobran, y valida que
    la auditoría sea *append-only* respecto del head firmado (una cadena recalculada por un
    atacante pasa el check interno pero NO la firma — demostrado en tests).

## Cifrado
- Verificador de passphrase (`check`): passphrase equivocada aborta ANTES de cifrar, y los errores
  distinguen "passphrase incorrecta" (`WrongPassphrase`) de "datos alterados" (`CorruptCiphertext`).
- AD v2 ata `container_id`: un side-car no se puede trasplantar entre contenedores (splice bloqueado).
- Scrypt N=2^17 (OWASP) para contenedores nuevos; los v1 se leen con sus parámetros guardados.
- `decrypt_columns_in_surx()` nuevo: revierte columnas a texto plano y limpia side-cars.
- **Compat total con contenedores cifrados por 0.1.5**: se leen, se extienden y se upgradean
  (meta v2 + verificador) manteniendo AD legacy para los side-cars viejos.

## Auditoría
- `verify_audit_chain()` nuevo: en 0.1.5 la cadena se escribía pero nada la verificaba.
- Firma encadenada ACTIVA por defecto (`SURX_AUDIT_SIGN=0` para apagar).
- Locking entre procesos: dos escritores concurrentes ya no pierden eventos (test: 2 proc × 10
  appends → 21/21 presentes, cadena válida).
- `read_audit_events()` para consumir el log.

## Durabilidad y limpieza
- `fsync` (archivo tmp + directorio) en TODAS las reescrituras atómicas del zip: un corte de
  energía tras el rename ya no puede dejar un contenedor corrupto.
- `__init__.py` reescrito: exports explícitos (los tres bloques PATCH de 0.1.5 se pisaban el
  `__all__` entre sí), BOM eliminado, `__version__` expuesto.
- Eliminado `optimize()` duplicado en `io.py` (código muerto tapado por la segunda definición).
- `datetime.now(timezone.utc)` en vez de `utcnow()` deprecado.

## CLI
- En 0.1.5 el help prometía `write|read|plan|inspect` pero ninguno estaba registrado (solo comandos
  PRO de un módulo no incluido en el paquete). Ahora: `write, read, plan, inspect, validate,
  optimize, snapshot, log, encrypt, decrypt, keygen, sign, verify, audit-verify` + PRO gated.
- `verify` y `audit-verify` devuelven exit code 0/1 (usables en CI).

## Tests
`tests/test_v020.py`: 28/28 PASS. Incluye ataque de reescritura completa de cadena, splice de
side-cars, tamper de chunks byte a byte, compat v1, concurrencia real con procesos.

## Pendiente conocido (no bloqueante)
- `write()` exige columna `country` (limitación del MVP de particionado).
- `license.py` sigue validando solo formato/presencia (el modelo real de licencias es el servicio
  de notarización, no el paquete).
- RFC 3161: vive en el servicio de notarización, no en el paquete (decisión de diseño open-core).

## Particionado genérico (agregado en esta misma release)
- Eliminado el requisito de columna `country`: `write()` funciona sin partición (chunks planos,
  manifest sin particiones) o con `partition_by=["<cualquier_columna>"]`.
- Bloom index con nombre dinámico (`indexes/<col>.bloom.json`); el lector detecta la columna de
  partición desde el propio índice, y `plan()`/pruning funcionan con columnas arbitrarias
  (verificado: 1 de 3 chunks seleccionados filtrando por partición custom).
- Contenedores viejos particionados por `country` siguen 100% compatibles.
- Batería ampliada a 38 checks (T10 sin partición, T11 partición custom + pruning).
