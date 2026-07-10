# Privacy — SURX Registry (hosted)
- **We never receive your data.** Sealing uploads a SHA-256 digest, a count, and the subject
  metadata you choose — not the dataset.
- **What we store:** seal payloads (public), hashed API keys, usage counters, coarse IP
  timestamps for free-key rate limiting, and standard server logs (30-day rotation).
- **Payments** are handled by Lemon Squeezy as merchant of record; we never see card data.
- **No trackers.** The site and verification pages have no analytics scripts or ad pixels.
- **Deletion.** API keys can be revoked on request. Log entries are append-only by design and
  cannot be deleted — that immutability is the product; do not seal what must be erasable.
- Contact: GitHub issues on the repository.
