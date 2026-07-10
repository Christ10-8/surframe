# Terms of Service — SURX Registry (hosted)
1. **Service.** The registry notarizes dataset digests in an append-only public log and serves
   verification. The `surframe` library is Apache-2.0 and independent of these terms.
2. **Accounts & keys.** API keys are bearer secrets; you are responsible for their use. Quotas
   per tier are enforced monthly (UTC).
3. **Public data.** Seal payloads (digests, signer name, dataset name, timestamps) are public
   by design. Do not put secrets in `signer` or `name`. Dataset *contents* are never uploaded.
4. **Acceptable use.** No sealing of digests tied to illegal content; abusive automation may be
   rate-limited or revoked with a refund of the unused period.
5. **Availability & warranty.** Best-effort uptime; the service is provided "as is" without
   warranties. Cryptographic verification can be performed offline and by third parties, which
   is your remedy against operator failure. Liability capped at fees paid in the prior 3 months.
6. **Billing.** Payments are processed by our merchant of record (Lemon Squeezy). Cancel any
   time; access lasts through the paid period.
7. **Changes.** Material changes announced 14 days in advance on the repository.
