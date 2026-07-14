# Technical post — skeleton (English)

**Working titles (pick one):**
1. "The EU AI Act wants your training data documented. Documentation isn't evidence."
2. "Data provenance for the EU AI Act: signed containers, not spreadsheets"
3. "Generating offline-verifiable dataset evidence for AI Act Articles 10–12 (open source)"

**Audience:** ML engineers and tech leads who just got the email from legal.
They know Python; they don't know EU regulation.
**Goal:** reader finishes with a signed container and an evidence pack generated,
and understands why a CSV of metadata is not evidence. The post IS the funnel.
**Length:** 1,500–2,500 words. **Publish date:** on/around 2 August 2026.

---

## 1. Hook (2–3 paragraphs)

- Open with the date: on 2 August 2026 the AI Act's high-risk obligations become applicable.
- The twist: every AI Act post is written by lawyers. This one is for engineers —
  it answers one question: *what concrete technical artifact satisfies the data requirements?*
- Thesis: "documenting your data" without cryptographic integrity is a promise,
  not evidence. Let's build evidence.

## 2. What the regulation actually requires (engineer's translation)

- Art. 10(2) as a table: legal text → what it means technically
  (origin, collection processes, transformations, bias examination, gaps).
- Art. 12: automatic, traceable records over the lifecycle.
- Art. 11 + Annex IV(2)(d): technical documentation includes dataset descriptions.
- ⚠️ Honest disclaimer here: not legal advice, this is the engineering reading.
  (Raises credibility, doesn't lower it.)

## 3. Why the obvious solutions fail as *evidence*

The argumentative core. Walk through the alternatives:

- **READMEs / data cards:** documentation with zero integrity guarantee. Editable after the fact.
- **Warehouse metadata:** mutable, and verifying it means trusting the producer's own
  infrastructure — the one thing an independent audit cannot do.
- **Git LFS / DVC:** versioning yes, but the auditor needs your repo and tooling,
  and the transformation chain isn't sealed.
- **MLOps platforms (MLflow, W&B):** great internal lineage, but the evidence lives in a
  vendor database. Not portable, not offline-verifiable.

Key line of the post: **the difference between documentation and evidence is that
evidence can be verified without trusting whoever produced it.**

## 4. What properties the artifact needs (tool-agnostic)

Define the standard before naming the tool (makes the post citable and honest):

1. Cryptographic integrity — a signature over the exact bytes, not a checksum next to them
2. Immutable audit chain — every transformation hash-linked, chain anchored under the signature
3. Embedded provenance — inside the artifact, not in a separate system
4. Offline third-party verification — open source, one command, exit codes
5. Portable format — survives you switching platforms or going out of business

## 5. Hands-on: building the evidence pack

Copy-pasteable code, real commands (SURFRAME 0.3.0):

```bash
pip install surframe
surx write train.csv trainset.surx
surx keygen
surx sign trainset.surx --key surx_signing.key --signer data-gov
surx export trainset.surx --format ai-act \
  -d "purpose=Training data, credit scoring v3" -d "license=CC-BY-4.0"
```

- Show the pack contents: EVIDENCE.json, REPORT.md, VERIFY.md, ai_act_mapping.md,
  audit_chain/, checksums.txt.
- **The "wow" moment:** flip one byte in the container →
  `surx verify` names the exact chunk, exit 1 →
  `surx export` **refuses to generate the pack**. A tool that cannot produce
  false evidence. (This mirrors the interactive demo on the homepage — link it.)
- Note the self-attested vs trusted-key distinction honestly (from THREAT_MODEL.md):
  the embedded key proves consistency; authorship needs the key via an independent channel.

## 6. Handing it to an auditor (or your legal team)

- What the pack contains and how it maps to Art. 10/11/12 (mini-table).
- The auditor's flow: receive pack → `pip install surframe` → `sha256sum -c` →
  `surx verify`. A mathematical result, not a promise.
- Bridge to product: CI gate with the ready-made GitHub Action
  (`surx-verify-action`) blocks unsigned datasets from reaching training.

## 7. Close

- Recap: evidence ≠ documentation; the right artifact exists and is open source.
- CTA: GitHub repo, /ai-act page, sample evidence pack download.
- Invite feedback, especially from compliance people — generates comments and reach.

---

## Distribution plan (publish day ≈ 2 August)

| Channel | Format | Note |
|---|---|---|
| surframe.dev/blog or GitHub Pages | Full post (EN) | The canonical |
| Hacker News (Show HN) | Link + own first technical comment | 14:00–16:00 UTC, Tue–Thu |
| r/MachineLearning | Link post | Check self-promo rules; frame as the technical problem |
| LinkedIn | 200-word summary + link | AI Act will be in headlines that day — ride the news cycle |
| PyAr (list + Discord) | **Spanish** summary | Soft-launch a few days EARLY for feedback |
| dev.to / Medium | Cross-post with canonical URL | Trailing SEO |

Language rule: **everything in English except PyAr.** The buyers and the news
cycle are English-speaking; PyAr is the friendly pre-flight check.

---

## To do before writing

- [x] `surx export --format ai-act` — built, 18/18 tests passing
- [ ] Publish 0.3.x to PyPI so `pip install surframe` in the post actually gets `export`
- [ ] Pick a public sample dataset for the hands-on
- [ ] Deploy site/ai-act.html and link it from the homepage nav
- [ ] Record the byte-flip demo as a 30s GIF for the post and LinkedIn
