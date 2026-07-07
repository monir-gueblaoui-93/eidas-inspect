# Progress

Status as of 2026-07-07, end of Day 1 (per BUILD_GUIDE.md).

## Done

- **`core/` package (`eidas_inspect_core`)**: pure-Python validation core,
  zero web deps, `pyproject.toml` + editable install into a project `.venv`
  (Python 3.12).
- **`verify_pdf(data, password=None) -> VerificationResult`**: signature
  discovery via pyHanko, ByteRange/CMS integrity checking, unsigned PDFs
  (`no-signatures`), corrupted PDFs (`CorruptedPdfError`), password-protected
  PDFs (`PasswordRequiredError` / `IncorrectPasswordError`).
- **Integrity vs. tampering vs. long-term-archival extension**: pyHanko's
  diff analysis (`ModificationLevel`) is mapped to two separate honest
  signals — `modified_after_signing` (real tampering only) and
  `lta_extended` (legitimate PAdES-LTA timestamp/DSS additions). A real
  Scrive-signed document extended for long-term validation is no longer
  misreported as tampered.
- **qcStatements classification (ETSI EN 319 412-5)**:
  `eidas_inspect_core/qc_statements.py` extracts QcCompliance, QcSSCD, and
  QcType from the signer certificate. `SignatureItem.type` distinguishes
  esign (signature) from eseal (seal); `SignatureItem.level` is
  QUALIFIED / ADVANCED / BASIC.
- **Tests**: 12/12 passing (`pytest core/tests`), covering unsigned,
  signed-without-qcStatements, clean QES, clean QSeal, sloppy/ambiguous
  cert, genuine tampering, LTA extension, corrupted PDF, and all three
  password-protection paths. Fixtures are generated in-memory with
  self-signed certs via pyHanko's own signing/timestamping/ASN.1 APIs — no
  fixture files committed to the repo.
- Verified against one real signed PDF (`Demo document.pdf`, gitignored,
  not committed) — see open item below.

## Key implementation decisions

- **Conservative QUALIFIED policy**: `SignatureItem.level` is only
  QUALIFIED when the certificate's qcStatements clearly and unambiguously
  support it — QcCompliance **and** QcSSCD **and** exactly one of
  esign/eseal in QcType. Any gap (missing statement, both/neither
  esign+eseal, malformed statement content) falls back to ADVANCED, with
  the specific missing piece(s) named in `technical_detail`. Never
  over-claim, per CLAUDE.md.
- **Level is decoupled from Trust chain on purpose**: `level` reflects only
  what the certificate *claims*; `trust_chain_status` stays `unknown` until
  the EU Trusted List engine exists. Plain-language copy is explicit about
  this split (e.g. "issuer has not yet been checked against the EU Trusted
  List") so nothing is silently over-promised in the UI later. Final
  "confirmed qualified" verdict logic will combine both fields — that's Day
  2+ work, not yet built.
- **Level is also decoupled from integrity, except when integrity is
  broken**: type (signature vs seal) is derived from QcType regardless of
  whether the signature validates, since a seal claim doesn't stop being a
  seal claim just because the crypto broke. But a signature that fails
  integrity (`intact=False` or `signature_valid=False`) is capped at BASIC
  — it can't be credited as "advanced" if it doesn't even hold up
  cryptographically.
- **Reuse pyHanko's own ASN.1 definitions for qcStatements** rather than
  redefining the OID table from scratch. Importing `pyhanko.sign` has a
  process-wide side effect of registering the qcStatements extension OID
  with asn1crypto's global extension registry (via
  `pyhanko.sign.ades.qualified_asn1`), so a locally-scoped from-scratch
  ASN.1 definition would have fought that global state. Using pyHanko's own
  `get_qc_statements()` sidesteps the issue entirely and avoids duplicating
  a correct, already-tested OID table. What's genuinely custom to this
  project is the classification/fallback logic layered on top, not the
  ASN.1 parsing.
- **`ModificationLevel` mapping**: pyHanko's diff analysis produces
  `NONE < LTA_UPDATES < FORM_FILLING < ANNOTATIONS < OTHER`. Only `NONE` and
  `LTA_UPDATES` are treated as non-tampering for now; `FORM_FILLING`,
  `ANNOTATIONS`, and `OTHER` all conservatively count as
  `modified_after_signing=True` until each is deliberately handled. Note:
  an early tampering fixture that only touched the `/Info` dictionary
  turned out to be classified as `LTA_UPDATES` by pyHanko's default policy
  (metadata-only changes are apparently lenient there) — the real tampering
  fixture mutates the page's `/MediaBox` instead, which reliably yields
  `OTHER`.

## Open items

- **Verify a real Scrive QES (Global variant) document.** `Demo
  document.pdf` (used for manual spot-checks, gitignored, not committed)
  turned out to carry **no qcStatements extension at all**, so it
  classifies as `ADVANCED` — we have not yet seen a real file produce a
  `QUALIFIED` result end-to-end. Before calling the classifier "done,"
  source a genuinely QES-signed Scrive document (Global/qualified variant)
  and confirm it reports `level=QUALIFIED`, `type=SIGNATURE`, with the
  expected plain-language copy.

## Next: Day 2 per BUILD_GUIDE.md

1. **Trusted List engine**: fetch the EU LOTL, resolve member-state TL
   URLs, parse trust service entries (CA/QC + QTST timestamp services),
   in-memory cache with per-list staleness flags and a 24h refresh loop.
   Degraded mode: if a list is unreachable, verification still proceeds and
   `trust_chain_status` reports "could not be confirmed right now" rather
   than failing the whole verdict.
2. **Revocation checking**: OCSP/CRL via pyHanko's validation context, hard
   5s timeout per endpoint; timeout/unreachable → "revocation status
   unavailable" rather than a failed verdict.
3. **Overall verdict logic**: combine `level` + `trust_chain_status` (+
   revocation) into the final trusted / partial / not-trusted /
   no-signatures verdict per PRD section 6, with uncertainty (degraded TL,
   unavailable revocation) lowering confidence honestly rather than
   guessing. `_overall_verdict()` in `verify.py` is currently a placeholder
   (partial whenever any signature is intact) and should be replaced by
   this real logic.
