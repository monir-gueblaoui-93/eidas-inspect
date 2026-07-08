# Progress

Status as of 2026-07-08, end of Day 2 (per BUILD_GUIDE.md). **The
`eidas_inspect_core` validation core is functionally complete**: signature
discovery, integrity/tampering detection, qcStatements classification, EU
Trusted List matching, OCSP/CRL revocation checking, and the overall
document verdict all work end-to-end against a real signed PDF. Day 3 is
the FastAPI layer wrapping this core — see "Next" below.

## Done (Day 1)

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
- **Tests**: 12/12 passing, covering unsigned, signed-without-qcStatements,
  clean QES, clean QSeal, sloppy/ambiguous cert, genuine tampering, LTA
  extension, corrupted PDF, and all three password-protection paths.
  Fixtures are generated in-memory with self-signed certs via pyHanko's own
  signing/timestamping/ASN.1 APIs — no fixture files committed to the repo.
- Verified against one real signed PDF (`Demo document.pdf`, gitignored,
  not committed) — see open item below.

## Done (Day 2): EU Trusted List engine

- **Key discovery — reuse, don't reinvent**: pyHanko 0.35.2 (behind the
  `etsi` and `async-http` extras) already ships a complete ETSI TS 119 612
  engine at `pyhanko.sign.validation.qualified`: LOTL/TL fetching
  (`eutl_fetch`), full XML parsing plus XAdES signature verification of the
  LOTL and every trusted list against bundled EU-published bootstrap certs
  with pivot-following (`eutl_parse`), a `TSPRegistry`/`TSPTrustManager`
  that plugs straight into `pyhanko_certvalidator.ValidationContext`
  (`tsp.py`), and the full ETSI TS 119 612 §5.5.9 qualifier-combination
  algorithm (`QualificationAssessor`, `assess.py`) — the exact same
  algorithm pyHanko's own internal AdES validation flow uses
  (`ades.py::_qualification_analysis` is a one-line call to
  `QualificationAssessor.check_entity_cert_qualified`). Day 2 therefore adds
  a thin caching/staleness/degraded-mode layer plus the glue to
  `verify.py`, not a from-scratch TL parser or XML-dsig implementation.
  `core/pyproject.toml` now depends on `pyhanko[etsi,async-http]>=0.35.2`.
- **`eidas_inspect_core/trust_list/` package**:
  - `registry.py`: `build_snapshot(lotl_xml, fetch, only_territories=None)`
    parses the LOTL once (`eutl_parse.validate_and_parse_lotl`), then fetches
    and verifies each referenced member-state list independently
    (`eutl_parse.trust_list_to_registry`) via an injectable async `fetch`
    callable. One state's failure (bad XML, wrong signing cert, timeout) is
    recorded against that state only in `territory_status` and never aborts
    the others. Returns an immutable `TrustListSnapshot`
    (registry + `lotl_status` + `territory_status` + `refreshed_at`) with an
    `is_degraded(moment)` predicate: true if the LOTL itself failed, the
    snapshot is older than `STALE_AFTER` (48h — one missed 24h refresh cycle
    shouldn't immediately look "unavailable"), or any territory failed this
    cycle.
  - `cache.py`: `TrustListCache` holds the current snapshot and exposes
    `async def refresh()` as a **plain coroutine with no built-in
    scheduling** — per design, the API layer owns the 24h refresh loop
    (FastAPI lifespan task) and can trigger it manually later; core just
    provides the primitive. If the LOTL fetch itself fails, the previous
    good snapshot is kept rather than discarded (it reads as degraded via
    staleness once old enough, but a transient outage doesn't erase
    otherwise-good data).
- **Matching**: identity is `(Subject DN, SubjectPublicKeyInfo)` —
  `pyhanko_certvalidator.authority.AuthorityWithCert`'s own equality, not
  something built for this project. This is more robust than SKI (often
  absent) or subject-name-only matching (inconsistent encoding across
  national PKI systems), and is exactly what PKIX path-building already
  uses. `verify_pdf` builds one `ValidationContext(trust_manager=
  TSPTrustManager(trust_list.registry), allow_fetching=False)` per call
  (revocation checking deliberately excluded — that's Prompt 5) and passes
  it as `signer_validation_context`/`ts_validation_context` into the
  existing `async_validate_pdf_signature`/`async_validate_pdf_timestamp`
  calls, unchanged otherwise. `status.validation_path` is `None` exactly
  when the issuing authority isn't registered in the snapshot at all — this
  works uniformly for CA/QC-issued signature certs (path walks up to a
  registered CA) **and** QTST timestamp certs (the TSA's own leaf cert is
  registered as its own trust anchor, a 0-length path) via the same
  `TSPTrustManager`, confirmed empirically and by inspecting pyHanko's own
  internal AdES code, which uses the identical mechanism for both.
- **Degraded mode, simplified (per explicit product decision)**: no
  cert-to-territory attribution heuristic. The rule is purely: found in the
  registry → assess normally (`TRUSTED`/`UNTRUSTED` per
  `QualificationAssessor`). Not found + all consulted lists fresh →
  confident `UNTRUSTED`. Not found + the snapshot is degraded (LOTL failed,
  stale, or any territory failed this cycle) → `UNAVAILABLE` ("could not be
  confirmed right now"). This never claims untrusted when the list that
  would have vindicated the issuer might simply be missing.
  A Subject-`C=`-country-attribution heuristic (to narrow "degraded" down
  to only the affected territory) was considered and deliberately dropped
  for v1 as an over-engineered, imperfect signal (cross-border TSPs exist);
  worth revisiting as a v2 refinement if false-`UNAVAILABLE` results turn
  out to be common in practice.
- **`TrustChainStatus` gained a 4th value, `UNAVAILABLE`**, distinct from
  `UNKNOWN` ("not checked at all" — the default when `verify_pdf()` is
  called without a `trust_list` snapshot, preserving all Day-1 behavior and
  tests unchanged).
- **Point-in-time correctness**: `QualificationAssessor` is evaluated at
  signing time, not verification time, via `ServiceHistory`-aware lookups —
  a CA validly granted at signing time but later withdrawn doesn't
  retroactively untrust an old document, and vice versa. Guarded further:
  signing time is only trusted as the qualification "moment" when it comes
  from a verified timestamp, not a bare self-reported `/M` claim — otherwise
  a forged signing time could be used to cherry-pick a moment when a
  since-withdrawn CA was still granted; falls back to verification time in
  that case.
- **QTST timestamps get the same trust-chain treatment as CA/QC signatures**,
  both for a signature's embedded RFC 3161 timestamp and for standalone
  `/DocTimeStamp` items. `TimestampQuality.QUALIFIED_TSA` is now actually set
  (previously unused) when the TSA is a granted, cert-qualified QTST
  service; plain-language copy distinguishes "backed by a qualified
  timestamp" from "the signer's own claim" (`CLAIMED_ONLY`) accordingly.
  Note: a genuinely qualified TSA cert needs its own qcStatements
  (`QcCompliance`) for `QualificationAssessor` to credit it — TL membership
  alone isn't sufficient, matching how it treats ordinary signer certs; this
  tripped up an early version of the test fixtures.
- **Tests (`core/tests/test_trust_list.py`)**: no network calls. Real,
  **untrimmed** fixtures committed at `core/tests/fixtures/trust_list/`
  (~640 KB total, well under the ~5 MB budget) — the full real EU LOTL plus
  two small real, untrimmed member-state lists (Malta for CA/QC coverage,
  Iceland for QTST coverage, chosen for small file size among ~30 states).
  These can't be trimmed by hand the way "fixture size" ask implies: TL/LOTL
  XML carries an XAdES signature over the whole document, so deleting most
  entries invalidates it; "trimming" is done at query time instead via
  `build_snapshot(..., only_territories={...})`, not by editing the XML
  bytes. Covers: real LOTL+TL parsing and signature verification, one
  territory failing while another succeeds, a tampered member-state list
  being isolated rather than aborting the whole refresh, a corrupted LOTL
  producing global `UNAVAILABLE`, `TrustListCache` refresh/retention
  behavior, and the full `verify_pdf(..., trust_list=...)` integration
  (granted+qualified → `TRUSTED`; unregistered+fresh → `UNTRUSTED`;
  unregistered+degraded → `UNAVAILABLE`; registered-but-not-qualified →
  `UNTRUSTED`; QTST-backed embedded and standalone timestamps →
  `QUALIFIED_TSA`). 27/27 tests passing. Matching/qualification tests build
  `TSPRegistry` objects directly in Python (no XML) against Day-1's
  self-signed test certs, decoupled from XML-parsing concerns.
- Day-1's shared test fixture (`generate_self_signed_signer`) now adds a
  `KeyUsage` extension (`digital_signature` + `content_commitment`) by
  default — real signing certs always declare this, and it's required for
  `pyhanko_certvalidator` path-building to succeed at all once a
  `ValidationContext` is actually supplied; harmless to the existing 12
  Day-1 tests, which don't assert on certificate extensions.

## Done (Day 2): OCSP/CRL revocation checking

- **`eidas_inspect_core/revocation.py`**: reuses pyhanko_certvalidator's own
  protocol-level helpers (CRLDP/AIA URL extraction, OCSP request/response
  formatting) rather than reimplementing RFC 5280/RFC 6960 — same reuse
  philosophy as the Trusted List engine. What's custom: `TrackedCRLFetcher`
  / `TrackedOCSPFetcher`, minimal `CRLFetcher`/`OCSPFetcher` implementations
  wrapping an **injectable async fetch callable** (`Callable[[str],
  Awaitable[bytes]]` for CRL, `Callable[[str, bytes], Awaitable[bytes]]` for
  OCSP — same shape as the Trusted List module's `Fetcher`), each call
  wrapped in `asyncio.wait_for(timeout=5s)`. `RevocationFetchers` bundles
  both callables + the timeout; defaults to real aiohttp GET/POST, tests
  inject stubs — no real network calls in tests.
- **Why a custom fetcher instead of pyhanko_certvalidator's own
  `AIOHttpFetcherBackend`**: pyhanko_certvalidator's own "soft-fail" mode
  (the mode this project uses, deliberately, so a bad endpoint never fails
  the whole verdict) leaves `revocation_details` at `None` both when the
  cert is genuinely fine **and** when the check couldn't be performed at
  all — it doesn't expose that distinction anywhere. Each tracked fetcher
  records, per certificate, whether a fetch was `attempted` and whether it
  `failed`; `_assess_revocation()` in `verify.py` combines that with
  pyHanko's `status.revocation_details` to tell `GOOD` (checked, clean),
  `REVOKED` (checked, found in a CRL/OCSP response, with the revocation
  date/time in the message), `UNAVAILABLE` (checked, endpoint unreachable
  or timed out), and `NOT_CHECKED` (no CRLDP/AIA on the cert at all, or
  `check_revocation=False`) apart honestly.
- **`verify_pdf` gained `check_revocation: bool = False` and
  `revocation_fetchers: RevocationFetchers | None = None`**.
  `check_revocation` is a no-op unless `trust_list` is also supplied (no
  trust anchor, no path, nothing to walk for revocation either) — matches
  how the feature was scoped. When enabled, the shared `ValidationContext`
  gets `allow_fetching=True` and the tracked fetchers; when disabled (the
  default), behavior is byte-for-byte identical to before this change (no
  `fetchers` param passed at all), so every Day-1/Day-2 TL test still
  passes unmodified.
- **`RevocationStatus` model field**, mirroring `TrustChainStatus`'s
  honest-uncertainty pattern exactly (`GOOD` / `REVOKED` / `UNAVAILABLE` /
  `NOT_CHECKED`). Revocation is deliberately its own field, not folded into
  `IntegrityStatus` — a revoked certificate doesn't change whether the CMS
  digest/signature cryptographically validates (`intact`/`signature_valid`
  stay `True`), it's a separate trust concern, same reasoning as keeping
  `trust_chain_status` apart from integrity.
- **Plain-language integration**: a revoked certificate gets its own
  leading clause in `plain_explanation` (`"The certificate used for this
  signature has been revoked and cannot be relied on."`), ahead of the
  modified-after-signing check, with the revocation date/time in
  `technical_detail`. `UNAVAILABLE` gets a quieter trailing note in the
  intact-signature happy path (`"Its revocation status could not be
  confirmed right now."`); `GOOD`/`NOT_CHECKED` stay silent in
  plain-language (the technical-details drawer always shows the outcome
  regardless).
- **Two-tier CA/leaf test fixtures were required, not optional.** Day 1 and
  Day 2's Trusted-List tests use self-signed leaf certs registered directly
  as their own trust anchor — fine for TL matching, but PKIX revocation
  checking never applies to a trust anchor itself (there's no issuer to
  vouch for it), so a self-signed cert can never be tested as revoked.
  `pdf_fixtures.py` gained `generate_ca()` /
  `generate_ca_issued_signer(...)` (a real CA-issued, non-self-signed leaf
  with CRLDP/AIA extensions) plus `build_crl()` / `build_ocsp_response()`
  (real signed revocation artifacts via `cryptography`'s
  `CertificateRevocationListBuilder` / `x509.ocsp.OCSPResponseBuilder`) to
  make this testable at all.
- **A real signed OCSP response needs its own qcStatements to be credited
  as "qualified" by `QualificationAssessor`** — same subtlety hit with QTST
  certs in the Trusted List work — but that's a `trust_chain_status`
  concern, orthogonal to `revocation_status`; not relevant to revocation
  correctness itself, just noted here since it surfaced again while
  building these fixtures.
- **Known simplification, stated plainly rather than silently shipped**:
  revocation (and the underlying PKIX path validation) is checked as of
  *now* (`ValidationContext`'s default `moment`), not as of signing time,
  unlike `QualificationAssessor`'s point-in-time-correct Trusted List
  check. Properly checking "was this valid and unrevoked at signing time"
  requires a two-pass validation model (discover signing time, then
  re-validate against that moment) that's out of scope for this task;
  today, a cert that's naturally expired since an old-but-valid signing
  would be evaluated against present-day validity/revocation data. Worth
  revisiting alongside the overall verdict logic (`_overall_verdict()`),
  which is the next remaining piece anyway.

## Done (Day 2): Overall verdict logic

- **`_overall_verdict()` is real now**, replacing the Day-1 placeholder
  ("partial whenever any signature is intact"). Every item first gets a
  `VerdictReason` (`CONFIRMED_QUALIFIED` / `BROKEN` / `TAMPERED` / `REVOKED`
  / `NOT_TRUSTED` / `UNCONFIRMED` / `NOT_QUALIFIED`), classified by
  `_classify_verdict_reason()` in strict priority order: a real problem
  (broken → tampered → revoked → confirmed not-trusted) always outranks an
  honest gap (unconfirmed), which always outranks "simply not qualified".
  The document verdict then reduces to two checks over the per-item
  reasons: all `CONFIRMED_QUALIFIED` → `TRUSTED`; all in the "issue" set
  (`BROKEN`/`TAMPERED`/`REVOKED`/`NOT_TRUSTED`) → `NOT_TRUSTED`; anything
  else → `PARTIAL`. `NO_SIGNATURES` is unchanged (early return, never
  reaches this logic).
- **`SignatureItem.verdict_reason`** is a first-class per-item field (not a
  side table), so a UI can render per-item badges/icons and the banner
  explanation without re-deriving any classification rules —
  `VerificationResult.verdict_breakdown` (a `VerdictBreakdown` with
  `total`/`confirmed_qualified`/`issues`/`unconfirmed`/`not_qualified`
  counts) gives the aggregate for the banner itself. Together these satisfy
  "list which items drove the verdict and why" without the UI needing to
  loop and re-count `SignatureItem` facts itself.
- **`VerificationResult.plain_summary`**: the document-level banner string,
  matching the PRD's own phrasing exactly where given ("Fully trusted — all
  N signatures are qualified and intact", "Do not rely on this document").
  For `PARTIAL`, wording is chosen by priority, matching the PRD's own
  mixed-document example (1 qualified+valid, 1 advanced+valid, 1 broken →
  "1 of 3 signatures has issues", silently not counting the advanced one as
  an "issue"): issues present → "N of M {noun} has/have issues"; else if
  anything's unconfirmed → "qualified status could not be confirmed right
  now for N of M {noun}" (deliberately different wording from "issues", per
  the PRD); else (only not-qualified-but-clean items, e.g. an ordinary
  advanced signature) → "N of M {noun} is/are qualified; the rest are valid
  but not qualified" — a third, distinct message this project added beyond
  the two the PRD names, since neither "issues" nor "unconfirmed" honestly
  describes "we know for a fact this isn't qualified, and that's fine."
  `{noun}` is singular/plural-correct and picks the right word
  (signature/seal/timestamp/item) based on the actual item types present.
- **Standalone timestamp items are excluded from the verdict count whenever
  at least one content-bearing signature/seal is present.** This is a
  deliberate design decision, not in the original ask: a PAdES-LTA
  timestamp appended to protect a document's long-term validity is
  infrastructure, not a separate trust decision the user needs to approve.
  Without this exclusion, attaching that protective timestamp to an
  otherwise fully-confirmed qualified signature would demote a `TRUSTED`
  verdict to `PARTIAL` purely because the timestamp itself isn't
  independently confirmed qualified — actively punishing good practice.
  Tested explicitly
  (`test_appended_unconfirmed_lta_timestamp_does_not_demote_a_trusted_signature`).
  If a document consists *only* of timestamps (no signature/seal at all),
  they're all there is to judge, so they're used directly instead.
- **Real-document regression caught by the Demo-document re-check, not by
  synthetic tests**: the "not qualified" fallback wording had a
  singular/plural grammar bug ("0 of 1 signature are qualified") that none
  of the seven hand-built verdict tests exercised, because none of them
  happened to produce a single not-qualified-only item. Fixed, and a
  dedicated regression test
  (`test_advanced_only_signature_is_partial_with_not_qualified_wording`)
  now locks in the exact real-document case (a plain advanced signature,
  nothing wrong, nothing uncertain → "Partially trusted — the signature is
  valid but not qualified."). Worth remembering: re-running against a real
  file surfaces gaps that synthetic combinatorial tests can miss simply by
  not happening to construct that exact shape.
- **First complete end-to-end verdict on a real document**: `Demo
  document.pdf`, verified with a live Trusted List snapshot and
  `check_revocation=True`, now returns `verdict=PARTIAL`,
  `plain_summary="Partially trusted — the signature is valid but not
  qualified."` — correct and honest: the signature is genuinely intact and
  unrevoked, just not qualified (no qcStatements extension at all, per the
  open item below) and its issuer doesn't resolve against Trusted List data
  right now anyway.
- **Removed `VerificationResult.trusted_list_status`** (a Day-1 field that
  was never read or written anywhere — dead weight, not part of this ask,
  but a natural cleanup while touching this exact class). Superseded by the
  real per-item `trust_chain_status` plus the new `verdict_breakdown`.
- **Tests (`core/tests/test_verdict.py`)**: 8 tests, all through the public
  `verify_pdf()` API (no private-function unit tests) —
  confirmed-qualified+good → `TRUSTED`; two co-signed signatures (one
  flagged by the same Day-1 `FORM_FILLING` conservatism used elsewhere,
  giving a real "one clean + one with an issue" document without hand-built
  fixtures) → `PARTIAL` with exact counts; advanced-only → `PARTIAL` with
  "not qualified" wording; qualified-but-degraded-TL → `PARTIAL` with
  "unconfirmed" wording; all-tampered → `NOT_TRUSTED`; revoked-only-item →
  `NOT_TRUSTED`; unsigned → `NO_SIGNATURES`; appended unconfirmed LTA
  timestamp on top of a confirmed signature → still `TRUSTED`. 44/44 tests
  passing across the whole core.

## Key implementation decisions

- **Conservative QUALIFIED policy**: `SignatureItem.level` is only
  QUALIFIED when the certificate's qcStatements clearly and unambiguously
  support it — QcCompliance **and** QcSSCD **and** exactly one of
  esign/eseal in QcType. Any gap (missing statement, both/neither
  esign+eseal, malformed statement content) falls back to ADVANCED, with
  the specific missing piece(s) named in `technical_detail`. Never
  over-claim, per CLAUDE.md.
- **Level is decoupled from Trust chain on purpose**: `level` reflects only
  what the certificate *claims* (Day 1's qcStatements-only classifier,
  untouched since); `trust_chain_status` reflects the real EU Trusted List
  check. The two are only combined at the very end, in
  `_classify_verdict_reason()`/`_overall_verdict()` — every earlier stage
  keeps them as separate, honest facts rather than collapsing them early.
- **Level is also decoupled from integrity, except when integrity is
  broken**: type (signature vs seal) is derived from QcType regardless of
  whether the signature validates, since a seal claim doesn't stop being a
  seal claim just because the crypto broke. But a signature that fails
  integrity (`intact=False` or `signature_valid=False`) is capped at BASIC
  — it can't be credited as "advanced" if it doesn't even hold up
  cryptographically.
- **Reuse pyHanko's own ASN.1 definitions for qcStatements** rather than
  redefining the OID table from scratch (Day 1), and **reuse pyHanko's own
  ETSI TS 119 612 engine wholesale** rather than reimplementing LOTL/TL
  parsing or XML-dsig verification (Day 2) — the same philosophy applied
  twice. What's genuinely custom to this project is the
  classification/fallback logic and the caching/degraded-mode bookkeeping
  layered on top, not the parsing or cryptography underneath.
- **`ModificationLevel` mapping**: pyHanko's diff analysis produces
  `NONE < LTA_UPDATES < FORM_FILLING < ANNOTATIONS < OTHER`. Only `NONE` and
  `LTA_UPDATES` are treated as non-tampering for now; `FORM_FILLING`,
  `ANNOTATIONS`, and `OTHER` all conservatively count as
  `modified_after_signing=True` until each is deliberately handled.

## Open items

- **Verify a real Scrive QES (Global variant) document.** `Demo
  document.pdf` (used for manual spot-checks, gitignored, not committed)
  turned out to carry **no qcStatements extension at all**, so it
  classifies as `ADVANCED` — we have not yet seen a real file produce a
  `QUALIFIED` result end-to-end. Before calling the classifier "done,"
  source a genuinely QES-signed Scrive document (Global/qualified variant)
  and confirm it reports `level=QUALIFIED`, `type=SIGNATURE`, with the
  expected plain-language copy.
- **Subject-`C=` country-attribution heuristic (v2 candidate)**: dropped for
  v1's degraded-mode logic (see above) in favor of a simpler, always-honest
  rule that never narrows "unavailable" down to a specific territory. If
  real-world usage shows too many `UNAVAILABLE` results because one
  irrelevant territory's list is flaky, revisit narrowing this by the
  issuing CA's Subject `C=` attribute — with the caveat that it's an
  imperfect signal (cross-border TSPs exist).
- **Cache refresh scheduling is not yet wired up anywhere.**
  `TrustListCache.refresh()` is a plain coroutine by design; nothing calls
  it yet. The API layer (Day 3+) needs to: call it once at startup (or
  decide to serve degraded until the first refresh completes), then run it
  on a 24h loop (e.g. a FastAPI lifespan background task).
- **Revocation is checked as of verification time, not signing time** — see
  the "known simplification" note above. Not incorrect for a currently-valid
  cert, but not full point-in-time AdES semantics for old signatures either.
- **Still haven't seen a real document exercise the full `TRUSTED` path, or
  the `GOOD`/`REVOKED` revocation states, end-to-end.** `Demo document.pdf`
  (verified live with `check_revocation=True` against the real EU LOTL)
  correctly lands on `PARTIAL` — "the signature is valid but not qualified"
  — because it has no qcStatements extension at all (see the QES open item
  above) and its issuer doesn't resolve against Trusted List data anyway,
  so `revocation_status` stays `NOT_CHECKED` (no path, nothing to walk).
  Every state has been proven correct against real cryptographic fixtures
  in tests; a genuinely QES-signed real document is what's needed to see
  `TRUSTED` fire outside of tests.

## Next: Day 3 per BUILD_GUIDE.md — the API layer

The validation core (`eidas_inspect_core`) is done: `verify_pdf()` returns
a complete, honest `VerificationResult` — signature discovery, integrity,
qcStatements classification, EU Trusted List matching, OCSP/CRL revocation,
and the overall verdict all wired together. Day 3 wraps this in `api/`
(FastAPI), per BUILD_GUIDE.md's Prompt 7:

1. `POST /api/verify` (multipart PDF + optional password, 50 MB cap,
   returns `VerificationResult` as JSON) and `POST /api/report` (PDF report
   generation, reportlab/weasyprint).
2. Own the `TrustListCache` lifecycle: refresh once at startup (or decide
   to serve degraded until the first refresh completes — an explicit open
   question from the Trusted List work), then a 24h refresh loop (FastAPI
   lifespan background task). Core deliberately exposes `refresh()` as a
   bare coroutine for exactly this.
3. Decide the default `check_revocation` behavior for the live API (the
   core defaults it to `False`) and whether/how a request can opt in or out
   given the added latency of live OCSP/CRL fetches.
4. IP-based rate limiting (10/hour, slowapi), anonymous SQLite counters
   (date, count, verdict distribution — nothing else), ephemerality
   enforcement (file bytes in request scope only, filenames/content never
   logged), health endpoint, serving the built frontend as static files.
