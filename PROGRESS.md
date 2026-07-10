# Progress

Status as of 2026-07-08, end of Day 3 (per BUILD_GUIDE.md). The
`eidas_inspect_core` validation core (Days 1–2) is functionally complete,
and the FastAPI `api/` layer (Day 3) now wraps it end-to-end: a real curl
against a running server, uploading a real signed PDF, returns the full
JSON verdict, and `/api/report` turns that JSON into a real single-page PDF
report. Day 4+ is the React frontend — see "Next" below.

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

## Done (Day 3): the FastAPI `api/` layer

- **`api/` is a plain top-level package, not pip-installed.** `core/` is a
  real distributable library (own `pyproject.toml`, installed editable);
  `api/` is just the app -- `uvicorn api.main:app` run from the repo root,
  third-party deps in `api/requirements.txt`. `create_app(...)` is the
  factory (module-level `app = create_app()` is what uvicorn runs); tests
  call it with injected, offline dependencies instead.
- **Startup/refresh, per the decision to never block startup**:
  `create_app()`'s FastAPI `lifespan` stores a `TrustListCache` on
  `app.state` and immediately spawns a background `asyncio` task looping
  `await cache.refresh(); await asyncio.sleep(24h)`. A request arriving
  before the first refresh completes reads `TrustListCache.snapshot`, which
  is already `TrustListSnapshot.empty()` (degraded/`UNAVAILABLE`) by
  design from the Trusted List work -- no special-casing needed here, core
  was already built for exactly this. Confirmed live: curling
  `/api/verify` immediately after starting the server hit the API while
  the background refresh was still mid-flight (visible in the server log)
  and still returned a clean, honest 200 response.
- **`check_revocation=True` always, no opt-out param exposed** (per
  explicit decision) -- `Settings.check_revocation` is a fixed `True`, not
  a per-request toggle, keeping the v1 API surface minimal.
- **`verify_pdf()` must never be awaited directly.** It's a synchronous
  function that calls `asyncio.run()` internally (once per signature item)
  -- calling it from a coroutine already running inside an event loop would
  raise `RuntimeError: asyncio.run() cannot be called from a running event
  loop`. The verify route calls it via
  `starlette.concurrency.run_in_threadpool`, which runs it in a plain
  worker thread with no event loop of its own, exactly where nested
  `asyncio.run()` is safe.
- **Ephemerality required raising Starlette's multipart spool
  threshold.** Starlette's multipart parser writes each uploaded file into
  a `SpooledTemporaryFile` that spills to a **real temp file on disk** once
  it exceeds 1 MB by default -- directly at odds with "processed in memory
  only, never written to disk" for any PDF over 1 MB (i.e. almost all of
  them). `MultiPartParser.spool_max_size` isn't exposed as a constructor
  or `Request.form()` parameter in the installed Starlette version, so
  `api/main.py` sets the class attribute directly
  (`MultiPartParser.spool_max_size = settings.max_upload_bytes`) at import
  time, so any upload within our own 50 MB cap can never spill. Layered
  with `MaxBodySizeMiddleware`, which rejects (413) any request whose
  declared `Content-Length` exceeds the cap *before* multipart parsing
  starts at all. Known gap, stated rather than silently shipped: a request
  using chunked transfer encoding without `Content-Length` bypasses the
  middleware and would only be caught by the route's own post-read size
  check, by which point the (raised) spool threshold has already kept it
  in memory up to that point -- acceptable for this project's threat model,
  not bulletproof against a determined adversary.
- **JSON response shape built directly from the core dataclasses** via
  Pydantic v2's `from_attributes=True` (`schemas.to_response()`) rather
  than a hand-maintained parallel field list -- the API's JSON shape can't
  silently drift out of sync with `eidas_inspect_core.models`. `StrEnum`
  values serialize as their plain string values automatically.
- **`/api/report` takes the already-computed JSON result, not the PDF
  file again.** The PRD allows either ("accepts verdict JSON, or
  re-verifies in-request"); accepting JSON avoids re-uploading the file
  and re-asking for its password just to render a summary of a verdict
  already computed, and keeps the endpoint trivially fast (local
  rendering only, not rate-limited). Renders via reportlab
  (`SimpleDocTemplate` flowables, `pageCompression=0` so the rendered text
  -- including the SHA-256 footer -- is verifiably present in the raw PDF
  bytes, not just asserted by trusting reportlab): verdict banner
  (color-coded, plain-language, matching `plain_summary`), a per-item
  table (Type/Level/Who/Integrity/When/Trust chain/Revocation), each
  item's `plain_explanation`, SHA-256 + generation timestamp footer, and
  the PRD's Article-33 disclaimer. One page for the realistic 1–3-signature
  case.
- **Typed errors, one envelope shape**: `{"error": {"code": "...",
  "message": "..."}}` for every failure -- `not_a_pdf` (400, checked via
  `%PDF-` magic bytes before core even runs, so a wrong-file-type upload
  gets the PRD's exact "PDF only for now" copy rather than a generic
  parse failure), `corrupted_pdf` / `password_required` /
  `incorrect_password` (400, straight from core's typed exceptions via
  FastAPI exception handlers), `file_too_large` (413), `rate_limited`
  (429, via slowapi). No raw exception ever reaches the client.
- **Rate limiting (slowapi) is a process-wide `Limiter` singleton**, since
  slowapi's `@limiter.limit(...)` decorator binds to whatever `Limiter`
  object exists at route-*definition* time (module import), not one
  freshly created per `create_app()` call. Fine for production (one
  process, one limiter); for test isolation, an autouse fixture calls
  `limiter.reset()` between every test so one test's quota never bleeds
  into the next.
- **Anonymous counters really are minimal**: one SQLite table,
  `(date, verdict, count)`, upserted per completed verification. No IP, no
  filename, no document content -- matches the PRD's persistent-storage
  line item exactly, not a superset of it.
- **Tests reuse core's own test fixtures rather than duplicating
  them**, since `core` was to stay untouched: `api/tests/conftest.py` adds
  `core/tests` to `sys.path` and imports `pdf_fixtures`/
  `trust_list_fixtures` directly (self-signed/CA-issued certs, CRL/OCSP
  builders, synthetic Trusted List registries) -- the same offline,
  no-real-network approach as core's own suite, just reused rather than
  reinvented. A `TestClient` must be entered as a context manager for
  FastAPI's `lifespan` (and therefore `app.state.trust_list_cache`) to run
  at all -- caught immediately by every test failing with
  `AttributeError: 'State' object has no attribute 'trust_list_cache'` on
  the first run; the `app_factory` fixture now enters/exits the client
  itself so individual tests don't have to remember to.
- **14 API tests, all through `TestClient` against the real HTTP surface**
  (no calling route functions directly): confirmed-qualified → `trusted`
  JSON; plain advanced signature → `partial`; unsigned → `no-signatures`;
  not-a-PDF, corrupted, oversized, password-required, wrong-password,
  correct-password; the 11th verification in an hour → 429 (and
  `/api/health` staying exempt); `/api/report` returning a real,
  parseable single-page PDF with the SHA-256 verifiably present in its
  bytes. 58/58 across `core/` + `api/` combined.
- **Live end-to-end confirmation**: started the server locally, curled
  `/api/verify` with `Demo document.pdf` while the background Trusted
  List refresh was still running, got back the identical honest verdict
  core produced directly (`partial`, "the signature is valid but not
  qualified") as real JSON over HTTP; piped that JSON into `/api/report`
  and got back a real, valid single-page PDF. Server logs contained
  pyHanko's own certificate-chain diagnostics but never the filename,
  password, or document content -- ephemerality held under a real request,
  not just by inspection of the code.

## Done: point-in-time validation (short-lived QES certs)

Triggered by verifying a real QES-signed document (`qes_document.pdf`,
gitignored, never committed): it came back `PARTIAL` instead of the
expected `TRUSTED`. Root cause -- diagnosed by reading
`pyhanko_certvalidator` source, not guessing -- was that the signing
certificate is short-lived (~15 min validity, standard for cloud/remote
QES providers) and had already expired by verification time, so the
library's own validity-period check aborted before revocation checking
ever ran. Fixed as the mainline case, not an edge case: short-lived
certs are how most real QES providers work, so without point-in-time
validation the product could never say `TRUSTED` on real documents.

- **Two-pass model per signature/timestamp item.** Pass 1 (discovery):
  validate with no revocation fetching, no DSS, `moment=now`, purely to
  extract the item's signing time and timestamp quality. Pass 2 (real
  validation): re-validate with a point-in-time `moment` set from pass
  1's result, DSS-aware, revocation fetching enabled. The reference
  moment is the verified embedded timestamp when one exists and isn't
  merely claimed; **the unverified, self-reported `/M` signing time is
  never used to anchor point-in-time validation** -- that would let a
  forged claimed time launder an already-revoked or expired certificate.
  Without a verified timestamp, behavior is unchanged from before this
  feature: checked as of "now," conservatively.
- **Applied uniformly**, per explicit decision, to the main signer cert,
  embedded-timestamp-within-signature sub-checks, and standalone
  `/DocTimeStamp` items alike -- consistency over minimalism.
- **DSS-aware revocation**: before either pass, the document's own
  `/DSS` (PAdES-LTA Document Security Store) is read once via pyHanko's
  `DocumentSecurityStore.read_dss()`. `TrackedCRLFetcher`/
  `TrackedOCSPFetcher` now check the DSS's embedded OCSP responses/CRLs
  for a match *before* attempting any live fetch -- this is what lets an
  already-expired short-lived cert still be confirmed `GOOD` long after
  expiry, from the proof captured at signing time. Matching is by
  certificate serial number / issuer (not a full RFC 6960 CertID hash);
  this is intentionally informational-labeling only and never gates the
  actual revocation decision, which stays entirely
  `pyhanko_certvalidator`'s -- a bad match just fails safe (falls through
  to live fetch, or a signature-verification rejection deeper in the
  library), it can't produce a wrong revocation answer. Full CertID-hash
  matching is the natural v2 upgrade.
- **New field: `RevocationSource` (`embedded` / `live`) on
  `SignatureItem`**, added now rather than later specifically because the
  API had already shipped and nothing yet consumed the string-only
  `technical_detail` prose -- this was the cheapest moment to add a real
  structured field instead of forcing a future frontend to parse prose to
  tell "confirmed via the document's own proof" from "confirmed via a
  live check just now." `None` when nothing answered the revocation
  question at all (`UNAVAILABLE`/`NOT_CHECKED`).
- **Real bug found and fixed along the way**: `pyhanko_certvalidator`'s
  own OCSP retrieval (`RevinfoManager.async_retrieve_ocsps`) prioritizes a
  *live* fetch over pre-loaded/DSS data whenever the cert declares an
  OCSP URL and fetching is enabled -- the opposite of its CRL handling,
  which correctly prefers already-available data first. Found via a test
  that returned `GOOD` where it should have returned `REVOKED` (a DSS-
  embedded revoked response was being ignored in favor of a live fetch in
  the test's world that would have found nothing). Fixed by making the
  tracked fetchers themselves DSS-first, independent of
  `pyhanko_certvalidator`'s internal precedence, so "DSS data wins when
  present" is guaranteed at this project's layer rather than assumed from
  the library's.
- **Test-fixture bug found and fixed**: `build_ocsp_response()` always
  stamped `this_update` at wall-clock "now," so a DSS response built to
  represent "captured at signing time" failed `pyhanko_certvalidator`'s
  own OCSP freshness check (`usable_at()`) when evaluated against a
  signing moment safely in the past. Fixed by adding a `produced_at`
  param threaded through from each test's actual signing moment.
- **6 new tests (`core/tests/test_point_in_time.py`)**: expired
  short-lived cert confirmed `GOOD` via embedded DSS → `TRUSTED`; same via
  live OCSP → `TRUSTED` with `revocation_source=LIVE`; revoked before the
  signing moment → `NOT_TRUSTED`; revoked *after* the signing moment (the
  classic AdES case) → still `TRUSTED`; expired cert with only a claimed
  (unverified) time → stays conservative, `NOT_CHECKED`, never falsely
  `TRUSTED`; a currently-valid cert with DSS data present → unaffected,
  proving this is additive, not a behavior change for the common case.
  64/64 across `core/` + `api/` combined, zero regressions.
- **Plain-language framing as a product feature, not a caveat**: the
  `TRUSTED` explanation for a qualified, trust-chain-confirmed signature
  now reads "...valid and qualified **at the time of signing**" --
  point-in-time correctness stated as the plain-language guarantee it
  actually is.
- **Acceptance test**: re-ran `qes_document.pdf` live end-to-end (real
  Trusted List refresh, `check_revocation=True`). Result: `verdict:
  trusted`, `level: qualified`, `trust_chain_status: trusted`,
  `revocation_status: good`, `revocation_source: embedded`,
  `verdict_reason: confirmed_qualified`, plain explanation ending "...
  valid and qualified at the time of signing." `revocation_source=embedded`
  is the proof this is genuine and not a lucky live-fetch success: the
  document's own OCSP proof, captured at signing time, is what confirmed
  a certificate that had long since expired by verification time.

## Done (Day 4): the React frontend (`web/`)

Built against the already-shipped `api/` layer: `POST /api/verify`
(multipart + optional password → full JSON verdict), `POST /api/report`
(JSON → PDF), typed error envelope, rate limiting. Plain Vite + React,
no router (single-page state machine), no UI framework or icon library --
hand-rolled `currentColor` SVG icons in `src/icons.jsx` to keep the bundle
small and the visual language consistent.

- **Design tokens (`src/theme.css`)**: warm cream background + near-black
  ink, a plum/berry brand accent for all interactive elements (buttons,
  links, focus rings), and a green/amber/red/taupe traffic-light set tuned
  to sit naturally against that base rather than the more common
  blue-on-white SaaS look -- and deliberately not Scrive's green-dominant
  palette. Type pairing is Fraunces (a characterful serif with real
  personality at display sizes) for headlines against Manrope (a rounded,
  friendly geometric sans) for everything functional -- serif-for-voice /
  sans-for-interface, distinct from the single-utilitarian-sans look of
  the EU DSS demo or Adobe Reader. Full token list -- colors, spacing
  scale, radii, shadows -- lives in that one file for easy iteration.
- **State machine in `App.jsx`**: `landing → (password) → verifying →
  result`, driven by explicit phase state rather than a router. The
  upload handler runs client-side pre-checks (PDF-only, 50 MB) before
  ever calling the API, matching the API's own `not_a_pdf`/`file_too_large`
  errors so both layers agree on the same limits.
- **Verifying animation is paced independently of the real request.**
  `/api/verify` is synchronous and reports no real progress, so
  `VerifyingAnimation` advances through the five real stages ("Reading
  document" → "Finding signatures" → "Checking integrity" → "Consulting
  EU Trusted Lists" → "Checking revocation status") on its own timer.
  Its `isComplete` flag is read via a ref inside a self-scheduling
  `setTimeout` loop (not as a `useEffect` dependency) specifically so the
  sequence *continues* from wherever it is and switches to a faster pace
  when the real response lands, rather than restarting from step 0 --
  a real bug caught and fixed during this build, not a hypothetical one.
  If the API is slower than the animation, it holds and pulses on the
  last stage rather than looking stuck or racing ahead of the truth.
- **Six-field signature cards, plus a seventh.** `Type`/`Level`/`Who`/
  `Integrity`/`When`/`Trust chain` per the PRD, plus a `Revocation` row
  that renders `revocation_source` directly (`embedded` vs `live`) rather
  than parsing it out of `technical_detail` prose -- exactly the
  consumption path that field was added for during the point-in-time
  validation work. `lta_extended` renders as a positive "Intact --
  extended for long-term validation" line, never a warning. A `verify_pdf`
  `timestamp_quality` of `unknown` (a cryptographically verified embedded
  timestamp whose TSA isn't confirmed qualified -- distinct from
  `claimed_only`, an unverified self-reported time) gets its own distinct
  wording rather than being collapsed into either extreme.
  `src/itemPresentation.js` holds this raw-JSON-to-plain-language mapping
  as pure functions, kept separate from the card markup.
- **PARTIAL banner distinguishes its three wording buckets** (issues /
  unconfirmed / valid-but-not-qualified) both in text -- `plain_summary`
  already carries the right sentence for each per the verdict-logic work
  -- and visually, via `verdict_breakdown` picking a different icon per
  bucket (warning triangle for real issues, info circle for an honest
  unconfirmed gap, check circle for "simply not qualified").
- **Educational glossary (`Term` component + `src/glossary.js`)**:
  Qualified, QES, QSeal, EU Trusted List, and qualified timestamp, each
  wired inline wherever the term appears (the Level field, the Trust
  chain field, the When field). Implemented as a click-to-expand block
  that pushes into normal document flow directly under the trigger word,
  not an absolutely-positioned popover -- avoids all mobile
  viewport-clipping edge cases that come with tooltip positioning.
- **Unsigned state is neutral, not an error**: explains that a scanned
  handwritten signature isn't a digital signature, with vendor-neutral
  signing suggestions, per PRD's explicit "must not feel like an error"
  requirement.
- **Report download** wired to `POST /api/report`, converting the
  returned blob to a same-tab download via a throwaway object URL,
  revoked immediately after the click to avoid leaking memory.
- **Vite dev proxy** (`vite.config.js`) forwards `/api` to
  `localhost:8000`, so the dev frontend and a locally running API share
  an origin with no CORS configuration needed -- and none is needed in
  production either, once the built frontend is served from `api/static/`
  (Day 6).
- **Verified against the live local API**, not just by inspection:
  `Demo document.pdf` → `partial`, "the signature is valid but not
  qualified" (Advanced-only cert, exactly the PRD's PARTIAL path);
  `qes_document.pdf` → still `trusted` with `revocation_source: embedded`,
  confirming the point-in-time validation work renders correctly end to
  end through this new layer; unsigned PDF → `no-signatures`; not-a-PDF,
  corrupted PDF, missing/wrong/correct password → each error code exactly
  matches what `App.jsx` branches on; `/api/report` round-tripped a real
  result into a real, valid single-page PDF. All done via direct API
  calls through the Vite proxy (matching exactly what the React code
  consumes) plus a clean `vite build` and a clean `oxlint` pass -- **not
  yet visually confirmed in an actual browser**: this environment has no
  headless browser available, and an attempted throwaway Playwright
  Chromium install stalled twice at 90% on a slow connection and was
  abandoned. Stated plainly rather than claimed: the data layer, error
  handling, and every code path are verified; the actual pixels have not
  been.
- **Rate-limit care while testing**: manual `curl` testing against the
  live API consumes the same 10/hour-per-IP quota real users get. The API
  process was restarted partway through this session specifically to
  reset the in-memory counter before handing off for manual browser
  testing, to avoid accidentally locking out that first real test.

## Done (Day 6): production build and Railway deployment

Root `Dockerfile`, `.dockerignore`, `railway.json`, and `DEPLOY.md` added.
No container runtime existed on this machine at all (no Docker, Podman, or
Colima) -- installed Colima + the Docker CLI via Homebrew specifically to
build and run the image for real rather than reviewing the Dockerfile
statically and hoping. Everything below was verified against an actual
running container, not just inspected.

- **Multi-stage Dockerfile**: stage 1 (`node:22-slim`) runs `npm ci` +
  `npm run build` for the frontend; stage 2 (`python:3.12-slim`) installs
  `core/` and `api/`'s *production-only* requirements, copies the app
  code, and copies stage 1's `dist/` straight into `api/static/` --
  exactly the directory FastAPI already serves as static files, so no new
  serving logic was needed. Final image: **~89 MB** of actual content.
- **Split `api/requirements.txt`**: the old file mixed prod and test-only
  deps (`httpx`, `pytest`) with a comment marking which was which --
  formalized that into `api/requirements-dev.txt` (`-r requirements.txt`
  plus the test deps). The Dockerfile installs only the prod file;
  confirmed by shelling into the built image and checking that `import
  pytest` / `import httpx` both fail. `CLAUDE.md`'s setup command updated
  to point at `requirements-dev.txt` for local dev.
- **`.dockerignore`** excludes `.venv/`, `web/node_modules/`, `web/dist/`,
  `.git/`, `core/tests/`, `api/tests/`, `api/data/`, and -- explicitly,
  redundantly, on purpose given what's at stake -- `qes_document.pdf`,
  `Demo document.pdf`, and a blanket `*.pdf`. Confirmed by shelling into
  the built image and running `find / -iname '*.pdf'`: zero results.
- **Counters DB path**: default changed from a path inside the repo to
  `/data/counters.db` (a Railway volume mount target), with a new
  `api/startup.resolve_counters_db_path()` that probes writability at
  startup and falls back to `/tmp/eidas-inspect-counters.db` with a
  logged warning if the configured path can't be created/written --
  wired into `create_app()`'s lifespan and threaded through to the
  `/api/verify` route via `app.state.counters_db_path`. The route call
  is additionally wrapped in `try`/`except` (defense in depth on top of
  the startup check): a full disk or a race between the startup probe
  and an actual write can never fail a verification that otherwise
  succeeded. Verified three ways: locally on macOS (`/data` is
  unwritable there, triggering the real fallback path and warning log);
  in a plain `docker run` with no volume (root fs is writable by
  default, so `/data/counters.db` is used directly -- ephemeral but
  harmless, exactly the "works without a volume, just doesn't persist"
  behavior `DEPLOY.md` documents); and in a `docker run --tmpfs
  /data:ro` container simulating a genuinely unwritable mount, which
  correctly logged the fallback warning and still returned `200` on
  `/api/verify`.
- **`/api/health` now reports Trusted List freshness**:
  `{"status": "ok", "trust_list": {"status": "fresh"|"stale"|"refreshing",
  "refreshed_at": "..."}}`. Reuses `TrustListSnapshot.is_degraded()` --
  the same definition already governing per-verification
  `trust_chain_status=UNAVAILABLE` -- rather than inventing a second
  notion of freshness. `refreshed_at is None` (no refresh has completed
  yet) reads as `"refreshing"`. Tests added for all three states.
  **Real-world note surfaced during testing**: this reads `"stale"` quite
  often in practice, because *any* single EU member state's trusted-list
  fetch failing this cycle marks the whole snapshot degraded -- confirmed
  live both locally and inside the container (EE/IE/CZ/IT entries
  routinely fail with 403s, TLS issues, or unparseable extensions). This
  is documented in `DEPLOY.md` as expected, not a sign of breakage.
- **`--forwarded-allow-ips='*'`** added to the production uvicorn command.
  Without it, uvicorn's proxy-header trust (on by default) only trusts
  `X-Forwarded-For` from `127.0.0.1` -- behind Railway's proxy, every
  request would otherwise appear to originate from the same internal
  proxy IP, putting every real user in the *same* rate-limit bucket. Not
  explicitly requested, but a real correctness bug for a per-IP rate
  limiter running behind any reverse proxy, so fixed as part of the
  production hardening pass.
- **Logs to stdout explicitly** (`logging.basicConfig`'s default is
  stderr) -- Railway and most container platforms treat stdout as the
  primary stream. Grepped every `logger.*`/`logging.*` call site across
  `api/` and `core/` (four total) to re-confirm none logs a filename,
  password, or document content -- all four are either sanitized
  Trusted-List-fetch diagnostics or the new counters-fallback warning,
  none of which can contain user data.
- **CORS**: confirmed no `CORSMiddleware` exists anywhere in `api/` --
  correct and intentional, since the built frontend is served from the
  same FastAPI app/origin in production. Nothing to add.
- **`railway.json`**: pins the Dockerfile builder explicitly and points
  Railway's healthcheck at `/api/health` (30s timeout, restart-on-failure
  up to 3 retries).
- **Full local container verification** (all against the actual running
  image, via `docker run` + `curl`, not just code review): frontend HTML
  served from `/`; `Demo document.pdf` → `partial` end-to-end;
  `qes_document.pdf` → still `trusted` with `revocation_source: embedded`
  inside the container; unsigned PDF → `no-signatures`; not-a-PDF →
  `not_a_pdf` error envelope; `/api/report` round-tripped a real,
  parseable PDF. Full `pytest core/tests api/tests` (68/68) re-run and
  green after every code change in this phase.

**Not done by this work**: nothing was actually deployed to Railway --
per instructions, only local verification was performed. `DEPLOY.md` has
the exact one-time setup steps (new project from GitHub, volume at
`/data`, generate domain) and the ongoing deploy flow (`git push` =
redeploy) for the user to click through themselves.

## Done: verdict card UX improvements (issuer prominence, certificate details, Trusted List link)

Triggered by real user feedback on the deployed card design: the issuing
TSP was buried as a "Who" sub-line, there was no structured view of the
certificate itself, and there was no way for a user to independently
verify a trust match against the EU's own published data. All three
required new structured facts from core, not just UI rearrangement --
`SignatureItem` gained two new fields.

- **New core model: `CertificateDetails`** (`subject_common_name`,
  `subject_organization`, `issuer_common_name`, `issuer_organization`,
  `valid_from`, `valid_until`, `serial_number`) -- read straight from the
  signing certificate's X.509 fields in a new `_certificate_details()`
  helper in `verify.py`. `serial_number` is hex, colon-separated (the
  `openssl x509 -serial` convention). Populated on every `SignatureItem`
  that got far enough to have a certificate at all (`None` only for the
  rare unreadable-item case) -- confirmed on `qes_document.pdf` this
  correctly surfaces its ~15-minute validity window
  (`09:47:20Z`–`10:02:20Z`), the exact short-lived-cert story this
  project is built around.
- **New core model: `TrustMatch`** (`territory`, `territory_name`,
  `trust_service_name`, `tl_location_url`) -- only populated when
  `trust_chain_status` is `TRUSTED`. This required real new tracking in
  the Trusted List module, not just plumbing: `TSPRegistry` (pyHanko's)
  is deliberately a flat, territory-agnostic cert/service index with no
  concept of "which member state's list did this come from" -- correct
  for path-building, useless for attribution. `build_snapshot()` now
  parses each territory's TL into its own throwaway registry first,
  registers those same service objects into the shared registry
  afterwards (preserving object identity end-to-end, confirmed
  experimentally before relying on it), and records
  `id(service_definition) -> ServiceTerritory` in a new side-table on
  `TrustListSnapshot` (`service_territories`, keyed by object identity
  since these are the literal objects a later
  `QualificationResult.service_definition` will point back to -- never
  copied anywhere in pyHanko's own code, verified by reading
  `QualificationAssessor.check_entity_cert_qualified`). A new
  `_TERRITORY_NAMES` table maps the EU eIDAS scheme's territory codes
  (not quite ISO 3166-1 -- notably `EL` for Greece, `UK` for the United
  Kingdom) to human names, covering all 32 codes the real LOTL fixture
  references.
- **The eIDAS Dashboard TL-browser URL was verified live, not guessed.**
  The user's suggested `eidas.ec.europa.eu/efda/tl-browser` domain
  turned out correct (confirmed via a redirect chain from the legacy
  `webgate.ec.europa.eu/tl-browser`), but the *deep-link* pattern for a
  specific territory required a web search past the Angular SPA's
  client-rendered shell (which returns no server-side content to fetch):
  confirmed via indexed page titles ("Trusted List France - eIDAS
  Dashboard" etc.) to be
  `eidas.ec.europa.eu/efda/trust-services/browse/eidas/tls/tl/{territory}`.
  Live-tested against `qes_document.pdf`'s real match: territory `NO`
  (Norway), URL `.../tl/NO`.
- **UI: issuer promoted to its own prominent row** (`IssuerRow` in
  `SignatureCard.jsx`), replacing the old buried "Certificate issued by"
  sub-line under "Who". Pairs with a small, deliberately subtle "On the
  EU Trusted List" badge -- styled as a soft neutral well, not a colored
  banner, so it doesn't compete with the main verdict banner per the
  explicit ask. Gated on `verdict_reason === 'confirmed_qualified'`
  rather than `level === 'qualified'` alone: a standalone qualified
  timestamp expresses its "qualified" fact through `timestamp_quality`,
  not `level` (which stays `UNKNOWN` for timestamps), so gating on level
  would have silently never shown the affirmation for a qualified
  timestamp item -- caught by tracing the card's own existing badge logic
  rather than assumed.
- **UI: new "Certificate" section** (`CertificateSection.jsx`), visible
  by default (no extra expand/collapse -- reusing the existing technical
  drawer for the one properly-technical fact instead of adding a second
  disclosure control): Subject and Issuer each lead with whichever name
  component means more for the item's type (organization for a seal,
  person for a signature/timestamp), with the other shown parenthetically
  only when present and different; Valid from/until in the same
  human-readable + time-of-day format used elsewhere (necessary, not
  decorative -- a date-only format would show identical dates for a
  same-day short-lived cert). Serial number moved into the existing
  technical-details drawer, alongside the trusted list's raw XML URL when
  a trust match exists.
- **UI: "Verify it yourself" link**, shown only alongside the Trusted
  List affirmation and only when a `trust_match` is actually present
  (never links into a list that didn't corroborate the match, per the
  explicit requirement) -- opens in a new tab, marked with an external-link
  icon plus a visually-hidden "(opens in a new tab)" for screen readers.
- **Tests**: 4 new core tests (territory tracking against the real LOTL
  fixture, `trust_match` present/absent, certificate subject-vs-issuer
  distinction) plus 2 new API tests asserting the JSON envelope. One
  genuine flake caught and fixed during this work: an early version of
  the territory-tracking test assumed Malta's TL registers only
  CA-type services and Iceland's only QTST-type, and grabbed "the first"
  authority from an unordered Python `set` -- true often enough to pass
  in isolation, false often enough (Iceland's TL also registers a CA-type
  service) to fail under full-suite hash-ordering. Fixed by asserting
  over every registered service rather than trusting iteration order.
  74/74 across `core/` + `api/`, run three times back to back to confirm
  the flake was actually gone, not just not-hit that time.
- **Acceptance**: re-verified `qes_document.pdf` live against the real
  EU Trusted List -- full JSON shown to the user, `certificate` and
  `trust_match` populated exactly as designed, before commit.

## Feature, complete for now: KSI (Guardtime) seal support

Support for verifying KSI-sealed documents (Guardtime Keyless Signature
Infrastructure -- the sealing method Scrive and others used historically,
before switching to PAdES). Researched first, plan approved, then
implemented checkpoint by checkpoint per that approval, through
detection, real verification tiers, real-sample validation, and the UI.

**Feature freeze called after this**: no new verification capabilities
until the "Next for this feature" items below are picked back up
deliberately -- the two open items are both either external-dependency
work (the GlobalSign trust-chain gap) or need a real pre-boundary
sample that doesn't exist yet, so there's nothing left to build blind.
Next up is Day 7 polish.

### Research findings (full detail: session transcript; summarized here)

- **Embedding, confirmed via Guardtime's own official
  `ksi-pdf-verifier` source (Apache-2.0) and byte-level inspection of
  their own demo file**: a KSI seal is a PDF AcroForm field, `/Subtype
  /Widget`, whose field type is the **non-standard literal `/FT /KSI`**
  (not `/Sig`) -- exactly why pyHanko's `collect_embedded_signatures()`
  (filters strictly on `/FT /Sig`) never sees one, and why a KSI-sealed
  document used to silently report `NO_SIGNATURES`. The field's `/V`
  points to a dictionary with `/Contents <hex>` (the raw TLV-encoded KSI
  token), `/Filter /GT.KSI`, and a standard 4-element `/ByteRange`.
- **Tooling**: no viable Python-native KSI library exists.
  `guardtime/ksi-python` (a thin C-binding wrapper) is explicitly
  "Experimental, non-supported" per its own README, last released 2018,
  and its GitHub source has since been deleted. The official C SDK
  (`libksi`) and CLI (`ksi-tool`) are Apache-2.0 and actively maintained
  (pushed 2024-07), with ready Debian/RHEL packages via Guardtime's own
  APT/YUM repos. **Decision: subprocess to `ksi-tool` inside the
  container for actual cryptographic verification** -- same philosophy as
  never reimplementing PAdES/CMS ourselves and instead trusting pyHanko;
  we do the PDF-container parsing (find the field, extract
  `/ByteRange`+`/Contents`, hash), `ksi-tool` does all KSI-specific
  verification.
- **Verification tiers**, confirmed via Guardtime's own CLI man page and
  SDK tutorial: **internal** (hash-chain shape only, always possible,
  no external dependency) -> **key-based** (anonymous -- needs only the
  publicly downloadable publications file, PKI-backed by Guardtime's
  calendar-signing cert; a freshly-sealed *unextended* signature normally
  already carries what this needs) -> **publication-based**/"extended"
  (anonymous once extended -- verifiable against a publicly witnessed
  record, no trust in any single party's key -- our strongest case) ->
  **calendar-based** (requires a live, authenticated Guardtime account --
  out of scope for an anonymous public tool).
- **Critical finding, verified two independent ways**: Guardtime's own
  EU eIDAS qualification (as a QTST on Estonia's trusted list) **was
  withdrawn on 2025-06-12** -- confirmed both by Guardtime's own blog
  announcement and by fetching the live LOTL/Estonia TL ourselves and
  finding every one of Guardtime's 22 historical service entries at
  `status=withdrawn`. **No EU Trusted List affirmation is honest for KSI
  seals verified today**, regardless of extension status -- this
  overturns the premise of an (now-stale) old Scrive blog post claiming
  otherwise. Seals aggregated *before* the withdrawal date can still
  honestly note they were qualified at the time (point-in-time wording,
  this product's whole thesis) -- deriving that boundary from trusted-list
  data turned out to need a small, targeted addition rather than reusing
  `TrustListSnapshot`/`TSPRegistry` as-is: pyHanko's registry only
  materializes *currently-granted* services (by design, for path-building
  against certificates), and Guardtime's most recent (now-withdrawn)
  history entry also lacks a bundled X.509 certificate, so it's invisible
  to `known_timestamp_authorities` even when queried at a past moment.
  The raw per-territory TL XML pyHanko already parses does carry the
  needed `StatusStartingTime` transitions (confirmed by direct
  inspection); the fix is to read them via pyHanko's lower-level
  `eutl_parse.read_qualified_service_definitions()` generator directly,
  filtered by provider name, bypassing the cert-keyed registry index
  entirely for this one lookup -- deferred to the point-in-time-wording
  checkpoint, not yet implemented.

### Done: checkpoint 1 -- detection (the live bug fix)

- **New discovery path** (`_collect_ksi_seals` in `verify.py`): walks
  `/AcroForm/Fields` for `/FT /KSI` entries via pyHanko's own
  `pyhanko.sign.fields.enumerate_fields_in(..., target_field_type='/KSI')`
  -- reusing pyHanko's battle-tested field-walking (handles `/Kids`
  recursion, circular-reference detection, inheritable `/FT`) with a
  different target type, rather than reimplementing AcroForm traversal.
  Runs alongside (never instead of) `collect_embedded_signatures()`;
  `verify_pdf()` only returns `NO_SIGNATURES` when *both* come back empty.
- **New model**: `SignatureType.KSI_SEAL` and `KsiVerificationTier`
  (`NOT_VERIFIED` / `BROKEN` / `INTERNAL_ONLY` / `CALENDAR_VERIFIED` /
  `PUBLICATION_VERIFIED` -- calendar-based/live-account verification
  deliberately has no tier at all, per the tooling decision above). Three
  new `ksi_*`-prefixed optional fields bolted onto the existing
  `SignatureItem` (`ksi_verification_tier`, `ksi_aggregation_time`,
  `ksi_identity_chain`) rather than a parallel dataclass -- reuses the
  existing card UI for v1; a code comment on `SignatureItem` flags a
  dedicated `KSISealItem` (or tagged union) as the v2 refactor if KSI
  grows more fields.
- **`_build_ksi_seal_item()`**: structural detection and parsing only --
  confirms `/Contents`/`/ByteRange` are present and well-formed, computes
  `fully_covered` honestly from whether `/ByteRange` reaches EOF. No
  cryptographic verification yet, so every structurally sound seal gets
  `ksi_verification_tier=NOT_VERIFIED`, mapped to
  `VerdictReason.UNCONFIRMED` -- not because it fits that reason's usual
  TL/revocation-gap story, but because its actual banner text ("qualified
  status could not be confirmed right now") is honest for "not yet
  checked", where `NOT_QUALIFIED`'s text ("valid but not qualified")
  would overclaim a validity never actually checked.
  `IntegrityStatus.intact`/`.signature_valid` (plain bools, no "unknown"
  state available) are set `True` only because `False` would read as "a
  problem was found" rather than "unknown" -- documented in code as a
  real tension, with the instruction that any future UI work must drive
  KSI tone/badges from `ksi_verification_tier`, never from these two
  fields.
- **Test fixture**: `build_ksi_sealed_pdf()` in `pdf_fixtures.py`, built
  from the confirmed real structure (not guessed). Found and fixed a real
  bug while writing it: naively overwriting `/AcroForm` wholesale silently
  dropped an existing signature's own field entry when the two coexist in
  one document; fixed to merge into the existing `/AcroForm`/`/Fields`,
  discovering along the way that `/AcroForm` is commonly its own indirect
  object (as pyHanko's signer writes it) requiring an explicit
  `mark_update` on that object, not just `update_root()`.
- **5 new core tests + 1 new API test**: detection fixes `NO_SIGNATURES`;
  item fields are as documented; a malformed `/FT /KSI` field (missing
  `/ByteRange`) is reported `BROKEN`, not silently ignored or
  misreported as fine; a KSI seal coexists correctly alongside an
  ordinary signature in the same document (both items present); the
  plain-unsigned-PDF case is unaffected (regression guard). API schema
  updated so the three new `ksi_*` fields round-trip through the JSON
  envelope, keeping the "schema mirrors core exactly" contract intact.
  80/80 across `core/` + `api/`.

### Done: checkpoint 2 -- verification tiers via `ksi-tool` subprocess

- **New module `eidas_inspect_core.ksi_tool`**: `KsiToolRunner`, an
  injectable subprocess boundary (mirrors `RevocationFetchers`' DI
  pattern -- tests inject a stub `invoke`, never shell out to a real
  binary). `verify_internal`/`verify_publication_based` both always bind
  to this specific document's hash via `-f` (never a bare, document-free
  `--ver-int` check) -- deliberate: without that binding, a genuine
  KSI token pasted onto an unrelated document would still read as
  "internally consistent", true but actively misleading for a
  per-document seal verifier.
- **Output parsing confirmed empirically, not guessed**: installed
  `ksi-tool` locally (Homebrew's official `guardtime/ksi` tap, after
  inspecting the formula before trusting a third-party tap) specifically
  to run the real binary against a real signature before writing any
  parsing code. Extracted the actual KSI token + `/ByteRange`-covered
  bytes from Guardtime's own demo file
  (`github.com/guardtime/ksi-pdf-verifier`'s `demo/signed.pdf`, Apache-2.0)
  and ran real `--dump` output through internal, tampered, and
  publication-based checks. Confirmed: the "Final result:" line uses
  exactly three tokens (`OK`, `NA`, `FAIL` -- not "FAILED", despite the
  man page's prose), identity metadata and aggregation ("signing") time
  are both present in a clean, regex-parseable form. These exact
  transcripts are now committed as canned fixtures in
  `test_ksi_tool.py` and as real binary files in
  `core/tests/fixtures/ksi/` (with a README noting provenance).
- **Tier computation wired into `_build_ksi_seal_item`**: internal check
  first; `FAIL` -> `BROKEN`, anything but `OK` -> `NOT_VERIFIED` (no base
  to build on). If internal holds, publication-based check follows:
  `OK` -> `PUBLICATION_VERIFIED`, `FAIL` -> `BROKEN` (a real mismatch,
  never silently downgraded to a milder tier), otherwise ->
  `INTERNAL_ONLY`. `verdict_reason` mapping decided: KSI's two "verified"
  tiers reuse `NOT_QUALIFIED`'s bucket (imprecise -- its usual banner
  text doesn't distinguish a publicly-witnessed KSI seal from an
  ordinary advanced X.509 signature -- but a dedicated bucket would
  ripple into `VerdictBreakdown`, the API schema, and the already-shipped
  frontend banner; deferred to the point-in-time-wording checkpoint,
  which touches this same area anyway). The full nuance is never lost:
  it's always on the item via `ksi_verification_tier`.
- **API wiring**: `create_app(ksi_runner=...)`, threaded through
  `verify_upload` to `verify_pdf`. Deliberately *not* defaulted the way
  `revocation_fetchers` implicitly falls back to live network fetchers:
  `ksi-tool` is an optional external binary, not a pip dependency, so
  `ksi_runner=None` means "skip tiers, report `NOT_VERIFIED`" unless
  explicitly opted in. Production's module-level `app` opts in
  explicitly (`KsiToolRunner()`); tests stay hermetic by default via the
  same `app_factory(ksi_runner=...)` injection point already used for
  `revocation_fetchers`.
- **A real, non-obvious finding, confirmed in a clean container, not just
  locally**: publication-based verification against Guardtime's own live
  publications file currently can't reach a conclusive `OK` in *any*
  environment tested (local Homebrew build, or a clean
  `python:3.12-slim-bookworm` container with a full, current
  `ca-certificates` bundle) -- `ksi-tool` reports
  `[GEN-02] ... unable to get local issuer certificate`. Root-caused, not
  just observed: extracted the actual DER certs embedded in the live
  publications file by hand (`openssl` can't parse the file directly --
  it's KSI's own TLV format, not CMS) and found the chain runs through
  **GlobalSign Document Signing Root R45** -- a specialized document-signing
  root, not a general TLS root, and not part of Debian's (or macOS's)
  standard CA bundle. Downloaded that exact root from GlobalSign directly
  and tried supplying it via `ksi-tool`'s own `-V` flag; it was rejected
  ("Unable to add cert to PKI trust store") -- a further libksi/OpenSSL
  compatibility snag not resolved in this checkpoint. **Practical
  consequence: `PUBLICATION_VERIFIED` is correctly wired but not
  currently reachable against the live publications file** -- every
  real seal tested lands on `INTERNAL_ONLY` (or `BROKEN`, correctly, for
  a genuinely tampered one) instead. This is an external limitation in
  Guardtime's own published trust chain, not a bug in this project's
  code: the fallback to `INTERNAL_ONLY` is exactly the honest,
  degraded-but-correct behavior the whole tier system exists to produce
  when a check can't reach a conclusive answer. Sourcing/trusting the
  right anchor (or getting `-V` to accept it) is a well-scoped v2
  follow-up, not a blocker.
- **Serendipitous real-world validation**: Guardtime's own demo PDF
  turned out to contain *three* separate KSI seals, not the one found
  during research -- and one of them is genuinely broken (a real
  document-hash mismatch, `[GEN-01] Wrong document`), almost certainly
  included deliberately by Guardtime to exercise their own verifier's
  failure path. Running it through our full pipeline produced exactly
  the expected mix (`internal_only`, `broken`, `internal_only`) with
  zero code changes needed -- real, independent confirmation that
  discovery, extraction, hashing, and tier mapping are all correct
  together, not just individually unit-tested.
- **Container verification performed before pushing, per instruction**:
  `python:3.12-slim` was pinned to `python:3.12-slim-bookworm` (Guardtime
  only publishes a Debian 12/bookworm APT repo; the plain `-slim` tag has
  already moved to Debian 13/trixie) and the build pinned to
  `--platform linux/amd64` (Guardtime's repo is amd64-only; Railway's
  build infrastructure is amd64 anyway, so this removes ambiguity rather
  than relying on the build host's own architecture). Had to install
  Homebrew's `docker-buildx` plugin (the legacy builder can't resolve a
  per-stage `--platform` correctly). Built the real image, confirmed
  `ksi-tools`/`libksi`/`libparamset` present at the exact pinned versions
  via `dpkg -l`, ran the container, and POSTed Guardtime's real
  three-seal demo PDF to the actual `/api/verify` endpoint -- identical,
  correct results to the local run. A plain non-KSI document
  (`Demo document.pdf`) was re-checked too, as a regression guard.
- 10 new core tests (tier computation via stubbed runners, covering every
  branch: publication-verified, internal-only, broken-via-internal,
  broken-via-publication-mismatch, tool-error-falls-back-to-not-verified)
  plus 6 unit tests for the output parser (using the real captured
  transcripts) plus 3 skip-if-missing-binary integration tests that
  exercise the real installed binary when available (this machine, and
  now the container). 94/94 across `core/` + `api/` combined.

### Done: checkpoint 3 -- validated against a real Scrive-produced sample

A real Scrive KSI-sealed document (`ksi_sample.pdf`, gitignored --
never committed, same rule as `Demo document.pdf`/`qes_document.pdf`/
`test-real.pdf`) was run through the full validation gauntlet.

- **Structural diff vs. Guardtime's reference embedding** (confirmed in
  checkpoint 1's research): matches on everything that matters --
  `/FT /KSI` on the widget, `/Filter /GT.KSI` + `/FT /DocTimeStamp` on
  the inner signature dict (Guardtime's own reference reuses that same
  key at that level, so it's not a Scrive quirk), the standard 4-element
  `/ByteRange`, and hex `/Contents` encoding. `/ByteRange`'s tail
  (`800955 + 3867`) lands exactly on the file's own length, so this
  seal is `fully_covered`. Two genuine, harmless Scrive-specific
  additions found: the inner signature dict also carries `/Type /Sig`
  (Guardtime's reference doesn't set `/Type` there at all -- plausibly
  for extra interop with generic PDF tools that key off `/Type /Sig`
  rather than `/FT`; our own discovery code never reads `/Type`, so
  this changes nothing here) and `/Name (Scrive)` instead of
  Guardtime's instructional-URL string (just an identifying label, same
  key). The widget also omits `/AP` (no visible appearance stream) and
  the AcroForm dict omits `/SigFlags` -- neither read by our code,
  flagged here only because the task asked for a full diff.
- **Answered the open empirical question**: yes, this real signature
  carries a Calendar Authentication Record as its trust anchor (`ksi
  verify --ver-int --dump` shows `Trust anchor: Calendar Authentication
  Record.` plus a full `Calendar Authentication Record PKI signature:`
  block) -- confirming the tier this project's existing
  `CALENDAR_VERIFIED` enum value was written for is real, not
  speculative.
- **Implemented the key-based tier**: `KsiToolRunner.verify_key_based`
  (`ksi verify --ver-key -P <pubfile> --cnstr <constraint>`), wired into
  `_run_ksi_verification` as a fallback after publication-based comes
  back NA/TOOL_ERROR (publication-based stays tried first since it's
  the strongest tier; key-based is what an unextended signature -- the
  common case -- actually has a trust anchor for). `OK` ->
  `CALENDAR_VERIFIED`, `FAIL` -> `BROKEN`, otherwise -> `INTERNAL_ONLY`.
- **Validated the real sample through it -- and found the same external
  gap checkpoint 2 already documented also blocks this tier**:
  `--ver-key` against the live publications file lands on the identical
  `[GEN-02] ... unable to get local issuer certificate` /
  `CertificateExistence` NA that `--ver-pub` hits, for the same reason
  (the Calendar Authentication Record's PKI signature chains through
  GlobalSign's Document Signing Root R45, absent from this
  environment's CA trust store). So this real document's tier resolves
  to `INTERNAL_ONLY`, not `CALENDAR_VERIFIED` -- correct, honest
  behavior given the environment, and further confirmation (now against
  a genuinely-in-the-wild seal, not just Guardtime's own demo file) that
  this is a real, externally-rooted trust-store gap rather than
  something specific to Guardtime's demo file.
- **Full pipeline run at the API level** (`POST /api/verify` via
  `TestClient`, real `KsiToolRunner()`, not stubbed): 200 OK,
  `ksi_verification_tier: "internal_only"`, `ksi_aggregation_time:
  "2026-07-08T14:07:48Z"`, `ksi_identity_chain: ["GT:ANe2:2",
  "GT:ASe2-0:0", "Scrive:ALe2-1-3:16", "public:anon:1"]` (note Scrive's
  own client ID appearing in the aggregation chain -- direct evidence
  this seal really was produced by Scrive's own KSI-signing
  infrastructure, not a synthetic fixture), `verdict: "partial"`,
  `plain_summary: "Partially trusted — qualified status could not be
  confirmed right now for 1 of 1 seal."` -- the exact `INTERNAL_ONLY`
  plain-language string from checkpoint 2, rendered against a real
  production document for the first time.
- **Point-in-time wording (checkpoint 3's other half) does not apply to
  this document**: its aggregation time (2026-07-08) is *after*
  Guardtime's 2025-06-12 EU-qualification withdrawal, not before it, so
  the "sealed while still qualified" grandfather wording would be
  wrong to show here regardless of whether it existed. The
  `read_qualified_service_definitions()`-based boundary-lookup feature
  itself therefore remains unimplemented -- still correctly scoped as
  future work (see "Next for this feature" below), just not exercised
  by this sample. A pre-2025-06-12 KSI-sealed document would be needed
  to actually render it.
- 5 new tests (`verify_key_based`'s flag usage + real captured NA output
  in `test_ksi_tool.py`; `CALENDAR_VERIFIED` reachable + a key-based-FAIL
  case in `test_ksi.py`; a real-binary integration test tolerating
  `NA`/`OK`/`TOOL_ERROR` in `test_ksi_tool_integration.py`), one existing
  test extended to cover the new 3-tier fallback chain. 99/99 across
  `core/` + `api/` combined.

### Done: KSI UI

- **Distinct icon**: `IconLink` (a two-link chain glyph, `web/src/icons.jsx`)
  for `KSI_SEAL` items -- visually unambiguous against the existing
  person/building/clock set. Also drives the card header, wrapped in a
  `<Term id="ksiSeal">` trigger so "KSI seal" itself opens the new
  glossary entry, the same pattern `levelDisplay` already used for
  "Qualified".
- **Card layout adapted for KSI's own fields**: `SignatureCard` now
  branches on `isKsiSeal(item)`. KSI items skip the `IssuerRow` and the
  Level/Who/Trust chain/Revocation fields entirely (all X.509/EU-TL
  concepts with no KSI equivalent -- `certificate`/`trust_match` are
  always `None`, `level`/`trust_chain_status` always `unknown`,
  `revocation_status` always `not_checked` for this item type, so
  showing them would just be empty/meaningless rows). In their place:
  a **Verification** field (`ksiTierDisplay` -- a short, plain-language
  label per `KsiVerificationTier`, distinct from the full sentence
  already in `plain_explanation`), a **Sealed** field (`ksiSealedDisplay`,
  sourced from `ksi_aggregation_time` rather than the X.509-signature
  `signing_time` field, which KSI items never populate), and an
  **Identity chain** field (`ksiIdentityChainDisplay`, arrow-joined).
  `CertificateSection` already returned `null` for a missing
  `certificate` -- no change needed there.
- **Integrity, adapted rather than reused as-is**: the generic
  `integrityDisplay` branches on `modified_after_signing`, which is
  always `null` for a KSI item (no incremental-update diff analysis is
  done for this seal type) -- reusing it unmodified would show every
  KSI seal, however strongly verified, as "could not fully confirm the
  document was unchanged". `ksiIntegrityDisplay` reads `fully_covered`
  (the real, computed `/ByteRange`-covers-to-EOF fact) instead, and
  still leads with "Broken" when `intact`/`signature_valid` are false.
- **New glossary entry** (`ksiSeal` in `glossary.js`): one plain
  paragraph, publicly-witnessed-record framing, vendor-neutral --
  Guardtime/KSI named as the technology, Scrive named only as an
  example producer, and an explicit "not currently confirmed as an
  eIDAS-qualified seal by this tool" line so the entry can't be
  mistaken for a qualification claim.
- **Verified in a real browser, against a real fixture**: re-fetched
  Guardtime's own Apache-2.0 demo file
  (`github.com/guardtime/ksi-pdf-verifier`'s `demo/signed.pdf` -- the
  same one checkpoint 2 validated against, containing three real KSI
  seals: two `internal_only` and one genuinely `broken`) and drove the
  actual running app (`vite` dev server + local `uvicorn`) with
  `puppeteer-core` against the already-installed local Chrome --
  real file upload through the app's own hidden `<input type=file>`,
  not a synthetic/mocked render. Confirmed all three cards render with
  the link icon, no X.509/TL rows, correct per-tier Verification/
  Integrity/Sealed/Identity-chain values (including both
  `fully_covered: true` and `fully_covered: false` cases rendering
  distinctly), and the glossary panel opening with the intended
  vendor-neutral copy. `npm run lint` and `npm run build` both clean.

### Next for this feature

1. **Point-in-time qualification wording**: "sealed before 2025-06-12" ->
   honest note that the sealing service was eIDAS-qualified at the time.
   Needs the `read_qualified_service_definitions()`-based boundary lookup
   described in checkpoint 1's research notes (not yet implemented) --
   deriving the date from TL data, never hardcoding it. Wording-only; no
   new verdict tier. Still unvalidated against a real pre-boundary
   sample -- `ksi_sample.pdf` postdates the boundary, so it can't
   exercise this path.
2. **`CALENDAR_VERIFIED`/`PUBLICATION_VERIFIED` reachability**:
   sourcing/trusting the correct root (or resolving the `-V` rejection)
   so a genuine KSI seal can actually reach either tier against the live
   publications file -- confirmed against a second, real-world signature
   this checkpoint to be the same external trust-chain gap for both
   tiers, not our own code, not specific to Guardtime's demo file.

## Done (Day 7): wider in-process fixture set

Feature freeze in effect (no new verification capabilities) -- this is
test coverage and docs only.

- **`multi_signer_pdf`** (`core/tests/conftest.py`): a real two-signer
  PDF -- Alice's certificate declares a qualified signature, Bob's is
  plain advanced. Deliberately not a hand-picked pair of outcomes:
  because of this project's own conservative diff-analysis policy (see
  `_modification_status`), Alice's earlier revision gets flagged with an
  integrity issue purely because Bob co-signed over it afterwards, while
  Bob's (the last revision) reads clean. This is what "mixed validity"
  honestly looks like for any real multi-sig document under today's
  code, not a contrived edge case -- confirmed via a new item-level test,
  `test_multi_signer_pdf_reports_both_signers_with_mixed_outcomes`.
  (A real, aggregate-verdict-level version of this same two-signer shape
  already existed in `test_verdict.py`; this promotes it to a reusable
  fixture and adds the item-level assertions that test didn't cover.)
- **`document_timestamp_only_pdf`**: a PDF carrying only a standalone
  `/DocTimeStamp` -- no `/Sig` field at all, unlike
  `lta_extended_signed_pdf` (which timestamps an already-signed
  document). Reuses `add_lta_timestamp` applied directly to an unsigned
  base PDF. New test confirms this resolves to a single `TIMESTAMP` item
  (not `NO_SIGNATURES`) and an honest `PARTIAL`/`not_qualified` verdict,
  since the stand-in TSA isn't a registered authority.
- **Unsigned PDF**: already covered (`unsigned_pdf` fixture, tested in
  both `test_verify_pdf.py` and `test_verdict.py`) -- confirmed, no gap
  to fill.
- 101/101 across `core/` + `api/` combined (was 99).

### Manual test documents (real files, gitignored, never committed)

Beyond the in-process fixtures above, a few real vendor documents have
been used for manual/ad hoc verification throughout this project and
stay local-only (see `.gitignore`) -- listed here so a future session
knows they exist and what each is good for, without ever committing
them:

- **`Demo document.pdf`** -- an ordinary real signed PDF, plain advanced
  signature (no qcStatements). Day-1 regression case: resolves to
  `partial`/"valid but not qualified".
- **`qes_document.pdf`** -- a real QES-signed document (Norwegian
  signer/territory `NO`). Resolves to `trusted`, with
  `revocation_source: embedded` once a Trusted List + revocation
  checking are wired in -- the main real-world "everything confirmed"
  acceptance case used throughout Days 2-6.
- **`ksi_sample.pdf`** -- a real Scrive-produced KSI seal (see the KSI
  feature section above for its full validation writeup). Carries a
  Calendar Authentication Record; currently resolves to `internal_only`
  because of the external GlobalSign trust-chain gap, not a bug here.

(`test-real.pdf` was an even earlier Day-1 ad hoc file, superseded by
the two above -- no longer present on disk; its `.gitignore` entry is
harmless to leave as-is.)

## Fixed: overall verdict logic undercounted multi-item trust

**The bug, as reported**: documents with multiple independently-valid
signatures/seals were reported `PARTIAL` when they should be `TRUSTED` --
specifically (1) a valid QES + a valid KSI seal, and (2) multiple valid
qualified signatures.

**Verified empirically before touching anything** (per instruction --
this is core, plan the rule first): built both scenarios for real and
confirmed two *distinct* root causes, not one:

1. `_KSI_TIER_VERDICT_REASON` mapped *even the strongest* KSI tier
   (`PUBLICATION_VERIFIED`) to `NOT_QUALIFIED`, and `_overall_verdict`
   only awarded `TRUSTED` when literally every item was
   `CONFIRMED_QUALIFIED` -- a KSI seal structurally can never earn that
   label (correctly; Guardtime isn't eIDAS-qualified), so it could never
   contribute to `TRUSTED` no matter how well verified. This is the
   aggregation bug as originally understood.
2. A **second, deeper bug**, discovered while building a real
   multi-signer test case: any genuine two-signer PDF has its earlier
   signer(s) misclassified as `TAMPERED`, regardless of the aggregation
   rule. pyHanko's diff-analysis engine correctly classifies a second
   party validly co-signing as `ModificationLevel.FORM_FILLING` ("filling
   in a form field, or adding/modifying a digital signature" -- a real,
   standards-recognized permission level, distinct from `ANNOTATIONS`/
   `OTHER`), but `_modification_status` only ever excused `NONE` and
   `LTA_UPDATES` from counting as tampering. Fixing only the aggregation
   layer could not have made "two valid QES -> TRUSTED" true against a
   real PDF -- confirmed by reproducing it, not by inspection alone.

### Decision table (agreed before implementation)

| Item | State | Old reason | Counted toward `TRUSTED`? | New reason | Counts now? |
|---|---|---|---|---|---|
| X.509 sig/seal | qualified, intact, TL-trusted, revocation good | `CONFIRMED_QUALIFIED` | yes | unchanged | yes |
| X.509 sig/seal | qualified claim, TL/revocation unavailable | `UNCONFIRMED` | no | unchanged | no (honest gap) |
| X.509 sig/seal | advanced only, no qualified claim | `NOT_QUALIFIED` | no | unchanged -- **out of scope** | no |
| X.509 sig/seal | broken / tampered / revoked / untrusted | issue reasons | no | unchanged | no |
| KSI seal | `BROKEN` tier | `BROKEN` | no | unchanged | no |
| KSI seal | `NOT_VERIFIED` tier | `UNCONFIRMED` | no | unchanged | no |
| KSI seal | `INTERNAL_ONLY` tier | `UNCONFIRMED` | no | **corrected: `CONFIRMED_INTACT`** (see below) | **yes** |
| KSI seal | `CALENDAR_VERIFIED` tier | `NOT_QUALIFIED` | no (bug) | new: `CONFIRMED_INDEPENDENT` | yes |
| KSI seal | `PUBLICATION_VERIFIED` tier | `NOT_QUALIFIED` | no (bug) | new: `CONFIRMED_INDEPENDENT` | yes |

New rule: **`TRUSTED` iff every counted item's reason is
`CONFIRMED_QUALIFIED`, `CONFIRMED_INDEPENDENT`, or `CONFIRMED_INTACT`.**
Everything else about `_overall_verdict` (`NOT_TRUSTED` when every item is
an issue, `PARTIAL` otherwise) is unchanged.

**The `INTERNAL_ONLY` row above is corrected, not original** -- see
"Fixed: KSI `INTERNAL_ONLY` was mis-verdicted as an unconfirmed qualified
claim" further down for the full writeup and why this table's original
`INTERNAL_ONLY` call (quoted below for the historical record) was itself
a bug, not a considered trade-off:

> **The `INTERNAL_ONLY` call, made explicitly rather than by default**:
> stays `UNCONFIRMED`, not trusted. It means *neither* independent check
> (key-based or publication-based) reached a conclusive answer -- the
> token is self-consistent, but nothing outside it corroborates that, the
> same honest gap as a certificate whose Trusted List status is
> unavailable. Treating bare self-consistency as "trusted" would let any
> internally-coherent token -- including a forged one with no real
> anchoring -- carry a verdict to green.

That reasoning conflated two different questions: whether a *qualified
claim* was confirmed (the honest-gap axis `UNCONFIRMED` exists for), and
whether *integrity* was confirmed (the only axis KSI ever claims to
answer). `INTERNAL_ONLY` means the seal's own hash-chain check -- the
actual integrity question -- already came back conclusively OK; nothing
about it is a forged or unconfirmed token. What's unreached is a
*stronger, external* corroboration of that same already-confirmed
integrity fact, not a pending answer to a claim the seal never made.

**Two forks surfaced and resolved before coding** (both: yes, per
explicit confirmation):

- Extend `_modification_status` to also excuse `FORM_FILLING` from
  tampering (needed for case 2's test to pass honestly against a real
  PDF -- accepted, since the alternative was leaving a confirmed, real bug
  in tamper classification untouched purely to keep this fix's diff
  smaller).
- A KSI-only document (no X.509 item at all) *can* reach `TRUSTED` on its
  own -- a `PUBLICATION_VERIFIED`/`CALENDAR_VERIFIED` seal is a conclusive
  positive result and isn't held to "must also have a QES". The wording
  must make the distinction unmistakable regardless (see below).

### Implementation

- **`VerdictReason.CONFIRMED_INDEPENDENT`** (new): "intact and
  independently confirmed by a trust mechanism outside the eIDAS/EU-TL
  model entirely" -- counts toward `TRUSTED` the same way
  `CONFIRMED_QUALIFIED` does, but must never be described as "qualified".
- **`VerdictBreakdown.confirmed_independent`** (new field, mirrored in
  `api/schemas.py`'s `VerdictBreakdownOut`) -- purely additive; no
  existing field renamed or removed.
- **`_modification_status`**: `ModificationLevel.FORM_FILLING` now maps to
  `(modified_after_signing=False, lta_extended=False)`. `ANNOTATIONS`/
  `OTHER` are unaffected -- still conservative.
- **`_plain_summary`**: three-way-aware now, not two-way.
  "Trusted"/"qualified" are kept as distinct claims throughout:
  - All trusted items are `CONFIRMED_QUALIFIED` -> unchanged wording,
    e.g. `"Fully trusted — all 2 signatures are qualified and intact."`
  - All trusted items are `CONFIRMED_INDEPENDENT` (KSI-only) -> no
    `"Fully"`, no `"qualified"` anywhere:
    `"Trusted — integrity independently verified against a publicly
    witnessed record."` (descriptor varies by tier -- see
    `_ksi_independent_descriptor`: `"against a publicly witnessed
    record"` for `PUBLICATION_VERIFIED`, `"against the sealing
    infrastructure's own signing certificate"` for `CALENDAR_VERIFIED`,
    a bare `"independently verified"` if a document somehow mixes both).
  - A genuine mix -> named separately, never lumped:
    `"Fully trusted — 1 of 2 items is qualified and intact; 1 is
    independently verified against a publicly witnessed record."`
  - The existing `PARTIAL` "no issues, nothing unconfirmed" branch also
    gained a three-way-aware variant for when `CONFIRMED_INDEPENDENT`
    and `NOT_QUALIFIED` items coexist without any qualified/issue/
    unconfirmed items at all; the original two-way wording is preserved
    byte-for-byte when no KSI item is in the mix (verified via the
    pre-existing tests, unchanged).
- Two **pre-existing tests were re-grounded, not just updated**: both
  had been (unknowingly) asserting the `FORM_FILLING` bug's own symptom
  as expected behavior. `test_two_signatures_one_with_an_issue_is_partial_with_correct_counts`
  now tampers *between* two co-signatures (a real, still-genuine "one
  clean + one broken" case) instead of relying on co-signing alone to
  produce an "issue". `test_multi_signer_pdf_reports_both_signers_with_mixed_outcomes`
  (from the Day 7 fixture work) now asserts both signers read clean,
  distinguished instead by qualification/confirmation, not integrity.
- 6 new tests in `test_verdict.py` lock in the decision table: two valid
  co-signers -> `TRUSTED`; QES + `PUBLICATION_VERIFIED` KSI -> `TRUSTED`
  with mixed wording; KSI-only `PUBLICATION_VERIFIED` -> `TRUSTED` with
  the no-"qualified" wording; QES + `CALENDAR_VERIFIED` KSI -> `TRUSTED`
  with the certificate-specific wording; QES + `INTERNAL_ONLY` KSI ->
  stays `PARTIAL` (the explicit decision-table call, locked in); three
  items (2 valid + 1 genuinely broken) -> `PARTIAL` with the correct
  count. 107/107 across `core/` + `api/` combined (was 101).
- Not touched this pass: the frontend's `itemTone`/`itemBadge` switches
  (`web/src/itemPresentation.js`) have no dedicated case for
  `confirmed_independent` yet -- it currently falls through to the
  existing neutral default ("Valid, not qualified" badge), which still
  reads honestly, just not with a dedicated label. A v2 candidate, not a
  correctness bug.

## Done: verdict page frontend polish (five related improvements)

Frontend-only -- no verdict logic touched, per instruction. All five
items verified in a real browser (a multi-signer fixture, a single QES,
and a KSI seal, at desktop and mobile widths) via `puppeteer-core`
driving local Chrome against `web/dist`'s production build served
through a locally stub-wired API (real HTTP, real upload, not a mocked
render) -- see this section's last bullet for how that stub was set up.

1. **Multi-item layout**: `SignatureCard` gained a `collapsible` mode.
   Multiple items render as compact, clickable summary rows (type,
   level/tier badge, signer name, a plain Valid/Invalid chip, the
   existing status badge) in a responsive grid
   (`grid-template-columns: repeat(auto-fit, minmax(300px, 1fr))`,
   paired with a wider `.app-main--wide` container used only for this
   phase) -- collapsed rows sit side by side on a wide viewport and
   stack to one column under 720px. An item defaults *expanded* when it
   needs attention (`not-trusted`/`partial` tone, same rule the
   technical-details drawer already used), so a genuine problem is
   never hidden behind a click. An expanded item spans the full grid
   row (`grid-column: 1 / -1`) so its full body has real width. A
   single-item document skips `collapsible` entirely and always shows
   the full card -- unchanged from before, just with the new identity
   strip (next item).
2. **Trusted green, strengthened**: new, more saturated
   `--verdict-trusted-*` tokens plus a `--verdict-trusted-bg-strong`
   token for the one or two elements that should pop hardest (the
   Qualified/Independently-verified badge, the trusted banner's icon
   backdrop). Verified by computing WCAG contrast ratios directly
   (not eyeballed): bg/text 8.17:1, bg/icon 4.27:1, bg-strong/text
   7.36:1 -- all clear AA's 4.5:1 (text) / 3:1 (non-text) floors with
   room to spare, exceeding the previous (already-passing) ratios.
   Partial/danger tokens untouched, so amber/red stay exactly as
   distinct from both each other and the lemon accent as before.
3. **Level badge, prominent**: `levelDisplay`'s `Qualified` case now
   carries an icon (`IconShieldCheck`) and a `strong: true` flag driving
   the punchier fill; `Advanced`/`Basic` stay the plain tone-colored
   pill. Promoted out of the field grid into a new always-visible
   identity strip at the top of every card (single or multi-item).
4. **Signer, prominent**: the same identity strip shows `whoDisplay`'s
   "Signed by X"/"Sealed by X" text directly beside the level badge --
   the two things the task asked to be first-glance facts. Issuer/TSP
   stays in its existing, separate `IssuerRow` as supporting detail,
   unchanged.
5. **`CONFIRMED_INDEPENDENT` handled**: `itemTone`/`itemBadge` gained an
   explicit case (was silently falling to the neutral default) --
   tone `TRUSTED` (same green family as `Qualified`), badge text
   "Independently verified" (never "Qualified"). New
   `ksiLevelBadgeDisplay` mirrors `levelDisplay`'s shape for the
   identity strip specifically (`CALENDAR_VERIFIED`/
   `PUBLICATION_VERIFIED` -> "Independently verified", `strong: true`,
   same fill as Qualified); the existing, more detailed `ksiTierDisplay`
   (used in the field grid) is unchanged except fixing `CALENDAR_VERIFIED`'s
   own tone from `NEUTRAL` to `TRUSTED` -- a real inconsistency this
   task surfaced, now that core treats both KSI tiers as the same trust
   bucket.
   - **A real bug this pass also caught**: `VerdictBanner`'s heading was
     a static per-verdict label ("Fully trusted" for every `trusted`
     verdict), completely overriding core's own careful "Trusted" vs.
     "Fully trusted" distinction (the KSI-only wording from the verdict-logic
     fix, deliberately never claiming "qualified") in the one place users
     read first. Fixed: the heading is now derived from `plain_summary`'s
     own text, falling back to the static label only when there's no
     em-dash to split on.
- **Visual QA harness** (scratchpad only, not committed): a small script
  builds three real PDFs (single QES, a genuinely mixed two-signer
  document, a KSI seal) and serves them through `create_app()` wired
  with a seeded Trusted List snapshot, a clean CRL, and a stub
  `KsiToolRunner` reaching `PUBLICATION_VERIFIED` -- then `puppeteer-core`
  drives real Chrome through the actual upload flow against that server,
  at both a desktop and a mobile viewport, screenshotting the result.
  Confirmed: the responsive grid, the collapse/expand interaction (both
  directions), the strengthened green, the Qualified/Independently-verified
  badges side by side in a two-item grid, and the corrected banner
  heading -- all rendering as designed, not just passing a lint/build
  check.

## Fixed: multi-item layout at realistic (8+) signature counts

The previous "multi-item layout" fix (see above) was only verified against
a 2-item fixture, where a side-by-side card grid happens to look fine.
Reported broken against a real 8-signature document: all 8 cards rendered
fully expanded, stacked in one column -- because expand-by-default was keyed
off each item's tone (`needsAttention`), and real documents routinely have
several qualified-but-unconfirmed/not-yet-trusted items, whose `partial`
tone forced them open regardless of count.

- **`COLLAPSE_THRESHOLD = 3` in `ResultView.jsx`.** At or below it (1-3
  items), behavior is exactly as before: full cards, expand-by-default
  driven by tone, side-by-side grid for 2-3. Above it ("dense" mode), every
  row starts collapsed **regardless of tone** -- the collapsed row itself
  (tone-colored left border, validity tick, verdict badge) is what surfaces
  a problem now, not forced expansion, which is what let a document with
  several unconfirmed/tampered items degenerate into a wall of open cards.
- **`SignatureCard` gained a controlled-expansion mode**: `dense`,
  `expanded`, `onToggle` props. When `expanded` is provided the card defers
  entirely to the parent instead of managing its own `useState` -- needed
  so a single "expand all/collapse all" control (new
  `.result-view__toggle-all` button, only rendered in dense mode) can drive
  every row's state at once via a `Set` of expanded indices in
  `ResultView`. Small-count documents are untouched: `expanded` stays
  `undefined`, so the card falls back to its original internal,
  tone-driven `useState`.
- **Dense-mode CSS** (`sig-card--dense`, `result-view__cards--dense`):
  single-column list (not the auto-fit grid --multi uses), tighter
  collapsed-row padding, `flex-wrap: nowrap` on desktop so the row spreads
  across the full width (type icon, level badge, signer name -- `flex: 1`
  with ellipsis truncation and a `title` tooltip so a long name doesn't
  wrap the row -- validity tick, verdict badge, chevron, in that order),
  falling back to `flex-wrap: wrap` under 720px so mobile still reads
  cleanly across two lines per row instead of clipping.
- **Verified against a real 8-signer PDF, not a synthetic 2-item
  fixture** -- explicitly the gap that let the previous pass ship broken.
  Built via `core/tests`' own fixture helpers (co-signed 8 times over one
  minimal PDF, `tamper_page_after_signing` applied between the 1st and 2nd
  signature): 3 CA-issued qualified signers registered on a seeded Trusted
  List snapshot with a matching CRL (-> `confirmed_qualified`, green), 1
  genuinely tampered (-> red), 1 qualified-but-unregistered against a
  deliberately degraded snapshot (-> `unconfirmed`, amber), 3 plain
  advanced signers (-> `not_qualified`, neutral) -- deliberately diverse
  tones, not just a repeated shape. Served through the real `create_app()`
  (seeded `TrustListCache`, stub CRL fetcher, `start_background_refresh=False`)
  behind the actual production `web/dist` build (no dev-proxy shortcut),
  driven by `puppeteer-core` against real Chrome: uploaded via the real
  file input, screenshotted collapsed (all 8 rows, no scrolling, problem
  rows visually distinct by border/badge color alone), one row expanded
  in place, "expand all" expanding all 8 without disturbing the others,
  and the same at a 390px mobile viewport. Also re-verified the 1-item and
  2-item paths against fresh fixtures on the same running server to
  confirm no regression: full card / side-by-side grid, byte-for-byte the
  previous behavior, no dense-mode controls rendered.
- **Threshold choice, stated explicitly per the ask**: collapse-by-default
  above 3 items. 1-3 items keep the existing "clean, nothing to scan past"
  full-card treatment; 4+ is where a card grid stops being scannable and
  the dense list takes over.

## Fixed: KSI `INTERNAL_ONLY` was mis-verdicted as an unconfirmed qualified claim

**The bug, as reported**: an intact KSI seal that reached only
`INTERNAL_ONLY` (its own hash-chain check passed; neither the key-based
nor the publication-based external check was reachable) was reported
`PARTIAL` -- "qualified status could not be confirmed right now" -- and a
single-item document consisting of only such a seal read as
`PARTIAL`/amber instead of `TRUSTED`/green.

**Root cause**: a category error in the original verdict-logic fix (see
"Fixed: overall verdict logic undercounted multi-item trust" above).
`INTERNAL_ONLY` was mapped to `VerdictReason.UNCONFIRMED` -- the same
reason an X.509 signature gets when it *claims* to be qualified but that
claim can't be confirmed (Trusted List/revocation data unavailable). KSI
never makes a qualified-identity claim at all; it only ever answers one
question -- has the document been altered since sealing? -- and
`INTERNAL_ONLY` means that question already came back a conclusive yes,
intact. Judging it against "is the qualified claim confirmed?" was
applying the wrong axis, not identifying a real gap.

### The corrected rule

1. An intact KSI seal counts as `TRUSTED` on the integrity axis,
   regardless of qualified status -- which simply doesn't apply to KSI.
2. Only a genuinely broken/inconsistent seal (`BROKEN` tier) demotes a KSI
   item off that axis. "Couldn't reach a stronger external confirmation"
   is not an integrity failure.
3. Wording keeps one honest distinction, never a trust-bucket one:
   `CALENDAR_VERIFIED`/`PUBLICATION_VERIFIED` (a real external check
   passed) get "independently verified" language; `INTERNAL_ONLY` (intact,
   but no external check reachable) gets its own honest wording -- never
   "independently verified" (that would overclaim an external
   corroboration that didn't happen) and never "qualified" (not this
   mechanism's claim to begin with).
4. No KSI path may use the "qualified status could not be confirmed"
   phrase -- that phrase is reserved for X.509 items that actually claim
   qualified status. This also caught a second, narrower instance of the
   same category error: `NOT_VERIFIED` (the tool hasn't even run yet)
   still correctly stays `UNCONFIRMED`, but `_plain_summary`'s wording for
   an all-KSI unconfirmed document was rewritten too, so it never borrows
   the X.509-specific phrase either (`"verification could not be
   completed right now for N of M seal(s)"` instead).
5. Mixed documents (a QES + an intact KSI seal) are `TRUSTED`, wording
   each item on its own terms -- never implying the KSI seal is a
   failed/partial qualified signature.

### Implementation

- **`VerdictReason.CONFIRMED_INTACT`** (new): intact and internally
  self-consistent, but no external corroboration reachable. Counts toward
  `TRUSTED` the same way `CONFIRMED_QUALIFIED`/`CONFIRMED_INDEPENDENT` do;
  must never be worded as "qualified" or "independently verified".
- **`_KSI_TIER_VERDICT_REASON[INTERNAL_ONLY]`** changed from
  `UNCONFIRMED` to `CONFIRMED_INTACT`. `NOT_VERIFIED` is unchanged
  (`UNCONFIRMED` -- genuinely nothing confirmed yet, not even the internal
  check).
- **`VerdictBreakdown.confirmed_intact`** (new field, mirrored in
  `api/schemas.py`'s `VerdictBreakdownOut`) -- purely additive.
- **`_overall_verdict`**: `trusted_count` now sums all three confirmed
  reasons (`confirmed_qualified + confirmed_independent +
  confirmed_intact`).
- **`_plain_summary`** rewritten to be three-bucket-aware on the `TRUSTED`
  side (qualified / independently-verified / intact-only, and every
  pairwise-or-triple mix), each described in its own terms and joined by
  `;` rather than lumped under one blanket claim. The `PARTIAL`
  `unconfirmed` branch is now KSI-vs-X.509-aware too, so an all-KSI
  unconfirmed document never says "qualified status".
- **`_KSI_TIER_PLAIN_TEXT[INTERNAL_ONLY]`** rewritten to the honest,
  positive framing: "This document's KSI seal is intact -- the document
  hasn't been altered since it was sealed. Independent confirmation
  against a public record wasn't reachable right now -- ...".
- **Frontend (`web/src/itemPresentation.js`)**: `itemTone`/`itemBadge`
  gained a `confirmed_intact` case (tone `TRUSTED`, badge "Intact" --
  distinct from both "Qualified & confirmed" and "Independently
  verified"). `internal_only`'s entries in `KSI_TIER_META` and
  `KSI_LEVEL_BADGE_META` flipped from `PARTIAL`/amber to `TRUSTED`/green,
  wording changed from "Internally consistent only" to "Intact" (level
  badge) / "Intact -- no external confirmation reachable yet" (field
  grid) -- no code path left describing an intact seal as a warning.
- **8 tests added/corrected** in `core/tests/test_verdict.py` and
  `core/tests/test_ksi.py`, locking in the decision table:
  `test_qes_and_internal_only_ksi_seal_is_trusted` (renamed from
  `..._stays_partial`, now asserts `TRUSTED` with per-item wording);
  `test_ksi_only_internal_only_is_trusted_without_qualified_or_independent_wording`
  (single intact `INTERNAL_ONLY` seal -> `TRUSTED`, bare "Trusted"
  heading, no "qualified"/"independently verified" anywhere);
  `test_broken_ksi_seal_alone_is_not_trusted` (genuinely broken KSI, only
  item -> `NOT_TRUSTED`); `test_ksi_only_not_verified_is_partial_without_qualified_wording`
  (locks in point 4 above); `test_internal_only_when_all_three_checks_are_inconclusive`
  in `test_ksi.py` updated to assert `CONFIRMED_INTACT` instead of the old
  `UNCONFIRMED`. The pre-existing `CALENDAR_VERIFIED`/`PUBLICATION_VERIFIED`
  tests were untouched and still pass byte-for-byte -- this fix only
  corrects `INTERNAL_ONLY`'s bucket, not the already-correct stronger
  tiers. 110/110 across `core/` + `api/` combined (was 107; net +3 new
  tests, one existing assertion corrected in place), zero regressions.
- **Re-verified against the real `ksi_sample.pdf`** (gitignored, per
  CLAUDE.md's ephemerality rule -- not committed), with the real `ksi`
  binary installed (Homebrew `ksi-tools`, not a stub): still lands on
  `INTERNAL_ONLY` (the GlobalSign trust-chain gap from the original KSI
  writeup is unchanged), but now returns `verdict: trusted` --
  `"Trusted — this document's KSI seal is intact, and hasn't been altered
  since it was sealed. Independent confirmation against a public record
  wasn't reachable right now."` -- instead of the old `partial`. This is
  the real-world document the original (buggy) decision table was
  calibrated against, so this is the concrete case the fix was for, not
  just a synthetic test.

## Rebrand: Scrive design system

The frontend was reskinned onto Scrive's brand (colors, type, logo) --
layout and interaction (collapsed multi-item list, expand/collapse, KSI
card, badges, six-field grid, "verify it yourself" link) are unchanged; this
was a token/CSS swap, not a rebuild.

- **`web/src/theme.css` replaced wholesale**: the "Limoncello" palette is
  gone. Surfaces are Botticelli (`#F2F6F9`)/white, ink is Shark (`#27282D`),
  interactive text/buttons/links use WCAG Blue (`#1A79CB`) -- Curious Blue
  (`#1E88E2`) is kept decorative-only per the brand guide's own callout,
  since it fails contrast as text (~3.7:1 on white). Traffic-light verdicts
  now map to Scrive's semantic tokens: success (green) -> TRUSTED, warning
  (yellow) -> PARTIAL, error (red) -> NOT_TRUSTED.
- **A few tokens are deliberately *derived*, not used verbatim**, each
  documented inline in `theme.css` with its measured contrast: green-700
  and red-500 text only reach ~3.4:1 against their own "light" verdict
  backgrounds, so both are darkened slightly (same hue) to clear 4.5:1.
  gray-500 is nudged similarly for muted text sitting directly on the page
  background (no card behind it). Warning was the tricky one -- pale
  yellow-200 is only ~1.05:1 apart in lightness from the page background
  and would nearly disappear as a banner fill, so the PARTIAL banner/notice
  use the bold yellow-500 instead (with Shark text, 11:1), plus a
  left-border accent for a defined edge; yellow-200 is kept for small
  badges/chips sitting on a white card, where it reads fine. A separate
  darkened-gold token (`--verdict-partial-icon`, `#7E711B`) covers the one
  case where warning needs to read as colored text/icon with no fill behind
  it (the inline field-value color, the card's left border) -- the raw
  yellow-500 fails outright there (1.34:1 on white).
- **Typography**: Fraunces/Manrope -> Montserrat throughout (400/500/700),
  per the guide. Line-heights are newly paired per size using the guide's
  own rule (font-size x 1.4, rounded to the nearest 4px) rather than a flat
  inherited ratio -- `--leading-xs` through `--leading-4xl` in `theme.css`,
  applied everywhere `font-size` is set in `app.css`.
- **Logo**: the real `scrive-logo.svg` (the "scrive." wordmark) now lives
  in `web/public/` and renders in a new `Header.jsx` component above
  `.app-main`, sized with generous clear space, aspect ratio preserved
  (`height` fixed, `width: auto`) -- not redrawn, not recolored. The
  favicon reuses the wordmark's own "s" glyph path (extracted by its
  bounding box, not hand-traced) centered on a Botticelli rounded square,
  since the brand only supplies a wordmark and no separate icon mark.
- **Disclaimer**: final wording landed in two forms, per the project
  owner. `Footer.jsx` carries the full version -- affiliation
  ("independent personal project by Monir Gueblaoui... not an official
  Scrive product or service, and nothing here represents Scrive") folded
  together with the pre-existing Article 33/not-legal-advice framing --
  in a bordered card (`.site-footer__disclaimer`, gray-700/text-sm, not
  muted fine print, since the affiliation point only works if it's
  actually read). `Landing.jsx` carries a short form ("Beta · an
  independent personal project, not an official Scrive product.") as a
  visible pill directly under the headline (`.landing__disclaimer`,
  blue-subtle background, Sapphire text, 7.76:1 contrast).
- **Verified locally** (`uvicorn` + `vite dev`, real `qes_document.pdf`,
  `ksi_sample.pdf`, and a fresh 8-signer fixture built from `core/tests`'
  own signing helpers -- 3 clean-qualified, 1 tampered, 1
  unregistered-qualified/unconfirmed, 3 advanced) via `puppeteer-core`
  driving real Chrome, at both a 1280px desktop and 390px mobile viewport,
  collapsed and fully expanded. All four verdict tones (trusted/partial/
  not-trusted/neutral) render legibly in both the banner and inline
  field-value contexts.

## Next: Day 7 -- polish, continued

1. Review the new KSI card design on the live Railway URL against a
   real KSI-sealed document -- confirmed the deploy itself is current
   (see below), but a full visual pass there is still only done via the
   local dev server so far.
2. README demo GIF and hero screenshot (placeholders added to README;
   images to be dropped in separately).
3. A small real-world test-document set beyond what's listed above
   (BankID-signed, D-Trust-sealed, a genuinely broken-seal fixture),
   per the PRD's own recommended open item -- still open.

Also still open from earlier days:
- The Subject-`C=` territory-attribution heuristic remains deliberately
  unimplemented (v2 candidate).
- CertID-hash matching for DSS-embedded revocation data (vs. today's
  serial/issuer match) is a v2 upgrade if serial collisions across
  issuers ever become a practical concern (see the point-in-time
  validation section above).
