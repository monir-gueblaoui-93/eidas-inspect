# Progress

Status as of 2026-07-08, end of Day 2 (per BUILD_GUIDE.md).

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
  untouched by Day 2); `trust_chain_status` now reflects the real EU Trusted
  List check. The final "confirmed qualified" verdict logic combining both
  fields is still Day 2+ work (`_overall_verdict()` in `verify.py` remains
  the Day-1 placeholder — see Next).
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
- Re-verified `Demo document.pdf` with `check_revocation=True` against the
  live EU LOTL: `revocation_status` correctly comes back `NOT_CHECKED`,
  because `trust_chain_status` is `UNAVAILABLE` for this document (its
  issuer, GlobalSign, doesn't resolve against the Trusted List data we have)
  — no PKIX path is built, so there's nothing for revocation checking to
  walk. Still haven't seen a real document exercise the `TRUSTED` +
  `GOOD`/`REVOKED` paths end-to-end; only the `Demo document.pdf` open item
  above would give us that.

## Next: Day 2, remainder per BUILD_GUIDE.md

1. **Overall verdict logic**: combine `level` + `trust_chain_status` +
   `revocation_status` into the final trusted / partial / not-trusted /
   no-signatures verdict per PRD section 6, with uncertainty (degraded TL,
   unavailable revocation) lowering confidence honestly rather than
   guessing. `_overall_verdict()` in `verify.py` is currently a placeholder
   (partial whenever any signature is intact) and should be replaced by
   this real logic.
