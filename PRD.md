# PRD: eidas-inspect

> Personal project. Informational verification tool — **not** a qualified validation service under eIDAS Article 33, and not legal advice.

## 1. User Story

*As a consumer or company employee in Europe who has received a digitally signed, sealed, or timestamped PDF, I want to upload it and get a clear, plain-language verdict on whether it is genuinely valid and qualified, so that I can act on the document with confidence.*

## 2. Summary

eidas-inspect is a free, hosted web service that verifies digital signatures, electronic seals, and timestamps in PDF documents against the eIDAS trust framework. Existing validators (EU DSS demo, Adobe Reader) produce output that is either impenetrable to non-experts or an unexplained checkmark. eidas-inspect's differentiator is **radical legibility**: an opinionated, traffic-light verdict in plain language, backed by a per-signature breakdown and an optional expandable technical layer.

The service is strictly ephemeral — documents are processed in memory and never stored or logged — which is both the correct GDPR posture and a core trust message. v1 ships as a mobile-responsive web app with a Python validation core deliberately separated from the interface, so the same engine can later power an API or paid tier. The project is a personal project, built end-to-end with Claude Code, targeting MVP live in production within one week.

## 3. Core User Flow

1. User lands on the page. Headline communicates the job in plain terms (e.g., "Check if your signed document is genuinely valid") plus the trust promise ("Your document is processed in memory and never stored").
2. User drags a PDF onto the drop zone or taps/clicks to open the native file picker (mobile: file picker / share-sheet-friendly upload).
3. If the PDF is password-protected, the UI prompts for the password with a reassuring note that nothing is stored.
4. An animated, step-by-step verification sequence plays with honest, real-time stages: *Reading document → Finding signatures → Verifying integrity → Consulting EU Trusted Lists → Checking revocation status.* The animation doubles as education.
5. Verdict page renders: a document-level traffic-light banner (e.g., "⚠️ Partially trusted — 1 of 3 signatures has issues"), followed by one card per signature/seal/timestamp with the six-field breakdown.
6. Failed items show a plain-language one-liner, with an expandable "technical details" section revealing the underlying cause.
7. Unfamiliar terms (Qualified, QES, Trusted List) carry lightweight educational tooltips/expandables.
8. User optionally downloads a PDF verification report — a snapshot of the verdict, generated within the same request.
9. Session ends; nothing persists server-side except anonymous counters.

**Alternate path — unsigned document:** neutral (not red) state: "This document contains no digital signatures," a one-line explanation that a scanned handwritten signature is not a digital signature, and vendor-neutral suggestions for how to get the document properly signed.

## 4. Functional Requirements

| # | User Action | Expected System Response |
|---|-------------|--------------------------|
| 1 | Uploads a PDF via drag-and-drop or file picker | File validated (type = PDF, size ≤ 50 MB); verification pipeline starts; animated progress sequence displays real stages |
| 2 | Uploads a non-PDF file | Friendly rejection: "PDF only for now" (other formats noted as coming) |
| 3 | Uploads a file > 50 MB | Friendly rejection stating the 50 MB limit |
| 4 | Uploads a password-protected PDF | Password prompt shown; on entry, decryption in memory and verification proceeds; wrong password → friendly retry |
| 5 | Uploads a corrupted/unreadable PDF | Friendly error, offer to try again |
| 6 | Uploads an unsigned PDF | Neutral "no signatures found" state with explanation and vendor-neutral signing suggestions |
| 7 | Verification completes | Document-level traffic-light verdict banner + per-item breakdown cards (Type, Level, Who, Integrity, When, Trust chain) |
| 8 | An item fails validation | Plain-language one-liner on the card; expandable technical-details section with underlying cause (e.g., revoked cert, digest mismatch, issuer not on TL) |
| 9 | Trusted List unreachable / cache stale | Degraded-but-honest mode: verify everything else; affected field labeled "qualified status could not be confirmed right now" |
| 10 | Revocation endpoint slow/unreachable | Timeout applied; item labeled "revocation status unavailable" rather than failing the verdict |
| 11 | Clicks "Download report" | PDF verification report generated in-request: snapshot of verdict + cards + verification timestamp (recommended: file SHA-256 in footer) |
| 12 | Hovers/taps an eIDAS term | Educational tooltip/expandable in plain language |
| 13 | Exceeds 10 verifications/hour from one IP | Friendly rate-limit message with retry time |
| 14 | Any request completes | Anonymous counters incremented (verifications/day, verdict distribution); zero document data or filenames logged |

## 5. Technical Requirements

### APIs

- `POST /api/verify` — multipart PDF upload (+ optional password); synchronous; returns full verdict JSON. No auth in v1.
- `POST /api/report` — accepts verdict JSON (or re-verifies in-request), returns generated PDF report. Must complete in the same request cycle (no async links — ephemerality constraint).
- IP-based rate limiting middleware: 10 verifications/hour/IP.
- External calls: EU LOTL + member-state Trusted List URLs (scheduled fetch), OCSP/CRL endpoints of issuing CAs (per-verification, with timeouts).

### Data Models (in-memory / transient only)

- `VerificationResult`: overall verdict (trusted / partial / not-trusted / no-signatures), list of `SignatureItem`s, document SHA-256, verified-at timestamp, TL freshness status.
- `SignatureItem`: type (signature/seal/timestamp), level (Qualified/Advanced/Basic), signer or org name, issuing TSP, integrity status, modified-after-signing flag, signing time + timestamp quality (qualified TSA / claimed only), trust-chain status, failure explanation (plain + technical).
- `TrustListCache`: parsed LOTL + per-member-state lists, in-memory, refreshed every 24h, per-list staleness flags.
- Persistent storage: **anonymous counters only** (date, count, verdict distribution). No documents, no filenames, no IP-to-document mapping.

### Integration Points

- **pyHanko** as the validation core: PAdES parsing, ByteRange/digest integrity, CMS validation, RFC 3161 timestamps, incremental-update analysis.
- Custom layer on top of pyHanko: qcStatements parsing (ETSI EN 319 412-5 — QcCompliance, QcSSCD, QcType for esign vs eseal), Trusted List resolution/matching, plain-language verdict mapping.
- Architecture mandate: validation core as a standalone Python package (`eidas_inspect_core`) with zero web dependencies; FastAPI wraps it. This preserves the future hosted-API / paid-tier path.
- Frontend: React (Vite), single monorepo with backend, one Dockerfile.
- Hosting: **Railway or Render**, hobby tier, git-push-to-deploy. Chosen explicitly for minimal ops burden.
- Built end-to-end with Claude Code (Lovable optionally for frontend polish).

### Non-Functional Requirements

- **Privacy**: strictly ephemeral — uploaded files processed in memory, never written to disk, never logged. Passwords never stored. This is a stated product promise on the landing page.
- **Performance**: typical verification (few-MB PDF, 1–3 signatures) target < 10 s including revocation checks; hard timeouts on OCSP/CRL (~5 s each) and TL fetches.
- **Availability**: hobby-tier best-effort; degraded modes ensure partial availability of external dependencies never takes the service down.
- **Security**: HTTPS only; uploaded content treated as untrusted (parser hardening via pyHanko); 50 MB cap; rate limiting; no accounts or auth surface in v1.
- **Mobile**: fully responsive; upload via native file picker; verdict cards stack on narrow screens.

## 6. Expected Behavior

- **Happy path**: valid QES-signed contract → green banner "Fully trusted — all signatures are qualified and intact," cards all green, report downloadable.
- **Mixed document**: 3 signatures (1 qualified+valid, 1 advanced+valid, 1 broken) → amber banner "⚠️ Partially trusted — 1 of 3 signatures has issues"; broken card leads with plain-language cause ("The document was changed after this signature was applied"), expandable technical detail beneath.
- **Untrusted document**: all signatures broken/revoked → red banner with plain "Do not rely on this document" framing (technical validation language, no legal judgment).
- **Unsigned PDF**: neutral informative state + signing suggestions (most common real-world case; must not feel like an error).
- **Degraded TL**: verdict renders; qualified-status field shows "could not be confirmed right now" with honest explanation; overall verdict reflects the uncertainty rather than guessing.
- **Revocation unavailable**: item marked "revocation status unavailable"; verdict language reflects reduced confidence honestly.
- **Sloppy qcStatements** (real-world qualified certs with incomplete type declarations): classifier falls back conservatively (never over-claims "Qualified"); technical details note the ambiguity.
- **Rate limit hit**: friendly message with time-until-retry; no CAPTCHA.

## 7. Design / UI Components

- **Landing page**: headline + drop zone / tap-to-upload button; ephemerality trust promise; light, consumer-friendly visual identity with personality — explicitly distinct from Scrive's brand. Footer: "Personal project" note + informational disclaimer.
- **Verification animation**: interactive, moving step-sequence with real stage names; doubles as education.
- **Verdict banner**: traffic-light system (green / amber / red / neutral-for-unsigned) with plain verdict phrases; no legalese anywhere.
- **Signature cards**: six fields (Type, Level, Who, Integrity, When, Trust chain); iconography per type (person / building / clock); expandable technical-details drawer on failures.
- **Educational layer**: tooltips/expandables for Qualified, QES, QSeal, Trusted List, timestamp — plain language, one short paragraph each.
- **Unsigned state**: helpful, vendor-neutral "how to get this signed" suggestions.
- **PDF report**: branded snapshot of verdict page; verification timestamp; recommended SHA-256 footer.
- **Disclaimer copy** (designed-in, not bolted on): informational verification, *not* a qualified validation service under eIDAS Article 33; not legal advice.
- **Accessibility**: color never the sole signal (icons + text accompany traffic lights); keyboard-navigable upload; mobile-first responsive layout.

## 8. Acceptance Criteria

- **Given** a PDF with valid qualified signatures, **when** uploaded, **then** a green document-level verdict renders with all six fields populated per signature, within ~10 s.
- **Given** a document modified after sealing, **when** verified, **then** the affected card shows integrity ✗ with the plain-language modification explanation and an expandable technical cause.
- **Given** a mixed-validity document, **when** verified, **then** an amber "Partially trusted — X of Y" banner renders with correct per-item statuses.
- **Given** an unsigned PDF, **when** uploaded, **then** the neutral no-signatures state renders with signing suggestions (not an error state).
- **Given** a password-protected PDF and the correct password, **when** submitted, **then** verification completes normally; **given** a wrong password, **then** a friendly retry prompt appears.
- **Given** an unreachable member-state Trusted List, **when** verifying a document from that state, **then** the verdict still renders with qualified status marked unconfirmable.
- **Given** any completed verification, **when** the server is inspected, **then** no document content, filename, or password exists on disk or in logs.
- **Given** "Download report," **when** clicked, **then** a PDF snapshot of the verdict is returned in the same request.
- **Given** an 11th verification from one IP within an hour, **when** submitted, **then** a friendly rate-limit message is returned.
- **Given** a phone-sized viewport, **when** the full flow is exercised, **then** upload, verdict, and report all function with stacked cards.
- **Given** the deployed production URL, **when** visited, **then** the full flow works end-to-end over HTTPS.

## 9. Success Metrics

Formal adoption metrics are **explicitly out of scope** — the goal is a live, working, well-crafted portfolio service. The success bar:

- **Binary launch criterion**: deployed to production, full flow working end-to-end, within 1 week.
- **Quality bar**: verdict UX legible to a non-expert (informal test: someone with no eIDAS knowledge correctly interprets a mixed-validity verdict unaided); polished README with demo GIF.
- **Operational health** (via anonymous counters only): verifications/day and verdict distribution — observational, no targets.
- **Recommended open item**: validate against a small real-world test set (e.g., BankID-signed, D-Trust-sealed, broken-seal fixtures) before calling v1 done.

**Future considerations on record**: XAdES + ASiC support, hosted API tier, paid tier with account-based contract storage and verification history.

---

*Note: This PRD is approximately 80% complete by design — some details will require clarification during implementation (e.g., exact TL parsing edge cases, final visual identity, hosting platform choice between Railway and Render).*
