# eidas-inspect — Build Guide

How to go from empty repo to live production service in one week, building everything with Claude Code. Written to be followed step by step; the prompts are copy-paste-ready.

---

## Day 0 (30 min): Setup

**1. Create the repo**

```bash
mkdir eidas-inspect && cd eidas-inspect
git init
gh repo create eidas-inspect --public --source=. --remote=origin
```

(Install GitHub CLI first if needed: `brew install gh` then `gh auth login`.)

**2. Drop in the PRD**

Put `PRD.md` in the repo root. This is Claude Code's source of truth.

**3. Create `CLAUDE.md` in the repo root**

This is the persistent context file Claude Code reads on every session. Starter content:

```markdown
# eidas-inspect

Personal project: hosted web service that verifies digital signatures, seals,
and timestamps in PDFs against the eIDAS framework, with radically legible UX.
Full requirements: see PRD.md — treat it as the source of truth.

## Architecture rules (non-negotiable)
- `core/` — pure Python validation package (`eidas_inspect_core`), zero web deps.
  pyHanko does crypto/PAdES; we add qcStatements parsing, EU Trusted List
  matching, and plain-language verdict mapping.
- `api/` — FastAPI app wrapping core. Strictly ephemeral: files processed
  in memory only, never written to disk, never logged. Passwords never stored.
- `web/` — React (Vite) frontend. Mobile-first responsive.
- One Dockerfile at root builds everything for Railway/Render deploy.

## Conventions
- Python 3.12, type hints everywhere, pytest for tests.
- Every validation outcome maps to BOTH a plain-language string and a
  technical-detail string. Never expose raw exceptions to the UI.
- Verdict levels: trusted / partial / not-trusted / no-signatures.
- Never over-claim "Qualified" — conservative fallback on ambiguous certs.
- No legalese in any user-facing copy.

## Commands
- `pytest core/tests` — run core tests
- `uvicorn api.main:app --reload` — run API locally
- `cd web && npm run dev` — run frontend locally
```

**4. Install Claude Code** (if you haven't)

```bash
npm install -g @anthropic-ai/claude-code
cd eidas-inspect && claude
```

---

## Day 1: The validation core (the hard part first)

Everything else is scaffolding around this. Do it first while energy is high.

**Session goal:** `eidas_inspect_core` package that takes PDF bytes (+ optional password) and returns a structured `VerificationResult`.

**Prompt 1 — scaffold + basic validation:**

> Read PRD.md and CLAUDE.md. Create the `core/` package: pyproject.toml, data models (VerificationResult, SignatureItem as described in PRD section 5), and a `verify_pdf(data: bytes, password: str | None) -> VerificationResult` entry point. Use pyHanko for signature discovery, ByteRange integrity checking, and CMS validation. For now, populate Type, Integrity, Who, and When fields; leave Level and Trust chain as "unknown". Handle: unsigned PDFs (no-signatures verdict), corrupted PDFs (raise a typed error), password-protected PDFs. Write pytest tests using fixture PDFs you generate with pyHanko's signing API (self-signed test certs are fine for fixtures).

**Prompt 2 — qcStatements + classification:**

> Add qcStatements parsing per ETSI EN 319 412-5: extract QcCompliance, QcSSCD, and QcType from the signer certificate to classify each item as signature (esign) vs seal (eseal), and Qualified vs Advanced vs Basic. Fall back conservatively — never claim Qualified on ambiguous certs. Distinguish document timestamps from signatures. Map every outcome to plain-language + technical-detail strings.

**Prompt 3 — modification detection:**

> Using pyHanko's incremental-update analysis, set the modified-after-signing flag per signature and generate the plain-language explanation ("The document was changed after this signature was applied"). Add test fixtures: sign a PDF, then modify it with an incremental update, and assert the flag.

**Checkpoint before Day 2:** `pytest` green; `verify_pdf()` returns sensible results on your fixtures. Also test against one *real* signed PDF (a Scrive-signed test doc is ideal — you have plenty).

---

## Day 2: Trusted Lists + revocation

**Prompt 4 — Trusted List engine:**

> Build the Trusted List module: fetch the EU LOTL, resolve member-state TL URLs from it, parse each TL's trust service entries (focus on CA/QC services and QTST timestamp services), and cache everything in memory with per-list staleness flags and a 24h refresh loop. Matching: given a signer cert's issuing CA, determine whether it appears as a granted qualified service. Degraded mode per PRD: if a list is unreachable, verification proceeds and the trust-chain field reports "could not be confirmed right now". Add unit tests with saved sample TL XML files as fixtures.

Note: this is the messiest module — real TL XML varies across member states. Let Claude Code iterate; give it actual failing member-state list URLs when parsing breaks.

**Prompt 5 — revocation:**

> Add OCSP/CRL revocation checking via pyHanko's validation context, with a hard 5-second timeout per endpoint. On timeout/unreachable, mark "revocation status unavailable" rather than failing. Wire revocation results into per-item status and the overall verdict logic.

**Prompt 6 — verdict logic:**

> Implement the overall document verdict per PRD section 6: trusted (all valid + qualified confirmed), partial (mixed), not-trusted (all broken/revoked), no-signatures. Uncertainty (degraded TL, unavailable revocation) lowers confidence honestly in the verdict phrasing rather than guessing. Full test matrix.

---

## Day 3: API layer

**Prompt 7:**

> Build `api/`: FastAPI app with POST /api/verify (multipart PDF + optional password, 50 MB cap, returns VerificationResult as JSON) and POST /api/report (returns a PDF report — verdict snapshot with verification timestamp and file SHA-256 in the footer, generated in-request with reportlab or weasyprint). Add IP-based rate limiting (10 verifications/hour, slowapi is fine), and a persistent anonymous counter (SQLite: date, count, verdict distribution — nothing else). Enforce ephemerality: file bytes live only in request scope, and configure logging so filenames and content never appear in logs. Health endpoint for the hosting platform. Serve the built frontend as static files from the same app.

**Checkpoint:** `curl -F "file=@test.pdf" localhost:8000/api/verify` returns clean JSON for every fixture.

---

## Day 4–5: Frontend

Two options — pick one:

- **Option A (recommended for coherence):** build it in Claude Code inside `web/`.
- **Option B:** prototype the visual design in Lovable first, then bring the components into the repo with Claude Code. Good if you want to iterate on look-and-feel fast, but budget the porting time.

**Prompt 8 — structure:**

> Read PRD.md sections 3, 6, and 7. Build the React (Vite) frontend in `web/`: landing page with drag-and-drop + tap-to-upload and the ephemerality trust promise; password prompt state; animated step-sequence verification loading state with real stages; verdict page with traffic-light banner and per-item cards (six fields, icons per type, expandable technical-details drawer on failures); neutral unsigned state with vendor-neutral signing suggestions; educational tooltips for Qualified/QES/QSeal/Trusted List/timestamp; download-report button; friendly error and rate-limit states. Mobile-first responsive. Icons + text alongside colors (never color alone). Footer: personal-project note + informational disclaimer per PRD.

**Prompt 9 — design pass:**

> Now a pure visual pass: consumer-friendly with personality, not corporate. Choose a distinctive type pairing and a palette where the traffic-light verdict colors feel native, not bolted on. The verification animation should feel alive and ongoing. Avoid anything resembling Scrive's brand (their palette/style: [paste a reference or just say "avoid green-dominant SaaS minimalism"]).

**Checkpoint:** full flow works locally end-to-end on desktop and phone-sized viewport, including all edge states (unsigned, wrong password, corrupted, rate-limited).

---

## Day 6: Deploy

**1. Dockerfile** — prompt Claude Code:

> Create a single root Dockerfile: build the Vite frontend, install the Python packages, run FastAPI with uvicorn serving both API and static frontend on $PORT. Add a railway.json / render.yaml as appropriate.

**2. Railway (simplest path):**

- Sign up at railway.app with your GitHub account
- New Project → Deploy from GitHub repo → select `eidas-inspect`
- It detects the Dockerfile and deploys; every `git push` redeploys
- Settings → Networking → Generate Domain (you get `something.up.railway.app`; add a custom domain later if you buy one)

Render is equivalent if you prefer (render.com → New Web Service → connect repo). Either works; don't agonize.

**3. Production smoke test:** run the full flow on the live URL from your phone, including a real signed PDF, an unsigned PDF, and the report download.

---

## Day 7: Polish — this is the portfolio payoff

**1. Real-document test set.** Verify against genuinely signed PDFs from different sources — a BankID/Scrive-signed doc, a D-Trust or other QTSP-sealed doc, your broken-seal fixture. Fix what surprises you (something will).

**2. README** — prompt Claude Code:

> Write the README: one-line pitch, a hero screenshot of the verdict page, a short "why" (existing validators are illegible), a demo GIF placeholder, the privacy promise, architecture diagram (core/api/web), local dev instructions, honest limitations section (informational tool, not an Article 33 qualified validation service; PDF-only for now; TL matching simplifications), and roadmap (XAdES/ASiC, API tier). Personal-project framing, MIT license.

**3. Demo GIF:** record the drop → animation → verdict flow (macOS: Cmd+Shift+5, then convert with `ffmpeg -i demo.mov demo.gif` or use Gifski). This single asset does more for the repo than anything else.

**4. Pin the repo** on your GitHub profile.

---

## Working effectively with Claude Code on this

- **One module per session.** Fresh session per prompt block above; the CLAUDE.md carries the context.
- **Make it prove things.** End every session with "run the tests and show me the output" — don't accept "this should work".
- **Feed it real failures.** When a member-state TL or a real cert breaks parsing, paste the actual error/XML back in; that's where the iteration value is.
- **Plan mode for the tricky bits.** For Day 2's TL engine, start with "plan this before writing code" (Shift+Tab into plan mode) and review the plan first.
- **Commit after every green checkpoint.** `git commit` at each day's checkpoint so you can always roll back a bad session.

## Risk watch-list (where the week can slip)

1. **TL parsing (Day 2)** — the known rabbit hole. If it's eating the schedule, ship with a subset of member states parsed correctly and honest "could not confirm" for the rest; that's PRD-compliant degraded mode, not a failure.
2. **Password-protected PDF handling** — pyHanko supports it but test both standard and AES-256 encrypted PDFs early.
3. **PDF report generation** — keep it simple (clean single-page reportlab layout); don't try to pixel-match the web verdict page.
4. **Scope creep on the frontend animation** — timebox it to half a day; a good CSS step-sequence beats a perfect one that costs Day 7.
