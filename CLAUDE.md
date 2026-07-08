# eidas-inspect

Personal project: hosted web service that verifies digital signatures, seals,
and timestamps in PDFs against the eIDAS framework, with radically legible UX.
Full requirements: see PRD.md — treat it as the source of truth.

## Current status

See PROGRESS.md for what's done, key implementation decisions, and what's
next — read it first at the start of a new session before making changes.

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
- `pytest api/tests` — run API tests (offline, reuses core's test fixtures)
- `pip install -e core/ -r api/requirements-dev.txt` — set up the venv for both
  (adds test-only deps; the production image installs `api/requirements.txt` only)
- `uvicorn api.main:app --reload` — run API locally
- `cd web && npm run dev` — run frontend locally
