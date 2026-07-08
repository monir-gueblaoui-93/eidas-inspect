# eidas-inspect — web

React (Vite) frontend for eidas-inspect. Single-page app, no router: a
plain state machine in `src/App.jsx` drives `landing → (password) →
verifying → result`.

## Development

```bash
npm install
npm run dev
```

The dev server proxies `/api/*` to `http://localhost:8000` (see
`vite.config.js`), so run the API locally alongside it:

```bash
# from the repo root, in a separate terminal
uvicorn api.main:app --reload
```

## Structure

- `src/theme.css` — design tokens (colors, type, spacing). Start here for
  any visual change.
- `src/app.css` — component styles, built on those tokens.
- `src/api.js` — thin client for `/api/verify` and `/api/report`.
- `src/itemPresentation.js` — pure functions mapping a `SignatureItemOut`
  (see `api/schemas.py`) to plain-language display data.
- `src/components/` — one component per screen/element.
- `src/glossary.js` — plain-language eIDAS term definitions, surfaced via
  the `Term` component.

## Build

```bash
npm run build
```

Output goes to `dist/`, which the production Dockerfile copies into
`api/static/` so FastAPI serves the built frontend and the API from one
origin.
