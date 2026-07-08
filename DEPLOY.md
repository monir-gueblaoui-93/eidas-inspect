# Deploying eidas-inspect to Railway

One Dockerfile builds everything (frontend + API); Railway builds and runs
it directly, no separate static hosting or build pipeline needed.

## One-time setup

1. **Sign up / log in** at [railway.app](https://railway.app) with your
   GitHub account.
2. **New Project → Deploy from GitHub repo → `eidas-inspect`.** Railway
   detects the root `Dockerfile` automatically (`railway.json` pins the
   builder explicitly, so there's no ambiguity even if a `render.yaml` or
   similar shows up later).
3. **Add a volume for the counters database:**
   - Project → your service → **Settings → Volumes → New Volume**
   - Mount path: **`/data`**
   - Size: 1 GB is overkill already (the counters DB is a handful of rows
     per day) -- the smallest size Railway offers is fine.
   - Without this volume, the service still works correctly (see
     "Counters without a volume" below) -- it just won't remember counts
     across deploys/restarts.
4. **Generate a public domain:** Settings → Networking → **Generate
   Domain**. You'll get `something.up.railway.app`; a custom domain can be
   added later the same way.
5. **Environment variables:** none are required to get a working
   deployment -- every setting has a sane default (see the table below).
   Only add one if you want to override a default.

That's it. Railway builds the image and starts the container; the health
check at `/api/health` (configured in `railway.json`) gates rollout so a
broken build/boot doesn't replace a working deployment.

## How deploys work afterward

**`git push` to your default branch = redeploy.** Railway watches the
connected GitHub repo and rebuilds/redeploys automatically on every push.
Nothing else to do -- no manual trigger, no separate CI step.

To ship a change:

```bash
git push origin main
```

Watch the build in Railway's dashboard (Deployments tab). Once it passes
the healthcheck, traffic cuts over.

## Environment variables reference

All optional; production-sane defaults are baked in.

| Variable | Default | What it controls |
|---|---|---|
| `PORT` | *(injected by Railway)* | Port uvicorn binds to. Don't set this yourself. |
| `EIDAS_INSPECT_COUNTERS_DB` | `/data/counters.db` | Anonymous verification counters. Falls back to `/tmp` with a logged warning if unwritable -- never crashes the service. |
| `EIDAS_INSPECT_MAX_UPLOAD_BYTES` | `52428800` (50 MB) | Upload size cap, enforced before parsing starts. |
| `EIDAS_INSPECT_RATE_LIMIT` | `10/hour` | Per-IP rate limit on `/api/verify`, in slowapi's `<count>/<period>` syntax. |
| `EIDAS_INSPECT_TL_REFRESH_SECONDS` | `86400` (24h) | How often the background task re-fetches the EU Trusted Lists. |
| `EIDAS_INSPECT_STATIC_DIR` | `api/static` (baked into the image by the Dockerfile) | Where FastAPI serves the built frontend from. No reason to override this in production. |

## Counters without a volume

If you skip the `/data` volume (or it's ever unmounted/misconfigured),
the service does **not** fail to start or fail requests. At startup it
probes whether `/data` is actually writable; if not, it logs a warning and
uses `/tmp/eidas-inspect-counters.db` instead -- counters just won't
survive a restart. Verified locally: `docker run` with `/data` mounted
read-only still serves `/api/verify` successfully and logs exactly this
fallback. Look for a line like:

```
WARNING api.startup: Counters DB path '/data/counters.db' isn't writable
(...) -- falling back to '/tmp/eidas-inspect-counters.db'.
```

in `railway logs` if you ever want to confirm which path is active.

## Production smoke test (do this after the first deploy)

From your phone, against the live `*.up.railway.app` URL:

1. Upload a real signed PDF -- confirm the verdict banner and per-item
   cards render correctly.
2. Upload an unsigned PDF -- confirm the neutral "no signatures" state,
   not an error.
3. Download the report from a completed verification.
4. Check `/api/health` directly -- should return `200` with
   `trust_list.status` eventually settling to `"fresh"` (or `"stale"`,
   which is often genuinely correct -- see below) once the first
   background refresh completes, a few seconds to ~30s after boot.

Real-world EU Trusted List note: it's normal and expected for
`trust_list.status` to read `"stale"` fairly often in production -- one
or two EU member states' trusted-list endpoints being temporarily
unreachable (rate limits, TLS cert issues, etc.) is common, and any single
territory's failure marks the whole snapshot as degraded even though
everything else is working fine. This does not mean the service is
broken; it means one piece of upstream data is honestly flagged as
unconfirmed, which is the whole point of the degraded-but-honest design.

## Local container verification (already done once, repeatable)

```bash
docker build -t eidas-inspect:local .
docker run -d --name eidas-inspect-test -p 8080:8080 -e PORT=8080 eidas-inspect:local
open http://localhost:8080
# ... test the flow ...
docker rm -f eidas-inspect-test
```

To specifically test the /data-unwritable fallback path:

```bash
docker run -d --name eidas-inspect-ro -p 8081:8081 -e PORT=8081 --tmpfs /data:ro eidas-inspect:local
docker logs eidas-inspect-ro | grep -i counter
docker rm -f eidas-inspect-ro
```
