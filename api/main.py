"""FastAPI application factory.

``app`` at module level is what ``uvicorn api.main:app`` runs in
production. ``create_app()`` lets tests build an isolated instance with an
injected, offline Trusted List cache and revocation fetchers and no
background refresh loop, so the whole test suite runs without touching the
network.
"""

import asyncio
import contextlib
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from slowapi.errors import RateLimitExceeded
from starlette.formparsers import MultiPartParser

from eidas_inspect_core.ksi_tool import KsiToolRunner
from eidas_inspect_core.revocation import RevocationFetchers
from eidas_inspect_core.trust_list import TrustListCache

from .config import settings
from .errors import register_exception_handlers
from .logging_config import configure_logging
from .middleware import MaxBodySizeMiddleware
from .rate_limit import limiter, rate_limit_exceeded_handler
from .routers import health, report, verify
from .startup import resolve_counters_db_path

logger = logging.getLogger(__name__)

# Multipart uploads spill to a real temp file on disk once they exceed this
# threshold (Starlette's default is 1 MB). "Strictly ephemeral" means an
# upload within our own size cap must never touch disk, so the in-memory
# spool ceiling is raised to match; anything actually oversized is already
# rejected by MaxBodySizeMiddleware before parsing even starts.
MultiPartParser.spool_max_size = settings.max_upload_bytes


async def _trust_list_refresh_loop(cache: TrustListCache) -> None:
    while True:
        try:
            await cache.refresh()
        except Exception:
            logger.exception('Trusted List refresh failed; will retry next cycle.')
        await asyncio.sleep(settings.trust_list_refresh_interval_seconds)


def create_app(
    *,
    trust_list_cache: TrustListCache | None = None,
    revocation_fetchers: RevocationFetchers | None = None,
    ksi_runner: KsiToolRunner | None = None,
    start_background_refresh: bool = True,
) -> FastAPI:
    configure_logging()
    cache = trust_list_cache if trust_list_cache is not None else TrustListCache()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # Serve degraded (trust_chain_status=UNAVAILABLE) until the first
        # refresh completes, rather than blocking startup on a network call.
        app.state.trust_list_cache = cache
        app.state.revocation_fetchers = revocation_fetchers
        # None here means "skip KSI verification tiers, report
        # NOT_VERIFIED" (see verify.py) -- deliberately not defaulted to a
        # real KsiToolRunner() the way revocation_fetchers implicitly
        # falls back to live network fetchers, because ksi-tool is an
        # optional external binary (not a pip dependency, not guaranteed
        # present) rather than something always available. Production
        # opts in explicitly at the bottom of this module; tests stay
        # hermetic by default.
        app.state.ksi_runner = ksi_runner
        app.state.counters_db_path = resolve_counters_db_path(settings.counters_db_path)
        refresh_task = (
            asyncio.create_task(_trust_list_refresh_loop(cache))
            if start_background_refresh
            else None
        )
        try:
            yield
        finally:
            if refresh_task is not None:
                refresh_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await refresh_task

    app = FastAPI(title='eidas-inspect API', lifespan=lifespan)

    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, rate_limit_exceeded_handler)
    app.add_middleware(MaxBodySizeMiddleware, max_bytes=settings.max_upload_bytes)
    register_exception_handlers(app)

    app.include_router(health.router)
    app.include_router(verify.router)
    app.include_router(report.router)

    app.mount('/', StaticFiles(directory=settings.static_dir, html=True), name='static')
    return app


app = create_app(ksi_runner=KsiToolRunner())
