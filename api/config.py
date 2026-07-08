"""Application settings. Hardcoded defaults with env-var overrides for the
handful of things that genuinely vary by deploy target (paths, limits,
refresh cadence) -- this is a personal project, not a multi-tenant config
surface.
"""

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    max_upload_bytes: int = int(
        os.environ.get('EIDAS_INSPECT_MAX_UPLOAD_BYTES', 50 * 1024 * 1024)
    )
    rate_limit: str = os.environ.get('EIDAS_INSPECT_RATE_LIMIT', '10/hour')
    trust_list_refresh_interval_seconds: int = int(
        os.environ.get('EIDAS_INSPECT_TL_REFRESH_SECONDS', 24 * 60 * 60)
    )
    check_revocation: bool = True
    """Always on for the live API -- it's core to the trust verdict. No
    opt-out exposed in v1; the per-endpoint 5s-per-OCSP/CRL-endpoint timeout
    already bounds the added latency."""
    static_dir: str = os.environ.get(
        'EIDAS_INSPECT_STATIC_DIR',
        os.path.join(os.path.dirname(__file__), 'static'),
    )
    counters_db_path: str = os.environ.get('EIDAS_INSPECT_COUNTERS_DB', '/data/counters.db')
    """Default assumes a volume mounted at /data (see DEPLOY.md). If that
    path isn't writable -- no volume attached, or running locally -- startup
    falls back to a /tmp path with a logged warning rather than crashing;
    see :func:`api.startup.resolve_counters_db_path`."""


settings = Settings()
