"""Application settings. Hardcoded defaults with env-var overrides for the
handful of things that genuinely vary by deploy target (paths, refresh
cadence) -- this is a personal project, not a multi-tenant config surface.
"""

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    max_upload_bytes: int = 50 * 1024 * 1024
    rate_limit: str = '10/hour'
    trust_list_refresh_interval_seconds: int = 24 * 60 * 60
    check_revocation: bool = True
    """Always on for the live API -- it's core to the trust verdict. No
    opt-out exposed in v1; the per-endpoint 5s-per-OCSP/CRL-endpoint timeout
    already bounds the added latency."""
    static_dir: str = os.environ.get(
        'EIDAS_INSPECT_STATIC_DIR',
        os.path.join(os.path.dirname(__file__), 'static'),
    )
    counters_db_path: str = os.environ.get(
        'EIDAS_INSPECT_COUNTERS_DB',
        os.path.join(os.path.dirname(__file__), 'data', 'counters.db'),
    )


settings = Settings()
