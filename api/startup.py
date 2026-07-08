"""One-time startup checks that need to run before the app starts serving
traffic, but must never prevent it from starting.
"""

import logging
import os

logger = logging.getLogger(__name__)

FALLBACK_COUNTERS_DB_PATH = '/tmp/eidas-inspect-counters.db'


def resolve_counters_db_path(configured_path: str) -> str:
    """Verify the configured counters DB's directory is writable; fall back
    to a `/tmp` path with a logged warning if not.

    Counters are anonymous, nice-to-have verification stats -- never worth
    crashing startup, or any individual request, over. In production this
    matters when the configured path (default `/data/counters.db`) points
    at a volume that hasn't been mounted yet: the service should still come
    up and serve verifications, just without persistent counters until the
    volume is attached.
    """
    directory = os.path.dirname(configured_path) or '.'
    try:
        os.makedirs(directory, exist_ok=True)
        probe_path = os.path.join(directory, '.write_test')
        with open(probe_path, 'w') as probe:
            probe.write('')
        os.remove(probe_path)
        return configured_path
    except OSError as e:
        logger.warning(
            "Counters DB path %r isn't writable (%s) -- falling back to %r. "
            'Verification counters will not persist across restarts until a '
            'writable volume is mounted at the configured path.',
            configured_path,
            e,
            FALLBACK_COUNTERS_DB_PATH,
        )
        return FALLBACK_COUNTERS_DB_PATH
