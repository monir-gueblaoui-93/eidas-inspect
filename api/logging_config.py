"""Logging setup.

Ephemerality rule for every logger in this package: never log an uploaded
filename, a password, or PDF bytes/content. Uvicorn's own access log only
ever records method/path/status (the filename lives inside the multipart
*body*, never the URL), so the default access log is safe as-is -- the
discipline required is entirely on our own log calls, which must stick to
exception type names and the already-sanitized messages our own code
produces (never raw exception args from a third-party library, which could
echo back parsed content).

Logs go to stdout explicitly (``logging.basicConfig``'s default is
stderr) -- Railway and most container platforms treat stdout as the
primary log stream.
"""

import logging
import sys


def configure_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(levelname)s %(name)s: %(message)s',
        stream=sys.stdout,
    )
