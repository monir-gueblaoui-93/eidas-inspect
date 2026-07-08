"""ASGI middleware enforcing the upload size cap before any multipart
parsing happens.

This is the first line of defense against an oversized upload ever
touching disk: rejecting on ``Content-Length`` before Starlette's
multipart parser runs means we never even start buffering it. It only
covers requests that declare ``Content-Length`` (true for every normal
browser/curl file upload); a request using chunked transfer encoding
without one would bypass this check, so the verify route also re-checks
the actual byte count after reading -- see ``main.py`` for how the
multipart parser's own in-memory spool threshold is raised to keep
uploads within the accepted size from ever spilling to a temp file
either way.
"""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse


class MaxBodySizeMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, max_bytes: int):
        super().__init__(app)
        self.max_bytes = max_bytes

    async def dispatch(self, request: Request, call_next):
        content_length = request.headers.get('content-length')
        if content_length is not None:
            try:
                declared_size = int(content_length)
            except ValueError:
                declared_size = None
            if declared_size is not None and declared_size > self.max_bytes:
                return _too_large_response(self.max_bytes)
        return await call_next(request)


def _too_large_response(max_bytes: int) -> JSONResponse:
    max_mb = max_bytes // (1024 * 1024)
    return JSONResponse(
        status_code=413,
        content={
            'error': {
                'code': 'file_too_large',
                'message': f'Files over {max_mb} MB are not supported.',
            }
        },
    )
