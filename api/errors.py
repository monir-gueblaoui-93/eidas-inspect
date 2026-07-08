"""Typed API errors and their FastAPI exception handlers.

Every handler returns the same envelope shape --
``{"error": {"code": "...", "message": "..."}}`` -- so the frontend can
branch on ``code`` without parsing prose. Messages are friendly, per
CLAUDE.md: no raw exceptions ever reach the client.
"""

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from eidas_inspect_core import (
    CorruptedPdfError,
    IncorrectPasswordError,
    PasswordRequiredError,
)


class NotAPdfError(Exception):
    """The upload doesn't even look like a PDF (no ``%PDF-`` header) --
    distinct from :class:`CorruptedPdfError`, which means it looked like a
    PDF but couldn't actually be parsed."""


class FileTooLargeError(Exception):
    def __init__(self, max_bytes: int):
        self.max_bytes = max_bytes
        super().__init__(f'File exceeds the {max_bytes}-byte cap.')


def _error_response(status_code: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(
        status_code=status_code, content={'error': {'code': code, 'message': message}}
    )


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(NotAPdfError)
    async def _not_a_pdf(request: Request, exc: NotAPdfError) -> JSONResponse:
        return _error_response(400, 'not_a_pdf', 'PDF only for now.')

    @app.exception_handler(CorruptedPdfError)
    async def _corrupted(request: Request, exc: CorruptedPdfError) -> JSONResponse:
        return _error_response(400, 'corrupted_pdf', str(exc))

    @app.exception_handler(PasswordRequiredError)
    async def _password_required(request: Request, exc: PasswordRequiredError) -> JSONResponse:
        return _error_response(400, 'password_required', str(exc))

    @app.exception_handler(IncorrectPasswordError)
    async def _incorrect_password(
        request: Request, exc: IncorrectPasswordError
    ) -> JSONResponse:
        return _error_response(400, 'incorrect_password', str(exc))

    @app.exception_handler(FileTooLargeError)
    async def _too_large(request: Request, exc: FileTooLargeError) -> JSONResponse:
        max_mb = exc.max_bytes // (1024 * 1024)
        return _error_response(
            413, 'file_too_large', f'Files over {max_mb} MB are not supported.'
        )
