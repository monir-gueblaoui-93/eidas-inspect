"""Verification service: orchestrates verify_pdf against the app's live
Trusted List snapshot and revocation config, off the event loop's thread
(verify_pdf is a synchronous function that runs its own event loop per
signature internally, so it must never be awaited directly from within a
running loop).
"""

from starlette.concurrency import run_in_threadpool

from eidas_inspect_core import VerificationResult, verify_pdf
from eidas_inspect_core.revocation import RevocationFetchers
from eidas_inspect_core.trust_list import TrustListCache

from ..config import settings
from ..errors import FileTooLargeError, NotAPdfError

_PDF_MAGIC = b'%PDF-'


def check_upload_size(data: bytes) -> None:
    if len(data) > settings.max_upload_bytes:
        raise FileTooLargeError(settings.max_upload_bytes)


def check_looks_like_pdf(data: bytes) -> None:
    if not data.startswith(_PDF_MAGIC):
        raise NotAPdfError()


async def verify_upload(
    data: bytes,
    password: str | None,
    trust_list_cache: TrustListCache,
    revocation_fetchers: RevocationFetchers | None,
) -> VerificationResult:
    check_upload_size(data)
    check_looks_like_pdf(data)
    return await run_in_threadpool(
        verify_pdf,
        data,
        password,
        trust_list_cache.snapshot,
        settings.check_revocation,
        revocation_fetchers,
    )
