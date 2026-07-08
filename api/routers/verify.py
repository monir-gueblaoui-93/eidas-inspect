from fastapi import APIRouter, File, Form, Request, UploadFile
from starlette.concurrency import run_in_threadpool

from .. import schemas
from ..config import settings
from ..rate_limit import limiter
from ..services import counters
from ..services.verification import verify_upload

router = APIRouter()


@router.post('/api/verify', response_model=schemas.VerificationResultOut)
@limiter.limit(settings.rate_limit)
async def verify(
    request: Request,
    file: UploadFile = File(...),
    password: str | None = Form(None),
) -> schemas.VerificationResultOut:
    data = await file.read()

    trust_list_cache = request.app.state.trust_list_cache
    revocation_fetchers = request.app.state.revocation_fetchers
    result = await verify_upload(data, password, trust_list_cache, revocation_fetchers)

    await run_in_threadpool(counters.record_verdict, result.verdict.value)

    return schemas.to_response(result)
