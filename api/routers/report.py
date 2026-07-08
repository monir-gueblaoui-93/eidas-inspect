from fastapi import APIRouter, Response

from .. import schemas
from ..services.report_pdf import render_report

router = APIRouter()


@router.post('/api/report')
async def report(result: schemas.VerificationResultOut) -> Response:
    """Renders a PDF snapshot of an already-computed verification result.

    Takes the JSON result /api/verify just returned rather than re-verifying
    the file: the client already has everything needed to render a report,
    and this avoids re-uploading the PDF (and re-asking for its password)
    just to produce a summary of a verdict that was already computed.
    """
    pdf_bytes = render_report(result)
    return Response(
        content=pdf_bytes,
        media_type='application/pdf',
        headers={'Content-Disposition': 'attachment; filename="eidas-inspect-report.pdf"'},
    )
