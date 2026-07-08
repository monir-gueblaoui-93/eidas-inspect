"""In-request PDF verification report generation via reportlab.

Renders the same result /api/verify already returned as JSON into a
single-page PDF snapshot -- no re-verification, no stored state, built
entirely in memory and returned within the same request cycle.
"""

import io
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from .. import schemas

_VERDICT_COLORS = {
    'trusted': colors.HexColor('#1a7f37'),
    'partial': colors.HexColor('#9a6700'),
    'not-trusted': colors.HexColor('#cf222e'),
    'no-signatures': colors.HexColor('#57606a'),
}

_DISCLAIMER = (
    'eidas-inspect is a personal project and an informational verification '
    'tool -- it is not a qualified validation service under eIDAS Article 33, '
    'and this report is not legal advice.'
)


def render_report(result: schemas.VerificationResultOut) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        pageCompression=0,
        topMargin=20 * mm,
        bottomMargin=20 * mm,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        title='eidas-inspect verification report',
    )

    styles = getSampleStyleSheet()
    body = styles['BodyText']
    small = ParagraphStyle(
        'small', parent=body, fontSize=8, textColor=colors.HexColor('#57606a')
    )
    verdict_style = ParagraphStyle(
        'verdict',
        parent=styles['Heading2'],
        textColor=_VERDICT_COLORS.get(result.verdict, colors.black),
        spaceAfter=4,
    )

    story = [
        Paragraph('eidas-inspect verification report', styles['Heading1']),
        Spacer(1, 4 * mm),
        Paragraph(result.plain_summary, verdict_style),
        Spacer(1, 6 * mm),
    ]

    if result.items:
        header = ['Type', 'Level', 'Who', 'Integrity', 'When', 'Trust chain', 'Revocation']
        rows = [header]
        for item in result.items:
            rows.append(
                [
                    item.type,
                    item.level,
                    item.signer_name or item.issuing_tsp or '—',
                    'Intact'
                    if item.integrity.intact and item.integrity.signature_valid
                    else 'Broken',
                    item.signing_time.strftime('%Y-%m-%d %H:%M UTC')
                    if item.signing_time
                    else '—',
                    item.trust_chain_status,
                    item.revocation_status,
                ]
            )
        table = Table(rows, repeatRows=1, hAlign='LEFT')
        table.setStyle(
            TableStyle(
                [
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f6f8fa')),
                    ('FONTSIZE', (0, 0), (-1, -1), 8),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#d0d7de')),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('LEFTPADDING', (0, 0), (-1, -1), 4),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 4),
                ]
            )
        )
        story.append(table)
        story.append(Spacer(1, 6 * mm))

        for index, item in enumerate(result.items, start=1):
            story.append(Paragraph(f'{index}. {item.plain_explanation}', body))
            story.append(Spacer(1, 2 * mm))

    story.append(Spacer(1, 8 * mm))
    generated_at = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
    story.append(
        Paragraph(
            f'File SHA-256: {result.document_sha256}<br/>Report generated: {generated_at}',
            small,
        )
    )
    story.append(Spacer(1, 3 * mm))
    story.append(Paragraph(_DISCLAIMER, small))

    doc.build(story)
    return buffer.getvalue()
