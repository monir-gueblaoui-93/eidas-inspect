import asyncio
import hashlib
import io
from datetime import datetime, timezone

from asn1crypto import x509
from pyhanko.pdf_utils.crypt.api import AuthStatus
from pyhanko.pdf_utils.misc import PdfError
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.diff_analysis import ModificationLevel
from pyhanko.sign.validation.pdf_embedded import (
    EmbeddedPdfSignature,
    async_validate_pdf_signature,
    async_validate_pdf_timestamp,
    collect_embedded_signatures,
)
from pyhanko.sign.validation.status import SignatureCoverageLevel

from .errors import CorruptedPdfError, IncorrectPasswordError, PasswordRequiredError
from .models import (
    IntegrityStatus,
    SignatureItem,
    SignatureType,
    TimestampQuality,
    VerificationResult,
    VerificationVerdict,
)


def verify_pdf(data: bytes, password: str | None = None) -> VerificationResult:
    document_sha256 = hashlib.sha256(data).hexdigest()
    verified_at = datetime.now(timezone.utc)

    reader = _open_reader(data, password)
    embedded_sigs = collect_embedded_signatures(reader)

    if not embedded_sigs:
        return VerificationResult(
            verdict=VerificationVerdict.NO_SIGNATURES,
            items=[],
            document_sha256=document_sha256,
            verified_at=verified_at,
        )

    items = [_build_signature_item(sig) for sig in embedded_sigs]
    return VerificationResult(
        verdict=_overall_verdict(items),
        items=items,
        document_sha256=document_sha256,
        verified_at=verified_at,
    )


def _open_reader(data: bytes, password: str | None) -> PdfFileReader:
    try:
        reader = PdfFileReader(io.BytesIO(data), strict=False)
    except (PdfError, ValueError) as e:
        raise CorruptedPdfError('The file could not be read as a PDF.') from e

    if reader.encrypted:
        if password is None:
            raise PasswordRequiredError('This PDF is password-protected.')
        try:
            auth_result = reader.decrypt(password)
        except PdfError as e:
            raise IncorrectPasswordError(
                'The password did not unlock this PDF.'
            ) from e
        if auth_result.status == AuthStatus.FAILED:
            raise IncorrectPasswordError('The password did not unlock this PDF.')

    return reader


def _build_signature_item(embedded_sig: EmbeddedPdfSignature) -> SignatureItem:
    is_timestamp = embedded_sig.sig_object_type == '/DocTimeStamp'
    sig_type = SignatureType.TIMESTAMP if is_timestamp else SignatureType.SIGNATURE

    try:
        if is_timestamp:
            status = asyncio.run(async_validate_pdf_timestamp(embedded_sig))
        else:
            status = asyncio.run(async_validate_pdf_signature(embedded_sig))
    except Exception as e:
        return _unreadable_signature_item(sig_type, e)

    modification_level = status.modification_level
    integrity = IntegrityStatus(
        intact=status.intact,
        signature_valid=status.valid,
        fully_covered=(
            status.coverage is not None
            and status.coverage >= SignatureCoverageLevel.ENTIRE_REVISION
        ),
        modified_after_signing=(
            None
            if modification_level is None
            else modification_level is not ModificationLevel.NONE
        ),
    )

    signing_time, timestamp_quality = _signing_time_info(is_timestamp, status)
    plain, technical = _explanations(sig_type, integrity)

    return SignatureItem(
        type=sig_type,
        integrity=integrity,
        plain_explanation=plain,
        technical_detail=technical,
        signer_name=_friendly_name(status.signing_cert.subject, 'common_name'),
        issuing_tsp=_friendly_name(status.signing_cert.issuer, 'organization_name'),
        signing_time=signing_time,
        timestamp_quality=timestamp_quality,
    )


def _unreadable_signature_item(sig_type: SignatureType, error: Exception) -> SignatureItem:
    integrity = IntegrityStatus(
        intact=False,
        signature_valid=False,
        fully_covered=False,
        modified_after_signing=None,
    )
    return SignatureItem(
        type=sig_type,
        integrity=integrity,
        plain_explanation="This signature could not be read or validated.",
        technical_detail=f'{type(error).__name__}: {error}',
    )


def _signing_time_info(is_timestamp: bool, status) -> tuple[datetime | None, TimestampQuality]:
    if is_timestamp:
        return status.timestamp, TimestampQuality.UNKNOWN

    timestamp_validity = status.timestamp_validity
    if timestamp_validity is not None:
        return timestamp_validity.timestamp, TimestampQuality.UNKNOWN

    return status.signer_reported_dt, TimestampQuality.CLAIMED_ONLY


def _explanations(sig_type: SignatureType, integrity: IntegrityStatus) -> tuple[str, str]:
    noun = 'timestamp' if sig_type is SignatureType.TIMESTAMP else 'signature'

    if not integrity.intact or not integrity.signature_valid:
        return (
            f"This {noun} is broken and cannot be relied on.",
            'Digest/signature verification failed: '
            f'intact={integrity.intact}, valid={integrity.signature_valid}.',
        )

    if integrity.modified_after_signing:
        return (
            f"The document was changed after this {noun} was applied.",
            'Incremental update analysis detected modifications past the '
            f'signed revision (coverage={ "full file" if integrity.fully_covered else "partial" }).',
        )

    return (
        f"This {noun} is intact and has not been tampered with.",
        'Digest and cryptographic signature verification succeeded; '
        'qualification and trust-chain status have not been checked yet.',
    )


def _friendly_name(name: x509.Name, preferred_key: str) -> str | None:
    native = name.native
    value = native.get(preferred_key)
    if isinstance(value, str) and value:
        return value
    human_friendly = name.human_friendly
    return human_friendly or None


def _overall_verdict(items: list[SignatureItem]) -> VerificationVerdict:
    if all(not i.integrity.intact or not i.integrity.signature_valid for i in items):
        return VerificationVerdict.NOT_TRUSTED
    # At least one signature is intact and cryptographically valid, but level
    # and trust-chain status are not yet determined, so this cannot be "trusted".
    return VerificationVerdict.PARTIAL
