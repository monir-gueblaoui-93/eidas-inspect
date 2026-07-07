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
    SignatureLevel,
    SignatureType,
    TimestampQuality,
    VerificationResult,
    VerificationVerdict,
)
from .qc_statements import QcStatements, extract_qc_statements


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
    provisional_type = (
        SignatureType.TIMESTAMP if is_timestamp else SignatureType.SIGNATURE
    )

    try:
        if is_timestamp:
            status = asyncio.run(async_validate_pdf_timestamp(embedded_sig))
        else:
            status = asyncio.run(async_validate_pdf_signature(embedded_sig))
    except Exception as e:
        return _unreadable_signature_item(provisional_type, e)

    modified_after_signing, lta_extended = _modification_status(
        status.modification_level
    )
    integrity = IntegrityStatus(
        intact=status.intact,
        signature_valid=status.valid,
        fully_covered=(
            status.coverage is not None
            and status.coverage >= SignatureCoverageLevel.ENTIRE_REVISION
        ),
        modified_after_signing=modified_after_signing,
        lta_extended=lta_extended,
    )

    coverage_name = status.coverage.name if status.coverage is not None else 'UNKNOWN'
    signing_time, timestamp_quality = _signing_time_info(is_timestamp, status)

    if is_timestamp:
        sig_type, level, qc_note = SignatureType.TIMESTAMP, SignatureLevel.UNKNOWN, None
    else:
        qc = extract_qc_statements(status.signing_cert)
        sig_type, level, qc_note = _classify_certificate(qc, integrity)

    plain, technical = _explanations(sig_type, integrity, coverage_name, level, qc_note)

    return SignatureItem(
        type=sig_type,
        level=level,
        integrity=integrity,
        plain_explanation=plain,
        technical_detail=technical,
        signer_name=_friendly_name(status.signing_cert.subject, 'common_name'),
        issuing_tsp=_friendly_name(status.signing_cert.issuer, 'organization_name'),
        signing_time=signing_time,
        timestamp_quality=timestamp_quality,
    )


def _classify_certificate(
    qc: QcStatements, integrity: IntegrityStatus
) -> tuple[SignatureType, SignatureLevel, str]:
    """Classify signer type and level from qcStatements (ETSI EN 319 412-5).

    Conservative by design: QUALIFIED is only claimed when QcCompliance,
    QcSSCD, and an unambiguous QcType (esign xor eseal) are all present.
    Anything less falls back to ADVANCED, with the gap noted so the UI can
    surface it. Type (signature vs seal) is derived from QcType independently
    of the level, since a seal claim doesn't stop being a seal claim just
    because the signature turned out to be broken.
    """
    type_matches = qc.qc_types & {'esign', 'eseal'}
    if type_matches == {'esign'}:
        sig_type = SignatureType.SIGNATURE
        type_unambiguous = True
    elif type_matches == {'eseal'}:
        sig_type = SignatureType.SEAL
        type_unambiguous = True
    else:
        sig_type = SignatureType.SIGNATURE
        type_unambiguous = False

    if not integrity.intact or not integrity.signature_valid:
        return (
            sig_type,
            SignatureLevel.BASIC,
            'Signature integrity could not be confirmed, so qualification '
            'was not assessed.',
        )

    if qc.qc_compliance and qc.qc_sscd and type_unambiguous:
        qc_type_name = 'esign' if sig_type is SignatureType.SIGNATURE else 'eseal'
        return (
            sig_type,
            SignatureLevel.QUALIFIED,
            f'Certificate asserts QcCompliance, QcSSCD, and QcType={qc_type_name}; '
            'the issuing provider has not yet been verified against the EU '
            'Trusted List.',
        )

    if not qc.qc_compliance and not qc.qc_sscd and not qc.qc_types:
        return (
            sig_type,
            SignatureLevel.ADVANCED,
            'No qcStatements extension found on the signing certificate; '
            'treated as a non-qualified advanced signature.',
        )

    missing = []
    if not qc.qc_compliance:
        missing.append('QcCompliance')
    if not qc.qc_sscd:
        missing.append('QcSSCD')
    if not type_unambiguous:
        missing.append('an unambiguous QcType (esign/eseal)')
    return (
        sig_type,
        SignatureLevel.ADVANCED,
        'Certificate qcStatements do not clearly support qualified status '
        f"(missing or ambiguous: {', '.join(missing)}); falling back to advanced.",
    )


def _modification_status(
    modification_level: ModificationLevel | None,
) -> tuple[bool | None, bool]:
    """Map pyHanko's modification level to (modified_after_signing, lta_extended).

    Only permissible PAdES long-term-archival additions (a document
    timestamp or DSS update) are excluded from ``modified_after_signing``;
    form-filling, annotations, and anything else fall back conservatively
    to "modified" until this classifier is refined further.
    """
    if modification_level is None:
        return None, False
    if modification_level is ModificationLevel.NONE:
        return False, False
    if modification_level is ModificationLevel.LTA_UPDATES:
        return False, True
    return True, False


def _unreadable_signature_item(sig_type: SignatureType, error: Exception) -> SignatureItem:
    integrity = IntegrityStatus(
        intact=False,
        signature_valid=False,
        fully_covered=False,
        modified_after_signing=None,
        lta_extended=False,
    )
    return SignatureItem(
        type=sig_type,
        integrity=integrity,
        plain_explanation=f"This {_noun_for(sig_type)} could not be read or validated.",
        technical_detail=f'{type(error).__name__}: {error}',
    )


def _noun_for(sig_type: SignatureType) -> str:
    if sig_type is SignatureType.TIMESTAMP:
        return 'timestamp'
    if sig_type is SignatureType.SEAL:
        return 'seal'
    return 'signature'


def _signing_time_info(is_timestamp: bool, status) -> tuple[datetime | None, TimestampQuality]:
    if is_timestamp:
        return status.timestamp, TimestampQuality.UNKNOWN

    timestamp_validity = status.timestamp_validity
    if timestamp_validity is not None:
        return timestamp_validity.timestamp, TimestampQuality.UNKNOWN

    return status.signer_reported_dt, TimestampQuality.CLAIMED_ONLY


def _explanations(
    sig_type: SignatureType,
    integrity: IntegrityStatus,
    coverage_name: str,
    level: SignatureLevel,
    qc_note: str | None,
) -> tuple[str, str]:
    noun = _noun_for(sig_type)
    qc_suffix = f' {qc_note}' if qc_note else ''

    if not integrity.intact or not integrity.signature_valid:
        return (
            f"This {noun} is broken and cannot be relied on.",
            'Digest/signature verification failed: '
            f'intact={integrity.intact}, valid={integrity.signature_valid}.'
            + qc_suffix,
        )

    if integrity.modified_after_signing:
        return (
            f"The document was changed after this {noun} was applied.",
            'Incremental update analysis found changes beyond what is '
            f'permitted after signing (coverage={coverage_name}).' + qc_suffix,
        )

    if integrity.lta_extended:
        plain = (
            f"This {noun} is intact. The document was later extended to "
            "keep it verifiable in the long term."
        )
        technical = (
            'Incremental update analysis found only long-term-archival '
            'additions (document timestamp/DSS update) after the signed '
            f'revision, consistent with PAdES-LTA (coverage={coverage_name}).'
        )
    else:
        plain = f"This {noun} is intact and has not been tampered with."
        technical = 'Digest and cryptographic signature verification succeeded.'

    return plain + _qualification_clause(level, noun), technical + qc_suffix


def _qualification_clause(level: SignatureLevel, noun: str) -> str:
    if level is SignatureLevel.QUALIFIED:
        return (
            f" The certificate declares this a qualified {noun}; the "
            "issuing provider has not yet been checked against the EU "
            "Trusted List."
        )
    if level is SignatureLevel.ADVANCED:
        return (
            f" This is an advanced {noun}; the certificate does not clearly "
            "declare qualified status."
        )
    return ''


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
