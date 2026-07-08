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
from pyhanko.sign.validation.qualified.assess import QualificationAssessor
from pyhanko.sign.validation.qualified.tsp import TSPTrustManager
from pyhanko.sign.validation.status import SignatureCoverageLevel
from pyhanko_certvalidator import ValidationContext
from pyhanko_certvalidator.path import ValidationPath

from .errors import CorruptedPdfError, IncorrectPasswordError, PasswordRequiredError
from .models import (
    IntegrityStatus,
    RevocationStatus,
    SignatureItem,
    SignatureLevel,
    SignatureType,
    TimestampQuality,
    TrustChainStatus,
    VerdictBreakdown,
    VerdictReason,
    VerificationResult,
    VerificationVerdict,
)
from .qc_statements import QcStatements, extract_qc_statements
from .revocation import RevocationFetchers, TrackedCRLFetcher, TrackedOCSPFetcher, build_fetchers
from .trust_list import TrustListSnapshot


def verify_pdf(
    data: bytes,
    password: str | None = None,
    trust_list: TrustListSnapshot | None = None,
    check_revocation: bool = False,
    revocation_fetchers: RevocationFetchers | None = None,
) -> VerificationResult:
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
            plain_summary='This document contains no digital signatures.',
            verdict_breakdown=None,
        )

    validation_context, crl_fetcher, ocsp_fetcher = _build_validation_context(
        trust_list, check_revocation, revocation_fetchers
    )
    items = [
        _build_signature_item(
            sig, trust_list, validation_context, crl_fetcher, ocsp_fetcher, verified_at
        )
        for sig in embedded_sigs
    ]
    verdict, plain_summary, breakdown = _overall_verdict(items)
    return VerificationResult(
        verdict=verdict,
        items=items,
        document_sha256=document_sha256,
        verified_at=verified_at,
        plain_summary=plain_summary,
        verdict_breakdown=breakdown,
    )


def _build_validation_context(
    trust_list: TrustListSnapshot | None,
    check_revocation: bool,
    revocation_fetchers: RevocationFetchers | None,
) -> tuple[ValidationContext | None, TrackedCRLFetcher | None, TrackedOCSPFetcher | None]:
    """Build the (optional) shared validation context for this verification
    call.

    Revocation checking is only meaningful alongside a Trusted List snapshot
    (there would be no trust anchor to build a path against otherwise), so
    ``check_revocation`` is a no-op unless ``trust_list`` is also supplied.
    Without it, this preserves the exact pre-revocation behavior: no
    fetching, no network calls, ``trust_chain_status`` stays whatever the
    Trusted List wiring alone produces.
    """
    if trust_list is None:
        return None, None, None

    crl_fetcher = ocsp_fetcher = None
    fetchers = None
    if check_revocation:
        fetchers, crl_fetcher, ocsp_fetcher = build_fetchers(
            revocation_fetchers or RevocationFetchers()
        )

    validation_context = ValidationContext(
        trust_manager=TSPTrustManager(trust_list.registry),
        allow_fetching=check_revocation,
        fetchers=fetchers,
        revocation_mode='soft-fail',
    )
    return validation_context, crl_fetcher, ocsp_fetcher


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


def _build_signature_item(
    embedded_sig: EmbeddedPdfSignature,
    trust_list: TrustListSnapshot | None,
    validation_context: ValidationContext | None,
    crl_fetcher: TrackedCRLFetcher | None,
    ocsp_fetcher: TrackedOCSPFetcher | None,
    verified_at: datetime,
) -> SignatureItem:
    is_timestamp = embedded_sig.sig_object_type == '/DocTimeStamp'
    provisional_type = (
        SignatureType.TIMESTAMP if is_timestamp else SignatureType.SIGNATURE
    )

    try:
        if is_timestamp:
            status = asyncio.run(
                async_validate_pdf_timestamp(embedded_sig, validation_context)
            )
        else:
            status = asyncio.run(
                async_validate_pdf_signature(
                    embedded_sig, signer_validation_context=validation_context
                )
            )
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

    # Only use signing_time as the qualification "moment" when it comes from
    # a verified timestamp, not a bare self-reported claim -- otherwise a
    # forged /M value could be used to pick a moment when a since-withdrawn
    # CA was still granted.
    qualification_moment = (
        signing_time
        if signing_time is not None
        and timestamp_quality is not TimestampQuality.CLAIMED_ONLY
        else verified_at
    )
    trust_chain_status, trust_note = _assess_trust_chain(
        status.validation_path, qualification_moment, trust_list, verified_at
    )

    if is_timestamp:
        sig_type, level, qc_note = SignatureType.TIMESTAMP, SignatureLevel.UNKNOWN, None
        if trust_chain_status is TrustChainStatus.TRUSTED:
            timestamp_quality = TimestampQuality.QUALIFIED_TSA
    else:
        qc = extract_qc_statements(status.signing_cert)
        sig_type, level, qc_note = _classify_certificate(qc, integrity)
        embedded_timestamp = status.timestamp_validity
        if embedded_timestamp is not None:
            ts_trust_status, _ = _assess_trust_chain(
                embedded_timestamp.validation_path,
                embedded_timestamp.timestamp,
                trust_list,
                verified_at,
            )
            if ts_trust_status is TrustChainStatus.TRUSTED:
                timestamp_quality = TimestampQuality.QUALIFIED_TSA

    revocation_status, revocation_note = _assess_revocation(
        status.signing_cert,
        status.revocation_details,
        crl_fetcher,
        ocsp_fetcher,
    )

    verdict_reason = _classify_verdict_reason(
        sig_type, level, integrity, trust_chain_status, revocation_status, timestamp_quality
    )

    plain, technical = _explanations(
        sig_type,
        integrity,
        coverage_name,
        level,
        qc_note,
        trust_chain_status,
        trust_note,
        timestamp_quality,
        revocation_status,
        revocation_note,
    )

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
        trust_chain_status=trust_chain_status,
        revocation_status=revocation_status,
        verdict_reason=verdict_reason,
    )


def _classify_verdict_reason(
    sig_type: SignatureType,
    level: SignatureLevel,
    integrity: IntegrityStatus,
    trust_chain_status: TrustChainStatus,
    revocation_status: RevocationStatus,
    timestamp_quality: TimestampQuality,
) -> VerdictReason:
    """Classify why this item counts the way it does towards the
    document-level verdict.

    Priority order (most severe first): a real problem (broken, tampered,
    revoked, confirmed not-trusted) always outranks an honest gap
    (unconfirmed), which always outranks "simply not qualified" -- matching
    how a single broken signature dominates the document summary even
    alongside an unrelated, perfectly valid advanced one.
    """
    if not integrity.intact or not integrity.signature_valid:
        return VerdictReason.BROKEN
    if integrity.modified_after_signing:
        return VerdictReason.TAMPERED
    if revocation_status is RevocationStatus.REVOKED:
        return VerdictReason.REVOKED
    if trust_chain_status is TrustChainStatus.UNTRUSTED:
        return VerdictReason.NOT_TRUSTED

    claims_qualified = (
        timestamp_quality is TimestampQuality.QUALIFIED_TSA
        if sig_type is SignatureType.TIMESTAMP
        else level is SignatureLevel.QUALIFIED
    )
    if not claims_qualified:
        return VerdictReason.NOT_QUALIFIED

    confirmed = (
        trust_chain_status is TrustChainStatus.TRUSTED
        and revocation_status is RevocationStatus.GOOD
    )
    return VerdictReason.CONFIRMED_QUALIFIED if confirmed else VerdictReason.UNCONFIRMED


def _assess_revocation(
    cert: x509.Certificate,
    revocation_details,
    crl_fetcher: TrackedCRLFetcher | None,
    ocsp_fetcher: TrackedOCSPFetcher | None,
) -> tuple[RevocationStatus, str | None]:
    """Map pyHanko's ``revocation_details`` (if any) plus our own
    fetch-outcome tracking onto :class:`RevocationStatus`.

    pyhanko_certvalidator's soft-fail mode leaves ``revocation_details`` at
    ``None`` both when the certificate is genuinely fine *and* when the
    check couldn't be performed at all (unreachable/timed-out endpoint) --
    outcome tracking on our own fetchers (see :mod:`.revocation`) is what
    lets those two cases be told apart honestly, instead of reporting a
    clean bill of health when the check never actually happened.
    """
    if crl_fetcher is None and ocsp_fetcher is None:
        return RevocationStatus.NOT_CHECKED, None

    if revocation_details is not None:
        revoked_at = revocation_details.revocation_date
        return RevocationStatus.REVOKED, (
            f'This certificate was revoked on {revoked_at:%Y-%m-%d} at '
            f'{revoked_at:%H:%M} UTC.'
        )

    crl_outcome = crl_fetcher.outcome_for(cert) if crl_fetcher else None
    ocsp_outcome = ocsp_fetcher.outcome_for(cert) if ocsp_fetcher else None
    attempted = (crl_outcome and crl_outcome.attempted) or (
        ocsp_outcome and ocsp_outcome.attempted
    )
    succeeded = (crl_outcome and crl_outcome.ok) or (ocsp_outcome and ocsp_outcome.ok)

    if not attempted:
        return RevocationStatus.NOT_CHECKED, None
    if succeeded:
        return RevocationStatus.GOOD, 'No revocation was found via OCSP/CRL check.'
    return RevocationStatus.UNAVAILABLE, (
        'Revocation status could not be confirmed: the OCSP/CRL endpoint(s) '
        'for this certificate were unreachable or timed out.'
    )


def _assess_trust_chain(
    validation_path: ValidationPath | None,
    moment: datetime,
    trust_list: TrustListSnapshot | None,
    verified_at: datetime,
) -> tuple[TrustChainStatus, str | None]:
    """Map a PKIX path built against the Trusted List's trust anchors onto
    our trust-chain model.

    ``validation_path`` is only non-``None`` if path-building actually found
    the issuing authority among the registered CA/QC or QTST services in the
    first place (see :class:`~.trust_list.registry.TrustListSnapshot` and
    ``TSPTrustManager``), so "no path" means "not found on the list". That's
    only reported as a confident :attr:`TrustChainStatus.UNTRUSTED` when the
    Trusted List data itself is fresh -- if any list failed to refresh or the
    snapshot has gone stale, we might simply be missing the data that would
    have vindicated the issuer, so we report
    :attr:`TrustChainStatus.UNAVAILABLE` instead of guessing in either
    direction.
    """
    if trust_list is None:
        return TrustChainStatus.UNKNOWN, None

    if validation_path is None:
        if trust_list.is_degraded(verified_at):
            return TrustChainStatus.UNAVAILABLE, (
                'Trusted List data is unavailable or out of date, so the '
                'issuing certificate authority could not be checked right '
                'now.'
            )
        return TrustChainStatus.UNTRUSTED, (
            'The issuing certificate authority was not found as a granted '
            'service on the EU Trusted List.'
        )

    result = QualificationAssessor(trust_list.registry).check_entity_cert_qualified(
        validation_path, moment=moment
    )
    if result.status.qualified:
        service_name = (
            result.service_definition.base_info.service_name
            if result.service_definition
            else 'a granted service'
        )
        return TrustChainStatus.TRUSTED, (
            f"Matched '{service_name}' as a granted qualified service on "
            'the EU Trusted List.'
        )
    return TrustChainStatus.UNTRUSTED, (
        'The issuing certificate authority is on the EU Trusted List but '
        'was not granted qualified status at the relevant time.'
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
            f'Certificate asserts QcCompliance, QcSSCD, and QcType={qc_type_name}.',
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
        verdict_reason=VerdictReason.BROKEN,
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
    trust_chain_status: TrustChainStatus,
    trust_note: str | None,
    timestamp_quality: TimestampQuality,
    revocation_status: RevocationStatus,
    revocation_note: str | None,
) -> tuple[str, str]:
    noun = _noun_for(sig_type)
    qc_suffix = f' {qc_note}' if qc_note else ''
    trust_suffix = f' {trust_note}' if trust_note else ''
    revocation_suffix = f' {revocation_note}' if revocation_note else ''

    if not integrity.intact or not integrity.signature_valid:
        return (
            f"This {noun} is broken and cannot be relied on.",
            'Digest/signature verification failed: '
            f'intact={integrity.intact}, valid={integrity.signature_valid}.'
            + qc_suffix
            + trust_suffix
            + revocation_suffix,
        )

    if revocation_status is RevocationStatus.REVOKED:
        return (
            f"The certificate used for this {noun} has been revoked and "
            "cannot be relied on.",
            (revocation_note or 'The certificate was revoked.')
            + qc_suffix
            + trust_suffix,
        )

    if integrity.modified_after_signing:
        return (
            f"The document was changed after this {noun} was applied.",
            'Incremental update analysis found changes beyond what is '
            f'permitted after signing (coverage={coverage_name}).'
            + qc_suffix
            + trust_suffix
            + revocation_suffix,
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

    timestamp_clause = (
        _timestamp_quality_clause(timestamp_quality)
        if sig_type is not SignatureType.TIMESTAMP
        else ''
    )
    revocation_clause = _revocation_clause(revocation_status)
    plain += (
        _qualification_clause(level, trust_chain_status, noun)
        + timestamp_clause
        + revocation_clause
    )
    technical += qc_suffix + trust_suffix + revocation_suffix
    return plain, technical


def _qualification_clause(
    level: SignatureLevel, trust_chain_status: TrustChainStatus, noun: str
) -> str:
    if level is SignatureLevel.QUALIFIED:
        if trust_chain_status is TrustChainStatus.TRUSTED:
            return (
                f" The certificate declares this a qualified {noun}, and the "
                "issuing provider is confirmed on the EU Trusted List."
            )
        if trust_chain_status is TrustChainStatus.UNTRUSTED:
            return (
                f" The certificate declares this a qualified {noun}, but the "
                "issuing provider was not found as a granted qualified "
                "service on the EU Trusted List, so qualified status is not "
                "confirmed."
            )
        if trust_chain_status is TrustChainStatus.UNAVAILABLE:
            return (
                f" The certificate declares this a qualified {noun}; the "
                "issuing provider's status could not be confirmed against "
                "the EU Trusted List right now."
            )
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


def _timestamp_quality_clause(timestamp_quality: TimestampQuality) -> str:
    if timestamp_quality is TimestampQuality.QUALIFIED_TSA:
        return " The signing time is backed by a qualified timestamp."
    if timestamp_quality is TimestampQuality.CLAIMED_ONLY:
        return (
            " No verifiable timestamp is present; the signing time shown is "
            "the signer's own claim."
        )
    return ''


def _revocation_clause(revocation_status: RevocationStatus) -> str:
    if revocation_status is RevocationStatus.UNAVAILABLE:
        return " Its revocation status could not be confirmed right now."
    return ''


def _friendly_name(name: x509.Name, preferred_key: str) -> str | None:
    native = name.native
    value = native.get(preferred_key)
    if isinstance(value, str) and value:
        return value
    human_friendly = name.human_friendly
    return human_friendly or None


_ISSUE_REASONS = frozenset(
    {VerdictReason.BROKEN, VerdictReason.TAMPERED, VerdictReason.REVOKED, VerdictReason.NOT_TRUSTED}
)


def _overall_verdict(
    items: list[SignatureItem],
) -> tuple[VerificationVerdict, str, VerdictBreakdown]:
    """Combine every item's :attr:`SignatureItem.verdict_reason` into the
    document-level verdict, per PRD section 6.

    Standalone timestamp items (typically PAdES-LTA archival additions) are
    excluded from the count whenever at least one content-bearing
    signature/seal is present: attaching a protective long-term-validation
    timestamp to an otherwise fully-confirmed qualified signature must not
    itself demote the verdict just because the timestamp isn't
    independently confirmed. If a document consists *only* of timestamps,
    they're all there is to judge, so they're used directly.
    """
    content_items = [i for i in items if i.type is not SignatureType.TIMESTAMP]
    counted_items = content_items or items

    reasons = [i.verdict_reason for i in counted_items]
    total = len(counted_items)
    confirmed = reasons.count(VerdictReason.CONFIRMED_QUALIFIED)
    issues = sum(1 for r in reasons if r in _ISSUE_REASONS)
    unconfirmed = reasons.count(VerdictReason.UNCONFIRMED)
    not_qualified = reasons.count(VerdictReason.NOT_QUALIFIED)

    if confirmed == total:
        verdict = VerificationVerdict.TRUSTED
    elif issues == total:
        verdict = VerificationVerdict.NOT_TRUSTED
    else:
        verdict = VerificationVerdict.PARTIAL

    breakdown = VerdictBreakdown(
        total=total,
        confirmed_qualified=confirmed,
        issues=issues,
        unconfirmed=unconfirmed,
        not_qualified=not_qualified,
    )
    return verdict, _plain_summary(verdict, counted_items, breakdown), breakdown


def _items_noun(items: list[SignatureItem]) -> str:
    types = frozenset(i.type for i in items)
    singular = {
        frozenset({SignatureType.SIGNATURE}): 'signature',
        frozenset({SignatureType.SEAL}): 'seal',
        frozenset({SignatureType.TIMESTAMP}): 'timestamp',
    }.get(types, 'item')
    return singular if len(items) == 1 else f'{singular}s'


def _plain_summary(
    verdict: VerificationVerdict,
    items: list[SignatureItem],
    breakdown: VerdictBreakdown,
) -> str:
    """Document-level banner text. Distinguishes real "issues" (tampering,
    revocation, confirmed not-trusted) from an honest "unconfirmed" gap
    (degraded Trusted List / unavailable revocation) -- these are different
    messages, not variations on the same one, per the PRD."""
    noun = _items_noun(items)
    total = breakdown.total

    if verdict is VerificationVerdict.TRUSTED:
        if total == 1:
            return f"Fully trusted — the {noun} is qualified and intact."
        return f"Fully trusted — all {total} {noun} are qualified and intact."

    if verdict is VerificationVerdict.NOT_TRUSTED:
        return "Do not rely on this document."

    if breakdown.issues:
        return (
            f"Partially trusted — {breakdown.issues} of {total} {noun} "
            f"{'has' if breakdown.issues == 1 else 'have'} issues."
        )
    if breakdown.unconfirmed:
        return (
            "Partially trusted — qualified status could not be confirmed "
            f"right now for {breakdown.unconfirmed} of {total} {noun}."
        )
    # No issues, nothing unconfirmed -- everything here is simply valid but
    # not qualified (e.g. an ordinary advanced signature). A known fact, not
    # a problem or an uncertainty.
    if total == 1:
        return f"Partially trusted — the {noun} is valid but not qualified."
    qualified_count = breakdown.confirmed_qualified
    return (
        f"Partially trusted — {qualified_count} of {total} {noun} "
        f"{'is' if qualified_count == 1 else 'are'} qualified; the rest are "
        "valid but not qualified."
    )
