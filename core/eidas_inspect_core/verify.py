import asyncio
import hashlib
import io
from datetime import datetime, timezone

from asn1crypto import x509
from pyhanko.pdf_utils.crypt.api import AuthStatus
from pyhanko.pdf_utils.misc import PdfError
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.diff_analysis import ModificationLevel
from pyhanko.sign.fields import enumerate_fields_in
from pyhanko.sign.validation.pdf_embedded import (
    EmbeddedPdfSignature,
    async_validate_pdf_signature,
    async_validate_pdf_timestamp,
    collect_embedded_signatures,
)
from pyhanko.sign.validation.dss import DocumentSecurityStore
from pyhanko.sign.validation.errors import NoDSSFoundError
from pyhanko.sign.validation.qualified.assess import QualificationAssessor
from pyhanko.sign.validation.qualified.tsp import TSPTrustManager
from pyhanko.sign.validation.status import SignatureCoverageLevel
from pyhanko_certvalidator import ValidationContext
from pyhanko_certvalidator.path import ValidationPath

from .errors import CorruptedPdfError, IncorrectPasswordError, PasswordRequiredError
from .models import (
    CertificateDetails,
    IntegrityStatus,
    KsiVerificationTier,
    RevocationSource,
    RevocationStatus,
    SignatureItem,
    SignatureLevel,
    SignatureType,
    TimestampQuality,
    TrustChainStatus,
    TrustMatch,
    VerdictBreakdown,
    VerdictReason,
    VerificationResult,
    VerificationVerdict,
)
from .qc_statements import QcStatements, extract_qc_statements
from .revocation import (
    RevocationFetchers,
    TrackedCRLFetcher,
    TrackedOCSPFetcher,
    build_fetchers,
    dss_covers_cert,
)
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
    # KSI seals are embedded as a non-standard /FT /KSI AcroForm field, not
    # /FT /Sig -- collect_embedded_signatures() never sees them (that's
    # exactly the bug this discovery path fixes: a KSI-sealed document used
    # to silently report NO_SIGNATURES). See _collect_ksi_seals.
    ksi_seals = _collect_ksi_seals(reader)

    if not embedded_sigs and not ksi_seals:
        return VerificationResult(
            verdict=VerificationVerdict.NO_SIGNATURES,
            items=[],
            document_sha256=document_sha256,
            verified_at=verified_at,
            plain_summary='This document contains no digital signatures.',
            verdict_breakdown=None,
        )

    dss = _read_dss(reader)
    dss_ocsps, dss_crls = _dss_revocation_data(dss)

    items = [
        _build_signature_item(
            sig,
            trust_list,
            check_revocation,
            revocation_fetchers,
            dss,
            dss_ocsps,
            dss_crls,
            verified_at,
        )
        for sig in embedded_sigs
    ] + [
        _build_ksi_seal_item(data, field_name, sig_dict)
        for field_name, sig_dict in ksi_seals
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


def _collect_ksi_seals(reader: PdfFileReader) -> list[tuple[str, object]]:
    """Find every Guardtime-KSI-style ``/FT /KSI`` AcroForm field in the
    document.

    Confirmed by inspecting Guardtime's own official demo file
    (github.com/guardtime/ksi-pdf-verifier's ``demo/signed.pdf``): a KSI
    seal is a ``/Subtype /Widget`` annotation whose field type is the
    non-standard literal ``/KSI``, not ``/Sig`` -- which is exactly why
    :func:`~pyhanko.sign.validation.pdf_embedded.collect_embedded_signatures`
    (filters strictly on ``/FT /Sig``) never finds one. Reuses pyHanko's own
    field-walking primitive (handles ``/Kids`` recursion, circular-reference
    detection, inheritable ``/FT``) with a different ``target_field_type``
    rather than reimplementing AcroForm traversal.

    Returns ``(field_name, signature_dict)`` pairs, where ``signature_dict``
    is the field's ``/V`` target -- a dictionary carrying ``/Contents``
    (the raw KSI signature, TLV-binary, hex-encoded the same way a CMS
    blob would be), ``/Filter`` (``/GT.KSI``), and a standard 4-element
    ``/ByteRange``.
    """
    try:
        fields = reader.root['/AcroForm']['/Fields']
    except KeyError:
        return []

    results = []
    for field_name, field_value, _field_ref in enumerate_fields_in(
        fields, filled_status=True, refs_seen=set(), target_field_type='/KSI'
    ):
        sig_dict = (
            field_value.get_object()
            if hasattr(field_value, 'get_object')
            else field_value
        )
        results.append((field_name, sig_dict))
    return results


def _build_ksi_seal_item(data: bytes, field_name: str, sig_dict) -> SignatureItem:
    """Detection + structural parsing only, for now.

    No cryptographic verification is performed here yet -- that's the
    verification-tiers phase of this feature (subprocess to ``ksi-tool``;
    see PROGRESS.md's KSI research notes), which will populate
    :attr:`~.models.KsiVerificationTier` properly. Until then, every
    structurally well-formed KSI seal gets
    :attr:`~.models.KsiVerificationTier.NOT_VERIFIED`, mapped to
    :attr:`~.models.VerdictReason.UNCONFIRMED` -- not because it fits that
    reason's usual TL-or-revocation-gap story, but because the resulting
    banner text ("qualified status could not be confirmed right now") is
    the honest one; :attr:`~.models.VerdictReason.NOT_QUALIFIED`'s text
    ("valid but not qualified") would overclaim a validity we haven't
    actually checked yet.

    ``IntegrityStatus.intact``/``.signature_valid`` are booleans with no
    "not yet checked" state to hold, unlike ``RevocationStatus.NOT_CHECKED``
    elsewhere in this module -- they're set ``True`` here only because
    ``False`` would be actively wrong (it reads as "a problem was found",
    not "unknown"), not because cryptographic validity was confirmed. The
    UI must drive tone/badges for KSI items from ``ksi_verification_tier``,
    never from these two fields.
    """
    try:
        contents = sig_dict['/Contents']
        byte_range_obj = sig_dict['/ByteRange']
        signature_bytes = bytes(contents)
        byte_range = [int(n) for n in byte_range_obj]
        if len(byte_range) != 4:
            raise ValueError(
                f'expected a 4-element /ByteRange, got {len(byte_range)}'
            )
    except Exception as e:
        return _unreadable_ksi_seal_item(e)

    fully_covered = (byte_range[2] + byte_range[3]) == len(data)
    integrity = IntegrityStatus(
        intact=True,
        signature_valid=True,
        fully_covered=fully_covered,
        modified_after_signing=None,
        lta_extended=False,
    )

    plain = (
        'This document carries a Guardtime KSI seal. This tool does not '
        "yet perform independent cryptographic verification of KSI seals, "
        'so its validity could not be confirmed.'
    )
    technical = (
        f"KSI seal found in field '{field_name}' "
        f'(Filter={sig_dict.get("/Filter")!r}, {len(signature_bytes)}-byte '
        'token, ByteRange present). Cryptographic verification (internal '
        'consistency, publication-based) is not yet implemented.'
    )

    return SignatureItem(
        type=SignatureType.KSI_SEAL,
        integrity=integrity,
        plain_explanation=plain,
        technical_detail=technical,
        verdict_reason=VerdictReason.UNCONFIRMED,
        ksi_verification_tier=KsiVerificationTier.NOT_VERIFIED,
    )


def _unreadable_ksi_seal_item(error: Exception) -> SignatureItem:
    integrity = IntegrityStatus(
        intact=False,
        signature_valid=False,
        fully_covered=False,
        modified_after_signing=None,
        lta_extended=False,
    )
    return SignatureItem(
        type=SignatureType.KSI_SEAL,
        integrity=integrity,
        plain_explanation='This seal could not be read or validated.',
        technical_detail=f'{type(error).__name__}: {error}',
        verdict_reason=VerdictReason.BROKEN,
        ksi_verification_tier=KsiVerificationTier.BROKEN,
    )


def _read_dss(reader: PdfFileReader) -> DocumentSecurityStore | None:
    try:
        return DocumentSecurityStore.read_dss(reader)
    except NoDSSFoundError:
        return None


def _dss_revocation_data(dss: DocumentSecurityStore | None) -> tuple[list, list]:
    """Parse a document's embedded ``/DSS`` OCSP responses and CRLs (if any)
    into asn1crypto objects, once per document, for the "does the document
    already carry proof for this cert" check (see :func:`.revocation.dss_covers_cert`).
    """
    if dss is None:
        return [], []
    vc = dss.as_validation_context({})
    return list(vc.ocsps), list(vc.crls)


def _build_validation_context(
    trust_list: TrustListSnapshot | None,
    check_revocation: bool,
    revocation_fetchers: RevocationFetchers | None,
    *,
    dss: DocumentSecurityStore | None = None,
    dss_ocsps: list | None = None,
    dss_crls: list | None = None,
    moment: datetime | None = None,
) -> tuple[ValidationContext | None, TrackedCRLFetcher | None, TrackedOCSPFetcher | None]:
    """Build a validation context.

    Revocation checking is only meaningful alongside a Trusted List snapshot
    (there would be no trust anchor to build a path against otherwise), so
    ``check_revocation`` is a no-op unless ``trust_list`` is also supplied.
    Without it, this preserves the exact pre-revocation behavior: no
    fetching, no network calls, ``trust_chain_status`` stays whatever the
    Trusted List wiring alone produces.

    When ``dss`` is given, the document's own embedded certs are merged in
    via ``DocumentSecurityStore.as_validation_context`` (helps path-building
    when an intermediate CA is only carried in the DSS, not the CMS).
    ``dss_ocsps``/``dss_crls`` are passed straight through to
    :func:`.revocation.build_fetchers`, which makes our own tracked fetchers
    check them *before* ever attempting a live fetch -- this is the part
    that actually matters: pyhanko_certvalidator's own OCSP retrieval
    prefers a live fetch over pre-loaded data whenever the cert declares an
    OCSP URL and fetching is enabled (unlike its CRL handling, which
    correctly prefers already-available data), so relying on
    ``as_validation_context`` alone would silently skip the document's own
    embedded proof for any cert that also has a live OCSP endpoint --
    exactly the shape of a real QTSP-issued short-lived certificate. This is
    what makes an expired short-lived signing certificate checkable long
    after the fact: the revocation proof was captured into the document at
    signing time, precisely so it wouldn't depend on a live responder still
    answering for a long-expired serial.

    ``moment`` governs point-in-time validation (both the certificate
    validity-period check and, per pyhanko_certvalidator's own
    ``control_time`` logic, whether a *later* revocation still invalidates
    an earlier-valid signature). Callers must never pass an unverified,
    self-reported time here -- see the security note in
    :func:`_build_signature_item`.
    """
    if trust_list is None:
        return None, None, None

    crl_fetcher = ocsp_fetcher = None
    fetchers = None
    if check_revocation:
        fetchers, crl_fetcher, ocsp_fetcher = build_fetchers(
            revocation_fetchers or RevocationFetchers(),
            dss_ocsps=dss_ocsps or (),
            dss_crls=dss_crls or (),
        )

    kwargs = dict(
        trust_manager=TSPTrustManager(trust_list.registry),
        allow_fetching=check_revocation,
        fetchers=fetchers,
        revocation_mode='soft-fail',
        moment=moment,
    )
    validation_context = (
        dss.as_validation_context(kwargs) if dss is not None else ValidationContext(**kwargs)
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
    check_revocation: bool,
    revocation_fetchers: RevocationFetchers | None,
    dss: DocumentSecurityStore | None,
    dss_ocsps: list,
    dss_crls: list,
    verified_at: datetime,
) -> SignatureItem:
    is_timestamp = embedded_sig.sig_object_type == '/DocTimeStamp'
    provisional_type = (
        SignatureType.TIMESTAMP if is_timestamp else SignatureType.SIGNATURE
    )

    # Pass 1 (discovery): crypto facts + signing time only. No revocation
    # fetching, no DSS, moment=now -- its trust/revocation conclusions are
    # provisional and always get replaced by pass 2's point-in-time-correct
    # results below. This pass exists purely so we know *when* to evaluate
    # pass 2 at.
    discovery_context, _, _ = _build_validation_context(trust_list, False, None)
    try:
        if is_timestamp:
            discovery_status = asyncio.run(
                async_validate_pdf_timestamp(embedded_sig, discovery_context)
            )
        else:
            discovery_status = asyncio.run(
                async_validate_pdf_signature(
                    embedded_sig, signer_validation_context=discovery_context
                )
            )
    except Exception as e:
        return _unreadable_signature_item(provisional_type, e)

    discovery_signing_time, discovery_timestamp_quality = _signing_time_info(
        is_timestamp, discovery_status
    )

    # SECURITY: a verified timestamp (embedded RFC 3161 token, or a
    # standalone /DocTimeStamp's own asserted time) is the only thing
    # allowed to anchor point-in-time validation. A bare self-reported
    # claim (/M, CLAIMED_ONLY) never does: pyhanko_certvalidator only
    # excuses a *later* revocation from invalidating a signature when an
    # explicit `moment` is passed (its own "control_time" logic) -- feeding
    # it an unverified time would let a forged /M value launder a
    # certificate that was already revoked or expired at the real signing
    # time. Leaving this unset for the unverified case preserves today's
    # conservative behavior exactly (checked as of "now", any revocation is
    # always fatal).
    reference_moment = (
        discovery_signing_time
        if is_timestamp
        or discovery_timestamp_quality is not TimestampQuality.CLAIMED_ONLY
        else None
    )

    # Pass 2 (real validation): point-in-time correct, and DSS-aware (when
    # revocation checking is requested at all) so the document's own
    # embedded revocation record is consulted before ever falling back to a
    # live fetch. DSS consultation is gated behind check_revocation just
    # like live fetching -- otherwise a revoked-per-embedded-proof cert
    # could populate status.revocation_details even with
    # check_revocation=False, which _assess_revocation's "no fetchers ->
    # not checked" gate would then incorrectly shadow.
    validation_context, crl_fetcher, ocsp_fetcher = _build_validation_context(
        trust_list,
        check_revocation,
        revocation_fetchers,
        dss=dss if check_revocation else None,
        dss_ocsps=dss_ocsps if check_revocation else None,
        dss_crls=dss_crls if check_revocation else None,
        moment=reference_moment,
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
    certificate = _certificate_details(status.signing_cert)

    qualification_moment = reference_moment if reference_moment is not None else verified_at
    trust_chain_status, trust_note, trust_match = _assess_trust_chain(
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
            ts_trust_status, _, _ = _assess_trust_chain(
                embedded_timestamp.validation_path,
                embedded_timestamp.timestamp,
                trust_list,
                verified_at,
            )
            if ts_trust_status is TrustChainStatus.TRUSTED:
                timestamp_quality = TimestampQuality.QUALIFIED_TSA

    dss_covers = dss_covers_cert(status.signing_cert, dss_ocsps, dss_crls)
    revocation_status, revocation_note, revocation_source = _assess_revocation(
        status.signing_cert,
        status.revocation_details,
        crl_fetcher,
        ocsp_fetcher,
        dss_covers,
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
        revocation_source=revocation_source,
        verdict_reason=verdict_reason,
        certificate=certificate,
        trust_match=trust_match,
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
    dss_covers: bool,
) -> tuple[RevocationStatus, str | None, RevocationSource | None]:
    """Map pyHanko's ``revocation_details`` (if any) plus our own
    fetch-outcome tracking onto :class:`RevocationStatus`.

    pyhanko_certvalidator's soft-fail mode leaves ``revocation_details`` at
    ``None`` both when the certificate is genuinely fine *and* when the
    check couldn't be performed at all (unreachable/timed-out endpoint) --
    outcome tracking on our own fetchers (see :mod:`.revocation`) is what
    lets those two cases be told apart honestly, instead of reporting a
    clean bill of health when the check never actually happened.

    ``dss_covers`` (see :func:`.revocation.dss_covers_cert`) is informational
    labeling only -- it decides whether we report
    :attr:`RevocationSource.EMBEDDED` instead of a plain live-fetch result,
    never whether the certificate is revoked. That decision was already made
    by pyhanko_certvalidator, via the same DSS data, before this function
    ever runs.
    """
    if crl_fetcher is None and ocsp_fetcher is None:
        return RevocationStatus.NOT_CHECKED, None, None

    if revocation_details is not None:
        revoked_at = revocation_details.revocation_date
        source = RevocationSource.EMBEDDED if dss_covers else RevocationSource.LIVE
        suffix = (
            ", per the document's own embedded revocation record."
            if dss_covers
            else '.'
        )
        return (
            RevocationStatus.REVOKED,
            f'This certificate was revoked on {revoked_at:%Y-%m-%d} at '
            f'{revoked_at:%H:%M} UTC{suffix}',
            source,
        )

    if dss_covers:
        return (
            RevocationStatus.GOOD,
            "No revocation was found, per the document's own embedded "
            'revocation record (captured at signing time) -- this is what '
            'keeps a short-lived signing certificate checkable long after '
            'it expires.',
            RevocationSource.EMBEDDED,
        )

    crl_outcome = crl_fetcher.outcome_for(cert) if crl_fetcher else None
    ocsp_outcome = ocsp_fetcher.outcome_for(cert) if ocsp_fetcher else None
    attempted = (crl_outcome and crl_outcome.attempted) or (
        ocsp_outcome and ocsp_outcome.attempted
    )
    succeeded = (crl_outcome and crl_outcome.ok) or (ocsp_outcome and ocsp_outcome.ok)

    if not attempted:
        return RevocationStatus.NOT_CHECKED, None, None
    if succeeded:
        return (
            RevocationStatus.GOOD,
            'No revocation was found via a live OCSP/CRL check just now.',
            RevocationSource.LIVE,
        )
    return (
        RevocationStatus.UNAVAILABLE,
        'Revocation status could not be confirmed: the OCSP/CRL endpoint(s) '
        'for this certificate were unreachable or timed out.',
        None,
    )


def _assess_trust_chain(
    validation_path: ValidationPath | None,
    moment: datetime,
    trust_list: TrustListSnapshot | None,
    verified_at: datetime,
) -> tuple[TrustChainStatus, str | None, TrustMatch | None]:
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

    The third return value is a :class:`TrustMatch` -- non-``None`` only
    when a service was actually matched *and* that service's originating
    territory is known (see
    :meth:`~.trust_list.registry.TrustListSnapshot.territory_for_service`).
    """
    if trust_list is None:
        return TrustChainStatus.UNKNOWN, None, None

    if validation_path is None:
        if trust_list.is_degraded(verified_at):
            return (
                TrustChainStatus.UNAVAILABLE,
                'Trusted List data is unavailable or out of date, so the '
                'issuing certificate authority could not be checked right '
                'now.',
                None,
            )
        return (
            TrustChainStatus.UNTRUSTED,
            'The issuing certificate authority was not found as a granted '
            'service on the EU Trusted List.',
            None,
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
        territory = trust_list.territory_for_service(result.service_definition)
        trust_match = (
            TrustMatch(
                territory=territory.territory,
                territory_name=territory.territory_name,
                trust_service_name=service_name,
                tl_location_url=territory.tl_location_url,
            )
            if territory is not None
            else None
        )
        return (
            TrustChainStatus.TRUSTED,
            f"Matched '{service_name}' as a granted qualified service on "
            'the EU Trusted List.',
            trust_match,
        )
    return (
        TrustChainStatus.UNTRUSTED,
        'The issuing certificate authority is on the EU Trusted List but '
        'was not granted qualified status at the relevant time.',
        None,
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
    if sig_type is SignatureType.SEAL or sig_type is SignatureType.KSI_SEAL:
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
                "issuing provider is confirmed on the EU Trusted List, valid "
                "and qualified at the time of signing."
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


def _name_component(name: x509.Name, key: str) -> str | None:
    """A single X.509 name attribute (e.g. just the CN, just the O), with
    no fallback to the full distinguished name -- unlike :func:`_friendly_name`,
    which is for the existing single-line "Who"/"Certificate issued by"
    fields. :class:`~.models.CertificateDetails` shows CN and O as
    separate, explicit facts, so a silent fallback here would blur which
    one was actually present on the certificate."""
    value = name.native.get(key)
    return value if isinstance(value, str) and value else None


def _format_serial(serial_number: int) -> str:
    """Hex, colon-separated, e.g. ``'51:F1:7D:EE:...'`` -- the conventional
    X.509 display form (as `openssl x509 -serial` prints it)."""
    hex_digits = format(serial_number, 'X')
    if len(hex_digits) % 2:
        hex_digits = '0' + hex_digits
    return ':'.join(hex_digits[i : i + 2] for i in range(0, len(hex_digits), 2))


def _certificate_details(cert: x509.Certificate) -> CertificateDetails:
    return CertificateDetails(
        subject_common_name=_name_component(cert.subject, 'common_name'),
        subject_organization=_name_component(cert.subject, 'organization_name'),
        issuer_common_name=_name_component(cert.issuer, 'common_name'),
        issuer_organization=_name_component(cert.issuer, 'organization_name'),
        valid_from=cert.not_valid_before,
        valid_until=cert.not_valid_after,
        serial_number=_format_serial(cert.serial_number),
    )


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
        frozenset({SignatureType.KSI_SEAL}): 'seal',
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
