"""Point-in-time validation: a short-lived signing certificate (the norm
for cloud/remote QES providers) must still be checkable after it expires,
as long as there's a verified timestamp to anchor the check to. Without one,
today's conservative "checked as of now" behavior must be unchanged --
that's the security boundary this whole feature respects.
"""

from datetime import datetime, timedelta, timezone

from asn1crypto import x509 as asn1_x509
from cryptography.hazmat.primitives import serialization
from pyhanko.sign.timestamps import DummyTimeStamper

from eidas_inspect_core import (
    RevocationSource,
    RevocationStatus,
    TrustChainStatus,
    VerdictReason,
    VerificationVerdict,
    verify_pdf,
)
from pdf_fixtures import (
    QC_TYPE_ESIGN_OID,
    add_dss_to_pdf,
    build_minimal_pdf,
    build_ocsp_response,
    generate_ca,
    generate_ca_issued_signer,
    generate_self_signed_signer,
    sign_pdf_bytes,
    sign_pdf_with_timestamp,
)
from trust_list_fixtures import fresh_snapshot, registry_with_granted_ca

NOW = None  # placeholder; real "now" is computed per-test to avoid staleness


def _asn1(cert_cx):
    return asn1_x509.Certificate.load(cert_cx.public_bytes(serialization.Encoding.DER))


def _short_lived_qualified_setup():
    """A QES-style leaf, valid only [now-20min, now-5min] -- already expired
    by the time verify_pdf() runs -- issued by a CA granted on a fresh
    Trusted List snapshot. Returns everything a test needs to build on top:
    (now, ca_key, ca_subject, ca_cert_cx, signer, leaf_cert_cx, snapshot).
    """
    now = datetime.now(timezone.utc)
    ca_key, ca_subject, ca_cert_cx = generate_ca()
    signer, leaf_cert_cx = generate_ca_issued_signer(
        ca_key,
        ca_subject,
        ca_cert_cx,
        qc_compliance=True,
        qc_sscd=True,
        qc_type_oid=QC_TYPE_ESIGN_OID,
        not_valid_before=now - timedelta(minutes=20),
        not_valid_after=now - timedelta(minutes=5),
    )
    snapshot = fresh_snapshot(registry_with_granted_ca(_asn1(ca_cert_cx)))
    return now, ca_key, ca_subject, ca_cert_cx, signer, leaf_cert_cx, snapshot


def test_expired_short_lived_cert_confirmed_good_via_embedded_dss_is_trusted():
    now, ca_key, ca_subject, ca_cert_cx, signer, leaf_cert_cx, snapshot = (
        _short_lived_qualified_setup()
    )
    signing_moment = now - timedelta(minutes=15)  # inside the cert's validity window

    tsa_signer = generate_self_signed_signer('Test TSA', 'Test TSA Org')
    timestamper = DummyTimeStamper(
        tsa_cert=tsa_signer.signing_cert,
        tsa_key=tsa_signer.signing_key,
        fixed_dt=signing_moment,
    )
    signed = sign_pdf_with_timestamp(build_minimal_pdf(), signer, timestamper)

    good_ocsp = build_ocsp_response(
        ca_key, ca_cert_cx, leaf_cert_cx, revoked=False, produced_at=signing_moment
    )
    final_pdf = add_dss_to_pdf(signed, certs=[ca_cert_cx], ocsp_responses_der=[good_ocsp])

    result = verify_pdf(final_pdf, trust_list=snapshot, check_revocation=True)

    item = result.items[0]
    assert item.level.value == 'qualified'
    assert item.trust_chain_status == TrustChainStatus.TRUSTED
    assert item.revocation_status == RevocationStatus.GOOD
    assert item.revocation_source == RevocationSource.EMBEDDED
    assert item.verdict_reason == VerdictReason.CONFIRMED_QUALIFIED
    assert result.verdict == VerificationVerdict.TRUSTED
    assert 'valid and qualified at the time of signing' in item.plain_explanation
    assert "document's own embedded revocation record" in item.technical_detail


def test_expired_short_lived_cert_confirmed_good_via_live_ocsp_is_trusted():
    now, ca_key, ca_subject, ca_cert_cx, signer, leaf_cert_cx, snapshot = (
        _short_lived_qualified_setup()
    )
    signing_moment = now - timedelta(minutes=15)

    tsa_signer = generate_self_signed_signer('Test TSA', 'Test TSA Org')
    timestamper = DummyTimeStamper(
        tsa_cert=tsa_signer.signing_cert,
        tsa_key=tsa_signer.signing_key,
        fixed_dt=signing_moment,
    )
    signed = sign_pdf_with_timestamp(build_minimal_pdf(), signer, timestamper)

    good_ocsp = build_ocsp_response(ca_key, ca_cert_cx, leaf_cert_cx, revoked=False)

    async def ocsp_fetch(url, request_der):
        return good_ocsp

    from eidas_inspect_core import RevocationFetchers

    result = verify_pdf(
        signed,
        trust_list=snapshot,
        check_revocation=True,
        revocation_fetchers=RevocationFetchers(ocsp_fetch=ocsp_fetch),
    )

    item = result.items[0]
    assert item.trust_chain_status == TrustChainStatus.TRUSTED
    assert item.revocation_status == RevocationStatus.GOOD
    assert item.revocation_source == RevocationSource.LIVE
    assert result.verdict == VerificationVerdict.TRUSTED


def test_revoked_before_signing_moment_is_not_trusted():
    now, ca_key, ca_subject, ca_cert_cx, signer, leaf_cert_cx, snapshot = (
        _short_lived_qualified_setup()
    )
    signing_moment = now - timedelta(minutes=15)

    tsa_signer = generate_self_signed_signer('Test TSA', 'Test TSA Org')
    timestamper = DummyTimeStamper(
        tsa_cert=tsa_signer.signing_cert,
        tsa_key=tsa_signer.signing_key,
        fixed_dt=signing_moment,
    )
    signed = sign_pdf_with_timestamp(build_minimal_pdf(), signer, timestamper)

    revoked_ocsp = build_ocsp_response(
        ca_key,
        ca_cert_cx,
        leaf_cert_cx,
        revoked=True,
        revocation_time=signing_moment - timedelta(minutes=2),  # before signing
        produced_at=signing_moment,
    )
    final_pdf = add_dss_to_pdf(
        signed, certs=[ca_cert_cx], ocsp_responses_der=[revoked_ocsp]
    )

    result = verify_pdf(final_pdf, trust_list=snapshot, check_revocation=True)

    item = result.items[0]
    assert item.revocation_status == RevocationStatus.REVOKED
    assert item.revocation_source == RevocationSource.EMBEDDED
    assert item.verdict_reason == VerdictReason.REVOKED
    assert result.verdict == VerificationVerdict.NOT_TRUSTED


def test_revoked_after_signing_moment_is_still_trusted():
    # The classic AdES case: a certificate revoked after a document was
    # validly signed doesn't retroactively invalidate that signature.
    now, ca_key, ca_subject, ca_cert_cx, signer, leaf_cert_cx, snapshot = (
        _short_lived_qualified_setup()
    )
    signing_moment = now - timedelta(minutes=15)

    tsa_signer = generate_self_signed_signer('Test TSA', 'Test TSA Org')
    timestamper = DummyTimeStamper(
        tsa_cert=tsa_signer.signing_cert,
        tsa_key=tsa_signer.signing_key,
        fixed_dt=signing_moment,
    )
    signed = sign_pdf_with_timestamp(build_minimal_pdf(), signer, timestamper)

    revoked_ocsp = build_ocsp_response(
        ca_key,
        ca_cert_cx,
        leaf_cert_cx,
        revoked=True,
        revocation_time=signing_moment + timedelta(minutes=2),  # after signing
        produced_at=signing_moment + timedelta(minutes=3),
    )
    final_pdf = add_dss_to_pdf(
        signed, certs=[ca_cert_cx], ocsp_responses_der=[revoked_ocsp]
    )

    result = verify_pdf(final_pdf, trust_list=snapshot, check_revocation=True)

    item = result.items[0]
    assert item.revocation_status == RevocationStatus.GOOD
    assert item.verdict_reason == VerdictReason.CONFIRMED_QUALIFIED
    assert result.verdict == VerificationVerdict.TRUSTED


def test_expired_cert_with_only_claimed_time_stays_conservative():
    # SECURITY: no verified timestamp exists, so the (forgeable) self-reported
    # /M claim must never anchor point-in-time validation. Behavior here must
    # be identical to before this feature existed: checked as of "now", so
    # the already-expired cert can't be confirmed -- never a false TRUSTED.
    now, ca_key, ca_subject, ca_cert_cx, signer, leaf_cert_cx, snapshot = (
        _short_lived_qualified_setup()
    )

    signed = sign_pdf_bytes(build_minimal_pdf(), signer)  # no embedded timestamp

    result = verify_pdf(signed, trust_list=snapshot, check_revocation=True)

    item = result.items[0]
    assert item.revocation_status == RevocationStatus.NOT_CHECKED
    assert item.revocation_source is None
    assert result.verdict != VerificationVerdict.TRUSTED


def test_currently_valid_cert_with_dss_present_is_unaffected():
    # Regression guard: a normal, currently-valid signature with DSS data
    # present must behave exactly as it did before DSS-awareness existed.
    ca_key, ca_subject, ca_cert_cx = generate_ca()
    signer, leaf_cert_cx = generate_ca_issued_signer(
        ca_key,
        ca_subject,
        ca_cert_cx,
        qc_compliance=True,
        qc_sscd=True,
        qc_type_oid=QC_TYPE_ESIGN_OID,
    )
    snapshot = fresh_snapshot(registry_with_granted_ca(_asn1(ca_cert_cx)))
    signed = sign_pdf_bytes(build_minimal_pdf(), signer)
    good_ocsp = build_ocsp_response(ca_key, ca_cert_cx, leaf_cert_cx, revoked=False)
    final_pdf = add_dss_to_pdf(signed, certs=[ca_cert_cx], ocsp_responses_der=[good_ocsp])

    result = verify_pdf(final_pdf, trust_list=snapshot, check_revocation=True)

    item = result.items[0]
    assert item.trust_chain_status == TrustChainStatus.TRUSTED
    assert item.revocation_status == RevocationStatus.GOOD
    assert result.verdict == VerificationVerdict.TRUSTED
