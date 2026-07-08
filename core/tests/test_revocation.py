import asyncio

from asn1crypto import x509 as asn1_x509
from cryptography.hazmat.primitives import serialization

from eidas_inspect_core import RevocationFetchers, RevocationStatus, verify_pdf
from pdf_fixtures import (
    build_crl,
    build_minimal_pdf,
    build_ocsp_response,
    generate_ca,
    generate_ca_issued_signer,
    sign_pdf_bytes,
)
from trust_list_fixtures import fresh_snapshot, registry_with_granted_ca


def _asn1(cert_cx):
    return asn1_x509.Certificate.load(cert_cx.public_bytes(serialization.Encoding.DER))


def _signed_pdf_with_ca(**signer_kwargs):
    ca_key, ca_subject, ca_cert_cx = generate_ca()
    signer, leaf_cert_cx = generate_ca_issued_signer(
        ca_key, ca_subject, ca_cert_cx, **signer_kwargs
    )
    signed = sign_pdf_bytes(build_minimal_pdf(), signer)
    snapshot = fresh_snapshot(registry_with_granted_ca(_asn1(ca_cert_cx)))
    return signed, ca_key, ca_subject, ca_cert_cx, leaf_cert_cx, snapshot


def _fetchers(*, crl_fetch=None, ocsp_fetch=None, timeout_seconds=5.0):
    kwargs = {'timeout_seconds': timeout_seconds}
    if crl_fetch is not None:
        kwargs['crl_fetch'] = crl_fetch
    if ocsp_fetch is not None:
        kwargs['ocsp_fetch'] = ocsp_fetch
    return RevocationFetchers(**kwargs)


def test_check_revocation_defaults_off_even_with_endpoints_present():
    signed, *_rest, snapshot = _signed_pdf_with_ca()

    result = verify_pdf(signed, trust_list=snapshot)

    assert result.items[0].revocation_status == RevocationStatus.NOT_CHECKED


def test_check_revocation_without_trust_list_is_a_no_op():
    signed, *_rest, _snapshot = _signed_pdf_with_ca()

    result = verify_pdf(signed, check_revocation=True)

    assert result.items[0].revocation_status == RevocationStatus.NOT_CHECKED


def test_good_crl_response_is_reported_as_good():
    signed, ca_key, ca_subject, ca_cert_cx, leaf_cert_cx, snapshot = _signed_pdf_with_ca()
    crl_der = build_crl(ca_key, ca_subject)

    async def crl_fetch(url):
        return crl_der

    result = verify_pdf(
        signed,
        trust_list=snapshot,
        check_revocation=True,
        revocation_fetchers=_fetchers(crl_fetch=crl_fetch),
    )

    item = result.items[0]
    assert item.revocation_status == RevocationStatus.GOOD
    assert item.integrity.intact is True
    assert item.integrity.signature_valid is True


def test_revoked_crl_response_is_reported_with_plain_language_and_time():
    signed, ca_key, ca_subject, ca_cert_cx, leaf_cert_cx, snapshot = _signed_pdf_with_ca()
    crl_der = build_crl(ca_key, ca_subject, revoked_serial=leaf_cert_cx.serial_number)

    async def crl_fetch(url):
        return crl_der

    result = verify_pdf(
        signed,
        trust_list=snapshot,
        check_revocation=True,
        revocation_fetchers=_fetchers(crl_fetch=crl_fetch),
    )

    item = result.items[0]
    assert item.revocation_status == RevocationStatus.REVOKED
    assert 'revoked' in item.plain_explanation.lower()
    assert 'revoked on' in item.technical_detail.lower()
    # Revocation is a distinct concern from cryptographic integrity.
    assert item.integrity.intact is True
    assert item.integrity.signature_valid is True


def test_unreachable_crl_endpoint_is_unavailable_not_a_failed_verdict():
    signed, ca_key, ca_subject, ca_cert_cx, leaf_cert_cx, snapshot = _signed_pdf_with_ca()

    async def crl_fetch(url):
        raise ConnectionError('simulated network failure')

    result = verify_pdf(
        signed,
        trust_list=snapshot,
        check_revocation=True,
        revocation_fetchers=_fetchers(crl_fetch=crl_fetch),
    )

    item = result.items[0]
    assert item.revocation_status == RevocationStatus.UNAVAILABLE
    assert 'could not be confirmed' in item.plain_explanation.lower()
    assert item.integrity.intact is True
    assert item.integrity.signature_valid is True


def test_crl_endpoint_timeout_is_unavailable():
    signed, ca_key, ca_subject, ca_cert_cx, leaf_cert_cx, snapshot = _signed_pdf_with_ca()

    async def crl_fetch(url):
        await asyncio.sleep(999)
        return b''

    result = verify_pdf(
        signed,
        trust_list=snapshot,
        check_revocation=True,
        revocation_fetchers=_fetchers(crl_fetch=crl_fetch, timeout_seconds=0.2),
    )

    assert result.items[0].revocation_status == RevocationStatus.UNAVAILABLE


def test_good_ocsp_response_is_reported_as_good():
    signed, ca_key, ca_subject, ca_cert_cx, leaf_cert_cx, snapshot = _signed_pdf_with_ca(
        crl_url=None
    )
    ocsp_der = build_ocsp_response(ca_key, ca_cert_cx, leaf_cert_cx, revoked=False)

    async def ocsp_fetch(url, request_der):
        return ocsp_der

    result = verify_pdf(
        signed,
        trust_list=snapshot,
        check_revocation=True,
        revocation_fetchers=_fetchers(ocsp_fetch=ocsp_fetch),
    )

    assert result.items[0].revocation_status == RevocationStatus.GOOD


def test_revoked_ocsp_response_is_reported_as_revoked():
    signed, ca_key, ca_subject, ca_cert_cx, leaf_cert_cx, snapshot = _signed_pdf_with_ca(
        crl_url=None
    )
    ocsp_der = build_ocsp_response(ca_key, ca_cert_cx, leaf_cert_cx, revoked=True)

    async def ocsp_fetch(url, request_der):
        return ocsp_der

    result = verify_pdf(
        signed,
        trust_list=snapshot,
        check_revocation=True,
        revocation_fetchers=_fetchers(ocsp_fetch=ocsp_fetch),
    )

    item = result.items[0]
    assert item.revocation_status == RevocationStatus.REVOKED
    assert 'revoked' in item.plain_explanation.lower()


def test_no_revocation_endpoints_on_cert_is_not_checked():
    signed, *_rest, snapshot = _signed_pdf_with_ca(crl_url=None, ocsp_url=None)

    async def unreachable_crl(url):
        raise AssertionError('should never be called: cert has no CRLDP')

    async def unreachable_ocsp(url, request_der):
        raise AssertionError('should never be called: cert has no AIA')

    result = verify_pdf(
        signed,
        trust_list=snapshot,
        check_revocation=True,
        revocation_fetchers=_fetchers(
            crl_fetch=unreachable_crl, ocsp_fetch=unreachable_ocsp
        ),
    )

    assert result.items[0].revocation_status == RevocationStatus.NOT_CHECKED
