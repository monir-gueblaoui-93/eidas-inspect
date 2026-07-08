import io

from asn1crypto import x509 as asn1_x509
from cryptography.hazmat.primitives import serialization
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation.pdf_embedded import collect_embedded_signatures
from pyhanko.sign.validation.qualified.tsp import TSPRegistry

from eidas_inspect_core import RevocationFetchers, VerificationVerdict, verify_pdf
from pdf_fixtures import (
    QC_TYPE_ESIGN_OID,
    add_lta_timestamp,
    build_crl,
    build_minimal_pdf,
    generate_ca,
    generate_ca_issued_signer,
    generate_self_signed_signer,
    sign_pdf_bytes,
)
from trust_list_fixtures import degraded_snapshot, fresh_snapshot, registry_with_granted_ca


def _asn1(cert_cx):
    return asn1_x509.Certificate.load(cert_cx.public_bytes(serialization.Encoding.DER))


def _qualified_signed_pdf_with_ca():
    """A QES-style signature (QcCompliance/QcSSCD/esign), issued by a
    separate CA (so revocation checking has somewhere to look), with a
    fresh (non-degraded) Trusted List snapshot granting that CA."""
    ca_key, ca_subject, ca_cert_cx = generate_ca()
    signer, leaf_cert_cx = generate_ca_issued_signer(
        ca_key,
        ca_subject,
        ca_cert_cx,
        qc_compliance=True,
        qc_sscd=True,
        qc_type_oid=QC_TYPE_ESIGN_OID,
    )
    signed = sign_pdf_bytes(build_minimal_pdf(), signer)
    snapshot = fresh_snapshot(registry_with_granted_ca(_asn1(ca_cert_cx)))
    return signed, ca_key, ca_subject, snapshot


def test_confirmed_qualified_and_good_is_trusted():
    signed, ca_key, ca_subject, snapshot = _qualified_signed_pdf_with_ca()
    crl_der = build_crl(ca_key, ca_subject)

    async def crl_fetch(url):
        return crl_der

    result = verify_pdf(
        signed,
        trust_list=snapshot,
        check_revocation=True,
        revocation_fetchers=RevocationFetchers(crl_fetch=crl_fetch),
    )

    assert result.verdict == VerificationVerdict.TRUSTED
    assert result.plain_summary == "Fully trusted — the signature is qualified and intact."
    assert result.verdict_breakdown.total == 1
    assert result.verdict_breakdown.confirmed_qualified == 1
    assert result.verdict_breakdown.issues == 0


def test_two_signatures_one_with_an_issue_is_partial_with_correct_counts():
    # Co-signing: the second signature's own coverage makes pyHanko's diff
    # analysis flag the first as modified (a documented Day-1 conservatism
    # for anything beyond NONE/LTA_UPDATES) -- a real, reproducible way to
    # get one clean item and one with an issue in the same document without
    # hand-building SignatureItem objects.
    alice = generate_self_signed_signer('Alice', 'Org A')
    bob = generate_self_signed_signer('Bob', 'Org B')
    pdf = build_minimal_pdf()
    once = sign_pdf_bytes(pdf, alice, field_name='Signature1')
    twice = sign_pdf_bytes(once, bob, field_name='Signature2')

    result = verify_pdf(twice)

    assert result.verdict == VerificationVerdict.PARTIAL
    assert result.plain_summary == "Partially trusted — 1 of 2 signatures has issues."
    assert result.verdict_breakdown.total == 2
    assert result.verdict_breakdown.issues == 1
    assert result.verdict_breakdown.confirmed_qualified == 0


def test_advanced_only_signature_is_partial_with_not_qualified_wording(signed_pdf):
    # A plain advanced signature (no qcStatements at all), nothing broken,
    # nothing unconfirmed -- simply not qualified. Distinct wording from
    # both "issues" and "unconfirmed": this is a known fact, not a problem
    # or a gap. Real-world regression case: Demo document.pdf hits exactly
    # this path.
    result = verify_pdf(signed_pdf)

    assert result.verdict == VerificationVerdict.PARTIAL
    assert result.plain_summary == "Partially trusted — the signature is valid but not qualified."
    assert result.verdict_breakdown.not_qualified == 1
    assert result.verdict_breakdown.issues == 0
    assert result.verdict_breakdown.unconfirmed == 0


def test_valid_but_trust_list_unavailable_is_partial_with_unconfirmed_wording(
    qes_signed_pdf,
):
    degraded = degraded_snapshot(TSPRegistry())  # issuer not found + degraded lists

    result = verify_pdf(qes_signed_pdf, trust_list=degraded)

    assert result.verdict == VerificationVerdict.PARTIAL
    assert 'could not be confirmed' in result.plain_summary
    assert 'issues' not in result.plain_summary
    assert result.plain_summary == (
        "Partially trusted — qualified status could not be confirmed right "
        "now for 1 of 1 signature."
    )
    assert result.verdict_breakdown.unconfirmed == 1
    assert result.verdict_breakdown.issues == 0


def test_all_tampered_is_not_trusted(tampered_signed_pdf):
    result = verify_pdf(tampered_signed_pdf)

    assert result.verdict == VerificationVerdict.NOT_TRUSTED
    assert result.plain_summary == "Do not rely on this document."
    assert result.verdict_breakdown.issues == result.verdict_breakdown.total


def test_revoked_only_item_is_not_trusted():
    signed, ca_key, ca_subject, snapshot = _qualified_signed_pdf_with_ca()
    revoked_crl = build_crl(ca_key, ca_subject, revoked_serial=_leaf_serial(signed))

    async def crl_fetch(url):
        return revoked_crl

    result = verify_pdf(
        signed,
        trust_list=snapshot,
        check_revocation=True,
        revocation_fetchers=RevocationFetchers(crl_fetch=crl_fetch),
    )

    assert result.verdict == VerificationVerdict.NOT_TRUSTED
    assert result.plain_summary == "Do not rely on this document."


def _leaf_serial(signed_pdf_bytes: bytes) -> int:
    reader = PdfFileReader(io.BytesIO(signed_pdf_bytes), strict=False)
    embedded = collect_embedded_signatures(reader)[0]
    return embedded.signer_cert.serial_number


def test_unsigned_pdf_is_no_signatures(unsigned_pdf):
    result = verify_pdf(unsigned_pdf)

    assert result.verdict == VerificationVerdict.NO_SIGNATURES
    assert result.plain_summary == 'This document contains no digital signatures.'
    assert result.verdict_breakdown is None


def test_appended_unconfirmed_lta_timestamp_does_not_demote_a_trusted_signature():
    signed, ca_key, ca_subject, snapshot = _qualified_signed_pdf_with_ca()
    crl_der = build_crl(ca_key, ca_subject)

    async def crl_fetch(url):
        return crl_der

    # add_lta_timestamp appends a standalone /DocTimeStamp from its own,
    # unregistered TSA -- it should show up as its own item, but must not
    # pull an otherwise fully-confirmed document down to PARTIAL.
    extended = add_lta_timestamp(signed)

    result = verify_pdf(
        extended,
        trust_list=snapshot,
        check_revocation=True,
        revocation_fetchers=RevocationFetchers(crl_fetch=crl_fetch),
    )

    assert len(result.items) == 2
    assert result.verdict == VerificationVerdict.TRUSTED
    assert result.verdict_breakdown.total == 1
