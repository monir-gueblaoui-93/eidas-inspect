import pytest

from eidas_inspect_core import (
    CorruptedPdfError,
    IncorrectPasswordError,
    PasswordRequiredError,
    SignatureType,
    TrustChainStatus,
    SignatureLevel,
    VerdictReason,
    VerificationVerdict,
    verify_pdf,
)
from pdf_fixtures import (
    QC_TYPE_ESIGN_OID,
    build_minimal_pdf,
    generate_ca,
    generate_ca_issued_signer,
    sign_pdf_bytes,
)


def test_unsigned_pdf_yields_no_signatures_verdict(unsigned_pdf):
    result = verify_pdf(unsigned_pdf)

    assert result.verdict == VerificationVerdict.NO_SIGNATURES
    assert result.items == []
    assert len(result.document_sha256) == 64


def test_signed_pdf_without_qc_statements_is_advanced_with_trust_unknown(signed_pdf):
    result = verify_pdf(signed_pdf)

    assert result.verdict == VerificationVerdict.PARTIAL
    assert len(result.items) == 1
    item = result.items[0]
    assert item.type == SignatureType.SIGNATURE
    assert item.integrity.intact is True
    assert item.integrity.signature_valid is True
    assert item.integrity.modified_after_signing is False
    assert item.integrity.lta_extended is False
    assert item.signer_name == 'Test Signer'
    assert item.issuing_tsp == 'Test QTSP'
    assert item.signing_time is not None
    assert item.level == SignatureLevel.ADVANCED
    assert item.trust_chain_status == TrustChainStatus.UNKNOWN
    assert 'No qcStatements' in item.technical_detail


def test_clean_qes_is_classified_as_qualified_signature(qes_signed_pdf):
    result = verify_pdf(qes_signed_pdf)

    item = result.items[0]
    assert item.type == SignatureType.SIGNATURE
    assert item.level == SignatureLevel.QUALIFIED
    assert 'qualified signature' in item.plain_explanation
    assert 'Trusted List' in item.plain_explanation
    assert item.trust_chain_status == TrustChainStatus.UNKNOWN


def test_clean_qseal_is_classified_as_qualified_seal(qseal_signed_pdf):
    result = verify_pdf(qseal_signed_pdf)

    item = result.items[0]
    assert item.type == SignatureType.SEAL
    assert item.level == SignatureLevel.QUALIFIED
    assert 'qualified seal' in item.plain_explanation


def test_sloppy_cert_missing_qc_type_falls_back_to_advanced(sloppy_qc_signed_pdf):
    result = verify_pdf(sloppy_qc_signed_pdf)

    item = result.items[0]
    assert item.level == SignatureLevel.ADVANCED
    assert item.type == SignatureType.SIGNATURE
    assert 'ambiguous' in item.technical_detail
    assert 'QcType' in item.technical_detail
    # Conservative: never over-claim qualified on an ambiguous certificate.
    assert 'declares this a qualified' not in item.plain_explanation


def test_modified_after_signing_is_detected(tampered_signed_pdf):
    result = verify_pdf(tampered_signed_pdf)

    item = result.items[0]
    assert item.integrity.intact is True
    assert item.integrity.signature_valid is True
    assert item.integrity.modified_after_signing is True
    assert item.integrity.lta_extended is False
    assert 'changed after' in item.plain_explanation
    # Certificate details are read from the cert itself, independent of
    # the tampering finding -- there's still a certificate to describe.
    assert item.certificate is not None


def test_certificate_details_are_structured_and_distinguish_subject_from_issuer():
    ca_key, ca_subject, ca_cert_cx = generate_ca()  # CN='Test CA', O='Test QTSP'
    signer, _leaf_cert_cx = generate_ca_issued_signer(
        ca_key,
        ca_subject,
        ca_cert_cx,
        common_name='Alice Natural Person',
        organization='Scrive AB',
        qc_compliance=True,
        qc_sscd=True,
        qc_type_oid=QC_TYPE_ESIGN_OID,
    )
    pdf = sign_pdf_bytes(build_minimal_pdf(), signer)

    result = verify_pdf(pdf)

    cert = result.items[0].certificate
    assert cert is not None
    assert cert.subject_common_name == 'Alice Natural Person'
    assert cert.subject_organization == 'Scrive AB'
    assert cert.issuer_common_name == 'Test CA'
    assert cert.issuer_organization == 'Test QTSP'
    assert cert.valid_from < cert.valid_until
    # Hex, colon-separated -- the conventional X.509 display form.
    assert cert.serial_number
    assert all(c in '0123456789ABCDEF:' for c in cert.serial_number)
    assert not cert.serial_number.startswith(':')
    assert not cert.serial_number.endswith(':')


def test_multi_signer_pdf_reports_both_signers_with_mixed_outcomes(multi_signer_pdf):
    result = verify_pdf(multi_signer_pdf)

    assert len(result.items) == 2
    alice_item = next(i for i in result.items if i.signer_name == 'Alice Natural Person')
    bob_item = next(i for i in result.items if i.signer_name == 'Bob')

    # Alice's certificate declares a qualified signature; Bob co-signing
    # afterward is a legitimate FORM_FILLING-level update, not tampering,
    # so her (earlier) revision reads clean too. No trust_list is passed
    # here, so her qualified *claim* can't be confirmed -- unconfirmed,
    # not an issue, and a genuinely different "mixed" outcome than
    # integrity: level/confirmation, not tamper detection.
    assert alice_item.level == SignatureLevel.QUALIFIED
    assert alice_item.integrity.modified_after_signing is False
    assert alice_item.verdict_reason == VerdictReason.UNCONFIRMED

    # Bob's (the last) revision is clean, but his plain certificate never
    # claimed qualified in the first place.
    assert bob_item.level == SignatureLevel.ADVANCED
    assert bob_item.integrity.modified_after_signing is False
    assert bob_item.verdict_reason == VerdictReason.NOT_QUALIFIED

    assert result.verdict == VerificationVerdict.PARTIAL
    assert result.verdict_breakdown.total == 2


def test_document_timestamp_only_pdf_is_a_single_timestamp_item(document_timestamp_only_pdf):
    result = verify_pdf(document_timestamp_only_pdf)

    assert result.verdict != VerificationVerdict.NO_SIGNATURES
    assert len(result.items) == 1
    item = result.items[0]
    assert item.type == SignatureType.TIMESTAMP
    assert item.integrity.intact is True
    assert item.integrity.signature_valid is True
    assert item.signing_time is not None
    assert 'timestamp' in item.plain_explanation.lower()
    # The stand-in TSA isn't a registered/qualified authority, so this is
    # an honest "not qualified", not "unconfirmed" or "issue".
    assert result.verdict == VerificationVerdict.PARTIAL
    assert result.verdict_breakdown.not_qualified == 1


def test_lta_extension_is_not_treated_as_tampering(lta_extended_signed_pdf):
    result = verify_pdf(lta_extended_signed_pdf)

    signature_item = next(
        i for i in result.items if i.type == SignatureType.SIGNATURE
    )
    assert signature_item.integrity.intact is True
    assert signature_item.integrity.signature_valid is True
    assert signature_item.integrity.modified_after_signing is False
    assert signature_item.integrity.lta_extended is True
    assert 'extended' in signature_item.plain_explanation
    assert result.verdict != VerificationVerdict.NOT_TRUSTED


def test_corrupted_pdf_raises_typed_error():
    with pytest.raises(CorruptedPdfError):
        verify_pdf(b'this is not a pdf')


def test_empty_bytes_raises_typed_error():
    with pytest.raises(CorruptedPdfError):
        verify_pdf(b'')


def test_encrypted_pdf_without_password_raises(encrypted_pdf):
    with pytest.raises(PasswordRequiredError):
        verify_pdf(encrypted_pdf)


def test_encrypted_pdf_with_wrong_password_raises(encrypted_pdf):
    with pytest.raises(IncorrectPasswordError):
        verify_pdf(encrypted_pdf, password='definitely-wrong')


def test_encrypted_pdf_with_correct_password_verifies(encrypted_pdf):
    result = verify_pdf(encrypted_pdf, password='correct-password')

    assert result.verdict == VerificationVerdict.NO_SIGNATURES
