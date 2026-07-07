import pytest

from eidas_inspect_core import (
    CorruptedPdfError,
    IncorrectPasswordError,
    PasswordRequiredError,
    SignatureType,
    TrustChainStatus,
    SignatureLevel,
    VerificationVerdict,
    verify_pdf,
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
