import pytest

from pdf_fixtures import (
    QC_TYPE_ESEAL_OID,
    QC_TYPE_ESIGN_OID,
    add_lta_timestamp,
    build_encrypted_pdf,
    build_minimal_pdf,
    generate_self_signed_signer,
    sign_pdf_bytes,
    tamper_page_after_signing,
)


@pytest.fixture
def signer():
    return generate_self_signed_signer()


@pytest.fixture
def unsigned_pdf():
    return build_minimal_pdf()


@pytest.fixture
def signed_pdf(unsigned_pdf, signer):
    return sign_pdf_bytes(unsigned_pdf, signer)


@pytest.fixture
def tampered_signed_pdf(signed_pdf):
    return tamper_page_after_signing(signed_pdf)


@pytest.fixture
def lta_extended_signed_pdf(signed_pdf):
    return add_lta_timestamp(signed_pdf)


@pytest.fixture
def encrypted_pdf():
    return build_encrypted_pdf('correct-password')


@pytest.fixture
def qes_signed_pdf(unsigned_pdf):
    """Clean QES: esign + QcCompliance + QcSSCD."""
    qes_signer = generate_self_signed_signer(
        common_name='Alice Natural Person',
        organization='Test QTSP',
        qc_compliance=True,
        qc_sscd=True,
        qc_type_oid=QC_TYPE_ESIGN_OID,
    )
    return sign_pdf_bytes(unsigned_pdf, qes_signer)


@pytest.fixture
def qseal_signed_pdf(unsigned_pdf):
    """Clean QSeal: eseal + QcCompliance + QcSSCD."""
    qseal_signer = generate_self_signed_signer(
        common_name='Acme Corp Seal',
        organization='Acme Corp',
        qc_compliance=True,
        qc_sscd=True,
        qc_type_oid=QC_TYPE_ESEAL_OID,
    )
    return sign_pdf_bytes(unsigned_pdf, qseal_signer)


@pytest.fixture
def sloppy_qc_signed_pdf(unsigned_pdf):
    """QcCompliance and QcSSCD asserted, but QcType missing (common in the
    wild); must fall back to advanced rather than claiming qualified."""
    sloppy_signer = generate_self_signed_signer(
        common_name='Sloppy Signer',
        organization='Sloppy CA',
        qc_compliance=True,
        qc_sscd=True,
        qc_type_oid=None,
    )
    return sign_pdf_bytes(unsigned_pdf, sloppy_signer)
