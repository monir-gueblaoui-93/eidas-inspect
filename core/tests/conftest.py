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


@pytest.fixture
def multi_signer_pdf(unsigned_pdf):
    """A real two-signer PDF, genuinely mixed: Alice's certificate declares
    a qualified signature, Bob's is a plain advanced one -- and, per this
    project's own conservative diff-analysis policy (see
    ``_modification_status``), Alice's earlier signature gets flagged with
    an integrity issue purely because Bob co-signed over it afterwards,
    while Bob's (the last revision) reads clean. Not a contrived edge
    case: any real two-signer PDF produces exactly this shape today, so
    this is what "mixed validity" honestly looks like for a multi-sig
    document right now, not a hand-picked pair of outcomes."""
    alice = generate_self_signed_signer(
        common_name='Alice Natural Person',
        organization='Test QTSP',
        qc_compliance=True,
        qc_sscd=True,
        qc_type_oid=QC_TYPE_ESIGN_OID,
    )
    bob = generate_self_signed_signer(common_name='Bob', organization='Org B')
    once = sign_pdf_bytes(unsigned_pdf, alice, field_name='Signature1')
    return sign_pdf_bytes(once, bob, field_name='Signature2')


@pytest.fixture
def document_timestamp_only_pdf(unsigned_pdf):
    """A PDF carrying only a standalone document timestamp -- no /Sig field
    at all, just a bare /DocTimeStamp applied straight to an otherwise
    unsigned document. A real, if less common, case in its own right (a
    timestamp asserting a document existed, unchanged, at some moment,
    without anyone having signed it) -- and a genuinely different shape
    from ``lta_extended_signed_pdf``, which timestamps an *already-signed*
    document. Reuses ``add_lta_timestamp`` for the timestamping mechanics
    (a real, local DummyTimeStamper -- no network calls); the "LTA" framing
    in that helper's name doesn't apply here since there's no prior
    signature for this to be a long-term-archival extension *of*."""
    return add_lta_timestamp(unsigned_pdf)
