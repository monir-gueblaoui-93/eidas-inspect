import pytest

from pdf_fixtures import (
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
