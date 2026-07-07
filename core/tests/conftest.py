import pytest

from pdf_fixtures import (
    append_incremental_junk,
    build_encrypted_pdf,
    build_minimal_pdf,
    generate_self_signed_signer,
    sign_pdf_bytes,
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
    return append_incremental_junk(signed_pdf)


@pytest.fixture
def encrypted_pdf():
    return build_encrypted_pdf('correct-password')
