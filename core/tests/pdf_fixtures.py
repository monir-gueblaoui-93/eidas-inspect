"""Helpers to synthesize fixture PDFs and self-signed signers for tests."""

import io
from datetime import datetime, timedelta, timezone

from asn1crypto import keys, x509 as asn1_x509
from cryptography import x509 as cx509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.pdf_utils.writer import PageObject, PdfFileWriter
from pyhanko.sign import PdfSignatureMetadata, SimpleSigner, sign_pdf
from pyhanko_certvalidator.registry import SimpleCertificateStore


def generate_self_signed_signer(
    common_name: str = 'Test Signer', organization: str = 'Test QTSP'
) -> SimpleSigner:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = cx509.Name(
        [
            cx509.NameAttribute(NameOID.COMMON_NAME, common_name),
            cx509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        ]
    )
    now = datetime.now(timezone.utc)
    cert = (
        cx509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(cx509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    signing_key = keys.PrivateKeyInfo.load(
        key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    signing_cert = asn1_x509.Certificate.load(
        cert.public_bytes(serialization.Encoding.DER)
    )
    return SimpleSigner(
        signing_cert=signing_cert,
        signing_key=signing_key,
        cert_registry=SimpleCertificateStore(),
    )


def build_minimal_pdf() -> bytes:
    w = PdfFileWriter()
    page = PageObject(contents=[], media_box=(0, 0, 200, 200))
    w.insert_page(page)
    buf = io.BytesIO()
    w.write(buf)
    return buf.getvalue()


def sign_pdf_bytes(
    pdf_bytes: bytes, signer: SimpleSigner, field_name: str = 'Signature1'
) -> bytes:
    w = IncrementalPdfFileWriter(io.BytesIO(pdf_bytes), strict=False)
    out = sign_pdf(w, PdfSignatureMetadata(field_name=field_name), signer=signer)
    return out.getvalue()


def build_encrypted_pdf(password: str) -> bytes:
    w = PdfFileWriter()
    page = PageObject(contents=[], media_box=(0, 0, 200, 200))
    w.insert_page(page)
    w.encrypt(owner_pass=password, user_pass=password)
    buf = io.BytesIO()
    w.write(buf)
    return buf.getvalue()


def append_incremental_junk(pdf_bytes: bytes) -> bytes:
    """Append a trivial incremental update after the file has been signed,
    to simulate modification-after-signing."""
    from pyhanko.pdf_utils import generic

    w = IncrementalPdfFileWriter(io.BytesIO(pdf_bytes), strict=False)
    w.set_info(
        generic.DictionaryObject(
            {generic.pdf_name('/Title'): generic.pdf_string('tampered')}
        )
    )
    buf = io.BytesIO()
    w.write(buf)
    return buf.getvalue()
