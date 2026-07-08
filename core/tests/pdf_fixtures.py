"""Helpers to synthesize fixture PDFs and self-signed signers for tests."""

import io
from datetime import datetime, timedelta, timezone

from asn1crypto import keys, x509 as asn1_x509
from cryptography import x509 as cx509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cryptography.x509 import ocsp as cx_ocsp
from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.pdf_utils.writer import PageObject, PdfFileWriter
from pyhanko.sign import PdfSignatureMetadata, PdfTimeStamper, SimpleSigner, sign_pdf
from pyhanko.sign.ades.qualified_asn1 import (
    QcCertificateType,
    QcStatement,
    QcStatements as PyhankoQcStatements,
)
from pyhanko.sign.timestamps import DummyTimeStamper
from pyhanko_certvalidator.registry import SimpleCertificateStore

QC_STATEMENTS_EXTENSION_OID = '1.3.6.1.5.5.7.1.3'
QC_TYPE_ESIGN_OID = '0.4.0.1862.1.6.1'
QC_TYPE_ESEAL_OID = '0.4.0.1862.1.6.2'

CRL_URL = 'http://test.invalid/crl'
OCSP_URL = 'http://test.invalid/ocsp'


def _build_qc_statements_der(
    *,
    qc_compliance: bool = False,
    qc_sscd: bool = False,
    qc_type_oid: str | None = None,
) -> bytes:
    statements = []
    if qc_compliance:
        statements.append(QcStatement({'statement_id': 'qc_compliance'}))
    if qc_sscd:
        statements.append(QcStatement({'statement_id': 'qc_sscd'}))
    if qc_type_oid is not None:
        statements.append(
            QcStatement(
                {
                    'statement_id': 'qc_type',
                    'statement_info': QcCertificateType([qc_type_oid]),
                }
            )
        )
    return PyhankoQcStatements(statements).dump()


def generate_self_signed_signer(
    common_name: str = 'Test Signer',
    organization: str = 'Test QTSP',
    *,
    qc_compliance: bool = False,
    qc_sscd: bool = False,
    qc_type_oid: str | None = None,
) -> SimpleSigner:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = cx509.Name(
        [
            cx509.NameAttribute(NameOID.COMMON_NAME, common_name),
            cx509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        ]
    )
    now = datetime.now(timezone.utc)
    builder = (
        cx509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(cx509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(
            cx509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )
    if qc_compliance or qc_sscd or qc_type_oid is not None:
        der = _build_qc_statements_der(
            qc_compliance=qc_compliance, qc_sscd=qc_sscd, qc_type_oid=qc_type_oid
        )
        builder = builder.add_extension(
            cx509.UnrecognizedExtension(
                cx509.ObjectIdentifier(QC_STATEMENTS_EXTENSION_OID), der
            ),
            critical=False,
        )
    cert = builder.sign(key, hashes.SHA256())
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


def add_lta_timestamp(pdf_bytes: bytes) -> bytes:
    """Append a document timestamp after signing, as PAdES-LTA permits.

    Uses pyHanko's own ``DummyTimeStamper`` (a local, self-signed TSA stand-in
    with no network calls) so the resulting incremental update is classified
    by pyHanko's diff analysis as ``ModificationLevel.LTA_UPDATES``, not
    tampering.
    """
    tsa_signer = generate_self_signed_signer(
        common_name='Test TSA', organization='Test TSA Org'
    )
    timestamper = DummyTimeStamper(
        tsa_cert=tsa_signer.signing_cert, tsa_key=tsa_signer.signing_key
    )
    w = IncrementalPdfFileWriter(io.BytesIO(pdf_bytes), strict=False)
    out = PdfTimeStamper(timestamper).timestamp_pdf(w, 'sha256')
    return out.getvalue()


def generate_ca() -> tuple[rsa.RSAPrivateKey, cx509.Name, cx509.Certificate]:
    """A self-signed CA cert, distinct from the leaf certs it issues -- real
    revocation checking needs an issuer that isn't the certificate being
    checked (a self-signed leaf is its own trust anchor and never gets
    revocation-checked at all)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = cx509.Name(
        [
            cx509.NameAttribute(NameOID.COMMON_NAME, 'Test CA'),
            cx509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Test QTSP'),
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
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(cx509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            cx509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return key, subject, cert


def generate_ca_issued_signer(
    ca_key: rsa.RSAPrivateKey,
    ca_subject: cx509.Name,
    ca_cert_cx: cx509.Certificate,
    *,
    common_name: str = 'Alice Natural Person',
    organization: str = 'Test QTSP',
    crl_url: str | None = CRL_URL,
    ocsp_url: str | None = OCSP_URL,
    qc_compliance: bool = False,
    qc_sscd: bool = False,
    qc_type_oid: str | None = None,
) -> tuple[SimpleSigner, cx509.Certificate]:
    """A leaf cert issued by ``ca_key``/``ca_subject`` (not self-signed),
    with CRL distribution point / OCSP responder extensions so revocation
    checking has somewhere to look. Returns the ``SimpleSigner`` plus the
    ``cryptography`` certificate object (needed to build matching CRLs/OCSP
    responses in tests)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = cx509.Name(
        [
            cx509.NameAttribute(NameOID.COMMON_NAME, common_name),
            cx509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        ]
    )
    now = datetime.now(timezone.utc)
    builder = (
        cx509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_subject)
        .public_key(key.public_key())
        .serial_number(cx509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(
            cx509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )
    if crl_url is not None:
        builder = builder.add_extension(
            cx509.CRLDistributionPoints(
                [
                    cx509.DistributionPoint(
                        full_name=[cx509.UniformResourceIdentifier(crl_url)],
                        relative_name=None,
                        reasons=None,
                        crl_issuer=None,
                    )
                ]
            ),
            critical=False,
        )
    if ocsp_url is not None:
        builder = builder.add_extension(
            cx509.AuthorityInformationAccess(
                [cx509.AccessDescription(cx509.OID_OCSP, cx509.UniformResourceIdentifier(ocsp_url))]
            ),
            critical=False,
        )
    if qc_compliance or qc_sscd or qc_type_oid is not None:
        der = _build_qc_statements_der(
            qc_compliance=qc_compliance, qc_sscd=qc_sscd, qc_type_oid=qc_type_oid
        )
        builder = builder.add_extension(
            cx509.UnrecognizedExtension(
                cx509.ObjectIdentifier(QC_STATEMENTS_EXTENSION_OID), der
            ),
            critical=False,
        )
    cert_cx = builder.sign(ca_key, hashes.SHA256())

    signing_key = keys.PrivateKeyInfo.load(
        key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    signing_cert = asn1_x509.Certificate.load(cert_cx.public_bytes(serialization.Encoding.DER))
    ca_cert_asn1 = asn1_x509.Certificate.load(ca_cert_cx.public_bytes(serialization.Encoding.DER))
    cert_registry = SimpleCertificateStore()
    cert_registry.register(ca_cert_asn1)
    signer = SimpleSigner(
        signing_cert=signing_cert,
        signing_key=signing_key,
        cert_registry=cert_registry,
    )
    return signer, cert_cx


def build_crl(
    ca_key: rsa.RSAPrivateKey,
    ca_subject: cx509.Name,
    *,
    revoked_serial: int | None = None,
    revocation_time: datetime | None = None,
) -> bytes:
    """A real, signed CRL from the given CA, optionally revoking one serial."""
    now = datetime.now(timezone.utc)
    builder = (
        cx509.CertificateRevocationListBuilder()
        .issuer_name(ca_subject)
        .last_update(now)
        .next_update(now + timedelta(days=7))
    )
    if revoked_serial is not None:
        revoked = (
            cx509.RevokedCertificateBuilder()
            .serial_number(revoked_serial)
            .revocation_date(revocation_time or (now - timedelta(hours=1)))
            .build()
        )
        builder = builder.add_revoked_certificate(revoked)
    return builder.sign(ca_key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


def build_ocsp_response(
    ca_key: rsa.RSAPrivateKey,
    ca_cert_cx: cx509.Certificate,
    leaf_cert_cx: cx509.Certificate,
    *,
    revoked: bool = False,
    revocation_time: datetime | None = None,
) -> bytes:
    """A real, signed OCSP response for ``leaf_cert_cx``, from the CA acting
    as its own OCSP responder (fine for test purposes)."""
    now = datetime.now(timezone.utc)
    if revoked:
        cert_status = cx_ocsp.OCSPCertStatus.REVOKED
        revocation_reason = cx509.ReasonFlags.unspecified
        revocation_time = revocation_time or (now - timedelta(hours=1))
    else:
        cert_status = cx_ocsp.OCSPCertStatus.GOOD
        revocation_reason = None
        revocation_time = None

    response = (
        cx_ocsp.OCSPResponseBuilder()
        .add_response(
            cert=leaf_cert_cx,
            issuer=ca_cert_cx,
            algorithm=hashes.SHA1(),
            cert_status=cert_status,
            this_update=now,
            next_update=now + timedelta(days=1),
            revocation_time=revocation_time,
            revocation_reason=revocation_reason,
        )
        .responder_id(cx_ocsp.OCSPResponderEncoding.HASH, ca_cert_cx)
        .sign(ca_key, hashes.SHA256())
    )
    return response.public_bytes(serialization.Encoding.DER)


def tamper_page_after_signing(pdf_bytes: bytes) -> bytes:
    """Mutate the first page's content after signing, as an incremental
    update, to simulate genuine tampering (not a permissible LTA update)."""
    w = IncrementalPdfFileWriter(io.BytesIO(pdf_bytes), strict=False)
    kids = w.root['/Pages']['/Kids']
    page_ref = kids.raw_get(0)
    page_obj = page_ref.get_object()
    page_obj[generic.pdf_name('/MediaBox')] = generic.ArrayObject(
        map(generic.FloatObject, (0, 0, 999, 999))
    )
    w.mark_update(page_ref)
    buf = io.BytesIO()
    w.write(buf)
    return buf.getvalue()
