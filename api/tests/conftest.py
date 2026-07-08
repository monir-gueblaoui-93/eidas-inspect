"""Shared fixtures for the API test suite.

Reuses core's own test fixture helpers (self-signed/CA-issued certs, CRL/
OCSP builders, synthetic Trusted List registries) rather than duplicating
them -- ``core`` stays untouched, so these live in ``core/tests`` and are
imported here by adding that directory to ``sys.path``.
"""

import sys
from pathlib import Path

import pytest
from asn1crypto import x509 as asn1_x509
from cryptography.hazmat.primitives import serialization
from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parents[2]
CORE_TESTS_DIR = REPO_ROOT / 'core' / 'tests'
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(CORE_TESTS_DIR))

from pdf_fixtures import (  # noqa: E402
    QC_TYPE_ESIGN_OID,
    build_crl,
    build_encrypted_pdf,
    build_minimal_pdf,
    generate_ca,
    generate_ca_issued_signer,
    generate_self_signed_signer,
    sign_pdf_bytes,
)
from trust_list_fixtures import fresh_snapshot, registry_with_granted_ca  # noqa: E402

from api.main import create_app  # noqa: E402
from api.rate_limit import limiter  # noqa: E402
from eidas_inspect_core.revocation import RevocationFetchers  # noqa: E402
from eidas_inspect_core.trust_list import TrustListCache  # noqa: E402


def _asn1(cert_cx):
    return asn1_x509.Certificate.load(cert_cx.public_bytes(serialization.Encoding.DER))


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    """The Limiter is a process-wide singleton (slowapi's decorator API
    binds it at route-definition/import time) -- reset its in-memory
    storage between tests so quota used by one test doesn't bleed into the
    next."""
    limiter.reset()
    yield


@pytest.fixture
def app_factory():
    """Build an isolated, already-started TestClient with a pre-seeded,
    offline Trusted List snapshot and no background refresh loop -- the
    whole suite runs without any network access.

    Returns a ready-to-use ``TestClient`` (not a bare app): the FastAPI
    lifespan -- which populates ``app.state.trust_list_cache`` -- only runs
    once the client's context is entered, so entry/exit is handled here
    rather than in every test.
    """
    clients: list[TestClient] = []

    def _make(snapshot=None, revocation_fetchers: RevocationFetchers | None = None):
        cache = TrustListCache()
        if snapshot is not None:
            # Test-only seeding: there's no real (signed, ETSI-schema) XML
            # fixture that would produce a registry granting our synthetic
            # test CA, so the snapshot is injected directly rather than
            # built via TrustListCache.refresh().
            cache._snapshot = snapshot
        app = create_app(
            trust_list_cache=cache,
            revocation_fetchers=revocation_fetchers,
            start_background_refresh=False,
        )
        client = TestClient(app)
        client.__enter__()
        clients.append(client)
        return client

    yield _make

    for client in clients:
        client.__exit__(None, None, None)


@pytest.fixture
def qualified_pdf_and_snapshot():
    """A QES-style signed PDF, a fresh (non-degraded) Trusted List snapshot
    granting its issuing CA, and a "good" CRL response -- the end-to-end
    confirmed-qualified/TRUSTED case."""
    ca_key, ca_subject, ca_cert_cx = generate_ca()
    signer, _leaf_cert_cx = generate_ca_issued_signer(
        ca_key,
        ca_subject,
        ca_cert_cx,
        qc_compliance=True,
        qc_sscd=True,
        qc_type_oid=QC_TYPE_ESIGN_OID,
    )
    pdf_bytes = sign_pdf_bytes(build_minimal_pdf(), signer)
    snapshot = fresh_snapshot(registry_with_granted_ca(_asn1(ca_cert_cx)))
    crl_der = build_crl(ca_key, ca_subject)

    async def crl_fetch(url):
        return crl_der

    revocation_fetchers = RevocationFetchers(crl_fetch=crl_fetch)
    return pdf_bytes, snapshot, revocation_fetchers


@pytest.fixture
def plain_signed_pdf() -> bytes:
    signer = generate_self_signed_signer()
    return sign_pdf_bytes(build_minimal_pdf(), signer)


@pytest.fixture
def encrypted_pdf() -> bytes:
    return build_encrypted_pdf('correct-password')
