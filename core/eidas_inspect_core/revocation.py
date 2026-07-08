"""OCSP/CRL revocation checking.

Reuses pyhanko_certvalidator's own protocol-level helpers -- URL extraction
from CRLDP/AIA extensions, OCSP request/response formatting -- rather than
reimplementing RFC 5280/RFC 6960 details. What's custom here is the
transport (an injectable async fetch callable, mirroring the Trusted List
module's ``Fetcher`` design) plus per-certificate outcome tracking: in
pyhanko_certvalidator's own "soft-fail" mode, "couldn't reach the responder"
and "nothing to check" both just leave ``revocation_details`` at ``None``,
and this project needs to tell those two apart honestly rather than
reporting a clean bill of health when the check never actually happened.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

import aiohttp
from asn1crypto import crl, ocsp, pem
from pyhanko_certvalidator.errors import CRLFetchError, OCSPFetchError
from pyhanko_certvalidator.fetchers.api import (
    CertificateFetcher,
    CRLFetcher,
    Fetchers,
    OCSPFetcher,
)
from pyhanko_certvalidator.fetchers.common_utils import (
    enumerate_delivery_point_urls,
    format_ocsp_request,
    process_ocsp_response_data,
)
from pyhanko_certvalidator.util import get_ocsp_urls, get_relevant_crl_dps, issuer_serial

__all__ = [
    'DEFAULT_TIMEOUT_SECONDS',
    'CrlBytesFetch',
    'FetchOutcome',
    'OcspBytesFetch',
    'RevocationFetchers',
    'TrackedCRLFetcher',
    'TrackedOCSPFetcher',
    'build_fetchers',
    'default_fetch_crl',
    'default_fetch_ocsp',
]

DEFAULT_TIMEOUT_SECONDS = 5.0
"""Hard per-endpoint timeout for OCSP/CRL fetches -- an unreachable or slow
responder must never stall verification, per the PRD's degraded-but-honest
requirement."""

CrlBytesFetch = Callable[[str], Awaitable[bytes]]
OcspBytesFetch = Callable[[str, bytes], Awaitable[bytes]]


async def default_fetch_crl(url: str) -> bytes:
    async with aiohttp.ClientSession() as session:
        async with session.get(
            url, headers={'Accept': 'application/pkix-crl'}
        ) as response:
            response.raise_for_status()
            return await response.read()


async def default_fetch_ocsp(url: str, request_der: bytes) -> bytes:
    headers = {
        'Content-Type': 'application/ocsp-request',
        'Accept': 'application/ocsp-response',
    }
    async with aiohttp.ClientSession() as session:
        async with session.post(
            url, data=request_der, headers=headers
        ) as response:
            response.raise_for_status()
            return await response.read()


@dataclass(frozen=True)
class RevocationFetchers:
    """Injectable transport for revocation checking. Defaults fetch over the
    real network with a hard per-endpoint timeout; tests supply stub
    callables the same way the Trusted List module's ``Fetcher`` is
    stubbed -- no real OCSP/CRL network calls in tests."""

    crl_fetch: CrlBytesFetch = default_fetch_crl
    ocsp_fetch: OcspBytesFetch = default_fetch_ocsp
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS


@dataclass
class FetchOutcome:
    """Whether revocation info was actually sought for one certificate, and
    whether that attempt succeeded."""

    attempted: bool = False
    failed: bool = False

    @property
    def ok(self) -> bool:
        return self.attempted and not self.failed


class TrackedCRLFetcher(CRLFetcher):
    def __init__(self, fetch: CrlBytesFetch, timeout_seconds: float):
        self._fetch = fetch
        self._timeout = timeout_seconds
        self._crls_by_cert: dict[bytes, list] = {}
        self._outcome_by_cert: dict[bytes, FetchOutcome] = {}

    def outcome_for(self, cert) -> FetchOutcome:
        return self._outcome_by_cert.get(issuer_serial(cert), FetchOutcome())

    async def fetch(self, cert, *, use_deltas=None):
        key = issuer_serial(cert)
        outcome = self._outcome_by_cert.setdefault(key, FetchOutcome())
        sources = get_relevant_crl_dps(cert, use_deltas=use_deltas)
        if not sources:
            # No CRL distribution point on the cert at all -- nothing to
            # attempt, this is "not checked", not "failed".
            self._crls_by_cert[key] = []
            return []

        outcome.attempted = True
        results = []
        last_error: Exception | None = None
        for dp in sources:
            for url in enumerate_delivery_point_urls(dp):
                try:
                    data = await asyncio.wait_for(
                        self._fetch(url), timeout=self._timeout
                    )
                    if pem.detect(data):
                        _, _, data = pem.unarmor(data)
                    results.append(crl.CertificateList.load(data))
                except Exception as e:
                    last_error = e

        if not results and last_error is not None:
            outcome.failed = True
            raise CRLFetchError(f'Failed to fetch CRL: {last_error}') from last_error

        self._crls_by_cert[key] = results
        return results

    def fetched_crls(self):
        return [c for lst in self._crls_by_cert.values() for c in lst]

    def fetched_crls_for_cert(self, cert):
        return self._crls_by_cert[issuer_serial(cert)]


class TrackedOCSPFetcher(OCSPFetcher):
    def __init__(self, fetch: OcspBytesFetch, timeout_seconds: float):
        self._fetch = fetch
        self._timeout = timeout_seconds
        self._responses: dict[tuple, ocsp.OCSPResponse] = {}
        self._outcome_by_cert: dict[bytes, FetchOutcome] = {}

    def outcome_for(self, cert) -> FetchOutcome:
        return self._outcome_by_cert.get(issuer_serial(cert), FetchOutcome())

    async def fetch(self, cert, authority):
        cert_key = issuer_serial(cert)
        outcome = self._outcome_by_cert.setdefault(cert_key, FetchOutcome())
        urls = get_ocsp_urls(cert)
        if not urls:
            raise OCSPFetchError('No URLs to fetch OCSP responses from')

        outcome.attempted = True
        last_error: Exception | None = None
        for url in urls:
            try:
                request = format_ocsp_request(
                    cert, authority, certid_hash_algo='sha1', request_nonces=False
                )
                data = await asyncio.wait_for(
                    self._fetch(url, request.dump()), timeout=self._timeout
                )
                response = process_ocsp_response_data(
                    data, ocsp_request=request, ocsp_url=url
                )
                self._responses[(cert_key, authority.hashable)] = response
                return response
            except Exception as e:
                last_error = e

        outcome.failed = True
        raise OCSPFetchError('Failed to fetch OCSP response') from last_error

    def fetched_responses(self):
        return list(self._responses.values())

    def fetched_responses_for_cert(self, cert):
        target = issuer_serial(cert)
        return [
            response
            for (subject_issuer_serial, _authority), response in self._responses.items()
            if subject_issuer_serial == target
        ]


class _NullCertFetcher(CertificateFetcher):
    """We always supply the full chain explicitly (via the CMS's embedded
    certs / an explicit certificate registry), so no certificate ever needs
    fetching -- this exists only to satisfy the ``Fetchers`` contract."""

    async def fetch_cert_issuers(self, cert):
        return
        yield  # pragma: no cover -- makes this an (empty) async generator

    async def fetch_crl_issuers(self, certificate_list):
        return
        yield  # pragma: no cover

    def fetched_certs(self):
        return []


def build_fetchers(
    revocation_fetchers: RevocationFetchers,
) -> tuple[Fetchers, TrackedCRLFetcher, TrackedOCSPFetcher]:
    crl_fetcher = TrackedCRLFetcher(
        revocation_fetchers.crl_fetch, revocation_fetchers.timeout_seconds
    )
    ocsp_fetcher = TrackedOCSPFetcher(
        revocation_fetchers.ocsp_fetch, revocation_fetchers.timeout_seconds
    )
    fetchers = Fetchers(
        ocsp_fetcher=ocsp_fetcher,
        crl_fetcher=crl_fetcher,
        cert_fetcher=_NullCertFetcher(),
    )
    return fetchers, crl_fetcher, ocsp_fetcher
