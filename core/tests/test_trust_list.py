import asyncio
import io
from pathlib import Path

import pytest
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import PdfSignatureMetadata, PdfTimeStamper, sign_pdf
from pyhanko.sign.timestamps import DummyTimeStamper
from pyhanko.sign.validation.qualified.tsp import TSPRegistry

from eidas_inspect_core import (
    SignatureLevel,
    SignatureType,
    TimestampQuality,
    TrustChainStatus,
    verify_pdf,
)
from eidas_inspect_core.trust_list import LotlStatus, TrustListSnapshot, build_snapshot
from eidas_inspect_core.trust_list.cache import TrustListCache
from pdf_fixtures import (
    QC_TYPE_ESIGN_OID,
    build_minimal_pdf,
    generate_self_signed_signer,
    sign_pdf_bytes,
)
from trust_list_fixtures import (
    degraded_snapshot,
    fresh_snapshot,
    registry_with_granted_ca,
    registry_with_granted_ca_and_territory,
    registry_with_granted_qtst,
)

FIXTURES = Path(__file__).parent / 'fixtures' / 'trust_list'


def _read(name: str) -> str:
    return (FIXTURES / name).read_text()


def _stub_fetch(contents: dict[str, str]):
    async def fetch(url: str) -> str:
        for needle, text in contents.items():
            if needle in url:
                return text
        raise LookupError(f'no fixture registered for {url}')

    return fetch


def _sign_with_embedded_timestamp(pdf_bytes, main_signer, tsa_signer):
    timestamper = DummyTimeStamper(
        tsa_cert=tsa_signer.signing_cert, tsa_key=tsa_signer.signing_key
    )
    w = IncrementalPdfFileWriter(io.BytesIO(pdf_bytes), strict=False)
    return sign_pdf(
        w,
        PdfSignatureMetadata(field_name='Sig1'),
        signer=main_signer,
        timestamper=timestamper,
    ).getvalue()


# --- Real-fixture XML parsing / signature verification -----------------


def test_build_snapshot_parses_real_lotl_and_member_states():
    lotl_xml = _read('eu-lotl.xml')
    fetch = _stub_fetch(
        {'mca.org.mt': _read('MT.xml'), 'fjarskiptastofa.is': _read('IS.xml')}
    )

    snapshot = asyncio.run(
        build_snapshot(lotl_xml, fetch, only_territories={'MT', 'IS'})
    )

    assert snapshot.lotl_status == LotlStatus.OK
    assert snapshot.territory_status['MT'].ok
    assert snapshot.territory_status['IS'].ok
    assert not snapshot.is_degraded(snapshot.refreshed_at)

    cas = list(snapshot.registry.known_certificate_authorities)
    tsas = list(snapshot.registry.known_timestamp_authorities)
    assert len(cas) > 0  # Malta's CA/QC services
    assert len(tsas) > 0  # Iceland's QTST services


def test_build_snapshot_tracks_which_territory_each_service_came_from():
    lotl_xml = _read('eu-lotl.xml')
    fetch = _stub_fetch(
        {'mca.org.mt': _read('MT.xml'), 'fjarskiptastofa.is': _read('IS.xml')}
    )

    snapshot = asyncio.run(
        build_snapshot(lotl_xml, fetch, only_territories={'MT', 'IS'})
    )

    # Every service registered from either territory's TL must resolve back
    # to that exact territory -- checked over the whole set rather than "the
    # first" authority found, since a plain Python set has no defined
    # iteration order and either territory's TL might register both CA and
    # QTST-type services.
    authorities = set(snapshot.registry.known_certificate_authorities) | set(
        snapshot.registry.known_timestamp_authorities
    )
    territories_seen = set()
    for authority in authorities:
        for service in snapshot.registry.applicable_service_definitions(authority, None):
            territory = snapshot.territory_for_service(service)
            assert territory is not None
            if territory.territory == 'MT':
                assert territory.territory_name == 'Malta'
                assert 'mca.org.mt' in territory.tl_location_url
            elif territory.territory == 'IS':
                assert territory.territory_name == 'Iceland'
                assert 'fjarskiptastofa.is' in territory.tl_location_url
            else:
                pytest.fail(f'unexpected territory: {territory.territory}')
            territories_seen.add(territory.territory)

    assert territories_seen == {'MT', 'IS'}


def test_territory_for_service_is_none_for_no_match():
    assert TrustListSnapshot.empty().territory_for_service(None) is None


def test_build_snapshot_isolates_one_territory_failure():
    lotl_xml = _read('eu-lotl.xml')
    # No MT entry in the stub, so fetching Malta's list raises.
    fetch = _stub_fetch({'fjarskiptastofa.is': _read('IS.xml')})

    snapshot = asyncio.run(
        build_snapshot(lotl_xml, fetch, only_territories={'MT', 'IS'})
    )

    assert snapshot.lotl_status == LotlStatus.OK
    assert not snapshot.territory_status['MT'].ok
    assert snapshot.territory_status['IS'].ok
    assert snapshot.is_degraded(snapshot.refreshed_at)


def test_build_snapshot_isolates_a_tampered_member_state_list():
    lotl_xml = _read('eu-lotl.xml')
    tampered_mt = _read('MT.xml').replace('Malta', 'Latvia', 1)
    fetch = _stub_fetch(
        {'mca.org.mt': tampered_mt, 'fjarskiptastofa.is': _read('IS.xml')}
    )

    snapshot = asyncio.run(
        build_snapshot(lotl_xml, fetch, only_territories={'MT', 'IS'})
    )

    assert snapshot.lotl_status == LotlStatus.OK
    assert not snapshot.territory_status['MT'].ok
    assert snapshot.territory_status['MT'].error
    assert snapshot.territory_status['IS'].ok


def test_build_snapshot_reports_unavailable_when_lotl_itself_is_corrupt():
    corrupt_lotl = _read('eu-lotl.xml').replace(
        'TrustServiceStatusList', 'Nonsense', 1
    )

    snapshot = asyncio.run(build_snapshot(corrupt_lotl, _stub_fetch({})))

    assert snapshot.lotl_status == LotlStatus.UNAVAILABLE
    assert snapshot.lotl_error is not None
    assert snapshot.is_degraded(snapshot.refreshed_at)


# --- TrustListCache ------------------------------------------------------


def test_cache_starts_empty_and_degraded():
    cache = TrustListCache(fetch=_stub_fetch({}))

    assert cache.snapshot.lotl_status == LotlStatus.UNAVAILABLE
    assert cache.snapshot.refreshed_at is None


def test_cache_refresh_populates_snapshot():
    lotl_xml = _read('eu-lotl.xml')

    async def fetch(url: str) -> str:
        if url == 'https://example.test/lotl.xml':
            return lotl_xml
        if 'mca.org.mt' in url:
            return _read('MT.xml')
        raise LookupError(url)

    cache = TrustListCache(
        lotl_url='https://example.test/lotl.xml',
        fetch=fetch,
        only_territories={'MT'},
    )
    asyncio.run(cache.refresh())

    assert cache.snapshot.lotl_status == LotlStatus.OK
    assert cache.snapshot.territory_status['MT'].ok


def test_cache_keeps_previous_snapshot_when_lotl_fetch_fails():
    lotl_xml = _read('eu-lotl.xml')
    should_fail = False

    async def fetch(url: str) -> str:
        if should_fail:
            raise ConnectionError('simulated outage')
        if url == 'https://example.test/lotl.xml':
            return lotl_xml
        if 'mca.org.mt' in url:
            return _read('MT.xml')
        raise LookupError(url)

    cache = TrustListCache(
        lotl_url='https://example.test/lotl.xml',
        fetch=fetch,
        only_territories={'MT'},
    )
    asyncio.run(cache.refresh())
    good_snapshot = cache.snapshot
    assert good_snapshot.lotl_status == LotlStatus.OK

    should_fail = True
    asyncio.run(cache.refresh())

    assert cache.snapshot is good_snapshot


# --- Trust chain assessment wired into verify_pdf ------------------------


def test_no_trust_list_supplied_keeps_trust_chain_unknown(signer, unsigned_pdf):
    signed = sign_pdf_bytes(unsigned_pdf, signer)
    result = verify_pdf(signed)
    assert result.items[0].trust_chain_status == TrustChainStatus.UNKNOWN


def test_granted_ca_yields_trusted_and_qualified():
    qes_signer = generate_self_signed_signer(
        common_name='Alice Natural Person',
        organization='Test QTSP',
        qc_compliance=True,
        qc_sscd=True,
        qc_type_oid=QC_TYPE_ESIGN_OID,
    )
    pdf = sign_pdf_bytes(build_minimal_pdf(), qes_signer)
    snapshot = fresh_snapshot(registry_with_granted_ca(qes_signer.signing_cert))

    result = verify_pdf(pdf, trust_list=snapshot)

    item = result.items[0]
    assert item.level == SignatureLevel.QUALIFIED
    assert item.trust_chain_status == TrustChainStatus.TRUSTED
    assert 'confirmed on the EU Trusted List' in item.plain_explanation


def test_granted_ca_yields_trust_match_with_territory_info():
    qes_signer = generate_self_signed_signer(
        common_name='Alice Natural Person',
        organization='Test QTSP',
        qc_compliance=True,
        qc_sscd=True,
        qc_type_oid=QC_TYPE_ESIGN_OID,
    )
    pdf = sign_pdf_bytes(build_minimal_pdf(), qes_signer)
    registry, service_territories = registry_with_granted_ca_and_territory(
        qes_signer.signing_cert,
        service_name='Test QTSP CA',
        territory='FR',
        territory_name='France',
        tl_location_url='https://example.test/FR-trusted-list.xml',
    )
    snapshot = fresh_snapshot(registry, service_territories)

    result = verify_pdf(pdf, trust_list=snapshot)

    item = result.items[0]
    assert item.trust_chain_status == TrustChainStatus.TRUSTED
    assert item.trust_match is not None
    assert item.trust_match.territory == 'FR'
    assert item.trust_match.territory_name == 'France'
    assert item.trust_match.trust_service_name == 'Test QTSP CA'
    assert item.trust_match.tl_location_url == 'https://example.test/FR-trusted-list.xml'


def test_granted_ca_without_territory_info_has_no_trust_match():
    # registry_with_granted_ca (no territory tracking) mirrors a snapshot
    # built by hand rather than by build_snapshot() -- trust_chain_status
    # still resolves correctly, but there's no trusted list to link to.
    qes_signer = generate_self_signed_signer(
        common_name='Alice Natural Person',
        organization='Test QTSP',
        qc_compliance=True,
        qc_sscd=True,
        qc_type_oid=QC_TYPE_ESIGN_OID,
    )
    pdf = sign_pdf_bytes(build_minimal_pdf(), qes_signer)
    snapshot = fresh_snapshot(registry_with_granted_ca(qes_signer.signing_cert))

    result = verify_pdf(pdf, trust_list=snapshot)

    assert result.items[0].trust_chain_status == TrustChainStatus.TRUSTED
    assert result.items[0].trust_match is None


def test_unregistered_ca_with_fresh_lists_is_confidently_untrusted(
    signer, unsigned_pdf
):
    signed = sign_pdf_bytes(unsigned_pdf, signer)
    empty_but_fresh = fresh_snapshot(TSPRegistry())

    result = verify_pdf(signed, trust_list=empty_but_fresh)

    assert result.items[0].trust_chain_status == TrustChainStatus.UNTRUSTED
    assert result.items[0].trust_match is None


def test_unregistered_ca_with_degraded_lists_is_unavailable_not_untrusted(
    signer, unsigned_pdf
):
    signed = sign_pdf_bytes(unsigned_pdf, signer)
    empty_and_degraded = degraded_snapshot(TSPRegistry())

    result = verify_pdf(signed, trust_list=empty_and_degraded)

    item = result.items[0]
    assert item.trust_chain_status == TrustChainStatus.UNAVAILABLE
    assert item.trust_chain_status != TrustChainStatus.UNTRUSTED


def test_ca_on_list_but_cert_not_qualified_is_untrusted_not_trusted(
    signer, unsigned_pdf
):
    # Registered as a granted CA/QC service, but the cert itself carries no
    # qcStatements -- ETSI's own algorithm still requires the cert to assert
    # qualification, so this must not be silently upgraded to TRUSTED.
    signed = sign_pdf_bytes(unsigned_pdf, signer)
    snapshot = fresh_snapshot(registry_with_granted_ca(signer.signing_cert))

    result = verify_pdf(signed, trust_list=snapshot)

    item = result.items[0]
    assert item.level == SignatureLevel.ADVANCED
    assert item.trust_chain_status == TrustChainStatus.UNTRUSTED


def test_qtst_backed_embedded_timestamp_is_marked_qualified():
    main_signer = generate_self_signed_signer(
        common_name='Alice Natural Person',
        organization='Test QTSP',
        qc_compliance=True,
        qc_sscd=True,
        qc_type_oid=QC_TYPE_ESIGN_OID,
    )
    # Real qualified TSA certs carry their own qcStatements (QcCompliance) --
    # pyHanko's QualificationAssessor checks the leaf cert's own statements
    # for TSAs exactly like it does for signer certs, TL membership alone
    # isn't sufficient.
    tsa_signer = generate_self_signed_signer(
        'Test TSA', 'Test TSA Org', qc_compliance=True
    )
    signed = _sign_with_embedded_timestamp(
        build_minimal_pdf(), main_signer, tsa_signer
    )

    snapshot = fresh_snapshot(registry_with_granted_qtst(tsa_signer.signing_cert))
    result = verify_pdf(signed, trust_list=snapshot)

    item = result.items[0]
    assert item.timestamp_quality == TimestampQuality.QUALIFIED_TSA
    assert 'backed by a qualified timestamp' in item.plain_explanation


def test_embedded_timestamp_from_unregistered_tsa_stays_unknown_quality(
    signer, unsigned_pdf
):
    tsa_signer = generate_self_signed_signer('Test TSA', 'Test TSA Org')
    signed = _sign_with_embedded_timestamp(unsigned_pdf, signer, tsa_signer)

    snapshot = fresh_snapshot(registry_with_granted_ca(signer.signing_cert))
    result = verify_pdf(signed, trust_list=snapshot)

    item = result.items[0]
    assert item.timestamp_quality == TimestampQuality.UNKNOWN


def test_standalone_doctimestamp_from_qtst_is_trusted_and_qualified(unsigned_pdf):
    tsa_signer = generate_self_signed_signer(
        'Test TSA', 'Test TSA Org', qc_compliance=True
    )
    timestamper = DummyTimeStamper(
        tsa_cert=tsa_signer.signing_cert, tsa_key=tsa_signer.signing_key
    )
    w = IncrementalPdfFileWriter(io.BytesIO(unsigned_pdf), strict=False)
    signed = PdfTimeStamper(timestamper).timestamp_pdf(w, 'sha256').getvalue()

    snapshot = fresh_snapshot(registry_with_granted_qtst(tsa_signer.signing_cert))
    result = verify_pdf(signed, trust_list=snapshot)

    item = next(i for i in result.items if i.type == SignatureType.TIMESTAMP)
    assert item.trust_chain_status == TrustChainStatus.TRUSTED
    assert item.timestamp_quality == TimestampQuality.QUALIFIED_TSA
