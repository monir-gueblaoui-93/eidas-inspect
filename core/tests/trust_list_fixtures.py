"""Helpers to build synthetic TSPRegistry-backed snapshots for matching and
degraded-mode tests, decoupled from real TL XML parsing (see
test_trust_list.py's fixture-based tests for that)."""

from datetime import datetime, timedelta, timezone

from pyhanko.sign.validation.qualified.tsp import (
    CA_QC_URI,
    QTST_URI,
    BaseServiceInformation,
    CAServiceInformation,
    QTSTServiceInformation,
    TSPRegistry,
)

from eidas_inspect_core.trust_list import (
    LotlStatus,
    ServiceTerritory,
    TerritoryStatus,
    TrustListSnapshot,
)


def registry_with_granted_ca(cert, service_name: str = 'Test QTSP CA') -> TSPRegistry:
    registry = TSPRegistry()
    registry.register_ca(
        CAServiceInformation(
            base_info=BaseServiceInformation(
                service_type=CA_QC_URI,
                service_name=service_name,
                valid_from=datetime.now(timezone.utc) - timedelta(days=10),
                valid_until=None,
                provider_certs=(cert,),
                additional_info_certificate_type=frozenset(),
                other_additional_info=frozenset(),
            ),
            qualifications=frozenset(),
            expired_certs_revocation_info=None,
        )
    )
    return registry


def registry_with_granted_ca_and_territory(
    cert,
    *,
    service_name: str = 'Test QTSP CA',
    territory: str = 'FR',
    territory_name: str = 'France',
    tl_location_url: str = 'https://example.test/FR-trusted-list.xml',
) -> tuple[TSPRegistry, dict[int, ServiceTerritory]]:
    """Like :func:`registry_with_granted_ca`, but also returns the
    ``service_territories`` side-mapping a real :func:`build_snapshot` run
    would have produced -- for tests that need :attr:`SignatureItem.trust_match`
    to actually populate, not just :attr:`SignatureItem.trust_chain_status`."""
    registry = TSPRegistry()
    service = CAServiceInformation(
        base_info=BaseServiceInformation(
            service_type=CA_QC_URI,
            service_name=service_name,
            valid_from=datetime.now(timezone.utc) - timedelta(days=10),
            valid_until=None,
            provider_certs=(cert,),
            additional_info_certificate_type=frozenset(),
            other_additional_info=frozenset(),
        ),
        qualifications=frozenset(),
        expired_certs_revocation_info=None,
    )
    registry.register_ca(service)
    service_territories = {
        id(service): ServiceTerritory(
            territory=territory,
            territory_name=territory_name,
            tl_location_url=tl_location_url,
        )
    }
    return registry, service_territories


def registry_with_granted_qtst(cert, service_name: str = 'Test QTSA') -> TSPRegistry:
    registry = TSPRegistry()
    registry.register_tst(
        QTSTServiceInformation(
            base_info=BaseServiceInformation(
                service_type=QTST_URI,
                service_name=service_name,
                valid_from=datetime.now(timezone.utc) - timedelta(days=10),
                valid_until=None,
                provider_certs=(cert,),
                additional_info_certificate_type=frozenset(),
                other_additional_info=frozenset(),
            ),
            qualifications=frozenset(),
        )
    )
    return registry


def fresh_snapshot(
    registry: TSPRegistry, service_territories: dict[int, ServiceTerritory] | None = None
) -> TrustListSnapshot:
    """A snapshot with all lists freshly and successfully refreshed."""
    now = datetime.now(timezone.utc)
    return TrustListSnapshot(
        registry=registry,
        lotl_status=LotlStatus.OK,
        lotl_error=None,
        territory_status={'XX': TerritoryStatus('XX', now, None)},
        refreshed_at=now,
        service_territories=service_territories or {},
    )


def degraded_snapshot(registry: TSPRegistry) -> TrustListSnapshot:
    """A snapshot where one territory failed to refresh this cycle."""
    now = datetime.now(timezone.utc)
    return TrustListSnapshot(
        registry=registry,
        lotl_status=LotlStatus.OK,
        lotl_error=None,
        territory_status={'XX': TerritoryStatus('XX', None, 'simulated fetch failure')},
        refreshed_at=now,
    )
