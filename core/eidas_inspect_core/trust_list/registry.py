"""EU Trusted List (ETSI TS 119 612) fetching, parsing, and staleness tracking.

pyHanko's own ``pyhanko.sign.validation.qualified`` engine already does the
hard parts -- LOTL/TL XML parsing, XAdES signature verification of every list
against bundled EU-published bootstrap certs, and pivot-following -- so this
module doesn't re-derive any of that. What's custom here is the caching and
degraded-mode bookkeeping pyHanko doesn't provide: per-territory fetch
failures must never abort the whole refresh, and a caller needs to be able
to tell "confidently not on the list" apart from "we don't know right now".
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import StrEnum

import aiohttp
from pyhanko.sign.validation.qualified import eutl_parse
from pyhanko.sign.validation.qualified.eutl_fetch import EU_LOTL_LOCATION
from pyhanko.sign.validation.qualified.eutl_parse import LOTL_RULE
from pyhanko.sign.validation.qualified.tsp import TSPRegistry

__all__ = [
    'EU_LOTL_LOCATION',
    'STALE_AFTER',
    'Fetcher',
    'LotlStatus',
    'TerritoryStatus',
    'TrustListSnapshot',
    'build_snapshot',
    'default_fetch',
]

logger = logging.getLogger(__name__)

STALE_AFTER = timedelta(hours=48)
"""Grace window past the intended 24h refresh cadence before a snapshot
counts as stale. One missed refresh cycle should not immediately make every
signature report "could not be confirmed"."""

Fetcher = Callable[[str], Awaitable[str]]


class LotlStatus(StrEnum):
    OK = 'ok'
    UNAVAILABLE = 'unavailable'


@dataclass(frozen=True)
class TerritoryStatus:
    """Fetch/verify outcome for one member state's trusted list this cycle."""

    territory: str
    fetched_at: datetime | None
    error: str | None

    @property
    def ok(self) -> bool:
        return self.error is None and self.fetched_at is not None


@dataclass(frozen=True)
class TrustListSnapshot:
    """An immutable, point-in-time view of the EU Trusted List data.

    Signature verification only ever reads a fully-built snapshot, never a
    half-populated one -- a refresh builds a brand new snapshot (a
    :class:`~pyhanko.sign.validation.qualified.tsp.TSPRegistry` has no way to
    unregister a withdrawn service, so incremental patching isn't viable
    anyway) and the cache swaps it in atomically.
    """

    registry: TSPRegistry
    lotl_status: LotlStatus
    lotl_error: str | None
    territory_status: Mapping[str, TerritoryStatus]
    refreshed_at: datetime | None

    @classmethod
    def empty(cls) -> 'TrustListSnapshot':
        return cls(
            registry=TSPRegistry(),
            lotl_status=LotlStatus.UNAVAILABLE,
            lotl_error='Trusted List data has not been loaded yet.',
            territory_status={},
            refreshed_at=None,
        )

    def is_degraded(
        self, moment: datetime, stale_after: timedelta = STALE_AFTER
    ) -> bool:
        """Whether this snapshot is unreliable enough that a "not found"
        result can't be trusted as confidently "not on the list" -- the LOTL
        itself failed, the snapshot is older than ``stale_after``, or at
        least one member state's list failed to refresh this cycle."""
        if self.lotl_status is not LotlStatus.OK:
            return True
        if self.refreshed_at is None or moment - self.refreshed_at > stale_after:
            return True
        return any(not status.ok for status in self.territory_status.values())


async def default_fetch(url: str) -> str:
    async with aiohttp.ClientSession() as session:
        async with session.get(
            url, timeout=aiohttp.ClientTimeout(total=30, sock_connect=5)
        ) as response:
            response.raise_for_status()
            return await response.text()


async def build_snapshot(
    lotl_xml: str,
    fetch: Fetcher,
    only_territories: set[str] | None = None,
) -> TrustListSnapshot:
    """Build a fresh :class:`TrustListSnapshot` from LOTL XML already in hand.

    Each referenced member-state trusted list is fetched and verified
    independently: one state's failure (bad XML, wrong signing cert, a
    timeout) is recorded against that state only and never aborts the
    others, per the PRD's degraded-but-honest requirement.

    :param lotl_xml:
        The LOTL XML payload, already fetched by the caller.
    :param fetch:
        Async callable used to retrieve each referenced trusted list by URL.
    :param only_territories:
        If given, restrict processing to these ISO 3166-1 alpha-2 territory
        codes (mainly useful for tests working from a handful of fixture
        lists rather than the full ~30-state LOTL).
    """
    now = datetime.now(timezone.utc)
    try:
        lotl_result = eutl_parse.validate_and_parse_lotl(lotl_xml)
    except Exception as e:
        logger.warning('Failed to validate/parse the LOTL: %s', e)
        return TrustListSnapshot(
            registry=TSPRegistry(),
            lotl_status=LotlStatus.UNAVAILABLE,
            lotl_error=f'{type(e).__name__}: {e}',
            territory_status={},
            refreshed_at=now,
        )

    registry = TSPRegistry()
    territory_status: dict[str, TerritoryStatus] = {}
    for ref in lotl_result.references:
        if LOTL_RULE in ref.scheme_rules:
            continue  # the LOTL's pointer to itself
        if only_territories is not None and ref.territory not in only_territories:
            continue
        try:
            tl_xml = await fetch(ref.location_uri)
            _, entry_errors = eutl_parse.trust_list_to_registry(
                tl_xml, ref.tlso_certs, registry
            )
            if entry_errors:
                logger.info(
                    "Trusted list for %s parsed with %d non-fatal entry "
                    "error(s): %s",
                    ref.territory,
                    len(entry_errors),
                    entry_errors,
                )
            territory_status[ref.territory] = TerritoryStatus(
                territory=ref.territory, fetched_at=now, error=None
            )
        except Exception as e:
            logger.warning(
                "Failed to fetch/verify trusted list for %s at %s: %s",
                ref.territory,
                ref.location_uri,
                e,
            )
            territory_status[ref.territory] = TerritoryStatus(
                territory=ref.territory,
                fetched_at=None,
                error=f'{type(e).__name__}: {e}',
            )

    return TrustListSnapshot(
        registry=registry,
        lotl_status=LotlStatus.OK,
        lotl_error=None,
        territory_status=territory_status,
        refreshed_at=now,
    )
