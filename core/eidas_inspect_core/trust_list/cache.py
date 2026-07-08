"""In-memory :class:`TrustListSnapshot` cache.

Owned by core, scheduled by whoever embeds it: :meth:`TrustListCache.refresh`
is a plain coroutine with no built-in timer, so the API layer decides when
and how often to call it (a FastAPI lifespan background task, a manual
admin-triggered refresh, etc).
"""

from __future__ import annotations

import asyncio

from .registry import (
    EU_LOTL_LOCATION,
    Fetcher,
    TrustListSnapshot,
    build_snapshot,
    default_fetch,
)

__all__ = ['TrustListCache']


class TrustListCache:
    def __init__(
        self,
        *,
        lotl_url: str = EU_LOTL_LOCATION,
        fetch: Fetcher | None = None,
        only_territories: set[str] | None = None,
    ):
        self._lotl_url = lotl_url
        self._fetch = fetch or default_fetch
        self._only_territories = only_territories
        self._snapshot = TrustListSnapshot.empty()
        self._lock = asyncio.Lock()

    @property
    def snapshot(self) -> TrustListSnapshot:
        """The most recently completed snapshot. Never blocks; readers never
        see a partially-built refresh in progress."""
        return self._snapshot

    async def refresh(self) -> TrustListSnapshot:
        """Fetch the LOTL and every referenced trusted list, then swap in a
        freshly-built snapshot.

        If the LOTL itself can't be fetched, the previous snapshot is kept
        as-is rather than discarded -- it will read as degraded via
        :meth:`TrustListSnapshot.is_degraded` once it's old enough, but a
        single transient outage doesn't have to erase otherwise-good data.
        """
        try:
            lotl_xml = await self._fetch(self._lotl_url)
        except Exception:
            return self._snapshot

        new_snapshot = await build_snapshot(
            lotl_xml, self._fetch, only_territories=self._only_territories
        )
        async with self._lock:
            self._snapshot = new_snapshot
        return new_snapshot
