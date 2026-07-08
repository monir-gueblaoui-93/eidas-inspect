from datetime import datetime, timezone

from fastapi import APIRouter, Request

from eidas_inspect_core.trust_list import TrustListSnapshot

router = APIRouter()


def _trust_list_status(snapshot: TrustListSnapshot, moment: datetime) -> str:
    """fresh / stale / refreshing, for Railway's healthcheck and general
    observability. Reuses :meth:`TrustListSnapshot.is_degraded` (the same
    definition already used to decide whether a "not found on the list"
    result can be trusted) rather than a separate notion of freshness --
    "stale" here means exactly what it means everywhere else in this
    project."""
    if snapshot.refreshed_at is None:
        return 'refreshing'
    return 'stale' if snapshot.is_degraded(moment) else 'fresh'


@router.get('/api/health')
async def health(request: Request) -> dict:
    cache = request.app.state.trust_list_cache
    snapshot = cache.snapshot
    moment = datetime.now(timezone.utc)
    return {
        'status': 'ok',
        'trust_list': {
            'status': _trust_list_status(snapshot, moment),
            'refreshed_at': snapshot.refreshed_at.isoformat() if snapshot.refreshed_at else None,
        },
    }
