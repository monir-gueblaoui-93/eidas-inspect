from pyhanko.sign.validation.qualified.tsp import TSPRegistry

from trust_list_fixtures import degraded_snapshot, fresh_snapshot


def test_health_reports_refreshing_before_any_snapshot_loaded(app_factory):
    client = app_factory()

    response = client.get('/api/health')

    assert response.status_code == 200
    body = response.json()
    assert body['status'] == 'ok'
    assert body['trust_list'] == {'status': 'refreshing', 'refreshed_at': None}


def test_health_reports_fresh_for_a_clean_snapshot(app_factory):
    client = app_factory(snapshot=fresh_snapshot(TSPRegistry()))

    response = client.get('/api/health')

    body = response.json()
    assert body['trust_list']['status'] == 'fresh'
    assert body['trust_list']['refreshed_at'] is not None


def test_health_reports_stale_for_a_degraded_snapshot(app_factory):
    client = app_factory(snapshot=degraded_snapshot(TSPRegistry()))

    response = client.get('/api/health')

    assert response.json()['trust_list']['status'] == 'stale'
