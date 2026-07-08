def test_health_ok(app_factory):
    client = app_factory()

    response = client.get('/api/health')

    assert response.status_code == 200
    assert response.json() == {'status': 'ok'}
