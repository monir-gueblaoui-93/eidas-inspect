def test_eleventh_verification_in_an_hour_is_rate_limited(app_factory, plain_signed_pdf):
    client = app_factory()

    for _ in range(10):
        response = client.post(
            '/api/verify', files={'file': ('doc.pdf', plain_signed_pdf, 'application/pdf')}
        )
        assert response.status_code == 200

    response = client.post(
        '/api/verify', files={'file': ('doc.pdf', plain_signed_pdf, 'application/pdf')}
    )

    assert response.status_code == 429
    assert response.json()['error']['code'] == 'rate_limited'


def test_health_endpoint_is_not_rate_limited(app_factory, plain_signed_pdf):
    client = app_factory()

    for _ in range(10):
        client.post(
            '/api/verify', files={'file': ('doc.pdf', plain_signed_pdf, 'application/pdf')}
        )

    response = client.get('/api/health')

    assert response.status_code == 200
