from api.config import settings
from pdf_fixtures import build_minimal_pdf


def test_verify_confirmed_qualified_signature_is_trusted(app_factory, qualified_pdf_and_snapshot):
    pdf_bytes, snapshot, revocation_fetchers = qualified_pdf_and_snapshot
    client = app_factory(snapshot=snapshot, revocation_fetchers=revocation_fetchers)

    response = client.post(
        '/api/verify', files={'file': ('doc.pdf', pdf_bytes, 'application/pdf')}
    )

    assert response.status_code == 200
    body = response.json()
    assert body['verdict'] == 'trusted'
    assert body['plain_summary'] == 'Fully trusted — the signature is qualified and intact.'
    assert body['verdict_breakdown']['confirmed_qualified'] == 1
    item = body['items'][0]
    assert item['level'] == 'qualified'
    assert item['trust_chain_status'] == 'trusted'
    assert item['revocation_status'] == 'good'
    assert item['verdict_reason'] == 'confirmed_qualified'


def test_verify_plain_advanced_signature_is_partial(app_factory, plain_signed_pdf):
    client = app_factory()

    response = client.post(
        '/api/verify', files={'file': ('doc.pdf', plain_signed_pdf, 'application/pdf')}
    )

    assert response.status_code == 200
    assert response.json()['verdict'] == 'partial'


def test_verify_unsigned_pdf_is_no_signatures(app_factory):
    client = app_factory()

    response = client.post(
        '/api/verify',
        files={'file': ('doc.pdf', build_minimal_pdf(), 'application/pdf')},
    )

    assert response.status_code == 200
    body = response.json()
    assert body['verdict'] == 'no-signatures'
    assert body['plain_summary'] == 'This document contains no digital signatures.'
    assert body['verdict_breakdown'] is None


def test_verify_rejects_non_pdf(app_factory):
    client = app_factory()

    response = client.post(
        '/api/verify', files={'file': ('doc.txt', b'this is not a pdf', 'text/plain')}
    )

    assert response.status_code == 400
    assert response.json()['error']['code'] == 'not_a_pdf'


def test_verify_rejects_corrupted_pdf(app_factory):
    client = app_factory()

    response = client.post(
        '/api/verify',
        files={'file': ('doc.pdf', b'%PDF-1.7\nthis is garbage, not a real pdf', 'application/pdf')},
    )

    assert response.status_code == 400
    assert response.json()['error']['code'] == 'corrupted_pdf'


def test_verify_rejects_oversized_file(app_factory):
    client = app_factory()
    oversized = b'%PDF-1.7\n' + b'0' * (settings.max_upload_bytes + 1)

    response = client.post(
        '/api/verify', files={'file': ('doc.pdf', oversized, 'application/pdf')}
    )

    assert response.status_code == 413
    assert response.json()['error']['code'] == 'file_too_large'


def test_verify_password_protected_without_password(app_factory, encrypted_pdf):
    client = app_factory()

    response = client.post(
        '/api/verify', files={'file': ('doc.pdf', encrypted_pdf, 'application/pdf')}
    )

    assert response.status_code == 400
    assert response.json()['error']['code'] == 'password_required'


def test_verify_password_protected_with_wrong_password(app_factory, encrypted_pdf):
    client = app_factory()

    response = client.post(
        '/api/verify',
        files={'file': ('doc.pdf', encrypted_pdf, 'application/pdf')},
        data={'password': 'definitely-wrong'},
    )

    assert response.status_code == 400
    assert response.json()['error']['code'] == 'incorrect_password'


def test_verify_password_protected_with_correct_password(app_factory, encrypted_pdf):
    client = app_factory()

    response = client.post(
        '/api/verify',
        files={'file': ('doc.pdf', encrypted_pdf, 'application/pdf')},
        data={'password': 'correct-password'},
    )

    assert response.status_code == 200
    assert response.json()['verdict'] == 'no-signatures'
