def test_report_returns_a_valid_pdf(app_factory, qualified_pdf_and_snapshot):
    pdf_bytes, snapshot, revocation_fetchers = qualified_pdf_and_snapshot
    client = app_factory(snapshot=snapshot, revocation_fetchers=revocation_fetchers)

    verify_response = client.post(
        '/api/verify', files={'file': ('doc.pdf', pdf_bytes, 'application/pdf')}
    )
    result_json = verify_response.json()

    report_response = client.post('/api/report', json=result_json)

    assert report_response.status_code == 200
    assert report_response.headers['content-type'] == 'application/pdf'
    assert report_response.content.startswith(b'%PDF-')
    assert len(report_response.content) > 0


def test_report_reflects_the_document_sha256_in_the_footer(app_factory, plain_signed_pdf):
    client = app_factory()

    verify_response = client.post(
        '/api/verify', files={'file': ('doc.pdf', plain_signed_pdf, 'application/pdf')}
    )
    result_json = verify_response.json()

    report_response = client.post('/api/report', json=result_json)

    assert report_response.status_code == 200
    # A crude but real check that the sha256 made it into the rendered PDF's
    # content stream, not just decorative -- reportlab text ends up as
    # literal bytes in an uncompressed content stream for a document this
    # small.
    assert result_json['document_sha256'].encode() in report_response.content
