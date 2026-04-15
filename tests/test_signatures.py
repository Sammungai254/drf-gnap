from drf_gnap.signatures import sign_request

def test_sign_request_returns_dict():
    headers = sign_request(
        method="GET",
        url="http://example.com",
        headers={},
        body=b"",
        key="test-key"
    )

    assert isinstance(headers, dict)
    assert len(headers) > 0