from unittest.mock import patch

import httpx
import pytest
import stamina
from dnsrecon.lib.crtenum import is_transient_error, scrape_crtsh


def test_scrape_crtsh():
    with patch('dnsrecon.lib.crtenum.httpx.get') as mock_get:
        mock_get.return_value.json.return_value = [
            {'common_name': 'subdomain1.example.com'},
            {'common_name': 'subdomain2.example.com'},
            {'common_name': '*.example.com'},
            {'common_name': 'another.com'},
        ]
        result = scrape_crtsh('example.com')
        assert result == ['subdomain1.example.com', 'subdomain2.example.com']


def test_is_transient_error():
    assert is_transient_error(httpx.TimeoutException('Connection timeout'))
    assert is_transient_error(httpx.HTTPStatusError(message='Bad http status from crt.sh', request=httpx.Request(url='https://crt.sh', method='GET'), response=httpx.Response(status_code=500)))
    assert not is_transient_error(httpx.RequestError(message='Request error', request=httpx.Request(url='https://crt.sh', method='GET')))
    assert not is_transient_error(ValueError('Test error'))


def test_scrape_crtsh_reraises_after_retries():
    """When every attempt returns 5xx, stamina exhausts retries and re-raises the original
    httpx.HTTPStatusError. This is the exception call sites must be prepared to catch
    (see issue #503)."""
    error = httpx.HTTPStatusError(
        message='Server error 502 Bad Gateway',
        request=httpx.Request(url='https://crt.sh', method='GET'),
        response=httpx.Response(status_code=502),
    )
    with stamina.set_testing(True, attempts=1):
        with patch('dnsrecon.lib.crtenum.httpx.get') as mock_get:
            mock_get.return_value.raise_for_status.side_effect = error
            with pytest.raises(httpx.HTTPStatusError):
                scrape_crtsh('example.com')
