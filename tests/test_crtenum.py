import textwrap
from unittest.mock import patch

import httpx
from dnsrecon.lib.crtenum import is_transient_error, scrape_crtsh


def test_scrape_crtsh():
    with patch('dnsrecon.lib.crtenum.httpx.get') as mock_get:
        mock_get.return_value.text = textwrap.dedent('''\
            <html>
                <body>
                    <table>
                        <tr>
                            <td>
                                <table>
                                    <tr>
                                        <td></td>
                                        <td></td>
                                        <td></td>
                                        <td></td>
                                        <td>subdomain1.example.com</td>
                                    </tr>
                                </table>
                            </td>
                        </tr>
                        <tr>
                            <td>
                                <table>
                                    <tr>
                                        <td></td>
                                        <td></td>
                                        <td></td>
                                        <td></td>
                                        <td>subdomain2.example.com</td>
                                    </tr>
                                </table>
                            </td>
                        </tr>
                        <tr>
                            <td>
                                <table>
                                    <tr>
                                        <td></td>
                                        <td></td>
                                        <td></td>
                                        <td></td>
                                        <td>*.example.com</td>
                                    </tr>
                                </table>
                            </td>
                        </tr>
                    </table>
                </body>
            </html>
            ''')
        result = scrape_crtsh('example.com')
        assert result == ['subdomain1.example.com', 'subdomain2.example.com']


def test_is_transient_error():
    assert is_transient_error(httpx.TimeoutException('Connection timeout'))
    assert is_transient_error(httpx.HTTPStatusError(message='Bad http status from crt.sh', request=httpx.Request(url='https://crt.sh', method='GET'), response=httpx.Response(status_code=500)))
    assert not is_transient_error(httpx.RequestError(message='Request error', request=httpx.Request(url='https://crt.sh', method='GET')))
    assert not is_transient_error(ValueError('Test error'))