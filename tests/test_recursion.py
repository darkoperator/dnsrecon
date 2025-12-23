import pytest
from unittest.mock import patch, MagicMock
from dnsrecon.lib.dnshelper import DnsHelper
import dns.resolver
import dns.message
import dns.rdatatype


def test_dnshelper_recursion_default():
    # By default, recursion should be enabled
    helper = DnsHelper("example.com")
    # In dnspython 2.x, if flags is None it defaults to RD when making query
    # but dnsrecon might have initialized it or we can check what it does.
    # Actually, let's check if we can set it.
    assert helper._res.flags is None or (helper._res.flags & dns.flags.RD)


def test_dnshelper_recursion_disabled():
    # When disabled, RD flag should not be set in flags
    try:
        helper = DnsHelper("example.com", recursion_desired=False)
        assert helper._res.flags == 0
    except TypeError:
        pytest.fail("DnsHelper does not support recursion_desired parameter")


@patch('dns.message.make_query')
@patch('dns.query.udp')
@patch('dnsrecon.lib.dnshelper.DnsHelper.get_answers')
def test_get_soa_recursion_disabled(mock_get_answers, mock_udp, mock_make_query):
    mock_response = MagicMock()
    mock_response.answer = []
    mock_response.authority = []
    mock_udp.return_value = mock_response
    mock_get_answers.return_value = []

    # Use proto='udp' to match mocked query func
    helper = DnsHelper("example.com", recursion_desired=False, proto='udp')
    # Mock nameservers to avoid IndexError if empty
    helper._res.nameservers = ['8.8.8.8']
    helper.get_soa()

    # Check if make_query was called with flags=0
    args, kwargs = mock_make_query.call_args
    assert kwargs.get('flags') == 0
