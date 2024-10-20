from unittest.mock import patch, MagicMock
from dnsrecon import cli


def test_check_wildcard():
    with patch('dnsrecon.lib.dnshelper.DnsHelper') as mock_dns_helper:
        mock_instance = mock_dns_helper.return_value
        mock_instance.check_wildcard.return_value = (True, ["192.0.2.1"])
        result = cli.check_wildcard(mock_instance, "zonetransfer.me")
        assert result == set()  # The function returns an empty set


def test_expand_range():
    input_range = "192.0.2.0"
    end_ip = "192.0.2.3"
    result = cli.expand_range(input_range, end_ip)
    assert len(result) == 4
    assert "192.0.2.0" in result
    assert "192.0.2.3" in result


def test_brute_domain():
    with patch('dnsrecon.lib.dnshelper.DnsHelper') as mock_dns_helper, \
            patch('builtins.input', return_value='y'):  # Mock user input
        mock_instance = mock_dns_helper.return_value
        mock_instance.get_a.return_value = ["192.0.2.1"]
        mock_instance.get_aaaa.return_value = ["2001:db8::1"]
        mock_instance.check_wildcard.return_value = (False, [])

        # Mock the generate_testname function to return a valid string
        with patch('dnsrecon.cli.generate_testname', return_value='testname.zonetransfer.me'):
            result = cli.brute_domain(mock_instance, "zonetransfer.me", ["subdomain"])

    assert isinstance(result, list)


def test_general_enum():
    with patch('dnsrecon.lib.dnshelper.DnsHelper') as mock_dns_helper:
        mock_instance = mock_dns_helper.return_value
        mock_instance.get_a.return_value = ["192.0.2.1"]
        mock_instance.get_aaaa.return_value = ["2001:db8::1"]
        mock_instance.get_mx.return_value = ["mail.zonetransfer.me"]
        mock_instance.get_txt.return_value = ["txt.zonetransfer.me"]
        mock_instance.get_ns.return_value = ["ns.zonetransfer.me"]
        mock_instance.get_soa.return_value = ["soa.zonetransfer.me"]
        mock_instance.get_srv.return_value = ["srv.zonetransfer.me"]
        mock_instance.get_spf.return_value = ["spf.zonetransfer.me"]
        mock_instance.get_nsec.return_value = ["nsec.zonetransfer.me"]
        mock_instance.get_nsec3.return_value = ["nsec3.zonetransfer.me"]
        mock_instance.get_nsec3param.return_value = ["nsec3param.zonetransfer.me"]
        mock_instance.get_ds.return_value = ["ds.zonetransfer.me"]
        mock_instance.get_dnskey.return_value = ["dnskey.zonetransfer.me"]
        mock_instance.get_rrsig.return_value = ["rrsig.zonetransfer.me"]
        result = cli.general_enum(mock_instance, "zonetransfer.me", True, True, True, True, True, True, True, 5.0)
        assert result is None  # The function doesn't return anything


def test_get_nsec_type():
    with patch('dnsrecon.lib.dnshelper.DnsHelper') as mock_dns_helper:
        mock_instance = mock_dns_helper.return_value
        mock_instance._res = MagicMock()
        mock_instance._res.nameservers = ["8.8.8.8"]
        mock_instance._res.timeout = 2.0

        mock_answer = MagicMock()
        mock_answer.authority = []

        with patch('dnsrecon.cli.get_a_answer', return_value=mock_answer):
            result = cli.get_nsec_type("zonetransfer.me", mock_instance)

        assert result is None
