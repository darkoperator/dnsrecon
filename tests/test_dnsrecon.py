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

def test_se_result_process():
    with patch('dnsrecon.lib.dnshelper.DnsHelper') as mock_dns_helper:
        mock_instance = mock_dns_helper.return_value
        mock_instance.get_ip.return_value = [
            ("A", "zonetransfer.me", "192.0.2.1"),
            ("CNAME", "zonetransfer.me", "some.domain.com"),
            ("AAAA", "zonetransfer.me", "2001:db8::1"),
        ]
        results = cli.se_result_process(mock_instance, "zonetransfer.me", ["zonetransfer.me"])
        assert len(results) == 2
        assert results[0]['type'] == 'A'
        assert results[0]['name'] == 'zonetransfer.me'
        assert results[0]['domain'] == 'zonetransfer.me'
        assert results[0]['address'] == '192.0.2.1'
        assert results[1]['type'] == 'CNAME'
        assert results[1]['name'] == 'zonetransfer.me'
        assert results[1]['domain'] == 'zonetransfer.me'
        assert results[1]['target'] == 'some.domain.com'

def test_write_db():
    with patch('sqlite3.connect') as mock_sqlite3_connect:
        cursor = MagicMock()
        cursor.return_value.execute.return_value = None
        mock_sqlite3_connect.return_value = MagicMock()
        mock_sqlite3_connect.return_value.cursor.return_value = cursor
        result = cli.write_db("test.db", [
            {"domain": "zonetransfer.me", "type": "A", "name": "zonetransfer.me", "address": "192.0.2.1"},
            {"domain": "zonetransfer.me", "type": "CAA", "name": "zonetransfer.me", "address": "192.0.2.1", "target": "example.com"},
            {"domain": "zonetransfer.me", "type": "CNAME", "name": "zonetransfer.me", "target": "some.domain.com"},
            {"domain": "zonetransfer.me", "type": "AAAA", "name": "zonetransfer.me", "address": "2001:db8::1"},
            {"domain": "zonetransfer.me", "type": "MX", "name": "zonetransfer.me", "exchange": "mail.zonetransfer.me", "address": "192.0.2.1"},
            {"domain": "zonetransfer.me", "type": "TXT", "name": "zonetransfer.me", "text": "txt.zonetransfer.me", "strings": "txt.zonetransfer.me"},
            {"domain": "zonetransfer.me", "type": "NS", "name": "zonetransfer.me", "target": "ns.zonetransfer.me", "address": "192.0.2.1"},
            {"domain": "zonetransfer.me", "type": "SOA", "name": "zonetransfer.me", "mname": "soa.zonetransfer.me", "address": "192.0.2.1"},
            {"domain": "zonetransfer.me", "type": "SRV", "name": "zonetransfer.me", "target": "srv.zonetransfer.me", "address": "192.0.2.1", "port": "80"},
            {"domain": "zonetransfer.me", "type": "SPF", "name": "zonetransfer.me", "strings": "spf.zonetransfer.me"},
            {"domain": "zonetransfer.me", "type": "PTR", "name": "zonetransfer.me", "address": "192.0.2.1"},
            {"domain": "zonetransfer.me", "type": "OTHER", "name": "zonetransfer.me", "strings": "spf.zonetransfer.me"},
        ])
        assert cursor.execute.call_count == 12
        assert cursor.execute.call_args_list[0][0][0] == 'insert into data( domain, type, name, address ) values( "zonetransfer.me", "A", "zonetransfer.me", "192.0.2.1" )'
        assert cursor.execute.call_args_list[1][0][0] == "insert into data( domain, type, name, target, address, text ) values ('zonetransfer.me', 'CAA', 'zonetransfer.me', 'example.com', '192.0.2.1', 'domain=zonetransfer.me,name=zonetransfer.me,address=192.0.2.1,target=example.com')"
        assert cursor.execute.call_args_list[2][0][0] == 'insert into data( domain, type, name, target ) values( "zonetransfer.me", "CNAME", "zonetransfer.me", "some.domain.com" )'
        assert cursor.execute.call_args_list[3][0][0] == 'insert into data( domain, type, name, address ) values( "zonetransfer.me", "AAAA", "zonetransfer.me", "2001:db8::1" )'
        assert cursor.execute.call_args_list[4][0][0] == 'insert into data( domain, type, name, address ) values( "zonetransfer.me", "MX", "mail.zonetransfer.me", "192.0.2.1" )'
        assert cursor.execute.call_args_list[5][0][0] == 'insert into data( domain, type, text) values( "zonetransfer.me", "TXT", "txt.zonetransfer.me" )'
        assert cursor.execute.call_args_list[6][0][0] == 'insert into data( domain, type, name, address ) values( "zonetransfer.me", "NS", "ns.zonetransfer.me", "192.0.2.1" )'
        assert cursor.execute.call_args_list[7][0][0] == 'insert into data( domain, type, name, address ) values( "zonetransfer.me", "SOA", "soa.zonetransfer.me", "192.0.2.1" )'
        assert cursor.execute.call_args_list[8][0][0] == 'insert into data( domain, type, name, target, address, port ) values( "zonetransfer.me", "SRV", "zonetransfer.me", "srv.zonetransfer.me", "192.0.2.1", "80" )'
        assert cursor.execute.call_args_list[9][0][0] == 'insert into data( domain, type, text) values( "zonetransfer.me", "SPF", "spf.zonetransfer.me" )'
        assert cursor.execute.call_args_list[10][0][0] == 'insert into data( domain, type, name, address ) values( "zonetransfer.me", "PTR", "zonetransfer.me", "192.0.2.1" )'
        assert cursor.execute.call_args_list[11][0][0] == 'insert into data( domain, type, text ) values ("%(domain)", \'OTHER\', \'domain=zonetransfer.me,name=zonetransfer.me,strings=spf.zonetransfer.me,\')'