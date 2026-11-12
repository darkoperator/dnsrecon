"""Exercise standalone SRV reporting without making network requests."""

import csv
import json
import sqlite3
import sys
from unittest.mock import MagicMock
from xml.etree import ElementTree

import dns.message
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import dns.rrset
import pytest

from dnsrecon import cli


@pytest.fixture
def srv_resolver(monkeypatch):
    """Supply DNS answers at the transport boundary, keeping record construction real."""
    calls = []

    def resolve(self, qname, rdtype, **kwargs):
        name = dns.name.from_text(qname)
        rdtype = dns.rdatatype.RdataType.make(rdtype)
        calls.append((name.to_text(), rdtype))
        response = dns.message.make_response(dns.message.make_query(name, rdtype))
        if rdtype == dns.rdatatype.SRV and name.to_text() in (
            '_ldap._tcp.example.com.',
            '_ldap._tcp.example.org.',
        ):
            # The target is outside both queried domains; provenance must use the scan domain.
            response.answer.append(dns.rrset.from_text(name, 60, 'IN', 'SRV', '0 0 389 shared.example.net.'))
        elif name.to_text() == 'shared.example.net.' and rdtype == dns.rdatatype.A:
            response.answer.append(dns.rrset.from_text(name, 60, 'IN', 'A', '192.0.2.10'))
        response = dns.message.from_wire(response.to_wire())
        return dns.resolver.Answer(name, rdtype, dns.rdataclass.IN, response)

    monkeypatch.setattr(dns.resolver.Resolver, 'resolve', resolve)
    return calls


@pytest.mark.parametrize('domains', [('example.com',), ('example.com', 'example.org')])
def test_standalone_srv_cli_preserves_domain_in_reports(tmp_path, monkeypatch, srv_resolver, domains):
    xml_path = tmp_path / 'records.xml'
    csv_path = tmp_path / 'records.csv'
    json_path = tmp_path / 'records.json'
    db_path = tmp_path / 'records.db'
    domain_args = ['-d', domains[0]]
    if len(domains) > 1:
        input_path = tmp_path / 'domains.txt'
        input_path.write_text('\n'.join(domains) + '\n')
        domain_args = ['-iL', str(input_path)]
    monkeypatch.setattr(
        sys,
        'argv',
        [
            'dnsrecon',
            *domain_args,
            '-t',
            'srv',
            '-n',
            '192.0.2.53',
            '--threads',
            '1',
            '--xml',
            str(xml_path),
            '--csv',
            str(csv_path),
            '--json',
            str(json_path),
            '--db',
            str(db_path),
        ],
    )
    # Avoid writing the CLI's normal log file in the user's home directory.
    monkeypatch.setattr(cli, 'logger', MagicMock())
    monkeypatch.setattr(cli, 'CONFIG', cli.CONFIG.copy())

    with pytest.raises(SystemExit) as exit_info:
        cli.main()
    assert exit_info.value.code == 0
    assert not cli.logger.error.call_args_list, cli.logger.error.call_args_list
    assert ('shared.example.net.', dns.rdatatype.A) in srv_resolver
    for domain in domains:
        assert (f'_ldap._tcp.{domain}.', dns.rdatatype.SRV) in srv_resolver

    root = ElementTree.parse(xml_path).getroot()
    assert [element.get('domain_name') for element in root.findall('domain')] == list(domains)
    for element in root.findall('domain'):
        domain = element.get('domain_name')
        assert [record.attrib for record in element.findall('record')] == [
            {
                'type': 'SRV',
                'name': f'_ldap._tcp.{domain}',
                'target': 'shared.example.net',
                'address': '192.0.2.10',
                'port': '389',
            }
        ]

    with csv_path.open(newline='') as csv_file:
        csv_rows = list(csv.DictReader(csv_file))
    assert [row['Domain'] for row in csv_rows] == list(domains)
    assert all(row['Target'] == 'shared.example.net' for row in csv_rows)
    json_rows = json.loads(json_path.read_text())
    assert json_rows[0]['type'] == 'ScanInfo'
    assert [row['domain'] for row in json_rows[1:]] == list(domains)
    with sqlite3.connect(db_path) as connection:
        db_rows = connection.execute('SELECT domain, type, target FROM data ORDER BY domain').fetchall()
    assert db_rows == [(domain, 'SRV', 'shared.example.net') for domain in domains]


def test_empty_srv_scan_still_exports_empty_domain(srv_resolver):
    resolver = cli.DnsHelper('empty.example', '192.0.2.53')
    records = cli.brute_srv(resolver, 'empty.example', thread_num=1)
    assert records == []
    root = ElementTree.fromstring(cli.dns_record_from_dict(records, ('-t srv', 'test'), ['empty.example']))
    assert root.find('domain').get('domain_name') == 'empty.example'
    assert root.findall('.//record') == []
