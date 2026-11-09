"""Zone-transfer domain provenance and its XML export.

Everything here runs the real product path: ``DnsHelper.zone_transfer`` builds the records
exactly as it always did, the returned list is fed to ``dnsrecon.cli.dns_record_from_dict``
(the exporter the ``--xml`` path calls) and the result is read back with the standard
library XML parser. The record dictionaries are never hand-built and the product's
association logic is never re-implemented here.

Substituted boundaries, both test-scoped and transport/resolver level only:
``dns.query.xfr`` (the AXFR response stream a name server would have produced) and the
resolver helpers ``get_soa``/``get_ns``/``get_ip``/``check_tcp_dns``. The zone data is
genuine ``dns.zone``/``dns.message`` material produced by ``dns.zone.from_text`` and passed
through a real wire round trip, and it lives in the fixtures, not in the assertions.
"""

import xml.etree.ElementTree as ET

import dns.message
import dns.name
import dns.query
import dns.rdatatype
import dns.rrset
import dns.zone
import pytest

from dnsrecon.cli import dns_record_from_dict
from dnsrecon.lib.dnshelper import DnsHelper

# One shared name-server address serves both zones: the normal shared-hosting case in which
# the transferred rows cannot be attributed to a domain by their zone_server value.
NS_IP = '192.0.2.53'

ZONE_TEXT = {
    'example.com.': (
        'example.com. 3600 IN SOA ns1.example.com. hostmaster.example.com. '
        '(2026110601 7200 3600 1209600 3600)\n'
        'example.com. 3600 IN NS ns1.example.com.\n'
        'example.com. 3600 IN MX 10 mail.example.com.\n'
        'example.com. 3600 IN TXT "v=spf1 -all"\n'
        'ns1.example.com. 3600 IN A 192.0.2.53\n'
        'www.example.com. 3600 IN A 192.0.2.10\n'
        'mail.example.com. 3600 IN A 192.0.2.20\n'
    ),
    'example.net.': (
        'example.net. 3600 IN SOA ns1.example.net. hostmaster.example.net. '
        '(2026110601 7200 3600 1209600 3600)\n'
        'example.net. 3600 IN NS ns1.example.net.\n'
        'example.net. 3600 IN MX 10 mail.example.net.\n'
        'example.net. 3600 IN TXT "v=spf1 -all"\n'
        'ns1.example.net. 3600 IN A 192.0.2.53\n'
        'www.example.net. 3600 IN A 192.0.2.30\n'
        'mail.example.net. 3600 IN A 192.0.2.40\n'
    ),
}

# Addresses that exist only in example.com. / only in example.net.: used to prove that rows
# are associated to the domain they were transferred for and never mixed across zones.
ADDRESSES = {
    'example.com': {'192.0.2.10', '192.0.2.20', '192.0.2.53'},
    'example.net': {'192.0.2.30', '192.0.2.40', '192.0.2.53'},
}

SCAN_INFO = (['-d', 'example.com', '--axfr', '--xml', 'out.xml'], '2026-11-06 20:00:00')


def _constructed_zones():
    return {
        origin: dns.zone.from_text(text, origin=dns.name.from_text(origin), relativize=False)
        for origin, text in ZONE_TEXT.items()
    }


ZONES = _constructed_zones()

# The resolver answers the producer would have received: an A record is only known for the
# names that really carry one in the fixture zone, everything else resolves to the shared
# name-server address.
A_MAP = {}
for _zone in ZONES.values():
    for _name, _rdataset in _zone.iterate_rdatasets(dns.rdatatype.A):
        A_MAP[str(_name)] = [rdata.address for rdata in _rdataset]


def _xfr_stream(origin_text):
    """The message stream ``dns.query.xfr`` yields for one zone, as a real wire round trip."""
    origin = dns.name.from_text(origin_text)
    rrsets = []
    for name, rdataset in ZONES[origin_text].iterate_rdatasets():
        rrset = dns.rrset.RRset(name, rdataset.rdclass, rdataset.rdtype)
        rrset.update(rdataset)
        rrsets.append(rrset)
    message = dns.message.Message(id=0)
    message.answer = rrsets
    return [dns.message.from_wire(message.to_wire(), xfr=True, origin=origin)]


class Transport:
    """Test-scoped stand-in for the AXFR stream and the resolver answers."""

    def __init__(self):
        self.tcp_open = True
        self.xfr_error = None
        self.resolver_error = None
        self.xfr_calls = []

    def xfr(self, where, domain, **kwargs):
        self.xfr_calls.append((str(where), str(domain)))
        if self.xfr_error is not None:
            raise self.xfr_error
        origin = str(domain).rstrip('.') + '.'
        return iter(_xfr_stream(origin))

    def check_tcp_dns(self, address):
        return self.tcp_open

    def get_soa(self, helper):
        if self.resolver_error is not None:
            raise self.resolver_error
        return [['SOA', 'ns1.' + helper._domain, NS_IP]]

    def get_ns(self, helper):
        if self.resolver_error is not None:
            raise self.resolver_error
        return [['NS', 'ns1.' + helper._domain, NS_IP]]

    def get_ip(self, helper, hostname):
        return [['A', str(hostname), address] for address in A_MAP.get(str(hostname), [NS_IP])]


@pytest.fixture
def transport(monkeypatch):
    fake = Transport()
    monkeypatch.setattr(dns.query, 'xfr', fake.xfr)
    monkeypatch.setattr(DnsHelper, 'check_tcp_dns', lambda self, address: fake.check_tcp_dns(address))
    monkeypatch.setattr(DnsHelper, 'get_soa', lambda self: fake.get_soa(self))
    monkeypatch.setattr(DnsHelper, 'get_ns', lambda self: fake.get_ns(self))
    monkeypatch.setattr(DnsHelper, 'get_ip', lambda self, hostname: fake.get_ip(self, hostname))
    return fake


def _transfer(domain):
    """Run the real producer exactly as the CLI's domain loop does."""
    helper = DnsHelper(domain, NS_IP, 3.0, 'tcp', recursion_desired=True)
    return helper.zone_transfer()


def _domain_records(xml_text):
    root = ET.fromstring(xml_text)
    return {
        domelem.get('domain_name'): [dict(record.attrib) for record in domelem.findall('record')]
        for domelem in root.findall('domain')
    }


def test_transferred_rows_are_associated_and_reach_the_xml(transport):
    domains = ['example.com', 'example.net']
    all_rows = []
    per_domain = {}
    for domain in domains:
        rows = _transfer(domain)
        per_domain[domain] = rows
        all_rows.extend(rows)

    # The producer really transferred both zones from the same name-server address.
    assert sorted(transport.xfr_calls) == sorted([(NS_IP, 'example.com'), (NS_IP, 'example.net')])
    assert len(all_rows) > len(domains)

    for domain, rows in per_domain.items():
        assert rows, f'no records produced for {domain}'
        assert all('domain' in row for row in rows), f'{domain} rows lost their provenance key'
        assert {row['domain'] for row in rows} == {domain}
        # A successful transfer is reported, and the status row carries the provenance too.
        successes = [r for r in rows if r.get('zone_transfer') == 'success']
        assert successes
        assert successes[0]['domain'] == domain

    # Records stay with the zone they came from: no address crosses over.
    for domain, rows in per_domain.items():
        for row in rows:
            if 'address' in row:
                assert row['address'] in ADDRESSES[domain], (domain, row)

    records_by_domain = _domain_records(dns_record_from_dict(all_rows, SCAN_INFO, domains))
    assert set(records_by_domain) == set(domains)
    for domain in domains:
        assert len(records_by_domain[domain]) == len(per_domain[domain])
        # The exporter renders every non-domain key as an attribute, so the produced rows
        # and the XML record elements must agree field for field.
        produced = sorted(tuple(sorted((k, str(v)) for k, v in row.items() if k != 'domain')) for row in per_domain[domain])
        exported = sorted(tuple(sorted(record.items())) for record in records_by_domain[domain])
        assert produced == exported

    # A single-domain export of the same list selects only that domain's rows.
    single = _domain_records(dns_record_from_dict(all_rows, SCAN_INFO, ['example.net']))
    assert len(single['example.net']) == len(per_domain['example.net'])


def test_failed_tcp_and_failed_transfer_status_rows_remain_attributed(transport):
    transport.tcp_open = False
    filtered = _transfer('example.com')
    assert [r['zone_transfer'] for r in filtered] == ['failed']
    assert filtered[0]['ns_server'] == NS_IP
    assert filtered[0].get('domain') == 'example.com'
    assert _domain_records(dns_record_from_dict(filtered, SCAN_INFO, ['example.com']))['example.com'] == [
        {'type': 'info', 'zone_transfer': 'failed', 'ns_server': NS_IP}
    ]

    transport.tcp_open = True
    transport.xfr_error = RuntimeError('transfer refused')
    refused = _transfer('example.net')
    assert [r['zone_transfer'] for r in refused] == ['failed']
    assert refused[0].get('domain') == 'example.net'


def test_empty_discovery_still_returns_an_empty_list(transport):
    transport.resolver_error = RuntimeError('no name server answers')
    assert transport.tcp_open is True
    assert _transfer('example.com') == []
    assert _domain_records(dns_record_from_dict([], SCAN_INFO, ['example.com'])) == {'example.com': []}
