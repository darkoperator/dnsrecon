"""Offline tests for the record owner reported by ``DnsHelper.get_a``/``get_aaaa``.

Every answer here is a real ``dns.resolver.Answer`` built from a real
``dns.message.Message`` that was round-tripped through the wire format, so the
message carries the RRset index dnspython builds when a resolver parses a
response. Only the ``get_answers`` transport boundary is mocked: no query is
sent, no socket is opened and no name is resolved.
"""

import itertools
import socket
from unittest.mock import call, patch

import dns.message
import dns.resolver
import dns.rrset
import pytest

from dnsrecon.lib.dnshelper import DnsHelper

# RFC 5737 documentation address: passing it as the nameserver keeps
# ``dns.resolver.Resolver(configure=False)`` from reading the system resolver
# configuration (and thus from doing any setup lookup).
NS_SERVER = '192.0.2.53'
HOST = 'alias.example.invalid'
MIDDLE = 'middle.example.invalid'
TARGET = 'target.example.invalid'
CHAIN = (HOST, MIDDLE, TARGET)
ADDRESSES = {'A': '192.0.2.10', 'AAAA': '2001:db8::10'}

# Literal expectation for the two-hop alias chain, in chain order. Permuted
# answers are expected to produce the same rows in the permuted order.
CHAIN_ROWS = {
    'A': [
        ['CNAME', 'alias.example.invalid', 'middle.example.invalid'],
        ['CNAME', 'middle.example.invalid', 'target.example.invalid'],
        ['A', 'target.example.invalid', '192.0.2.10'],
    ],
    'AAAA': [
        ['CNAME', 'alias.example.invalid', 'middle.example.invalid'],
        ['CNAME', 'middle.example.invalid', 'target.example.invalid'],
        ['AAAA', 'target.example.invalid', '2001:db8::10'],
    ],
}


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """Fail closed on any socket use and record the attempts."""
    attempts = []

    def _deny(*args, **kwargs):
        attempts.append((args, kwargs))
        raise AssertionError('offline test attempted network access')

    monkeypatch.setattr(socket, 'socket', _deny)
    monkeypatch.setattr(socket, 'create_connection', _deny)
    monkeypatch.setattr(socket, 'getaddrinfo', _deny)
    yield attempts
    assert attempts == []


def _answer(qname, rdtype, rrsets):
    """Return a real Answer whose answer section holds ``rrsets`` in that order."""
    query = dns.message.make_query(qname, rdtype)
    response = dns.message.make_response(query)
    response.answer = list(rrsets)
    # A resolver parses the response from the wire, which builds the message's
    # RRset index; reproduce that instead of handing over a hand-built message.
    wire_response = dns.message.from_wire(response.to_wire())
    question = query.question[0]
    return dns.resolver.Answer(question.name, question.rdtype, question.rdclass, wire_response)


def _chain_rrsets(rdtype):
    """The alias -> middle -> target chain as (CNAME, CNAME, address) RRsets."""
    return [
        dns.rrset.from_text(f'{HOST}.', 60, 'IN', 'CNAME', f'{MIDDLE}.'),
        dns.rrset.from_text(f'{MIDDLE}.', 60, 'IN', 'CNAME', f'{TARGET}.'),
        dns.rrset.from_text(f'{TARGET}.', 60, 'IN', rdtype, ADDRESSES[rdtype]),
    ]


def _helper():
    return DnsHelper('example.invalid', ns_server=NS_SERVER)


@pytest.mark.parametrize('order', list(itertools.permutations(range(3))))
@pytest.mark.parametrize('rdtype', ['A', 'AAAA'])
def test_chain_rows_use_rrset_owner_in_wire_order(rdtype, order):
    """Owners follow each RRset name, and rows keep the answer's iteration order."""
    rrsets = _chain_rrsets(rdtype)
    answer = _answer(HOST, rdtype, [rrsets[index] for index in order])
    helper = _helper()

    with patch.object(helper, 'get_answers', return_value=answer) as get_answers:
        rows = helper.get_a(HOST) if rdtype == 'A' else helper.get_aaaa(HOST)

    get_answers.assert_called_once_with(rdtype, HOST)
    assert rows == [CHAIN_ROWS[rdtype][index] for index in order]


@pytest.mark.parametrize('rdtype', ['A', 'AAAA'])
def test_direct_address_row_uses_rrset_owner(rdtype):
    """A non-aliased answer reports the queried name as the owner of the address."""
    rrset = dns.rrset.from_text(f'{HOST}.', 60, 'IN', rdtype, ADDRESSES[rdtype])
    answer = _answer(HOST, rdtype, [rrset])
    helper = _helper()

    with patch.object(helper, 'get_answers', return_value=answer) as get_answers:
        rows = helper.get_a(HOST) if rdtype == 'A' else helper.get_aaaa(HOST)

    get_answers.assert_called_once_with(rdtype, HOST)
    assert rows == [[rdtype, HOST, ADDRESSES[rdtype]]]


@pytest.mark.parametrize('rdtype', ['A', 'AAAA'])
def test_multi_rdata_rrset_shares_one_owner(rdtype):
    """Every rdata of one RRset is reported under that RRset's owner."""
    addresses = ['192.0.2.10', '192.0.2.11'] if rdtype == 'A' else ['2001:db8::10', '2001:db8::11']
    rrset = dns.rrset.from_text(f'{HOST}.', 60, 'IN', rdtype, *addresses)
    answer = _answer(HOST, rdtype, [rrset])
    helper = _helper()

    with patch.object(helper, 'get_answers', return_value=answer) as get_answers:
        rows = helper.get_a(HOST) if rdtype == 'A' else helper.get_aaaa(HOST)

    get_answers.assert_called_once_with(rdtype, HOST)
    assert [row[0] for row in rows] == [rdtype, rdtype]
    assert [row[1] for row in rows] == [HOST, HOST]
    assert sorted(row[2] for row in rows) == sorted(addresses)


@pytest.mark.parametrize('rdtype', ['A', 'AAAA'])
def test_single_alias_rows_use_rrset_owner(rdtype):
    """The ordinary one-hop alias keeps its CNAME row and its target address row."""
    rrsets = [
        dns.rrset.from_text(f'{HOST}.', 60, 'IN', 'CNAME', f'{TARGET}.'),
        dns.rrset.from_text(f'{TARGET}.', 60, 'IN', rdtype, ADDRESSES[rdtype]),
    ]
    answer = _answer(HOST, rdtype, rrsets)
    helper = _helper()

    with patch.object(helper, 'get_answers', return_value=answer) as get_answers:
        rows = helper.get_a(HOST) if rdtype == 'A' else helper.get_aaaa(HOST)

    get_answers.assert_called_once_with(rdtype, HOST)
    assert rows == [['CNAME', HOST, TARGET], [rdtype, TARGET, ADDRESSES[rdtype]]]


@pytest.mark.parametrize('rdtype', ['A', 'AAAA'])
def test_missing_answer_returns_empty_list(rdtype):
    """A transport failure still yields no rows and a single lookup."""
    helper = _helper()

    with patch.object(helper, 'get_answers', return_value=None) as get_answers:
        rows = helper.get_a(HOST) if rdtype == 'A' else helper.get_aaaa(HOST)

    get_answers.assert_called_once_with(rdtype, HOST)
    assert rows == []


def test_get_ip_combines_families_with_rrset_owners():
    """``get_ip`` keeps A rows then AAAA rows, each owned by its own RRset name."""
    a_answer = _answer(HOST, 'A', list(reversed(_chain_rrsets('A'))))
    aaaa_answer = _answer(HOST, 'AAAA', _chain_rrsets('AAAA'))
    answers = {'A': a_answer, 'AAAA': aaaa_answer}
    helper = _helper()

    def _get_answers(rdtype, host):
        assert host == HOST
        return answers[rdtype]

    with patch.object(helper, 'get_answers', side_effect=_get_answers) as get_answers:
        rows = helper.get_ip(HOST)

    assert get_answers.call_args_list == [call('A', HOST), call('AAAA', HOST)]
    assert rows == list(reversed(CHAIN_ROWS['A'])) + CHAIN_ROWS['AAAA']
