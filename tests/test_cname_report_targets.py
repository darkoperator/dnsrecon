"""CNAME report target propagation for enumerator-produced records.

The producer path is real.  ``DnsHelper.get_a`` returns ``['CNAME', name,
target]`` rows and ``general_enum`` stores the third element in the ``address``
key (no ``target`` key).  The CSV and SQLite writers used to read only
``target``, so the target was omitted from those reports while the record
itself was still listed.

Only the DNS transport seam is replaced here: ``dns.query.udp``/``dns.query.tcp``
return a genuine ``dns.message.Message`` built with dnspython's own API.  The
real ``Resolver`` parses it into a real ``Answer``/``rdata``/``RRset``; no report
DTO is hand-built for the exporters.
"""

import csv
import io
import sqlite3

import dns.message
import dns.query
import dns.rdatatype
import dns.rrset
import pytest

from dnsrecon import cli
from dnsrecon.lib import dnshelper

QNAME = 'example.com.'
CNAME_NAME = 'example.com'
CNAME_TARGET = 'www.example.com'
A_ADDRESS = '192.0.2.10'
HEADER = 'Domain,Type,Name,Address,Target,Port,String'


def _transport(request, where, *args, **kwargs):
    """DNS transport seam: a real Message, never a socket."""
    message = dns.message.make_response(request)
    question = request.question[0]
    if question.rdtype == dns.rdatatype.A and question.name.to_text().lower() == QNAME:
        message.answer.append(dns.rrset.from_text(QNAME, 300, 'IN', 'CNAME', CNAME_TARGET + '.'))
        message.answer.append(dns.rrset.from_text(CNAME_TARGET + '.', 300, 'IN', 'A', A_ADDRESS))
    # Sections were appended directly, so the parsed index must be rebuilt; the
    # real Message/Answer machinery then reads them like any parsed response.
    message.index = None
    return message


@pytest.fixture
def transport(monkeypatch):
    monkeypatch.setattr(dns.query, 'udp', _transport)
    monkeypatch.setattr(dns.query, 'tcp', _transport)


@pytest.fixture
def producer_records(transport):
    helper = dnshelper.DnsHelper('example.com', '192.0.2.53', request_timeout=0.25)
    return cli.general_enum(
        helper,
        'example.com',
        False,
        False,
        False,
        False,
        False,
        False,
        False,
        3.0,
        thread_num=1,
    )


def _csv_rows(record):
    # The exporter receives the caller's dict object itself, so the tests can
    # detect any in-place mutation of the record on the CNAME path.
    text = cli.make_csv([record])
    return list(csv.reader(io.StringIO(text)))


def _db_targets(tmp_path, records, db_name='cname.db'):
    db_file = tmp_path / db_name
    cli.create_db(str(db_file))
    cli.write_db(str(db_file), records)
    con = sqlite3.connect(str(db_file))
    try:
        return con.execute('select domain, type, name, target from data').fetchall()
    finally:
        con.close()


def _db_addresses(tmp_path, records, db_name='address.db'):
    db_file = tmp_path / db_name
    cli.create_db(str(db_file))
    cli.write_db(str(db_file), records)
    con = sqlite3.connect(str(db_file))
    try:
        return con.execute('select type, name, address from data').fetchall()
    finally:
        con.close()


def test_general_enum_cname_target_reaches_csv_target_column(producer_records):
    cname_rows = [row for row in producer_records if row['type'] == 'CNAME']
    assert len(cname_rows) == 1
    row = cname_rows[0]
    # Producer contract: the target lives in 'address' and there is no 'target'.
    assert row['address'] == CNAME_TARGET
    assert 'target' not in row

    record = dict(row)
    rows = _csv_rows(record)
    assert rows[0] == HEADER.split(',')
    assert len(rows[0]) == 7
    assert len(rows[1]) == 7
    assert rows[1][2] == CNAME_NAME
    assert rows[1][4] == CNAME_TARGET
    assert record == row, 'make_csv must not mutate the caller record'


def test_general_enum_cname_target_reaches_sqlite_target_column(producer_records, tmp_path):
    cname_rows = [row for row in producer_records if row['type'] == 'CNAME']
    assert len(cname_rows) == 1
    record = dict(cname_rows[0])

    rows = _db_targets(tmp_path, [record])
    assert len(rows) == 1
    assert rows[0] == ('example.com', 'CNAME', CNAME_NAME, CNAME_TARGET)
    assert record == cname_rows[0], 'write_db must not mutate the caller record'


def test_a_record_exports_unchanged(producer_records, tmp_path):
    a_rows = [row for row in producer_records if row['type'] == 'A']
    assert len(a_rows) == 1
    row = a_rows[0]
    # get_a walks the CNAME chain, so the A row carries the target as its name.
    assert row['name'] == CNAME_TARGET

    rows = _csv_rows(row)
    assert len(rows[1]) == 7
    assert rows[1][2] == CNAME_TARGET
    assert rows[1][3] == A_ADDRESS
    assert rows[1][4] == ''

    db_rows = _db_addresses(tmp_path, [row])
    assert db_rows == [('A', CNAME_TARGET, A_ADDRESS)]


def test_explicit_cname_target_wins_over_address(tmp_path):
    record = {
        'domain': 'example.com',
        'type': 'CNAME',
        'name': 'alias.example.com',
        'address': 'address.example.net',
        'target': 'explicit.example.net',
    }

    rows = _csv_rows(record)
    assert rows[1][4] == 'explicit.example.net'

    db_rows = _db_targets(tmp_path, [record])
    assert db_rows == [('example.com', 'CNAME', 'alias.example.com', 'explicit.example.net')]
    assert record['target'] == 'explicit.example.net'


def test_empty_cname_target_key_is_not_backfilled(tmp_path):
    record = {
        'domain': 'example.com',
        'type': 'CNAME',
        'name': 'alias.example.com',
        'address': 'address.example.net',
        'target': '',
    }

    rows = _csv_rows(record)
    assert rows[1][4] == ''

    db_rows = _db_targets(tmp_path, [record])
    assert db_rows == [('example.com', 'CNAME', 'alias.example.com', '')]


def test_missing_target_and_address_stays_empty(tmp_path):
    record = {'domain': 'example.com', 'type': 'CNAME', 'name': 'alias.example.com'}

    rows = _csv_rows(record)
    assert len(rows[1]) == 7
    assert rows[1][4] == ''

    db_rows = _db_targets(tmp_path, [record])
    assert db_rows == [('example.com', 'CNAME', 'alias.example.com', '')]
