"""Regression tests for make_csv() non-mutating fallback handling.

make_csv() renders record types it has no dedicated column layout for (CAA and
other uncommon types) through a generic ``key=value`` fallback.  That fallback
used to ``del record['type']`` on the caller's dictionary, so the in-memory scan
results were destroyed as a side effect of writing the CSV: a later JSON (or any
other) consumer of the same records saw a record without ``type``.

These tests exercise the real product functions only (no DNS, no network, no
socket, no resolver stub) and are written for both ``unittest`` and ``pytest``.
"""

import copy
import json
import os
import tempfile
import unittest

from dnsrecon.cli import make_csv, write_json

SCAN_INFO = (['-d', 'example.com', '-t', 'std'], '2026-11-06 00:00:00')

CAA_RECORD = {
    'type': 'CAA',
    'name': 'example.com',
    'address': 'issue-wild',
    'target': 'example.com',
    'domain': 'example.com',
}

CAA_LINE = (
    "example.com,CAA,,,,,"
    "'name=example.com; address=issue-wild; target=example.com; domain=example.com'\n"
)


def _caa():
    return copy.deepcopy(CAA_RECORD)


class MakeCsvCaaTests(unittest.TestCase):
    def test_caa_record_not_mutated(self):
        records = [_caa()]
        before = copy.deepcopy(records)

        csv_data = make_csv(records)

        self.assertEqual(records, before)
        self.assertEqual(records[0]['type'], 'CAA')
        self.assertIn(CAA_LINE, csv_data)

    def test_legacy_list_wrapped_record_not_mutated(self):
        inner = _caa()
        wrapped = [[inner]]

        csv_data = make_csv(wrapped)

        self.assertEqual(inner, CAA_RECORD)
        self.assertEqual(wrapped[0][0]['type'], 'CAA')
        self.assertEqual(csv_data, 'Domain,Type,Name,Address,Target,Port,String\n' + CAA_LINE)

    def test_repeated_make_csv_is_stable(self):
        records = [_caa(), _caa()]

        first = make_csv(records)
        second = make_csv(records)
        third = make_csv([_caa(), _caa()])

        self.assertEqual(first, second)
        self.assertEqual(first, third)
        self.assertEqual(records, [_caa(), _caa()])

    def test_dict_and_list_wrapper_render_identically(self):
        as_dict = make_csv([_caa()])
        as_wrapper = make_csv([[_caa()]])

        self.assertEqual(as_dict, as_wrapper)

    def test_csv_to_json_consumer_keeps_type(self):
        records = [_caa()]

        csv_data = make_csv(records)
        self.assertIn(CAA_LINE, csv_data)

        with tempfile.TemporaryDirectory() as tmp:
            json_path = os.path.join(tmp, 'out.json')
            write_json(json_path, records, SCAN_INFO)
            with open(json_path, encoding='utf-8') as handle:
                payload = json.load(handle)

        # write_json() keeps inserting the ScanInfo header entry (unchanged).
        self.assertEqual(payload[0]['type'], 'ScanInfo')
        self.assertEqual(len(payload), 2)
        caa = payload[1]
        self.assertEqual(caa['type'], 'CAA')
        self.assertEqual(caa['name'], 'example.com')
        self.assertEqual(caa['address'], 'issue-wild')
        self.assertEqual(caa['target'], 'example.com')
        self.assertEqual(caa['domain'], 'example.com')


class MakeCsvControlTests(unittest.TestCase):
    def test_a_record_control_line(self):
        record = {
            'type': 'A',
            'name': 'www.example.com',
            'address': '192.0.2.10',
            'domain': 'example.com',
        }

        csv_data = make_csv([record])

        self.assertEqual(
            csv_data,
            'Domain,Type,Name,Address,Target,Port,String\n'
            'example.com,A,www.example.com,192.0.2.10,,,\n',
        )
        self.assertEqual(record['type'], 'A')

    def test_mixed_records_csv_bytes_exact_and_non_mutating(self):
        records = [
            {'type': 'A', 'name': 'www.example.com', 'address': '192.0.2.10', 'domain': 'example.com'},
            {'type': 'NS', 'target': 'ns1.example.com', 'address': '', 'domain': 'example.com'},
            {'type': 'MX', 'exchange': 'mx1.example.com', 'address': '', 'domain': 'example.com'},
            {'type': 'TXT', 'name': 'example.com', 'strings': 'v=spf1 -all', 'domain': 'example.com'},
            {'type': 'SRV', 'name': '_sip._tcp.example.com', 'address': '',
             'target': 'sip.example.com', 'port': '5060', 'domain': 'example.com'},
            {'type': 'CNAME', 'name': 'alias.example.com', 'target': 'real.example.com',
             'domain': 'example.com'},
            _caa(),
        ]
        before = copy.deepcopy(records)

        csv_data = make_csv(records)

        expected = (
            'Domain,Type,Name,Address,Target,Port,String\n'
            'example.com,A,www.example.com,192.0.2.10,,,\n'
            'example.com,NS,ns1.example.com,,,,\n'
            'example.com,MX,mx1.example.com,,,,\n'
            "example.com,TXT,example.com,,,,'v=spf1 -all'\n"
            'example.com,SRV,_sip._tcp.example.com,,sip.example.com,5060,\n'
            'example.com,CNAME,alias.example.com,,real.example.com,,\n'
            + CAA_LINE
        )
        self.assertEqual(csv_data, expected)
        self.assertEqual(csv_data.encode('utf-8'), expected.encode('utf-8'))
        self.assertEqual(records, before)


if __name__ == '__main__':
    unittest.main()
