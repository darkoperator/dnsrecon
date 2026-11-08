"""Regression test for make_csv() mutating records that later JSON output reads."""

from dnsrecon.cli import make_csv


def test_make_csv_does_not_mutate_records():
    record = {
        'type': 'CAA',
        'name': 'example.com',
        'address': 'issue-wild',
        'target': 'example.com',
        'domain': 'example.com',
    }
    csv_data = make_csv([record])
    assert record['type'] == 'CAA'
    assert "example.com,CAA,,,,,'name=example.com; address=issue-wild; target=example.com; domain=example.com'\n" in csv_data
