"""Tests for the man page generator in tools/generate_manpage.py."""

import importlib.util
from pathlib import Path

import pytest

from dnsrecon.cli import __version__, build_parser

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope='module')
def generator():
    spec = importlib.util.spec_from_file_location('generate_manpage', ROOT / 'tools' / 'generate_manpage.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_every_cli_option_is_documented(generator):
    page = generator.generate(date='2000-01-01')
    for action in build_parser()._actions:
        for option in action.option_strings:
            assert generator.flag(option) in page, f'{option} missing from man page'


def test_header_has_version_and_date(generator):
    page = generator.generate(date='2000-01-01')
    assert f'.TH DNSRECON 1 "2000-01-01" "dnsrecon {__version__}" "User Commands"' in page


def test_scan_types_rendered_as_list(generator):
    page = generator.generate(date='2000-01-01')
    for scan_type in ('std', 'rvl', 'brt', 'srv', 'axfr', 'bing', 'yand', 'crt', 'caa', 'snoop', 'tld', 'zonewalk'):
        assert f'\\fB{scan_type}\\fR' in page


def test_source_date_epoch_sets_date(generator, monkeypatch):
    monkeypatch.setenv('SOURCE_DATE_EPOCH', '1782691200')
    assert generator.page_date() == '2026-06-29'


def test_date_only_change_does_not_rewrite(generator, tmp_path, monkeypatch):
    out = tmp_path / 'dnsrecon.1'
    monkeypatch.setenv('SOURCE_DATE_EPOCH', '946684800')  # 2000-01-01
    generator.main(['-o', str(out)])
    original = out.read_text()

    monkeypatch.setenv('SOURCE_DATE_EPOCH', '1782691200')  # 2026-06-29
    generator.main(['-o', str(out)])
    assert out.read_text() == original
