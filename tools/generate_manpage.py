#!/usr/bin/env python3
"""Generate the dnsrecon(1) man page from the CLI argument parser.

SYNOPSIS and OPTIONS are built from ``dnsrecon.cli.build_parser()`` so they can
never drift from ``dnsrecon --help``. Everything else (DESCRIPTION, EXAMPLES,
FILES, ...) is hand-written below; edit it here, not in man/dnsrecon.1.

The original page was written for the Debian package by its maintainers and is
used here under the GPL-2+:
https://sources.debian.org/src/dnsrecon/1.6.3-1/debian/dnsrecon.1

Usage:
    uv run python tools/generate_manpage.py            # writes man/dnsrecon.1
    uv run python tools/generate_manpage.py -o -       # print to stdout

The page date comes from SOURCE_DATE_EPOCH when set, otherwise today (UTC). If
only the date would change, the existing file is left untouched so regenerating
never produces date-only churn.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from dnsrecon.cli import __version__, build_parser

if TYPE_CHECKING:
    from collections.abc import Iterable

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT = REPO_ROOT / 'man' / 'dnsrecon.1'
PROG = 'dnsrecon'

DESCRIPTION = r"""
.B dnsrecon
is a DNS enumeration and reconnaissance tool. It can:
.IP \(bu 2
Check all NS records for zone transfers (AXFR).
.IP \(bu 2
Enumerate general DNS records for a given domain (MX, SOA, NS, A, AAAA, SPF and TXT).
.IP \(bu 2
Perform common SRV record enumeration.
.IP \(bu 2
Perform top level domain (TLD) expansion.
.IP \(bu 2
Check for wildcard resolution.
.IP \(bu 2
Brute force subdomain and host A and AAAA records given a domain and a wordlist.
.IP \(bu 2
Perform PTR record lookups for a given IP range or CIDR.
.IP \(bu 2
Check a DNS server's cached records for A, AAAA and CNAME records given a list of host records (cache snooping).
.IP \(bu 2
Enumerate subdomains and hosts using Bing, Yandex and crt.sh.
.IP \(bu 2
Walk DNSSEC zones using NSEC records.
.IP \(bu 2
Expand netblocks found in SPF and WHOIS data using Shodan.
.PP
If no name server is given with
.BR \-n ,
the SOA server of the target domain is used.
"""

EXAMPLES = r"""
.TP
Standard enumeration of a domain:
.B dnsrecon \-d example.com
.TP
Attempt a zone transfer (AXFR) against all name servers of zonetransfer.me:
.B dnsrecon \-t axfr \-d zonetransfer.me
.TP
Brute force subdomains with a wordlist, saving the results as JSON:
.B dnsrecon \-t brt \-d example.com \-D /path/to/wordlist.txt \-j results.json
.TP
Reverse lookup of a CIDR range:
.B dnsrecon \-t rvl \-r 192.0.2.0/24
.TP
Standard enumeration plus crt.sh, SPF and WHOIS expansion through Shodan:
.B dnsrecon \-d example.com \-k \-s \-w \-\-shodan
"""

ENVIRONMENT = r"""
.TP
.B SHODAN_API_KEY
Shodan API key used by
.B \-\-shodan
when
.B \-\-shodan\-key
is not given.
"""

FILES = r"""
.TP
.I ~/.config/dnsrecon/dnsrecon.log
Log file, rotated at 100 MB.
.TP
.I /etc/dnsrecon/namelist.txt
Wordlist used for
.B brt
and
.B snoop
when
.B \-D
is not given. If it does not exist, the
.I namelist.txt
bundled with the Python package is used.
"""

SEE_ALSO = r"""
.BR dig (1),
.BR host (1),
.BR whois (1)
.PP
Project home page:
.UR https://github.com/darkoperator/dnsrecon
.UE
"""

AUTHORS = r"""
.B dnsrecon
was written by Carlos Perez <carlos_perez@darkoperator.com>.
.PP
This manual page was originally written for the Debian project and is now
generated from the
.B dnsrecon
argument parser.
"""

# Matches an indented "name: description" entry inside RawTextHelpFormatter help,
# e.g. the list of enumeration types under -t/--type.
_SUBITEM_RE = re.compile(r'^\s+(?P<name>[\w-]+):\s+(?P<desc>.*)$')
_OPTION_RE = re.compile(r'(?<![\w\\-])(--?)(?=[A-Za-z])')


def escape(text: str) -> str:
    """Escape text for roff and mark option-like dashes as real minus signs."""
    text = text.replace('\\', '\\e')
    text = _OPTION_RE.sub(lambda m: '\\-' * len(m.group(1)), text)
    return text


def line(text: str) -> str:
    """Guard against roff interpreting a leading . or ' as a request."""
    return f'\\&{text}' if text[:1] in ('.', "'") else text


def bold(text: str) -> str:
    return f'\\fB{escape(text)}\\fR'


def italic(text: str) -> str:
    return f'\\fI{escape(text)}\\fR'


def flag(option: str) -> str:
    """Bold option name with every dash as a roff minus sign (e.g. --shodan-active)."""
    return '\\fB' + option.replace('-', '\\-') + '\\fR'


def metavar_for(formatter: argparse.HelpFormatter, action: argparse.Action) -> str:
    if action.nargs == 0:
        return ''
    if action.choices and action.metavar is None and action.nargs is None:
        # Choices are listed in the option's description; keep the synopsis readable.
        return action.dest.upper()
    default = formatter._get_default_metavar_for_optional(action)
    return formatter._format_args(action, default)


def sentence(text: str) -> str:
    text = text.strip()
    if not text:
        return text
    text = text[0].upper() + text[1:]
    return text if text.endswith(('.', ':')) else text + '.'


def render_help(action: argparse.Action) -> list[str]:
    """Render an option's help text, turning indented ``name: desc`` lists into .TP items."""
    help_text = (action.help or '').replace('%(default)s', str(action.default)).replace('%%', '%')
    para: list[str] = []
    items: list[tuple[str, list[str]]] = []
    for raw in help_text.splitlines():
        if not raw.strip():
            continue
        match = _SUBITEM_RE.match(raw)
        if match:
            items.append((match['name'], [match['desc'].strip()]))
        elif items and raw.startswith(' '):
            items[-1][1].append(raw.strip())
        else:
            para.append(raw.strip())

    out = [line(escape(sentence(' '.join(para))))] if para else []
    if action.choices and not items:
        out.append(line('Possible values: ' + ', '.join(bold(str(c)) for c in action.choices) + '.'))
    if items:
        width = max(len(name) for name, _ in items) + 2
        out.append('.RS')
        for name, desc in items:
            out += [f'.TP {width}n', bold(name), line(escape(sentence(' '.join(desc))))]
        out.append('.RE')
    return out


def option_actions(parser: argparse.ArgumentParser) -> Iterable[argparse.Action]:
    return (a for a in parser._actions if a.option_strings and a.help is not argparse.SUPPRESS)


def render_synopsis(parser: argparse.ArgumentParser) -> list[str]:
    formatter = parser._get_formatter()
    out = ['.SY ' + PROG]
    for action in option_actions(parser):
        metavar = metavar_for(formatter, action)
        name = flag(action.option_strings[0])
        out.append(f'.OP {name} {italic(metavar)}' if metavar else f'.OP {name}')
    out.append('.YS')
    return out


def render_options(parser: argparse.ArgumentParser) -> list[str]:
    formatter = parser._get_formatter()
    out: list[str] = []
    for action in option_actions(parser):
        metavar = metavar_for(formatter, action)
        flags = ', '.join(f'{flag(opt)} {italic(metavar)}' if metavar else flag(opt) for opt in action.option_strings)
        out += ['.TP', flags, *render_help(action)]
    return out


def section(title: str, body: str | list[str]) -> list[str]:
    lines = body if isinstance(body, list) else body.strip('\n').splitlines()
    return [f'.SH {title}', *lines]


def page_date() -> str:
    epoch = os.environ.get('SOURCE_DATE_EPOCH')
    when = datetime.fromtimestamp(int(epoch), UTC) if epoch else datetime.now(UTC)
    return when.strftime('%Y-%m-%d')


def generate(date: str | None = None) -> str:
    parser = build_parser()
    parser.prog = PROG
    lines = [
        '.\\" Generated by tools/generate_manpage.py from the dnsrecon argument parser.',
        '.\\" Do not edit by hand: edit the generator and re-run it instead.',
        f'.TH DNSRECON 1 "{date or page_date()}" "dnsrecon {__version__}" "User Commands"',
        *section('NAME', f'{PROG} \\- DNS enumeration and scanning tool'),
        *section('SYNOPSIS', render_synopsis(parser)),
        *section('DESCRIPTION', DESCRIPTION),
        *section('OPTIONS', render_options(parser)),
        *section('EXAMPLES', EXAMPLES),
        *section('ENVIRONMENT', ENVIRONMENT),
        *section('FILES', FILES),
        *section('SEE ALSO', SEE_ALSO),
        *section('AUTHORS', AUTHORS),
    ]
    return '\n'.join(lines) + '\n'


_TH_RE = re.compile(r'^(\.TH \S+ \S+ )"[^"]*"', re.MULTILINE)


def _without_date(page: str) -> str:
    return _TH_RE.sub(r'\1""', page)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('-o', '--output', default=str(DEFAULT_OUTPUT), help='Output path, or - for stdout.')
    args = ap.parse_args(argv)

    page = generate()
    if args.output == '-':
        sys.stdout.write(page)
        return 0

    out = Path(args.output)
    if out.exists() and _without_date(out.read_text(encoding='utf-8')) == _without_date(page):
        print(f'{out} is already up to date')
        return 0
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(page, encoding='utf-8')
    print(f'Wrote {out}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
