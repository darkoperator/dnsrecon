
# DNSRecon

DNSRecon is a Python port of a Ruby script that I wrote to learn the language and about DNS in early 2007. 
This time I wanted to learn about Python and extend the functionality of the original tool and in the process re-learn how DNS works and how could it be used in the process of a security assessment and network troubleshooting. 

This script provides the ability to perform:
* Check all NS Records for Zone Transfers.
* Enumerate General DNS Records for a given Domain (MX, SOA, NS, A, AAAA, SPF and TXT).
* Perform common SRV Record Enumeration.
* Top Level Domain (TLD) Expansion.
* Check for Wildcard Resolution.
* Brute Force subdomain and host A and AAAA records given a domain and a wordlist.
* Perform a PTR Record lookup for a given IP Range or CIDR.
* Check a DNS Server Cached records for A, AAAA and CNAME Records provided a list of host records in a text file to check..

# Installation

## Requirements
DNSRecon requires Python 3.12 or higher.

## Using uv (Recommended)

1. Install uv if you haven't already:
   ```bash
   curl -LsSf https://astral.sh/uv/install.sh | sh
   ```

2. Clone the repository:
   ```bash
   git clone https://github.com/darkoperator/dnsrecon.git
   cd dnsrecon
   ```

3. Install dependencies and create virtual environment:
   ```bash
   uv sync
   ```

4. Run DNSRecon:
   ```bash
   uv run dnsrecon
   ```

## Development

To install development dependencies:
```bash
uv sync --extra dev
```

To run tests:
```bash
uv run pytest
```

To run linting and formatting:
```bash
uv run ruff check
```
```bash
uv run ruff format
```

## Shodan Netblock Expansion

DNSRecon can use Shodan to expand netblocks discovered during standard enumeration from SPF (`-s`) and/or WHOIS (`-w`) data.

### CLI examples

Passive Shodan enrichment (uses SPF + WHOIS netblocks):

```bash
uv run dnsrecon -d example.com -t std -s -w --shodan --shodan-key "$SHODAN_API_KEY"
```

Active validation of Shodan results (re-resolves hosts and confirms they still match the queried netblock):

```bash
uv run dnsrecon -d example.com -t std -s -w --shodan --shodan-active --shodan-key "$SHODAN_API_KEY"
```

You can also set the API key via environment variable instead of `--shodan-key`:

```bash
export SHODAN_API_KEY="your-shodan-api-key"
uv run dnsrecon -d example.com -t std -s -w --shodan
```

### REST API examples

Start the REST API:

```bash
uv run restdnsrecon
```

Call `/general_enum` with Shodan expansion enabled:

```bash
curl -s \
  -H "X-Shodan-Api-Key: $SHODAN_API_KEY" \
  "http://127.0.0.1:5000/general_enum?domain=example.com&do_spf=true&do_whois=true&do_shodan=true"
```

Enable active validation in the API:

```bash
curl -s \
  -H "X-Shodan-Api-Key: $SHODAN_API_KEY" \
  "http://127.0.0.1:5000/general_enum?domain=example.com&do_spf=true&do_whois=true&do_shodan=true&shodan_active=true"
```

## Packaging Versions
[![Packaging status](https://repology.org/badge/vertical-allrepos/dnsrecon.svg)](https://repology.org/project/dnsrecon/versions)
