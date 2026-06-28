# Changelog

## [1.6.2] - 2026-06-28

### Changed
- Bumped DNSRecon version to `1.6.2`.

### Fixed
- Corrected AXFR enumeration to call zone transfer once, return successful transfer records immediately, and only fall back to normal enumeration when the transfer does not succeed.
- Ensured successful TCP DNS connectivity checks close their sockets.
- Added SPF expansion safeguards for cyclic includes, malformed SPF networks, malformed TXT responses, and large address expansions.

## [1.6.1] - 2026-05-23

### Security
- Hardened REST API wordlist handling so requests can only use bundled wordlists or files under directories configured with `DNSRECON_WORDLIST_DIRS`. ([b7d8452](https://github.com/darkoperator/dnsrecon/commit/b7d8452))
- Parameterized SQLite output writes and capped REST API `thread_num` values to reduce injection and resource-exhaustion risk. ([b7d8452](https://github.com/darkoperator/dnsrecon/commit/b7d8452))
- Hardened GitHub Actions workflows and added dependency review and Scorecard coverage. ([e1b9d65](https://github.com/darkoperator/dnsrecon/commit/e1b9d65))

### Changed
- Bumped DNSRecon version to `1.6.1`. ([8df618d](https://github.com/darkoperator/dnsrecon/commit/8df618d))
- Updated runtime dependencies including `fastapi` to 0.136.1, `uvicorn[standard]` to 0.47.0, `stamina` to 26.1.0, `ujson` to 5.12.1, and `idna` to 3.15.
- Updated development, Docker, and CI dependencies including `ruff` to 0.15.14, `pytest` to 9.0.3, `setuptools` to `>=82.0.1`, the Python Docker base image, CodeQL, setup-uv, Docker actions, and harden-runner.
- Regenerated `uv.lock` for the 1.6.1 dependency set. ([1a8f575](https://github.com/darkoperator/dnsrecon/commit/1a8f575))

### Fixed
- Corrected general enumeration to use Yandex scraping for Yandex results and to guard optional `address` fields before collecting WHOIS IPs. ([91b8999](https://github.com/darkoperator/dnsrecon/commit/91b8999))
- Made WHOIS reverse lookup selection safe for non-interactive runs by defaulting to all discovered ranges when stdin is not a TTY. ([982aef8](https://github.com/darkoperator/dnsrecon/commit/982aef8))
- Made crt.sh, Bing, Yandex, and WHOIS enumeration log external-source failures and continue instead of aborting the scan. ([ec3ec7e](https://github.com/darkoperator/dnsrecon/commit/ec3ec7e))
- Corrected REST API reverse-range parsing, AXFR success reporting, recursion checks, empty reverse lookups, and related validation behavior. ([b7d8452](https://github.com/darkoperator/dnsrecon/commit/b7d8452))
- Removed stray XML text from the license header. ([214a96c](https://github.com/darkoperator/dnsrecon/commit/214a96c))

## [1.6.0] - 2026-02-28

### Added
- Added Shodan support for netblock expansion during DNS enumeration and API enhancements to leverage it (Fixes #104). ([12a5b15](https://github.com/darkoperator/dnsrecon/commit/12a5b15))

### Changed
- Bumped DNSRecon version to `1.6.0`.
- Updated FastAPI to 0.134.0 and replaced `UJSONResponse` with `JSONResponse` for compatibility. ([8360ec0](https://github.com/darkoperator/dnsrecon/commit/8360ec0))
- Bumped `fastapi` from 0.129.2 to 0.133.1. ([8476e35](https://github.com/darkoperator/dnsrecon/commit/8476e35))
- Bumped `ruff` from 0.15.2 to 0.15.4. ([0c8bc7e](https://github.com/darkoperator/dnsrecon/commit/0c8bc7e))
- Applied Ruff fixes and formatting. ([56c9c35](https://github.com/darkoperator/dnsrecon/commit/56c9c35))
- Updated dependencies. ([5db0595](https://github.com/darkoperator/dnsrecon/commit/5db0595))
- Bumped `uvicorn[standard]` from 0.40.0 to 0.41.0. ([78137d2](https://github.com/darkoperator/dnsrecon/commit/78137d2))
- Bumped `ruff` from 0.15.1 to 0.15.2. ([5fecb97](https://github.com/darkoperator/dnsrecon/commit/5fecb97))
- Updated dependencies. ([1cad9df](https://github.com/darkoperator/dnsrecon/commit/1cad9df))
- Updated dependencies. ([506d8d3](https://github.com/darkoperator/dnsrecon/commit/506d8d3))
- Bumped `fastapi` from 0.128.5 to 0.128.6. ([ed58132](https://github.com/darkoperator/dnsrecon/commit/ed58132))
- Bumped `fastapi` from 0.128.2 to 0.128.5. ([08c6dc4](https://github.com/darkoperator/dnsrecon/commit/08c6dc4))
- Merged pull request #454. ([1b90c5a](https://github.com/darkoperator/dnsrecon/commit/1b90c5a))
- Bumped `fastapi` from 0.128.0 to 0.128.2. ([09b5f09](https://github.com/darkoperator/dnsrecon/commit/09b5f09))
- Applied fix related to issue #453. ([32d2382](https://github.com/darkoperator/dnsrecon/commit/32d2382))

## [1.5.3] - 2025-12-30

### Removed
- Removed `lxml` dependency as it is no longer required for `crt.sh` scraping. ([1a3efd6](https://github.com/darkoperator/dnsrecon/commit/1a3efd6))

### Added
- Added recursion control to `DnsHelper` and corresponding CLI options this is in relation to #308. ([a27b244](https://github.com/darkoperator/dnsrecon/commit/a27b244))
- Added `uv.lock` for dependency management and improved project isolation. ([0e1f4bc](https://github.com/darkoperator/dnsrecon/commit/0e1f4bc))
- Added `FUNDING.yml` to enable project sponsorship. ([e9aef30](https://github.com/darkoperator/dnsrecon/commit/e9aef30))

### Changed
- Migrated CI/CD workflows to use `uv` for faster and more reliable builds. ([0e1f4bc](https://github.com/darkoperator/dnsrecon/commit/0e1f4bc))
- Updated multiple dependencies (`fastapi`, `uvicorn`, `stamina`, `pytest`, `ruff`) to their latest versions.
- Added type ignore comment for `CORSMiddleware` validation in API implementation. ([beda5fe](https://github.com/darkoperator/dnsrecon/commit/beda5fe))
- Refactored code across parser and DNS utility modules, including adding type annotations and improving error handling. ([e402af2](https://github.com/darkoperator/dnsrecon/commit/e402af2))
- Switched `crt.sh` enumeration to use the JSON API query instead of HTML scraping for improved reliability. ([1a3efd6](https://github.com/darkoperator/dnsrecon/commit/1a3efd6))
- Updated `fastapi` to version 0.128.0. ([1a3efd6](https://github.com/darkoperator/dnsrecon/commit/1a3efd6))

### Fixed
- Resolved issue #308 regarding recursion control. ([a27b244](https://github.com/darkoperator/dnsrecon/commit/a27b244))
- Adjusted zone transfer test threshold to improve test stability. ([c3ef676](https://github.com/darkoperator/dnsrecon/commit/c3ef676))
- Applied code style fixes and formatting using Ruff. ([302279f](https://github.com/darkoperator/dnsrecon/commit/302279f))

## [1.5.2] - 2025-12-23

### Added
- Added support for Python 3.14. ([12827ab](https://github.com/darkoperator/dnsrecon/commit/12827ab))

### Changed
- Replaced `requests` with `httpx` to modernize HTTP handling. ([12827ab](https://github.com/darkoperator/dnsrecon/commit/12827ab))
- Updated dependencies including `ruff`. ([67cd7f6](https://github.com/darkoperator/dnsrecon/commit/67cd7f6))

### Fixed
- Resolved issue #432 to actually fix python 3.14 support. ([880e76b](https://github.com/darkoperator/dnsrecon/commit/880e76b))

[1.6.2]: https://github.com/darkoperator/dnsrecon/compare/1.6.1...1.6.2
[1.6.1]: https://github.com/darkoperator/dnsrecon/compare/1.6.0...1.6.1
[1.6.0]: https://github.com/darkoperator/dnsrecon/compare/1.5.3...1.6.0
[1.5.3]: https://github.com/darkoperator/dnsrecon/compare/1.5.2...1.5.3
[1.5.2]: https://github.com/darkoperator/dnsrecon/compare/1.5.1...1.5.2
