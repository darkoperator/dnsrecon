# Changelog

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

[1.6.0]: https://github.com/darkoperator/dnsrecon/compare/1.5.3...1.6.0
[1.5.3]: https://github.com/darkoperator/dnsrecon/compare/1.5.2...1.5.3
[1.5.2]: https://github.com/darkoperator/dnsrecon/compare/1.5.1...1.5.2
