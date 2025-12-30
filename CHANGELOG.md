# Changelog

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

[1.5.4]: https://github.com/darkoperator/dnsrecon/compare/1.5.3...1.5.4
[1.5.3]: https://github.com/darkoperator/dnsrecon/compare/1.5.2...1.5.3
[1.5.2]: https://github.com/darkoperator/dnsrecon/compare/1.5.1...1.5.2
