from dataclasses import dataclass
from typing import Any, Protocol

import httpx

SHODAN_SEARCH_URL = 'https://api.shodan.io/shodan/host/search'


class ShodanClientError(Exception):
    """Raised when a Shodan backend fails to return usable search results."""


class ShodanClient(Protocol):
    def search_net(self, cidr: str, timeout: float = 5.0) -> list[dict[str, Any]]:
        """Search a netblock and return raw match objects."""


@dataclass(slots=True)
class HttpxShodanClient:
    """
    Thin adapter around the Shodan HTTP API.

    This keeps dnsrecon's Shodan integration backend-agnostic so it can be
    switched to the official SDK later without changing enumeration code.
    """

    api_key: str
    search_url: str = SHODAN_SEARCH_URL

    def search_net(self, cidr: str, timeout: float = 5.0) -> list[dict[str, Any]]:
        try:
            response = httpx.get(
                self.search_url,
                params={'key': self.api_key, 'query': f'net:{cidr}'},
                timeout=timeout,
            )
            response.raise_for_status()
            payload = response.json()
        except httpx.HTTPStatusError as e:
            status_code = e.response.status_code if e.response is not None else 'unknown'
            raise ShodanClientError(f'Shodan search failed for net:{cidr} ({status_code}): {e!s}') from e
        except httpx.HTTPError as e:
            raise ShodanClientError(f'Shodan request failed for net:{cidr}: {e!s}') from e
        except ValueError as e:
            raise ShodanClientError(f'Invalid JSON from Shodan for net:{cidr}: {e!s}') from e

        matches = payload.get('matches', [])
        if not isinstance(matches, list):
            return []

        return [match for match in matches if isinstance(match, dict)]


class ShodanSdkClient:
    """
    Optional backend for the official `shodan` Python SDK.

    Not used by default and does not add a dependency unless explicitly enabled.
    """

    def __init__(self, api_key: str, sdk_client: Any | None = None):
        if sdk_client is not None:
            self._client = sdk_client
            return

        try:
            import shodan as shodan_sdk  # type: ignore[import-not-found]
        except ImportError as e:
            raise ShodanClientError('The `shodan` Python SDK is not installed') from e

        self._client = shodan_sdk.Shodan(api_key)

    def search_net(self, cidr: str, timeout: float = 5.0) -> list[dict[str, Any]]:
        # The official SDK does not expose a per-call timeout consistently across versions.
        # Keep the method signature aligned with the protocol for backend interchangeability.
        _ = timeout
        try:
            result = self._client.search(f'net:{cidr}')
        except Exception as e:
            raise ShodanClientError(f'Shodan SDK search failed for net:{cidr}: {e!s}') from e

        matches = result.get('matches', []) if isinstance(result, dict) else []
        if not isinstance(matches, list):
            return []

        return [match for match in matches if isinstance(match, dict)]


def make_shodan_client(api_key: str, backend: str = 'httpx') -> ShodanClient:
    """
    Factory for Shodan backends.

    Supported backends:
    - `httpx` (default): direct API requests using current project dependency
    - `sdk`: official `shodan` package (optional dependency)
    """
    if backend == 'httpx':
        return HttpxShodanClient(api_key=api_key)
    if backend == 'sdk':
        return ShodanSdkClient(api_key=api_key)
    raise ValueError(f'Unsupported Shodan backend: {backend}')
