import os
import traceback

from fastapi import FastAPI, Header, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse, Response, UJSONResponse
from pydantic import BaseModel, Field
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from dnsrecon.cli import (
    brute_domain,
    brute_reverse,
    brute_srv,
    brute_tlds,
    check_bindversion,
    check_nxdomain_hijack,
    check_recursive,
    check_wildcard,
    ds_zone_walk,
    general_enum,
    in_cache,
)
from dnsrecon.lib.dnshelper import DnsHelper

API_RATE_LIMIT = os.getenv('API_RATE_LIMIT', '5/minute')


# Define Pydantic models for request and response validation
class DnsRecord(BaseModel):
    name: str = Field(..., description='DNS record name')
    type: str = Field(..., description='DNS record type')
    address: str = Field(..., description='DNS record address/value')
    target: str | None = Field(None, description='DNS record target (for SRV records)')
    port: int | None = Field(None, description='Port number (for SRV records)')


class GeneralEnumResponse(BaseModel):
    domain: str = Field(..., description='Target domain')
    records: list[DnsRecord] = Field(default_factory=list, description='List of DNS records found')
    subdomains: list[str] = Field(default_factory=list, description='List of subdomains found')
    ips: list[str] = Field(default_factory=list, description='List of IP addresses found')


class BruteForceResponse(BaseModel):
    domain: str = Field(..., description='Target domain')
    subdomains: list[str] = Field(default_factory=list, description='List of subdomains found')
    records: list[DnsRecord] = Field(default_factory=list, description='List of DNS records found')


class ReverseResponse(BaseModel):
    ip_range: str = Field(..., description='IP range queried')
    records: list[DnsRecord] = Field(default_factory=list, description='List of reverse DNS records found')


class DnsSecResponse(BaseModel):
    domain: str = Field(..., description='Target domain')
    dnssec_enabled: bool = Field(..., description='Whether DNSSEC is enabled')
    ds_records: list[DnsRecord] = Field(default_factory=list, description='List of DS records')
    dnskey_records: list[DnsRecord] = Field(default_factory=list, description='List of DNSKEY records')


class ZoneWalkResponse(BaseModel):
    domain: str = Field(..., description='Target domain')
    records: list[DnsRecord] = Field(default_factory=list, description='List of records found via zone walking')


class WildcardResponse(BaseModel):
    domain: str = Field(..., description='Target domain')
    wildcard_enabled: bool = Field(..., description='Whether wildcard DNS is enabled')
    wildcard_ips: list[str] = Field(default_factory=list, description='List of wildcard IP addresses')


class ErrorResponse(BaseModel):
    detail: str = Field(..., description='Error message')
    error_type: str | None = Field(None, description='Type of error')
    traceback: str | None = Field(None, description='Error traceback')


limiter = Limiter(key_func=get_remote_address)
app = FastAPI(
    title='DNSRecon REST API',
    description='REST API for DNSRecon powered by FastAPI',
    version='1.0.0',
    docs_url='/docs',
    redoc_url='/redoc',
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)  # type: ignore

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,  # ty:ignore[invalid-argument-type]
    allow_origins=['*'],
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*'],
)


@app.get('/', response_class=HTMLResponse)
async def root(*, user_agent: str = Header(None)) -> Response:
    """
    Root endpoint that displays the DNSRecon logo and links to the API documentation.

    Also performs basic user agent filtering to redirect suspicious bots.
    """
    # Basic user agent filtering
    if user_agent and ('gobuster' in user_agent or 'sqlmap' in user_agent or 'rustbuster' in user_agent):
        response = RedirectResponse(app.url_path_for('bot'))
        return response

    return HTMLResponse(
        """
    <!DOCTYPE html>
    <html lang="en-US">
        <head>
            <title>DNSRecon API</title>
             <style>
              .header {
                text-align: center;
                display: block;
                font-family: Arial, sans-serif;
                margin: 50px 0;
              }
              .api-links {
                text-align: center;
                margin-top: 20px;
                font-family: Arial, sans-serif;
              }
              .api-links a {
                margin: 0 10px;
                text-decoration: none;
                color: #0366d6;
              }
              .api-links a:hover {
                text-decoration: underline;
              }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>DNSRecon REST API</h1>
            </div>
            <div class="api-links">
                <a href="/docs">API Documentation</a> | 
                <a href="/redoc">ReDoc Documentation</a> | 
                <a href="/capabilities">API Capabilities</a>
            </div>
        </body>
    </html>
    """
    )


class BotResponse(BaseModel):
    bot: str = Field(..., description='Bot message')


@app.get('/nicebot', response_model=BotResponse)
async def bot() -> Response:
    """
    Easter egg endpoint for bots.

    Returns a message when accessed by suspicious user agents.
    """
    return UJSONResponse({'bot': 'These are not the DNS records you are looking for'})


class CapabilitiesResponse(BaseModel):
    capabilities: list[str] = Field(..., description='List of supported DNS reconnaissance capabilities')


@app.get(
    '/capabilities',
    response_model=CapabilitiesResponse,
    responses={
        status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResponse},
        status.HTTP_429_TOO_MANY_REQUESTS: {'model': ErrorResponse},
    },
)
@limiter.limit(API_RATE_LIMIT)
async def get_capabilities(request: Request) -> Response:
    """
    Endpoint to query for available DNS reconnaissance capabilities.

    Returns a list of all supported operations that can be performed via the API.
    Rate limit is configurable via CLI argument (default: 5 requests per minute).
    """
    try:
        capabilities = [
            'general_enum - General DNS enumeration with multiple sources (supports do_shodan, shodan_active, X-Shodan-Api-Key header)',
            'brute_domain - Domain brute forcing',
            'brute_srv - SRV record brute forcing',
            'brute_tlds - TLD brute forcing',
            'brute_reverse - Reverse DNS lookup',
            'zone_walk - DNS zone walking',
            'wildcard_check - Wildcard DNS detection',
            'bind_version - BIND version detection',
            'recursive_check - Recursive DNS server check',
            'axfr_test - Zone transfer testing',
            'caa_records - CAA record lookup',
            'cache_snoop - DNS cache snooping',
            'nxdomain_hijack - NXDOMAIN hijacking check',
        ]
        return UJSONResponse({'capabilities': capabilities})
    except Exception as e:
        error_traceback = traceback.format_exc()
        print(f'Error in get_capabilities endpoint: {e!s}\n{error_traceback}')

        return UJSONResponse(
            {
                'detail': f'An error occurred while retrieving capabilities: {e!s}',
                'error_type': type(e).__name__,
                'traceback': error_traceback if os.getenv('DEBUG') == '1' else None,
            },
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@app.get(
    '/general_enum',
    response_model=GeneralEnumResponse,
    responses={
        status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResponse},
        status.HTTP_400_BAD_REQUEST: {'model': ErrorResponse},
        status.HTTP_429_TOO_MANY_REQUESTS: {'model': ErrorResponse},
    },
)
@limiter.limit(API_RATE_LIMIT)
async def general_enumeration(
    request: Request,
    user_agent: str | None = Header(None),
    shodan_api_key_header: str | None = Header(
        None,
        alias='X-Shodan-Api-Key',
        description='Optional Shodan API key header for Shodan-backed netblock expansion',
    ),
    domain: str = Query(..., description='Domain to enumerate'),
    do_axfr: bool = Query(False, description='Perform zone transfer'),
    do_bing: bool = Query(False, description='Use Bing search'),
    do_yandex: bool = Query(False, description='Use Yandex search'),
    do_spf: bool = Query(False, description='Check SPF records'),
    do_whois: bool = Query(False, description='Perform WHOIS lookup'),
    do_crt: bool = Query(False, description='Check certificate transparency'),
    do_shodan: bool = Query(False, description='Use Shodan to expand SPF/Whois-discovered netblocks'),
    shodan_active: bool = Query(False, description='Actively validate Shodan-discovered hosts using DNS resolution'),
    zw: bool = Query(False, description='Perform zone walking'),
    request_timeout: int = Query(3, description='Request timeout in seconds'),
    thread_num: int = Query(10, description='Number of threads to use'),
    recursion_desired: bool = Query(True, description='Enable recursion desired flag in queries'),
) -> Response:
    """
    Endpoint for general DNS enumeration.

    Performs comprehensive DNS reconnaissance using multiple techniques and sources.
    Rate limit is configurable via CLI argument (default: 5 requests per minute).
    """
    # Basic user agent filtering
    if user_agent and ('gobuster' in user_agent or 'sqlmap' in user_agent or 'rustbuster' in user_agent):
        response = RedirectResponse(app.url_path_for('bot'))
        return response

    try:
        # Validate domain
        if not domain or len(domain) < 3:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Domain must be at least 3 characters long')

        # Create DNS resolver
        res = DnsHelper(domain, recursion_desired=recursion_desired)

        shodan_api_key = shodan_api_key_header or os.getenv('SHODAN_API_KEY')

        # Perform general enumeration
        results = general_enum(
            res=res,
            domain=domain,
            do_axfr=do_axfr,
            do_bing=do_bing,
            do_yandex=do_yandex,
            do_spf=do_spf,
            do_whois=do_whois,
            do_crt=do_crt,
            do_shodan=do_shodan,
            shodan_api_key=shodan_api_key,
            shodan_active=shodan_active,
            zw=zw,
            request_timeout=request_timeout,
            thread_num=thread_num,
        )

        # Process results into a response format
        records = []
        subdomains = []
        ips = []

        if results:
            for result in results:
                if isinstance(result, dict):
                    record_type = result.get('type', 'Unknown')
                    name = result.get('name', '')
                    address = result.get('address', '')

                    records.append(DnsRecord(name=name, type=record_type, address=address))

                    if record_type == 'A' and address:
                        ips.append(address)
                    if name and name != domain:
                        subdomains.append(name)

        return UJSONResponse(
            {
                'domain': domain,
                'records': [record.model_dump() for record in records],
                'subdomains': list(set(subdomains)),
                'ips': list(set(ips)),
            }
        )

    except HTTPException as e:
        raise e
    except Exception as e:
        error_traceback = traceback.format_exc()
        print(f'Error in general_enumeration endpoint: {e!s}\n{error_traceback}')

        return UJSONResponse(
            {
                'detail': f'An error occurred while processing your request: {e!s}',
                'error_type': type(e).__name__,
                'traceback': error_traceback if os.getenv('DEBUG') == '1' else None,
            },
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@app.get(
    '/brute_domain',
    response_model=BruteForceResponse,
    responses={
        status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResponse},
        status.HTTP_400_BAD_REQUEST: {'model': ErrorResponse},
        status.HTTP_429_TOO_MANY_REQUESTS: {'model': ErrorResponse},
    },
)
@limiter.limit(API_RATE_LIMIT)
async def brute_force_domain(
    request: Request,
    user_agent: str = Header(None),
    domain: str = Query(..., description='Domain to brute force'),
    wordlist: str = Query('', description='Path to wordlist file (optional)'),
    filter_wildcards: bool = Query(True, description='Filter wildcard responses'),
    thread_num: int = Query(10, description='Number of threads to use'),
    recursion_desired: bool = Query(True, description='Enable recursion desired flag in queries'),
) -> Response:
    """
    Endpoint for domain brute forcing.

    Performs subdomain brute force attack using a wordlist.
    Rate limit is configurable via CLI argument (default: 5 requests per minute).
    """
    # Basic user agent filtering
    if user_agent and ('gobuster' in user_agent or 'sqlmap' in user_agent or 'rustbuster' in user_agent):
        response = RedirectResponse(app.url_path_for('bot'))
        return response

    try:
        # Validate domain
        if not domain or len(domain) < 3:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Domain must be at least 3 characters long')

        # Create a DNS resolver
        res = DnsHelper(domain, recursion_desired=recursion_desired)

        # Use default wordlist if none provided
        safe_root = os.path.join(os.path.dirname(__file__), 'data')
        if not wordlist:
            wordlist = os.path.join(safe_root, 'subdomains-top1mil-5000.txt')
        else:
            wordlist = os.path.normpath(os.path.join(safe_root, wordlist))
            if not wordlist.startswith(safe_root):
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Invalid wordlist path')

        results = brute_domain(
            res=res,
            dictfile=wordlist,
            dom=domain,
            filter_=None,
            verbose=False,
            ignore_wildcard=not filter_wildcards,
            thread_num=thread_num,
        )

        # Process results
        records = []
        subdomains = []

        if results:
            for result in results:
                if isinstance(result, dict):
                    name = result.get('name', '')
                    record_type = result.get('type', 'A')
                    address = result.get('address', '')

                    records.append(DnsRecord(name=name, type=record_type, address=address))

                    if name:
                        subdomains.append(name)

        return UJSONResponse(
            {'domain': domain, 'subdomains': list(set(subdomains)), 'records': [record.model_dump() for record in records]}
        )

    except HTTPException as e:
        raise e
    except Exception as e:
        error_traceback = traceback.format_exc()
        print(f'Error in brute_force_domain endpoint: {e!s}\n{error_traceback}')

        return UJSONResponse(
            {
                'detail': f'An error occurred while processing your request: {e!s}',
                'error_type': type(e).__name__,
                'traceback': error_traceback if os.getenv('DEBUG') == '1' else None,
            },
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@app.get(
    '/brute_reverse',
    response_model=ReverseResponse,
    responses={
        status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResponse},
        status.HTTP_400_BAD_REQUEST: {'model': ErrorResponse},
        status.HTTP_429_TOO_MANY_REQUESTS: {'model': ErrorResponse},
    },
)
@limiter.limit(API_RATE_LIMIT)
async def brute_force_reverse(
    request: Request,
    user_agent: str = Header(None),
    ip_range: str = Query(..., description='IP range to perform reverse DNS lookup (e.g., 192.168.1.1-192.168.1.254)'),
    thread_num: int = Query(10, description='Number of threads to use'),
    recursion_desired: bool = Query(True, description='Enable recursion desired flag in queries'),
) -> Response:
    """
    Endpoint for reverse DNS brute forcing.

    Performs reverse DNS lookups on a range of IP addresses.
    Rate limit is configurable via CLI argument (default: 5 requests per minute).
    """
    # Basic user agent filtering
    if user_agent and ('gobuster' in user_agent or 'sqlmap' in user_agent or 'rustbuster' in user_agent):
        response = RedirectResponse(app.url_path_for('bot'))
        return response

    try:
        # Validate IP range
        if not ip_range:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='IP range is required')

        # Parse IP range
        if '-' in ip_range:
            start_ip, end_ip = ip_range.split('-', 1)
            ip_list = [
                f'{start_ip.rsplit(".", 1)[0]}.{i}' for i in range(int(start_ip.split('.')[-1]), int(end_ip.split('.')[-1]) + 1)
            ]
        else:
            ip_list = [ip_range]

        res = DnsHelper('example.com', recursion_desired=recursion_desired)  # Domain not used for reverse lookups

        # Perform reverse brute force
        results = brute_reverse(res=res, ip_list=ip_list, verbose=False, thread_num=thread_num)

        # Process results
        records = []

        if results:
            for result in results:
                if isinstance(result, dict):
                    name = result.get('name', '')
                    address = result.get('address', '')

                    records.append(DnsRecord(name=name, type='PTR', address=address))

        return UJSONResponse({'ip_range': ip_range, 'records': [record.model_dump() for record in records]})

    except HTTPException as e:
        raise e
    except Exception as e:
        error_traceback = traceback.format_exc()
        print(f'Error in brute_force_reverse endpoint: {e!s}\n{error_traceback}')

        return UJSONResponse(
            {
                'detail': f'An error occurred while processing your request: {e!s}',
                'error_type': type(e).__name__,
                'traceback': error_traceback if os.getenv('DEBUG') == '1' else None,
            },
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@app.get(
    '/wildcard_check',
    response_model=WildcardResponse,
    responses={
        status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResponse},
        status.HTTP_400_BAD_REQUEST: {'model': ErrorResponse},
        status.HTTP_429_TOO_MANY_REQUESTS: {'model': ErrorResponse},
    },
)
@limiter.limit(API_RATE_LIMIT)
async def wildcard_check(
    request: Request,
    user_agent: str = Header(None),
    domain: str = Query(..., description='Domain to check for wildcard DNS'),
) -> Response:
    """
    Endpoint for wildcard DNS detection.

    Checks if the domain has wildcard DNS configured.
    Rate limit is configurable via CLI argument (default: 5 requests per minute).
    """
    # Basic user agent filtering
    if user_agent and ('gobuster' in user_agent or 'sqlmap' in user_agent or 'rustbuster' in user_agent):
        response = RedirectResponse(app.url_path_for('bot'))
        return response

    try:
        # Validate domain
        if not domain or len(domain) < 3:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Domain must be at least 3 characters long')

        res = DnsHelper(domain)

        wildcard_ips = check_wildcard(res, domain)

        wildcard_enabled = bool(wildcard_ips)
        if not wildcard_ips:
            wildcard_ips = []

        return UJSONResponse({'domain': domain, 'wildcard_enabled': wildcard_enabled, 'wildcard_ips': wildcard_ips})

    except HTTPException as e:
        raise e
    except Exception as e:
        error_traceback = traceback.format_exc()
        print(f'Error in wildcard_check endpoint: {e!s}\n{error_traceback}')

        return UJSONResponse(
            {
                'detail': f'An error occurred while processing your request: {e!s}',
                'error_type': type(e).__name__,
                'traceback': error_traceback if os.getenv('DEBUG') == '1' else None,
            },
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


class SrvResponse(BaseModel):
    domain: str = Field(..., description='Target domain')
    srv_records: list[DnsRecord] = Field(default_factory=list, description='List of SRV records found')


@app.get(
    '/brute_srv',
    response_model=SrvResponse,
    responses={
        status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResponse},
        status.HTTP_400_BAD_REQUEST: {'model': ErrorResponse},
        status.HTTP_429_TOO_MANY_REQUESTS: {'model': ErrorResponse},
    },
)
@limiter.limit(API_RATE_LIMIT)
async def brute_force_srv(
    request: Request,
    user_agent: str = Header(None),
    domain: str = Query(..., description='Domain to enumerate SRV records for'),
    thread_num: int = Query(10, description='Number of threads to use'),
    recursion_desired: bool = Query(True, description='Enable recursion desired flag in queries'),
) -> Response:
    """
    Endpoint for SRV record enumeration.

    Performs SRV record brute forcing to discover services.
    Rate limit is configurable via CLI argument (default: 5 requests per minute).
    """
    # Basic user agent filtering
    if user_agent and ('gobuster' in user_agent or 'sqlmap' in user_agent or 'rustbuster' in user_agent):
        response = RedirectResponse(app.url_path_for('bot'))
        return response

    try:
        # Validate domain
        if not domain or len(domain) < 3:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Domain must be at least 3 characters long')

        res = DnsHelper(domain, recursion_desired=recursion_desired)

        # Perform SRV enumeration
        results = brute_srv(res=res, domain=domain, verbose=False, thread_num=thread_num)

        srv_records = []

        if results:
            for result in results:
                if isinstance(result, dict):
                    name = result.get('name', '')
                    record_type = result.get('type', 'SRV')
                    address = result.get('address', '')
                    target = result.get('target', '')
                    port = result.get('port', None)

                    srv_records.append(DnsRecord(name=name, type=record_type, address=address, target=target, port=port))

        return UJSONResponse({'domain': domain, 'srv_records': [record.model_dump() for record in srv_records]})

    except HTTPException as e:
        raise e
    except Exception as e:
        error_traceback = traceback.format_exc()
        print(f'Error in brute_force_srv endpoint: {e!s}\n{error_traceback}')

        return UJSONResponse(
            {
                'detail': f'An error occurred while processing your request: {e!s}',
                'error_type': type(e).__name__,
                'traceback': error_traceback if os.getenv('DEBUG') == '1' else None,
            },
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


class TldResponse(BaseModel):
    domain: str = Field(..., description='Base domain')
    tld_records: list[DnsRecord] = Field(default_factory=list, description='List of TLD enumeration results')


@app.get(
    '/brute_tlds',
    response_model=TldResponse,
    responses={
        status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResponse},
        status.HTTP_400_BAD_REQUEST: {'model': ErrorResponse},
        status.HTTP_429_TOO_MANY_REQUESTS: {'model': ErrorResponse},
    },
)
@limiter.limit(API_RATE_LIMIT)
async def brute_force_tlds(
    request: Request,
    user_agent: str = Header(None),
    domain: str = Query(..., description='Base domain to test against different TLDs'),
    thread_num: int = Query(10, description='Number of threads to use'),
    recursion_desired: bool = Query(True, description='Enable recursion desired flag in queries'),
) -> Response:
    """
    Endpoint for TLD enumeration.

    Tests the base domain against all registered TLDs to find variations.
    Rate limit is configurable via CLI argument (default: 5 requests per minute).
    """
    # Basic user agent filtering
    if user_agent and ('gobuster' in user_agent or 'sqlmap' in user_agent or 'rustbuster' in user_agent):
        response = RedirectResponse(app.url_path_for('bot'))
        return response

    try:
        # Validate domain
        if not domain or len(domain) < 3:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Domain must be at least 3 characters long')

        res = DnsHelper(domain, recursion_desired=recursion_desired)

        # Perform TLD enumeration
        results = brute_tlds(res=res, domain=domain, verbose=False, thread_num=thread_num)

        tld_records = []

        if results:
            for result in results:
                if isinstance(result, dict):
                    name = result.get('name', '')
                    record_type = result.get('type', 'A')
                    address = result.get('address', '')

                    tld_records.append(DnsRecord(name=name, type=record_type, address=address))

        return UJSONResponse({'domain': domain, 'tld_records': [record.model_dump() for record in tld_records]})

    except HTTPException as e:
        raise e
    except Exception as e:
        error_traceback = traceback.format_exc()
        print(f'Error in brute_force_tlds endpoint: {e!s}\n{error_traceback}')

        return UJSONResponse(
            {
                'detail': f'An error occurred while processing your request: {e!s}',
                'error_type': type(e).__name__,
                'traceback': error_traceback if os.getenv('DEBUG') == '1' else None,
            },
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


class AxfrResponse(BaseModel):
    domain: str = Field(..., description='Target domain')
    zone_transfer_successful: bool = Field(..., description='Whether zone transfer was successful')
    records: list[DnsRecord] = Field(default_factory=list, description='List of records from zone transfer')


@app.get(
    '/axfr_test',
    response_model=AxfrResponse,
    responses={
        status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResponse},
        status.HTTP_400_BAD_REQUEST: {'model': ErrorResponse},
        status.HTTP_429_TOO_MANY_REQUESTS: {'model': ErrorResponse},
    },
)
@limiter.limit(API_RATE_LIMIT)
async def axfr_test(
    request: Request,
    user_agent: str = Header(None),
    domain: str = Query(..., description='Domain to test for zone transfer'),
) -> Response:
    """
    Endpoint for zone transfer testing.

    Tests if zone transfer (AXFR) is possible for the domain.
    Rate limit is configurable via CLI argument (default: 5 requests per minute).
    """
    # Basic user agent filtering
    if user_agent and ('gobuster' in user_agent or 'sqlmap' in user_agent or 'rustbuster' in user_agent):
        response = RedirectResponse(app.url_path_for('bot'))
        return response

    try:
        # Validate domain
        if not domain or len(domain) < 3:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Domain must be at least 3 characters long')

        # Create DNS resolver
        res = DnsHelper(domain)

        # Perform zone transfer test
        results = res.zone_transfer()

        # Process results
        records = []
        zone_transfer_successful = bool(results)

        if results:
            for result in results:
                if isinstance(result, dict):
                    name = result.get('name', '')
                    record_type = result.get('type', 'Unknown')
                    address = result.get('address', '')
                    target = result.get('target', '')

                    records.append(DnsRecord(name=name, type=record_type, address=address, target=target))

        return UJSONResponse(
            {
                'domain': domain,
                'zone_transfer_successful': zone_transfer_successful,
                'records': [record.model_dump() for record in records],
            }
        )

    except HTTPException as e:
        raise e
    except Exception as e:
        error_traceback = traceback.format_exc()
        print(f'Error in axfr_test endpoint: {e!s}\n{error_traceback}')

        return UJSONResponse(
            {
                'detail': f'An error occurred while processing your request: {e!s}',
                'error_type': type(e).__name__,
                'traceback': error_traceback if os.getenv('DEBUG') == '1' else None,
            },
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


class CaaResponse(BaseModel):
    domain: str = Field(..., description='Target domain')
    caa_records: list[DnsRecord] = Field(default_factory=list, description='List of CAA records found')


@app.get(
    '/caa_records',
    response_model=CaaResponse,
    responses={
        status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResponse},
        status.HTTP_400_BAD_REQUEST: {'model': ErrorResponse},
        status.HTTP_429_TOO_MANY_REQUESTS: {'model': ErrorResponse},
    },
)
@limiter.limit(API_RATE_LIMIT)
async def caa_records(
    request: Request,
    user_agent: str = Header(None),
    domain: str = Query(..., description='Domain to query for CAA records'),
) -> Response:
    """
    Endpoint for CAA record enumeration.

    Retrieves Certificate Authority Authorization (CAA) records for the domain.
    Rate limit is configurable via CLI argument (default: 5 requests per minute).
    """
    # Basic user agent filtering
    if user_agent and ('gobuster' in user_agent or 'sqlmap' in user_agent or 'rustbuster' in user_agent):
        response = RedirectResponse(app.url_path_for('bot'))
        return response

    try:
        # Validate domain
        if not domain or len(domain) < 3:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Domain must be at least 3 characters long')

        res = DnsHelper(domain)

        results = res.get_caa()

        caa_records_list = []

        if results:
            for result in results:
                if isinstance(result, (list, tuple)) and len(result) >= 3:
                    record_type, name, value = result[:3]

                    caa_records_list.append(DnsRecord(name=name, type=record_type, address=value))

        return UJSONResponse({'domain': domain, 'caa_records': [record.model_dump() for record in caa_records_list]})

    except HTTPException as e:
        raise e
    except Exception as e:
        error_traceback = traceback.format_exc()
        print(f'Error in caa_records endpoint: {e!s}\n{error_traceback}')

        return UJSONResponse(
            {
                'detail': f'An error occurred while processing your request: {e!s}',
                'error_type': type(e).__name__,
                'traceback': error_traceback if os.getenv('DEBUG') == '1' else None,
            },
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


class CacheSnoopResponse(BaseModel):
    nameserver: str = Field(..., description='Name server tested')
    cached_records: list[DnsRecord] = Field(default_factory=list, description='List of cached records found')


@app.get(
    '/cache_snoop',
    response_model=CacheSnoopResponse,
    responses={
        status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResponse},
        status.HTTP_400_BAD_REQUEST: {'model': ErrorResponse},
        status.HTTP_429_TOO_MANY_REQUESTS: {'model': ErrorResponse},
    },
)
@limiter.limit(API_RATE_LIMIT)
async def cache_snoop(
    request: Request,
    user_agent: str = Header(None),
    nameserver: str = Query(..., description='Name server to test for cache snooping'),
    wordlist: str = Query('', description='Path to wordlist file for cache snooping'),
) -> Response:
    """
    Endpoint for DNS cache snooping.

    Tests if the name server has cached records for domains in the wordlist.
    Rate limit is configurable via CLI argument (default: 5 requests per minute).
    """
    # Basic user agent filtering
    if user_agent and ('gobuster' in user_agent or 'sqlmap' in user_agent or 'rustbuster' in user_agent):
        response = RedirectResponse(app.url_path_for('bot'))
        return response

    try:
        # Validate nameserver
        if not nameserver:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Name server is required')

        # Use default wordlist if none provided
        if not wordlist:
            wordlist = os.path.join(os.path.dirname(__file__), 'data', 'namelist.txt')
        else:
            # Only allow wordlists within the data directory
            data_dir = os.path.join(os.path.dirname(__file__), 'data')
            requested_path = os.path.normpath(os.path.join(data_dir, wordlist))
            if not requested_path.startswith(data_dir):
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Invalid wordlist path')
            wordlist = requested_path

        if not os.path.exists(wordlist):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Wordlist file not found')

        res = DnsHelper('example.com')  # Domain not critical for cache snooping

        # Perform cache snooping
        results = in_cache(res=res, dict_file=wordlist, ns=nameserver)

        cached_records = []

        if results:
            for result in results:
                if isinstance(result, dict):
                    name = result.get('name', '')
                    record_type = result.get('type', 'A')
                    address = result.get('address', '')

                    cached_records.append(DnsRecord(name=name, type=record_type, address=address))

        return UJSONResponse({'nameserver': nameserver, 'cached_records': [record.model_dump() for record in cached_records]})

    except HTTPException as e:
        raise e
    except Exception as e:
        error_traceback = traceback.format_exc()
        print(f'Error in cache_snoop endpoint: {e!s}\n{error_traceback}')

        return UJSONResponse(
            {
                'detail': f'An error occurred while processing your request: {e!s}',
                'error_type': type(e).__name__,
                'traceback': error_traceback if os.getenv('DEBUG') == '1' else None,
            },
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


class ZoneWalkResponse(BaseModel):
    domain: str = Field(..., description='Target domain')
    zone_walk_records: list[DnsRecord] = Field(default_factory=list, description='List of records found via DNSSEC zone walking')


@app.get(
    '/zone_walk',
    response_model=ZoneWalkResponse,
    responses={
        status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResponse},
        status.HTTP_400_BAD_REQUEST: {'model': ErrorResponse},
        status.HTTP_429_TOO_MANY_REQUESTS: {'model': ErrorResponse},
    },
)
@limiter.limit(API_RATE_LIMIT)
async def zone_walk(
    request: Request,
    user_agent: str = Header(None),
    domain: str = Query(..., description='Domain to perform DNSSEC zone walking on'),
    timeout: float = Query(3.0, description='Request timeout in seconds'),
) -> Response:
    """
    Endpoint for DNSSEC zone walking.

    Performs DNSSEC zone walking using NSEC records to enumerate domain records.
    Rate limit is configurable via CLI argument (default: 5 requests per minute).
    """
    # Basic user agent filtering
    if user_agent and ('gobuster' in user_agent or 'sqlmap' in user_agent or 'rustbuster' in user_agent):
        response = RedirectResponse(app.url_path_for('bot'))
        return response

    try:
        # Validate domain
        if not domain or len(domain) < 3:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Domain must be at least 3 characters long')

        res = DnsHelper(domain)

        # Perform DNSSEC zone walking
        results = ds_zone_walk(res=res, domain=domain, request_timeout=timeout)

        zone_walk_records = []

        if results:
            for result in results:
                if isinstance(result, dict):
                    name = result.get('name', '')
                    record_type = result.get('type', 'Unknown')
                    address = result.get('address', '')
                    target = result.get('target', '')

                    zone_walk_records.append(DnsRecord(name=name, type=record_type, address=address, target=target))

        return UJSONResponse({'domain': domain, 'zone_walk_records': [record.model_dump() for record in zone_walk_records]})

    except HTTPException as e:
        raise e
    except Exception as e:
        error_traceback = traceback.format_exc()
        print(f'Error in zone_walk endpoint: {e!s}\n{error_traceback}')

        return UJSONResponse(
            {
                'detail': f'An error occurred while processing your request: {e!s}',
                'error_type': type(e).__name__,
                'traceback': error_traceback if os.getenv('DEBUG') == '1' else None,
            },
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


class BindVersionResponse(BaseModel):
    nameserver: str = Field(..., description='Name server tested')
    bind_version: str = Field(..., description='BIND version detected (if any)')
    version_detected: bool = Field(..., description='Whether BIND version was successfully detected')


@app.get(
    '/bind_version',
    response_model=BindVersionResponse,
    responses={
        status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResponse},
        status.HTTP_400_BAD_REQUEST: {'model': ErrorResponse},
        status.HTTP_429_TOO_MANY_REQUESTS: {'model': ErrorResponse},
    },
)
@limiter.limit(API_RATE_LIMIT)
async def bind_version(
    request: Request,
    user_agent: str = Header(None),
    nameserver: str = Query(..., description='Name server to check for BIND version'),
    timeout: float = Query(3.0, description='Request timeout in seconds'),
) -> Response:
    """
    Endpoint for BIND version detection.

    Attempts to detect the BIND version of the specified name server.
    Rate limit is configurable via CLI argument (default: 5 requests per minute).
    """
    # Basic user agent filtering
    if user_agent and ('gobuster' in user_agent or 'sqlmap' in user_agent or 'rustbuster' in user_agent):
        response = RedirectResponse(app.url_path_for('bot'))
        return response

    try:
        # Validate nameserver
        if not nameserver:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Name server is required')

        res = DnsHelper('example.com')

        # Check BIND version
        version_info = check_bindversion(res=res, ns_server=nameserver, timeout=timeout)

        version_detected = bool(version_info)
        bind_version = version_info if version_info else 'Version not detected'

        return UJSONResponse({'nameserver': nameserver, 'bind_version': bind_version, 'version_detected': version_detected})

    except HTTPException as e:
        raise e
    except Exception as e:
        error_traceback = traceback.format_exc()
        print(f'Error in bind_version endpoint: {e!s}\n{error_traceback}')

        return UJSONResponse(
            {
                'detail': f'An error occurred while processing your request: {e!s}',
                'error_type': type(e).__name__,
                'traceback': error_traceback if os.getenv('DEBUG') == '1' else None,
            },
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


class RecursiveResponse(BaseModel):
    nameserver: str = Field(..., description='Name server tested')
    recursive_enabled: bool = Field(..., description='Whether recursion is enabled')
    test_result: str = Field(..., description='Result of the recursion test')


@app.get(
    '/recursive_check',
    response_model=RecursiveResponse,
    responses={
        status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResponse},
        status.HTTP_400_BAD_REQUEST: {'model': ErrorResponse},
        status.HTTP_429_TOO_MANY_REQUESTS: {'model': ErrorResponse},
    },
)
@limiter.limit(API_RATE_LIMIT)
async def recursive_check(
    request: Request,
    user_agent: str = Header(None),
    nameserver: str = Query(..., description='Name server to check for recursion'),
    timeout: float = Query(3.0, description='Request timeout in seconds'),
) -> Response:
    """
    Endpoint for DNS recursion check.

    Tests if the specified name server allows recursive queries.
    Rate limit is configurable via CLI argument (default: 5 requests per minute).
    """
    # Basic user agent filtering
    if user_agent and ('gobuster' in user_agent or 'sqlmap' in user_agent or 'rustbuster' in user_agent):
        response = RedirectResponse(app.url_path_for('bot'))
        return response

    try:
        # Validate nameserver
        if not nameserver:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Name server is required')

        res = DnsHelper('example.com')

        # Check recursion
        recursion_result = check_recursive(res=res, ns_server=nameserver, timeout=timeout)

        recursive_enabled = bool(recursion_result)
        test_result = recursion_result if recursion_result else 'Recursion not enabled or test failed'

        return UJSONResponse({'nameserver': nameserver, 'recursive_enabled': recursive_enabled, 'test_result': test_result})

    except HTTPException as e:
        raise e
    except Exception as e:
        error_traceback = traceback.format_exc()
        print(f'Error in recursive_check endpoint: {e!s}\n{error_traceback}')

        return UJSONResponse(
            {
                'detail': f'An error occurred while processing your request: {e!s}',
                'error_type': type(e).__name__,
                'traceback': error_traceback if os.getenv('DEBUG') == '1' else None,
            },
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


class NxdomainHijackResponse(BaseModel):
    nameserver: str = Field(..., description='Name server tested')
    hijack_detected: bool = Field(..., description='Whether NXDOMAIN hijacking was detected')
    hijack_details: str = Field(..., description='Details about the hijacking test')


@app.get(
    '/nxdomain_hijack',
    response_model=NxdomainHijackResponse,
    responses={
        status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResponse},
        status.HTTP_400_BAD_REQUEST: {'model': ErrorResponse},
        status.HTTP_429_TOO_MANY_REQUESTS: {'model': ErrorResponse},
    },
)
@limiter.limit(API_RATE_LIMIT)
async def nxdomain_hijack(
    request: Request,
    user_agent: str = Header(None),
    nameserver: str = Query(..., description='Name server to check for NXDOMAIN hijacking'),
) -> Response:
    """
    Endpoint for NXDOMAIN hijacking detection.

    Tests if the specified name server hijacks NXDOMAIN responses.
    Rate limit is configurable via CLI argument (default: 5 requests per minute).
    """
    # Basic user agent filtering
    if user_agent and ('gobuster' in user_agent or 'sqlmap' in user_agent or 'rustbuster' in user_agent):
        response = RedirectResponse(app.url_path_for('bot'))
        return response

    try:
        # Validate nameserver
        if not nameserver:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Name server is required')

        hijack_result = check_nxdomain_hijack(nameserver=nameserver)

        hijack_detected = bool(hijack_result)
        hijack_details = hijack_result if hijack_result else 'No NXDOMAIN hijacking detected'

        return UJSONResponse({'nameserver': nameserver, 'hijack_detected': hijack_detected, 'hijack_details': hijack_details})

    except HTTPException as e:
        raise e
    except Exception as e:
        error_traceback = traceback.format_exc()
        print(f'Error in nxdomain_hijack endpoint: {e!s}\n{error_traceback}')

        return UJSONResponse(
            {
                'detail': f'An error occurred while processing your request: {e!s}',
                'error_type': type(e).__name__,
                'traceback': error_traceback if os.getenv('DEBUG') == '1' else None,
            },
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
