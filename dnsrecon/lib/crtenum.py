#    Copyright (C) 2010  Carlos Perez
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; Applies version 2 of the License.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program; if not, write to the Free Software
#    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA


import random

import httpx
import stamina
from loguru import logger
from lxml import etree

__name__ = 'crtenum'

RETRY_ATTEMPTS = 20
WAIT_MAX = 60

COMMON_USER_AGENTS = (
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0',
)


def is_transient_error(e: Exception) -> bool:
    if isinstance(e, httpx.TimeoutException):
        logger.error(f'Connection with crt.sh failed. Reason: "{e}"')
        return True
    if isinstance(e, httpx.HTTPStatusError) and e.response.status_code in {429, 500, 502, 503, 504}:
        logger.error(f'Bad http status from crt.sh: "{e.response.status_code}"')
        return True
    logger.error(f'Something went wrong. Reason: "{e}"')
    return False


@stamina.retry(on=is_transient_error, attempts=RETRY_ATTEMPTS, wait_max=WAIT_MAX)
def scrape_crtsh(dom):
    """
    Function for enumerating subdomains by scraping crt.sh.
    """
    results = []
    headers = {'User-Agent': random.choice(COMMON_USER_AGENTS)}
    url = f'https://crt.sh/?q=%25.{dom}'

    resp = httpx.get(url, headers=headers, timeout=30)
    resp.raise_for_status()
    data = resp.text

    root = etree.HTML(data)
    tbl = root.xpath('//table/tr/td/table/tr/td[5]')
    if len(tbl) < 1:
        logger.error('Certificates for subdomains not found')
        return results

    for ent in tbl:
        sub_dom = ent.text
        if not sub_dom.endswith('.' + dom):
            continue
        if sub_dom.startswith('*.'):
            logger.info(f'\t {sub_dom} wildcard')
            continue
        if sub_dom not in results:
            results.append(sub_dom)

    return results
