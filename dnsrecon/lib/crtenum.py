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


from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from loguru import logger
from lxml import etree

__name__ = 'crtenum'


def scrape_crtsh(dom):
    """
    Function for enumerating subdomains by scraping crt.sh.
    """
    results = []
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.3'
    }
    url = f'https://crt.sh/?q=%25.{dom}'

    req = Request(url=url, headers=headers)
    try:
        resp = urlopen(req, timeout=30)
        data = resp.read()
    except HTTPError as e:
        logger.error(f'Bad http status from crt.sh: "{e.code}"')
        return results
    except URLError as e:
        logger.error(f'Connection with crt.sh failed. Reason: "{e.reason}"')
        return results

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
