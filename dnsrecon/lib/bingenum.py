#    Copyright (C) 2017 Cristiano Maruti (twitter: @cmaruti)
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

import re
import time
import urllib.request

__name__ = 'bingenum'

url_opener = urllib.request.FancyURLopener


class AppURLopener(url_opener):
    version = 'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)'


def scrape_bing(dom):
    """
    Function for enumerating subdomains and hosts by scraping Bing.
    """
    results = []
    searches = [
        '10',
        '20',
        '30',
        '40',
        '50',
        '60',
        '70',
        '80',
        '90',
        '100',
        '110',
        '120',
        '130',
        '140',
        '150',
    ]
    urllib._urlopener = AppURLopener()

    for n in searches:
        url = 'https://www.bing.com/search?q=domain%3A' + dom + '&qs=n&first=' + n
        req = urllib.request.Request(
            url,
            data=None,
            headers={
                'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.47 Safari/537.36'
            },
        )

        sock = urllib.request.urlopen(req, timeout=10)
        data = sock.read().decode('utf-8')
        results.extend(re.findall(r'([a-zA-Z0-9\-.]+' + dom + ')/?', data))
        sock.close()
        time.sleep(5)

    return unique(results)


def unique(seq, idfun=repr):
    """
    Function to remove duplicates in an array. Returns array with duplicates
    removed.
    """
    seen = {}
    return [seen.setdefault(idfun(e), e) for e in seq if idfun(e) not in seen]
