#!/usr/bin/env python3

#    Copyright (C) 2020 Cristiano Maruti (twitter: @cmaruti)
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
import urllib
import urllib.request

from loguru import logger

__name__ = 'yandexenum'
url_opener = urllib.request.FancyURLopener


class AppURLopener(url_opener):
    version = """Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
                     (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246"""


def scrape_yandex(dom):
    """
    Function for enumerating sub-domains and hosts by scraping Yandex.
    """
    results = []
    searches = ['1', '2', '3', '4', '5', '10', '20', '30']
    urllib._urlopener = AppURLopener()

    for _ in searches:
        url = 'https://yandex.com/search/?text=site%3A' + dom
        try:
            sock = urllib.request.urlopen(url, timeout=10)
            data = sock.read().decode('utf-8')
            sock.close()
        except Exception as e:
            logger.error(e)
            return []

        if re.search('enter_captcha_value', data):
            logger.error("Yandex has detected the search as 'bot activity, stopping search...")
            return unique(results)

        results.extend(re.findall(r'([a-zA-Z0-9\-\.]+' + dom + ')/?', data))

        time.sleep(10)

    return unique(results)


def unique(seq, idfun=repr):
    """
    Function to remove duplicates in an array. Returns array with duplicates
    removed.
    """
    seen = {}
    return [seen.setdefault(idfun(e), e) for e in seq if idfun(e) not in seen]
