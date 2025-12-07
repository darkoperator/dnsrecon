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

import httpx
from loguru import logger

__name__ = 'yandexenum'


def scrape_yandex(dom):
    """
    Function for enumerating sub-domains and hosts by scraping Yandex.
    """
    results = []
    searches = ['1', '2', '3', '4', '5', '10', '20', '30']

    headers = {
        'User-Agent': (
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
            'AppleWebKit/537.36 (KHTML, like Gecko) '
            'Chrome/42.0.2311.135 Safari/537.36 Edge/12.246'
        )
    }

    with httpx.Client(headers=headers) as client:
        for _ in searches:
            url = 'https://yandex.com/search/?text=site%3A' + dom
            try:
                response = client.get(url, timeout=10.0)
                data = response.text
            except Exception as e:
                logger.error(e)
                return []

            if re.search('enter_captcha_value', data):
                logger.error("Yandex has detected the search as 'bot activity, stopping search...")
                return unique(results)

            safe_dom = re.escape(dom)
            results.extend(re.findall(r'([a-zA-Z0-9\-\.]+' + safe_dom + ')/?', data))

            time.sleep(10)

    return unique(results)


def unique(seq, idfun=repr):
    """
    Function to remove duplicates in an array. Returns array with duplicates
    removed.
    """
    seen = {}
    return [seen.setdefault(idfun(e), e) for e in seq if idfun(e) not in seen]
