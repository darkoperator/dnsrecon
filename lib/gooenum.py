#!/usr/bin/env python
# -*- coding: utf-8 -*-

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


import urllib
import re
import time

try:
    url_opener = urllib.FancyURLopener
except AttributeError:
    import urllib.request
    url_opener = urllib.request.FancyURLopener


class AppURLopener(url_opener):

    version = 'Mozilla/5.0 (compatible; Googlebot/2.1; + http://www.google.com/bot.html)'


def scrape_google(dom):
    """
    Function for enumerating sub-domains and hosts by scrapping Google. It returns a unique
    list if host name extracted from the HREF entries from the Google search.
    """
    results = []
    filtered = []
    searches = ["100", "200", "300", "400", "500"]
    data = ""
    urllib._urlopener = AppURLopener()
    user_agent = 'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.0.7) Gecko/2009021910 Firefox/3.0.7'
    headers = {'User-Agent': user_agent, }
    #opener.addheaders = [('User-Agent','Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)')]
    for n in searches:
        url = "http://google.com/search?hl=en&lr=&ie=UTF-8&q=%2B" + dom + "&start=" + n + "&sa=N&filter=0&num=100"
        try:
            sock = urllib.urlopen(url)
            data += sock.read()
            sock.close()
        except AttributeError:
            request = urllib.request.Request(url, None, headers)
            response = urllib.request.urlopen(request)
            data += str(response.read())
    results.extend(unique(re.findall("href=\"htt\w{1,2}:\/\/([^:?]*[a-b0-9]*[^:?]*\." + dom + ")\/", data)))
    # Make sure we are only getting the host
    for f in results:
        filtered.extend(re.findall("^([a-z.0-9^]*" + dom + ")", f))
    time.sleep(2)
    return unique(filtered)


def unique(seq, idfun=repr):
    """
    Function to remove duplicates in an array. Returns array with duplicates
    removed.
    """
    seen = {}
    return [seen.setdefault(idfun(e), e) for e in seq if idfun(e) not in seen]
