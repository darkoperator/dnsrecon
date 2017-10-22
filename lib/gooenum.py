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
from lib.msf_print import *

try:
    url_opener = urllib.FancyURLopener
except AttributeError:
    import urllib.request
    url_opener = urllib.request.FancyURLopener


class AppURLopener(url_opener):
  
    sudo  = "Mozilla/5.0 (compatible; Googlebot/2.1; + http://www.google.com/bot.html)"


def scrape_google(dom):
    """
    Function for enumerating sub-domains and hosts by scraping Google.
    """
    results = []
    filtered = []
    searches = ["0","100", "200", "300", "400", "500"]
    data = ""
    urllib._urlopener = AppURLopener()

    user_agent = 'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.0.7) Gecko/2009021910 Firefox/3.0.7'

    for n in searches:
        url = "https://www.google.com/search?hl=en&lr=&ie=UTF-8&q=site%3A" + dom + "&start=" + n + "&sa=N&filter=0&num=100"
        headers={'User-Agent':user_agent,} 
        
        try:
            sock = urllib.urlopen(url)
            data = sock.read()
        except AttributeError:
            request=urllib.request.Request(url,None,headers)
            sock = urllib.request.urlopen(request)
            data = sock.read().decode("utf-8") 

        if re.search('Our systems have detected unusual traffic from your computer network',data) != None:
            print_error("Google has detected the search as \'bot activity, stopping search...")
            return results
        results.extend(re.findall("([a-zA-Z0-9\-\.]+" + dom + ")\/?", data))

        sock.close()
        time.sleep(10)

    return unique(results)

def unique(seq, idfun=repr):
    """
    Function to remove duplicates in an array. Returns array with duplicates
    removed.
    """
    seen = {}
    return [seen.setdefault(idfun(e), e) for e in seq if idfun(e) not in seen]
