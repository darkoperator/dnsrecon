
import urllib
import re
import time

class AppURLopener(urllib.FancyURLopener):

    version = 'Mozilla/5.0 (compatible; Googlebot/2.1; + http://www.google.com/bot.html)'

def scrape_google(dom):
    """
    Function for enumerating sub-domains and hosts by scrapping Google. It returns a unique
    list if host name extracted from the HREF entries from the Google search.
    """
    results = []
    filtered = []
    searches = ["100", "200","300","400","500"]
    data = ""
    urllib._urlopener = AppURLopener()
    #opener.addheaders = [('User-Agent','Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)')]
    for n in searches:
        url = "http://google.com/search?hl=en&lr=&ie=UTF-8&q=%2B"+dom+"&start="+n+"&sa=N&filter=0&num=100"
        sock = urllib.urlopen(url)
        data += sock.read()
        sock.close()
    results.extend(unique(re.findall("href=\"htt\w{1,2}:\/\/([^:?]*[a-b0-9]*[^:?]*\."+dom+")\/", data)))
    # Make sure we are only getting the host
    for f in results:
        filtered.extend(re.findall("^([a-z.0-9^]*"+dom+")", f))
    time.sleep(2)
    return unique(filtered)

def unique(seq, idfun=repr):
    """
    Function to remove duplicates in an array. Returns array with duplicates
    removed.
    """
    seen = {}
    return [seen.setdefault(idfun(e),e) for e in seq if idfun(e) not in seen]
