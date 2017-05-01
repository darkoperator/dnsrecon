#!/usr/bin/env python
# -*- coding: utf-8 -*-

#    DNSRecon
#
#    Copyright (C) 2015  Carlos Perez
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

__version__ = '0.8.10'
__author__ = 'Carlos Perez, Carlos_Perez@darkoperator.com'

__doc__ = """
DNSRecon http://www.darkoperator.com

 by Carlos Perez, Darkoperator

requires dnspython http://www.dnspython.org/
requires netaddr https://github.com/drkjam/netaddr/

"""
import argparse
import os
import string
import sqlite3
import datetime

import netaddr


# Manage the change in Python3 of the name of the Queue Library
try:
    from Queue import Queue
except ImportError:
    from queue import Queue

from random import Random
from threading import Lock, Thread
from xml.dom import minidom
from xml.etree import ElementTree
from xml.etree.ElementTree import Element

import dns.message
import dns.query
import dns.rdatatype
import dns.resolver
import dns.reversename
import dns.zone
import dns.message
import dns.rdata
import dns.rdatatype
import dns.flags
import json
from dns.dnssec import algorithm_to_text

from lib.gooenum import *
from lib.whois import *
from lib.dnshelper import DnsHelper
from lib.msf_print import *

# Global Variables for Brute force Threads
brtdata = []


# Function Definitions
# -------------------------------------------------------------------------------

# Worker & Threadpool classes ripped from
# http://code.activestate.com/recipes/577187-python-thread-pool/

class Worker(Thread):
    """Thread executing tasks from a given tasks queue"""

    lck = Lock()

    def __init__(self, tasks):
        Thread.__init__(self)
        self.tasks = tasks
        self.daemon = True
        self.start()
        # Global variable that will hold the results
        global brtdata

    def run(self):

        found_record = []
        while True:
            (func, args, kargs) = self.tasks.get()
            try:
                found_record = func(*args, **kargs)
                if found_record:
                    Worker.lck.acquire()
                    brtdata.append(found_record)
                    for r in found_record:
                        if type(r).__name__ == "dict":
                            for k, v in r.iteritems():
                                print_status("\t{0}:{1}".format(k, v))
                            print_status()
                        else:
                            print_status("\t {0}".format(" ".join(r)))
                    Worker.lck.release()

            except Exception as e:
                print_debug(e)
            self.tasks.task_done()


class ThreadPool:
    """Pool of threads consuming tasks from a queue"""

    def __init__(self, num_threads):
        self.tasks = Queue(num_threads)
        for _ in range(num_threads):
            Worker(self.tasks)

    def add_task(self,
                 func,
                 *args,
                 **kargs):
        """Add a task to the queue"""

        self.tasks.put((func, args, kargs))

    def wait_completion(self):
        """Wait for completion of all the tasks in the queue"""

        self.tasks.join()

    def count(self):
        """Return number of tasks in the queue"""

        return self.tasks.qsize()


def exit_brute(pool):
    print_error("You have pressed Ctrl-C. Saving found records.")
    print_status("Waiting for {0} remaining threads to finish.".format(pool.count()))
    pool.wait_completion()


def process_range(arg):
    """
    Function will take a string representation of a range for IPv4 or IPv6 in
    CIDR or Range format and return a list of IPs.
    """
    try:
        ip_list = None
        range_vals = []
        if re.match(r'\S*\/\S*', arg):
            ip_list = IPNetwork(arg)

        elif (re.match(r'\S*\-\S*', arg)):
            range_vals.extend(arg.split("-"))
            if len(range_vals) == 2:
                ip_list = IPRange(range_vals[0], range_vals[1])
        else:
            print_error("Range provided is not valid")
            return []
    except:
        print_error("Range provided is not valid")
        return []
    return ip_list


def process_spf_data(res, data):
    """
    This function will take the text info of a TXT or SPF record, extract the
    IPv4, IPv6 addresses and ranges, request process include records and return
    a list of IP Addresses for the records specified in the SPF Record.
    """
    # Declare lists that will be used in the function.
    ipv4 = []
    ipv6 = []
    includes = []
    ip_list = []

    # check first if it is a sfp record
    if not re.search(r'v\=spf', data):
        return

    # Parse the record for IPv4 Ranges, individual IPs and include TXT Records.
    ipv4.extend(re.findall('ip4:(\S*) ', "".join(data)))
    ipv6.extend(re.findall('ip6:(\S*)', "".join(data)))

    # Create a list of IPNetwork objects.
    for ip in ipv4:
        for i in IPNetwork(ip):
            ip_list.append(i)

    for ip in ipv6:
        for i in IPNetwork(ip):
            ip_list.append(i)

    # Extract and process include values.
    includes.extend(re.findall('include:(\S*)', "".join(data)))
    for inc_ranges in includes:
        for spr_rec in res.get_txt(inc_ranges):
            spf_data = process_spf_data(res, spr_rec[2])
            if spf_data is not None:
                ip_list.extend(spf_data)

    # Return a list of IP Addresses
    return [str(ip) for ip in ip_list]


def expand_cidr(cidr_to_expand):
    """
    Function to expand a given CIDR and return an Array of IP Addresses that
    form the range covered by the CIDR.
    """
    ip_list = []
    c1 = IPNetwork(cidr_to_expand)
    return c1


def expand_range(startip, endip):
    """
    Function to expand a given range and return an Array of IP Addresses that
    form the range.
    """
    return IPRange(startip, endip)


def range2cidr(ip1, ip2):
    """
    Function to return the maximum CIDR given a range of IP's
    """
    r1 = IPRange(ip1, ip2)
    return str(r1.cidrs()[-1])


def write_to_file(data, target_file):
    """
    Function for writing returned data to a file
    """
    f = open(target_file, "w")
    f.write(data)
    f.close()


def check_wildcard(res, domain_trg):
    """
    Function for checking if Wildcard resolution is configured for a Domain
    """
    wildcard = None
    test_name = ''.join(Random().sample(string.hexdigits + string.digits,
                                        12)) + '.' + domain_trg
    ips = res.get_a(test_name)

    if len(ips) > 0:
        print_debug('Wildcard resolution is enabled on this domain')
        print_debug('It is resolving to {0}'.format(''.join(ips[0][2])))
        print_debug("All queries will resolve to this address!!")
        wildcard = ''.join(ips[0][2])

    return wildcard


def brute_tlds(res, domain, verbose=False):
    """
    This function performs a check of a given domain for known TLD values.
    prints and returns a dictionary of the results.
    """
    global brtdata
    brtdata = []

    # tlds taken from http://data.iana.org/TLD/tlds-alpha-by-domain.txt
    gtld = ['co', 'com', 'net', 'biz', 'org']
    tlds = ['ac', 'ad', 'ae', 'aero', 'af', 'ag', 'ai', 'al', 'am', 'an', 'ao', 'aq', 'ar',
            'arpa', 'as', 'asia', 'at', 'au', 'aw', 'ax', 'az', 'ba', 'bb', 'bd', 'be', 'bf', 'bg',
            'bh', 'bi', 'biz', 'bj', 'bm', 'bn', 'bo', 'br', 'bs', 'bt', 'bv', 'bw', 'by', 'bz', 'ca',
            'cat', 'cc', 'cd', 'cf', 'cg', 'ch', 'ci', 'ck', 'cl', 'cm', 'cn', 'co', 'com', 'coop',
            'cr', 'cu', 'cv', 'cx', 'cy', 'cz', 'de', 'dj', 'dk', 'dm', 'do', 'dz', 'ec', 'edu', 'ee',
            'eg', 'er', 'es', 'et', 'eu', 'fi', 'fj', 'fk', 'fm', 'fo', 'fr', 'ga', 'gb', 'gd', 'ge',
            'gf', 'gg', 'gh', 'gi', 'gl', 'gm', 'gn', 'gov', 'gp', 'gq', 'gr', 'gs', 'gt', 'gu', 'gw',
            'gy', 'hk', 'hm', 'hn', 'hr', 'ht', 'hu', 'id', 'ie', 'il', 'im', 'in', 'info', 'int',
            'io', 'iq', 'ir', 'is', 'it', 'je', 'jm', 'jo', 'jobs', 'jp', 'ke', 'kg', 'kh', 'ki', 'km',
            'kn', 'kp', 'kr', 'kw', 'ky', 'kz', 'la', 'lb', 'lc', 'li', 'lk', 'lr', 'ls', 'lt', 'lu',
            'lv', 'ly', 'ma', 'mc', 'md', 'me', 'mg', 'mh', 'mil', 'mk', 'ml', 'mm', 'mn', 'mo',
            'mobi', 'mp', 'mq', 'mr', 'ms', 'mt', 'mu', 'museum', 'mv', 'mw', 'mx', 'my', 'mz', 'na',
            'name', 'nc', 'ne', 'net', 'nf', 'ng', 'ni', 'nl', 'no', 'np', 'nr', 'nu', 'nz', 'om',
            'org', 'pa', 'pe', 'pf', 'pg', 'ph', 'pk', 'pl', 'pm', 'pn', 'pr', 'pro', 'ps', 'pt', 'pw',
            'py', 'qa', 're', 'ro', 'rs', 'ru', 'rw', 'sa', 'sb', 'sc', 'sd', 'se', 'sg', 'sh', 'si',
            'sj', 'sk', 'sl', 'sm', 'sn', 'so', 'sr', 'st', 'su', 'sv', 'sy', 'sz', 'tc', 'td', 'tel',
            'tf', 'tg', 'th', 'tj', 'tk', 'tl', 'tm', 'tn', 'to', 'tp', 'tr', 'travel', 'tt', 'tv',
            'tw', 'tz', 'ua', 'ug', 'uk', 'us', 'uy', 'uz', 'va', 'vc', 've', 'vg', 'vi', 'vn', 'vu',
            'wf', 'ws', 'ye', 'yt', 'za', 'zm', 'zw']
    found_tlds = []
    domain_main = domain.split(".")[0]

    # Let the user know how long it could take
    print_status("The operation could take up to: {0}".format(time.strftime('%H:%M:%S',
                                                                            time.gmtime(len(tlds) / 4))))

    try:
        for t in tlds:
            if verbose:
                print_status("Trying {0}".format(domain_main + "." + t))
            pool.add_task(res.get_ip, domain_main + "." + t)
            for g in gtld:
                if verbose:
                    print_status("Trying {0}".format(domain_main + "." + g + "." + t))
                pool.add_task(res.get_ip, domain_main + "." + g + "." + t)

        # Wait for threads to finish.
        pool.wait_completion()

    except (KeyboardInterrupt):
        exit_brute(pool)

    # Process the output of the threads.
    for rcd_found in brtdata:
        for rcd in rcd_found:
            if re.search(r'^A', rcd[0]):
                found_tlds.extend([{'type': rcd[0], 'name': rcd[1], 'address': rcd[2]}])

    print_good("{0} Records Found".format(len(found_tlds)))

    return found_tlds


def brute_srv(res, domain, verbose=False):
    """
    Brute-force most common SRV records for a given Domain. Returns an Array with
    records found.
    """
    global brtdata
    brtdata = []
    returned_records = []
    srvrcd = [
        '_gc._tcp.', '_kerberos._tcp.', '_kerberos._udp.', '_ldap._tcp.',
        '_test._tcp.', '_sips._tcp.', '_sip._udp.', '_sip._tcp.', '_aix._tcp.',
        '_aix._tcp.', '_finger._tcp.', '_ftp._tcp.', '_http._tcp.', '_nntp._tcp.',
        '_telnet._tcp.', '_whois._tcp.', '_h323cs._tcp.', '_h323cs._udp.',
        '_h323be._tcp.', '_h323be._udp.', '_h323ls._tcp.', '_https._tcp.',
        '_h323ls._udp.', '_sipinternal._tcp.', '_sipinternaltls._tcp.',
        '_sip._tls.', '_sipfederationtls._tcp.', '_jabber._tcp.',
        '_xmpp-server._tcp.', '_xmpp-client._tcp.', '_imap.tcp.',
        '_certificates._tcp.', '_crls._tcp.', '_pgpkeys._tcp.',
        '_pgprevokations._tcp.', '_cmp._tcp.', '_svcp._tcp.', '_crl._tcp.',
        '_ocsp._tcp.', '_PKIXREP._tcp.', '_smtp._tcp.', '_hkp._tcp.',
        '_hkps._tcp.', '_jabber._udp.', '_xmpp-server._udp.', '_xmpp-client._udp.',
        '_jabber-client._tcp.', '_jabber-client._udp.', '_kerberos.tcp.dc._msdcs.',
        '_ldap._tcp.ForestDNSZones.', '_ldap._tcp.dc._msdcs.', '_ldap._tcp.pdc._msdcs.',
        '_ldap._tcp.gc._msdcs.', '_kerberos._tcp.dc._msdcs.', '_kpasswd._tcp.', '_kpasswd._udp.',
        '_imap._tcp.', '_imaps._tcp.', '_submission._tcp.', '_pop3._tcp.', '_pop3s._tcp.',
        '_caldav._tcp.', '_caldavs._tcp.', '_carddav._tcp.', '_carddavs._tcp.',
        '_x-puppet._tcp.', '_x-puppet-ca._tcp.']

    try:
        for srvtype in srvrcd:
            if verbose:
                print_status("Trying {0}".format(res.get_srv, srvtype + domain))
            pool.add_task(res.get_srv, srvtype + domain)

        # Wait for threads to finish.
        pool.wait_completion()

    except (KeyboardInterrupt):
        exit_brute(pool)

    # Make sure we clear the variable
    if len(brtdata) > 0:
        for rcd_found in brtdata:
            for rcd in rcd_found:
                returned_records.extend([{'type': rcd[0],
                                          'name': rcd[1],
                                          'target': rcd[2],
                                          'address': rcd[3],
                                          'port': rcd[4]}])

    else:
        print_error("No SRV Records Found for {0}".format(domain))

    print_good("{0} Records Found".format(len(returned_records)))

    return returned_records


def brute_reverse(res, ip_list, verbose=False):
    """
    Reverse look-up brute force for given CIDR example 192.168.1.1/24. Returns an
    Array of found records.
    """
    global brtdata
    brtdata = []

    returned_records = []
    print_status("Performing Reverse Lookup from {0} to {1}".format(ip_list[0], ip_list[-1]))

    # Resolve each IP in a separate thread.
    try:
        ip_range = xrange(len(ip_list) - 1)
    except NameError:
        ip_range = range(len(ip_list) - 1)

    try:
        for x in ip_range:
            ipaddress = str(ip_list[x])
            if verbose:
                print_status("Trying {0}".format(ipaddress))
            pool.add_task(res.get_ptr, ipaddress)

        # Wait for threads to finish.
        pool.wait_completion()

    except (KeyboardInterrupt):
        exit_brute(pool)

    for rcd_found in brtdata:
        for rcd in rcd_found:
            returned_records.extend([{'type': rcd[0],
                                      "name": rcd[1],
                                      'address': rcd[2]}])

    print_good("{0} Records Found".format(len(returned_records)))

    return returned_records


def brute_domain(res, dict, dom, filter=None, verbose=False, ignore_wildcard=False):
    """
    Main Function for domain brute forcing
    """
    global brtdata
    brtdata = []
    wildcard_ip = None
    found_hosts = []
    continue_brt = 'y'

    # Check if wildcard resolution is enabled
    wildcard_ip = check_wildcard(res, dom)
    if wildcard_ip and not ignore_wildcard:
        print_status('Do you wish to continue? y/n ')
        continue_brt = str(sys.stdin.readline()[:-1])
    if re.search(r'y', continue_brt, re.I):
        # Check if Dictionary file exists

        if os.path.isfile(dict):
            with open(dict) as f:

                # Thread brute-force.
                try:
                    for line in f:
                        if verbose:
                            print_status("Trying {0}".format(line.strip() + '.' + dom.strip()))
                        target = line.strip() + '.' + dom.strip()
                        pool.add_task(res.get_ip, target)

                    # Wait for threads to finish
                    pool.wait_completion()

                except (KeyboardInterrupt):
                    exit_brute(pool)

        # Process the output of the threads.
        for rcd_found in brtdata:
            for rcd in rcd_found:
                if re.search(r'^A', rcd[0]):
                    # Filter Records if filtering was enabled
                    if filter:
                        if not wildcard_ip == rcd[2]:
                            found_hosts.extend([{'type': rcd[0], 'name': rcd[1], 'address': rcd[2]}])
                    else:
                        found_hosts.extend([{'type': rcd[0], 'name': rcd[1], 'address': rcd[2]}])
                elif re.search(r'^CNAME', rcd[0]):
                    found_hosts.extend([{'type': rcd[0], 'name': rcd[1], 'target': rcd[2]}])

        # Clear Global variable
        brtdata = []

    print_good("{0} Records Found".format(len(found_hosts)))
    return found_hosts


def in_cache(dict_file, ns):
    """
    Function for Cache Snooping, it will check a given NS server for specific
    type of records for a given domain are in it's cache.
    """
    found_records = []
    with open(dict_file) as f:

        for zone in f:
            dom_to_query = str.strip(zone)
            query = dns.message.make_query(dom_to_query, dns.rdatatype.A, dns.rdataclass.IN)
            query.flags ^= dns.flags.RD
            answer = dns.query.udp(query, ns)
            if len(answer.answer) > 0:
                for an in answer.answer:
                    for rcd in an:
                        if rcd.rdtype == 1:
                            print_status("\tName: {0} TTL: {1} Address: {2} Type: A".format(an.name, an.ttl, rcd.address))

                            found_records.extend([{'type': "A", 'name': an.name,
                                                   'address': rcd.address, 'ttl': an.ttl}])

                        elif rcd.rdtype == 5:
                            print_status("\tName: {0} TTL: {1} Target: {2} Type: CNAME".format(an.name, an.ttl, rcd.target))
                            found_records.extend([{'type': "CNAME", 'name': an.name,
                                                   'target': rcd.target, 'ttl': an.ttl}])

                        else:
                            print_status()
    return found_records


def scrape_google(dom):
    """
    Function for enumerating sub-domains and hosts by scraping Google.
    """
    results = []
    filtered = []
    searches = ["0","100", "200", "300", "400", "500"]
    data = ""
    urllib._urlopener = AppURLopener()

    for n in searches:
        url = "http://google.com/search?hl=en&lr=&ie=UTF-8&q=%2B" + dom + "&start=" + n + "&sa=N&filter=0&num=100"
        sock = urllib.urlopen(url)
        data += sock.read()
        if re.search('Our systems have detected unusual traffic from your computer network',data) != None:
          print_error("Google has detected the search as \'bot activity, stopping search...")
          return
        sock.close()
    results.extend(unique(re.findall("htt\w{1,2}:\/\/([^:?]*[a-b0-9]*[^:?]*\." + dom + ")\/", data)))

    # Make sure we are only getting the host
    for f in results:
        filtered.extend(re.findall("^([a-z.0-9^]*" + dom + ")", f))
    time.sleep(2)
    return unique(filtered)


def goo_result_process(res, found_hosts):
    """
    This function processes the results returned from the Google Search and does
    an A and AAAA query for the IP of the found host. Prints and returns a dictionary
    with all the results found.
    """
    returned_records = []
    if found_hosts == None:
        return None
    for sd in found_hosts:
        for sdip in res.get_ip(sd):
            if re.search(r'^A|CNAME', sdip[0]):
                print_status('\t {0} {1} {2}'.format(sdip[0], sdip[1], sdip[2]))
                if re.search(r'^A', sdip[0]):
                    returned_records.extend([{'type': sdip[0], 'name': sdip[1],
                                              'address': sdip[2]}])
                else:
                    returned_records.extend([{'type': sdip[0], 'name': sdip[1],
                                              'target': sdip[2]}])

    print_good("{0} Records Found".format(len(returned_records)))
    return returned_records


def get_whois_nets_iplist(ip_list):
    """
    This function will perform whois queries against a list of IP's and extract
    the net ranges and if available the organization list of each and remover any
    duplicate entries.
    """
    seen = {}
    idfun = repr
    found_nets = []
    for ip in ip_list:
        if ip != "no_ip":
            # Find appropriate Whois Server for the IP
            whois_server = get_whois(ip)
            # If we get a Whois server Process get the whois and process.
            if whois_server:
                whois_data = whois(ip, whois_server)
                arin_style = re.search('NetRange', whois_data)
                ripe_apic_style = re.search('netname', whois_data)
                if (arin_style or ripe_apic_style):
                    net = get_whois_nets(whois_data)
                    if net:
                        for network in net:
                            org = get_whois_orgname(whois_data)
                            found_nets.append({'start': network[0], 'end': network[1], 'orgname': "".join(org)})
                else:
                    for line in whois_data.splitlines():
                        recordentrie = re.match('^(.*)\s\S*-\w*\s\S*\s(\S*\s-\s\S*)', line)
                        if recordentrie:
                            org = recordentrie.group(1)
                            net = get_whois_nets(recordentrie.group(2))
                            for network in net:
                                found_nets.append({'start': network[0], 'end': network[1], 'orgname': "".join(org)})
    #Remove Duplicates
    return [seen.setdefault(idfun(e), e) for e in found_nets if idfun(e) not in seen]


def whois_ips(res, ip_list):
    """
    This function will process the results of the whois lookups and present the
    user with the list of net ranges found and ask the user if he wishes to perform
    a reverse lookup on any of the ranges or all the ranges.
    """
    answer = ""
    found_records = []
    print_status("Performing Whois lookup against records found.")
    list = get_whois_nets_iplist(unique(ip_list))
    if len(list) > 0:
        print_status("The following IP Ranges where found:")
        for i in range(len(list)):
            print_status(
                "\t {0} {1}-{2} {3}".format(str(i) + ")", list[i]['start'], list[i]['end'], list[i]['orgname']))
        print_status('What Range do you wish to do a Revers Lookup for?')
        print_status('number, comma separated list, a for all or n for none')
        val = sys.stdin.readline()[:-1]
        answer = str(val).split(",")

        if "a" in answer:
            for i in range(len(list)):
                print_status("Performing Reverse Lookup of range {0}-{1}".format(list[i]['start'], list[i]['end']))
                found_records.append(brute_reverse(res, expand_range(list[i]['start'], list[i]['end'])))

        elif "n" in answer:
            print_status("No Reverse Lookups will be performed.")
            pass
        else:
            for a in answer:
                net_selected = list[int(a)]
                print_status(net_selected['orgname'])
                print_status(
                    "Performing Reverse Lookup of range {0}-{1}".format(net_selected['start'], net_selected['end']))
                found_records.append(brute_reverse(res, expand_range(net_selected['start'], net_selected['end'])))
    else:
        print_error("No IP Ranges where found in the Whois query results")

    return found_records


def prettify(elem):
    """
    Return a pretty-printed XML string for the Element.
    """
    rough_string = ElementTree.tostring(elem, 'utf-8')
    reparsed = minidom.parseString(rough_string)
    return reparsed.toprettyxml(indent="    ")


def dns_record_from_dict(record_dict_list, scan_info, domain):
    """
    Saves DNS Records to XML Given a a list of dictionaries each representing
    a record to be saved, returns the XML Document formatted.
    """

    xml_doc = Element("records")
    for r in record_dict_list:
        elem = Element("record")
        if type(r) is not str:
            try:
                for k, v in r.items():
                    try:
                        k = unicode(str(k))
                        v = unicode(str(v))
                        elem.attrib[k] = v
                    except:
                        print_error("Could not convert key or value to unicode: '{0} = {1}'".format((repr(k), repr(v))))
                        print_error("In element: {0}".format(repr(elem.attrib)))
                        continue
                xml_doc.append(elem)
            except AttributeError:
                continue
                xml_doc.append(elem)
            except AttributeError:
                continue

    scanelem = Element("scaninfo")
    scanelem.attrib["arguments"] = scan_info[0]
    scanelem.attrib["time"] = scan_info[1]
    xml_doc.append(scanelem)
    if domain is not None:
        domelem = Element("domain")
        domelem.attrib["domain_name"] = domain
        xml_doc.append(domelem)
    return prettify(xml_doc)


def create_db(db):
    """
    Function will create the specified database if not present and it will create
    the table needed for storing the data returned by the modules.
    """

    # Connect to the DB
    con = sqlite3.connect(db)

    # Create SQL Queries to be used in the script
    make_table = """CREATE TABLE data (
    serial integer  Primary Key Autoincrement,
    type TEXT(8),
    name TEXT(32),
    address TEXT(32),
    target TEXT(32),
    port TEXT(8),
    text TEXT(256),
    zt_dns TEXT(32)
    )"""

    # Set the cursor for connection
    con.isolation_level = None
    cur = con.cursor()

    # Connect and create table
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='data';")
    if cur.fetchone() is None:
        cur.execute(make_table)
        con.commit()
    else:
        pass


def make_csv(data):
    csv_data = "Type,Name,Address,Target,Port,String\n"
    for n in data:
        # make sure that we are working with a dictionary.
        if isinstance(n, dict):
            if re.search(r'PTR|^[A]$|AAAA', n['type']):
                csv_data += n['type'] + "," + n['name'] + "," + n['address'] + "\n"

            elif re.search(r'NS$', n['type']):
                csv_data += n['type'] + "," + n['target'] + "," + n['address'] + "\n"

            elif re.search(r'SOA', n['type']):
                csv_data += n['type'] + "," + n['mname'] + "," + n['address'] + "\n"

            elif re.search(r'MX', n['type']):
                csv_data += n['type'] + "," + n['exchange'] + "," + n['address'] + "\n"

            elif re.search(r'SPF', n['type']):
                if "zone_server" in n:
                    csv_data += n['type'] + ",,,,,\'" + n['strings'] + "\'\n"
                else:
                    csv_data += n['type'] + ",,,,,\'" + n['strings'] + "\'\n"

            elif re.search(r'TXT', n['type']):
                if "zone_server" in n:
                    csv_data += n['type'] + ",,,,,\'" + n['strings'] + "\'\n"
                else:
                    csv_data += n['type'] + "," + n['name'] + ",,,,\'" + n['strings'] + "\'\n"

            elif re.search(r'SRV', n['type']):
                csv_data += n['type'] + "," + n['name'] + "," + n['address'] + "," + n['target'] + "," + n['port'] + "\n"

            elif re.search(r'CNAME', n['type']):
                csv_data += n['type'] + "," + n['name'] + ",," + n['target'] + ",\n"

            else:
                # Handle not common records
                t = n['type']
                del n['type']
                record_data = "".join(['%s =%s,' % (key, value) for key, value in n.items()])
                records = [t, record_data]
                csv_data + records[0] + ",,,,," + records[1] + "\n"

    return csv_data


def write_json(jsonfile, data, scan_info):
    scaninfo = {'type': 'ScanInfo', 'arguments': scan_info[0], 'date': scan_info[1]}
    data.insert(0, scaninfo)
    json_data = json.dumps(data, sort_keys=True, indent=4, separators=(',', ': '))
    write_to_file(json_data, jsonfile)


def write_db(db, data):
    """
    Function to write DNS Records SOA, PTR, NS, A, AAAA, MX, TXT, SPF and SRV to
    DB.
    """

    con = sqlite3.connect(db)
    # Set the cursor for connection
    con.isolation_level = None
    cur = con.cursor()


    # Normalize the dictionary data
    for n in data:

        if re.match(r'PTR|^[A]$|AAAA', n['type']):
            query = 'insert into data( type, name, address ) ' + \
                    'values( "%(type)s", "%(name)s","%(address)s" )' % n

        elif re.match(r'NS$', n['type']):
            query = 'insert into data( type, name, address ) ' + \
                    'values( "%(type)s", "%(target)s", "%(address)s" )' % n

        elif re.match(r'SOA', n['type']):
            query = 'insert into data( type, name, address ) ' + \
                    'values( "%(type)s", "%(mname)s", "%(address)s" )' % n

        elif re.match(r'MX', n['type']):
            query = 'insert into data( type, name, address ) ' + \
                    'values( "%(type)s", "%(exchange)s", "%(address)s" )' % n

        elif re.match(r'TXT', n['type']):
            query = 'insert into data( type, text) ' + \
                    'values( "%(type)s","%(strings)s" )' % n

        elif re.match(r'SPF', n['type']):
            query = 'insert into data( type, text) ' + \
                    'values( "%(type)s","%(text)s" )' % n

        elif re.match(r'SPF', n['type']):
            query = 'insert into data( type, text) ' + \
                    'values( "%(type)s","%(text)s" )' % n

        elif re.match(r'SRV', n['type']):
            query = 'insert into data( type, name, target, address, port ) ' + \
                    'values( "%(type)s", "%(name)s" , "%(target)s", "%(address)s" ,"%(port)s" )' % n

        elif re.match(r'CNAME', n['type']):
            query = 'insert into data( type, name, target ) ' + \
                    'values( "%(type)s", "%(name)s" , "%(target)s" )' % n

        else:
            # Handle not common records
            t = n['type']
            del n['type']
            record_data = "".join(['%s=%s,' % (key, value) for key, value in n.items()])
            records = [t, record_data]
            query = "insert into data(type,text) values ('" + \
                    records[0] + "','" + records[1] + "')"

        # Execute Query and commit
        cur.execute(query)
        con.commit()


def get_nsec_type(domain, res):
    target = "0." + domain

    answer = get_a_answer(target, res._res.nameservers[0], res._res.timeout)
    for a in answer.authority:
        if a.rdtype == 50:
            return "NSEC3"
        elif a.rdtype == 47:
            return "NSEC"


def dns_sec_check(domain, res):
    """
    Check if a zone is configured for DNSSEC and if so if NSEC or NSEC3 is used.
    """
    try:
        answer = res._res.query(domain, 'DNSKEY')
        print_status("DNSSEC is configured for {0}".format(domain))
        nsectype = get_nsec_type(domain, res)
        print_status("DNSKEYs:")
        for rdata in answer:
            if rdata.flags == 256:
                key_type = "ZSK"

            if rdata.flags == 257:
                key_type = "KSk"

            print_status("\t{0} {1} {2} {3}".format(nsectype, key_type, algorithm_to_text(rdata.algorithm),
                                                    dns.rdata._hexify(rdata.key)))

    except dns.resolver.NXDOMAIN:
        print_error("Could not resolve domain: {0}".format(domain))
        sys.exit(1)

    except dns.exception.Timeout:
        print_error("A timeout error occurred please make sure you can reach the target DNS Servers")
        print_error("directly and requests are not being filtered. Increase the timeout from {0} second".format(
            res._res.timeout))
        print_error("to a higher number with --lifetime <time> option.")
        sys.exit(1)
    except dns.resolver.NoAnswer:
        print_error("DNSSEC is not configured for {0}".format(domain))


def check_bindversion(ns_server, timeout):
    """
    Check if the version of Bind can be queried for.
    """
    version = ""
    request = dns.message.make_query('version.bind', 'txt', 'ch')
    try:
        response = dns.query.udp(request, ns_server, timeout=timeout, one_rr_per_rrset=True)
        if (len(response.answer) > 0):
            print_status("\t Bind Version for {0} {1}".format(ns_server, response.answer[0].items[0].strings[0]))
            version = response.answer[0].items[0].strings[0]
    except (dns.resolver.NXDOMAIN, dns.exception.Timeout, dns.resolver.NoAnswer, socket.error, dns.query.BadResponse):
        return version
    return version


def check_recursive(ns_server, timeout):
    """
    Check if a NS Server is recursive.
    """
    is_recursive = False
    query = dns.message.make_query('www.google.com.', dns.rdatatype.NS)
    try:
        response = dns.query.udp(query, ns_server, timeout)
        recursion_flag_pattern = "\.*RA\.*"
        flags = dns.flags.to_text(response.flags)
        result = re.findall(recursion_flag_pattern, flags)
        if (result):
            print_error("\t Recursion enabled on NS Server {0}".format(ns_server))
        is_recursive = True
    except (socket.error, dns.exception.Timeout):
        return is_recursive
    return is_recursive


def general_enum(res, domain, do_axfr, do_google, do_spf, do_whois, zw):
    """
    Function for performing general enumeration of a domain. It gets SOA, NS, MX
    A, AAAA and SRV records for a given domain. It will first try a Zone Transfer
    if not successful it will try individual record type enumeration. If chosen
    it will also perform a Google Search and scrape the results for host names and
    perform an A and AAAA query against them.
    """
    returned_records = []

    # Var for SPF Record Range Reverse Look-up
    found_spf_ranges = []

    # Var to hold the IP Addresses that will be queried in Whois
    ip_for_whois = []

    # Check if wildcards are enabled on the target domain
    check_wildcard(res, domain)

    # To identify when the records come from a Zone Transfer
    from_zt = None

    # Perform test for Zone Transfer against all NS servers of a Domain
    if do_axfr is not None:
        zonerecs = res.zone_transfer()
        if zonerecs is not None:
            returned_records.extend(res.zone_transfer())
            if len(returned_records) == 0:
                from_zt = True

    # If a Zone Trasfer was possible there is no need to enumerate the rest
    if from_zt is None:

        # Check if DNSSEC is configured
        dns_sec_check(domain, res)

        # Enumerate SOA Record

        try:
            found_soa_records = res.get_soa()
            for found_soa_record in found_soa_records:
                print_status('\t {0} {1} {2}'.format(found_soa_record[0], found_soa_record[1], found_soa_record[2]))

                # Save dictionary of returned record
                returned_records.extend([{'type': found_soa_record[0],
                                          "mname": found_soa_record[1], 'address': found_soa_record[2]}])

                ip_for_whois.append(found_soa_record[2])

        except:
            print_error("Could not Resolve SOA Record for {0}".format(domain))

        # Enumerate Name Servers
        try:
            for ns_rcrd in res.get_ns():
                print_status('\t {0} {1} {2}'.format(ns_rcrd[0], ns_rcrd[1], ns_rcrd[2]))

                # Save dictionary of returned record
                recursive = check_recursive(ns_rcrd[2], res._res.timeout)
                bind_ver = check_bindversion(ns_rcrd[2], res._res.timeout)
                returned_records.extend([
                    {'type': ns_rcrd[0], "target": ns_rcrd[1], 'address': ns_rcrd[2], 'recursive': str(recursive),
                     "Version": bind_ver}])
                ip_for_whois.append(ns_rcrd[2])

        except dns.resolver.NoAnswer:
            print_error("Could not Resolve NS Records for {0}".format(domain))

        # Enumerate MX Records
        try:
            for mx_rcrd in res.get_mx():
                print_status('\t {0} {1} {2}'.format(mx_rcrd[0], mx_rcrd[1], mx_rcrd[2]))

                # Save dictionary of returned record
                returned_records.extend([{'type': mx_rcrd[0], "exchange": mx_rcrd[1], 'address': mx_rcrd[2]}])

                ip_for_whois.append(mx_rcrd[2])

        except dns.resolver.NoAnswer:
            print_error("Could not Resolve MX Records for {0}".format(domain))

        # Enumerate A Record for the targeted Domain
        for a_rcrd in res.get_ip(domain):
            print_status('\t {0} {1} {2}'.format(a_rcrd[0], a_rcrd[1], a_rcrd[2]))

            # Save dictionary of returned record
            returned_records.extend([{'type': a_rcrd[0], "name": a_rcrd[1], 'address': a_rcrd[2]}])

            ip_for_whois.append(a_rcrd[2])

        # Enumerate SFP and TXT Records for the target domain
        text_data = ""
        spf_text_data = res.get_spf()

        # Save dictionary of returned record
        if spf_text_data is not None:
            for s in spf_text_data:
                print_status('\t {0} {1}'.format(s[0], s[1]))
                text_data = s[1]
                returned_records.extend([{'type': s[0], "strings": s[1]}])

        txt_text_data = res.get_txt()

        # Save dictionary of returned record
        if txt_text_data is not None:
            for t in txt_text_data:
                print_status('\t {0} {1} {2}'.format(t[0], t[1], t[2]))
                text_data += t[2]
                returned_records.extend([{'type': t[0], 'name': t[1], "strings": t[2]}])

        domainkey_text_data = res.get_txt("_domainkey." + domain)

        # Save dictionary of returned record
        if domainkey_text_data is not None:
            for t in domainkey_text_data:
                print_status('\t {0} {1} {2}'.format(t[0], t[1], t[2]))
                text_data += t[2]
                returned_records.extend([{'type': t[0], 'name': t[1], "strings": t[2]}])

        # Process SPF records if selected
        if do_spf is not None and len(text_data) > 0:
            print_status("Expanding IP ranges found in DNS and TXT records for Reverse Look-up")
            processed_spf_data = process_spf_data(res, text_data)
            if processed_spf_data is not None:
                found_spf_ranges.extend(processed_spf_data)
            if len(found_spf_ranges) > 0:
                print_status("Performing Reverse Look-up of SPF Ranges")
                returned_records.extend(brute_reverse(res, unique(found_spf_ranges)))
            else:
                print_status("No IP Ranges where found in SPF and TXT Records")

        # Enumerate SRV Records for the targeted Domain
        print_status('Enumerating SRV Records')
        srv_rcd = brute_srv(res, domain)
        if srv_rcd:
            for r in srv_rcd:
                ip_for_whois.append(r['address'])
                returned_records.append(r)

        # Do Google Search enumeration if selected
        if do_google is not None:
            print_status('Performing Google Search Enumeration')
            goo_rcd = goo_result_process(res, scrape_google(domain))
            if goo_rcd:
                for r in goo_rcd:
                    if 'address' in goo_rcd:
                        ip_for_whois.append(r['address'])
                returned_records.extend(goo_rcd)

        if do_whois:
            whois_rcd = whois_ips(res, ip_for_whois)
            if whois_rcd:
                for r in whois_rcd:
                    returned_records.extend(r)

        if zw:
            zone_info = ds_zone_walk(res, domain)
            if zone_info:
                returned_records.extend(zone_info)

        return returned_records

        #sys.exit(0)


def query_ds(target, ns, timeout=5.0):
    """
    Function for performing DS Record queries. Returns answer object. Since a
    timeout will break the DS NSEC chain of a zone walk it will exit if a timeout
    happens.
    """
    try:
        query = dns.message.make_query(target, dns.rdatatype.DS, dns.rdataclass.IN)
        query.flags += dns.flags.CD
        query.use_edns(edns=True, payload=4096)
        query.want_dnssec(True)
        answer = dns.query.udp(query, ns, timeout)
    except dns.exception.Timeout:
        print_error("A timeout error occurred please make sure you can reach the target DNS Servers")
        print_error(
            "directly and requests are not being filtered. Increase the timeout from {0} second".format(timeout))
        print_error("to a higher number with --lifetime <time> option.")
        sys.exit(1)
    except:
        print("Unexpected error: {0}".format(sys.exc_info()[0]))
        raise
    return answer


def get_constants(prefix):
    """
    Create a dictionary mapping socket module constants to their names.
    """
    return dict((getattr(socket, n), n)
                for n in dir(socket)
                if n.startswith(prefix))


def socket_resolv(target):
    """
    Resolve IPv4 and IPv6 .
    """
    found_recs = []
    families = get_constants('AF_')
    types = get_constants('SOCK_')
    try:
        for response in socket.getaddrinfo(target, 0):
            # Unpack the response tuple
            family, socktype, proto, canonname, sockaddr = response
            if families[family] == "AF_INET" and types[socktype] == "SOCK_DGRAM":
                found_recs.append(["A", target, sockaddr[0]])
            elif families[family] == "AF_INET6" and types[socktype] == "SOCK_DGRAM":
                found_recs.append(["AAAA", target, sockaddr[0]])
    except:
        return found_recs
    return found_recs


def lookup_next(target, res):
    """
    Try to get the most accurate information for the record found.
    """
    res_sys = DnsHelper(target)
    returned_records = []

    if re.search("^_[A-Za-z0-9_-]*._[A-Za-z0-9_-]*.", target, re.I):
        srv_answer = res.get_srv(target)
        if len(srv_answer) > 0:
            for r in srv_answer:
                print_status("\t {0}".format(" ".join(r)))
                returned_records.append({'type': r[0],
                                         'name': r[1],
                                         'target': r[2],
                                         'address': r[3],
                                         'port': r[4]})

    elif re.search("(_autodiscover\\.|_spf\\.|_domainkey\\.)", target, re.I):
        txt_answer = res.get_txt(target)
        if len(txt_answer) > 0:
            for r in txt_answer:
                print_status("\t {0}".format(" ".join(r)))
                returned_records.append({'type': r[0],
                                         'name': r[1], 'strings': r[2]})
        else:
            txt_answer = res_sys.get_tx(target)
            if len(txt_answer) > 0:
                for r in txt_answer:
                    print_status("\t {0}".format(" ".join(r)))
                    returned_records.append({'type': r[0],
                                             'name': r[1], 'strings': r[2]})
            else:
                print_status('\t A {0} no_ip'.format(target))
                returned_records.append({'type': 'A', 'name': target, 'address': "no_ip"})

    else:
        a_answer = res.get_ip(target)
        if len(a_answer) > 0:
            for r in a_answer:
                print_status('\t {0} {1} {2}'.format(r[0], r[1], r[2]))
                if r[0] == 'CNAME':
                    returned_records.append({'type': r[0], 'name': r[1], 'target': r[2]})
                else:
                    returned_records.append({'type': r[0], 'name': r[1], 'address': r[2]})
        else:
            a_answer = socket_resolv(target)
            if len(a_answer) > 0:
                for r in a_answer:
                    print_status('\t {0} {1} {2}'.format(r[0], r[1], r[2]))
                    returned_records.append({'type': r[0], 'name': r[1], 'address': r[2]})
            else:
                print_status('\t A {0} no_ip'.format(target))
                returned_records.append({'type': 'A', 'name': target, 'address': "no_ip"})

    return returned_records


def get_a_answer(target, ns, timeout):
    query = dns.message.make_query(target, dns.rdatatype.A, dns.rdataclass.IN)
    query.flags += dns.flags.CD
    query.use_edns(edns=True, payload=4096)
    query.want_dnssec(True)
    answer = dns.query.udp(query, ns, timeout)
    return answer


def get_next(target, ns, timeout):
    next_host = None
    response = get_a_answer(target, ns, timeout)
    for a in response.authority:
        if a.rdtype == 47:
            for r in a:
                next_host = r.next.to_text()[:-1]
    return next_host


def ds_zone_walk(res, domain):
    """
    Perform DNSSEC Zone Walk using NSEC records found the the error additional
    records section of the message to find the next host to query int he zone.
    """
    print_status("Performing NSEC Zone Walk for {0}".format(domain))

    print_status("Getting SOA record for {0}".format(domain))
    soa_rcd = res.get_soa()[0][2]

    print_status("Name Server {0} will be used".format(soa_rcd))
    res = DnsHelper(domain, soa_rcd, 3)
    nameserver = soa_rcd

    timeout = res._res.timeout

    records = []

    transformations = [
        # Send the hostname as-is
        lambda h, hc, dc: h,

        # Prepend a zero as a subdomain
        lambda h, hc, dc: "0.{0}".format(h),

        # Append a hyphen to the host portion
        lambda h, hc, dc: "{0}-.{1}".format(hc, dc),

        # Double the last character of the host portion
        lambda h, hc, dc: "{0}{1}.{2}".format(hc, hc[-1], dc)
    ]

    pending = set([domain])
    finished = set()

    try:
        while pending:
            # Get the next pending hostname
            hostname = pending.pop()
            finished.add(hostname)

            # Get all the records we can for the hostname
            records.extend(lookup_next(hostname, res))

            # Arrange the arguments for the transformations
            fields = re.search("(^[^.]*).(\S*)", hostname)
            params = [hostname, fields.group(1), fields.group(2)]

            for transformation in transformations:
                # Apply the transformation
                target = transformation(*params)

                # Perform a DNS query for the target and process the response
                response = get_a_answer(target, nameserver, timeout)
                for a in response.authority:
                    if a.rdtype != 47:
                        continue

                    # NSEC records give two results:
                    #   1) The previous existing hostname that is signed
                    #   2) The subsequent existing hostname that is signed
                    # Add the latter to our list of pending hostnames
                    for r in a:
                        pending.add(r.next.to_text()[:-1])

            # Ensure nothing pending has already been queried
            pending -= finished

    except (KeyboardInterrupt):
        print_error("You have pressed Ctrl + C. Saving found records.")

    except (dns.exception.Timeout):
        print_error("A timeout error occurred while performing the zone walk please make ")
        print_error("sure you can reach the target DNS Servers directly and requests")
        print_error("are not being filtered. Increase the timeout to a higher number")
        print_error("with --lifetime <time> option.")

    # Give a summary of the walk
    if len(records) > 0:
        print_good("{0} records found".format(len(records)))
    else:
        print_error("Zone could not be walked")

    return records


def usage():
    print("Version: {0}".format(__version__))
    print("Usage: dnsrecon.py <options>\n")
    print("Options:")
    print("   -h, --help                   Show this help message and exit.")
    print("   -d, --domain      <domain>   Target domain.")
    print("   -r, --range       <range>    IP range for reverse lookup brute force in formats (first-last) or in (range/bitmask).")
    print("   -n, --name_server <name>     Domain server to use. If none is given, the SOA of the target will be used.")
    print("   -D, --dictionary  <file>     Dictionary file of subdomain and hostnames to use for brute force.")
    print("   -f                           Filter out of brute force domain lookup, records that resolve to the wildcard defined")
    print("                                IP address when saving records.")
    print("   -t, --type        <types>    Type of enumeration to perform:")
    print("                                std       SOA, NS, A, AAAA, MX and SRV if AXRF on the NS servers fail.")
    print("                                rvl       Reverse lookup of a given CIDR or IP range.")
    print("                                brt       Brute force domains and hosts using a given dictionary.")
    print("                                srv       SRV records.")
    print("                                axfr      Test all NS servers for a zone transfer.")
    print("                                goo       Perform Google search for subdomains and hosts.")
    print("                                snoop     Perform cache snooping against all NS servers for a given domain, testing")
    print("                                          all with file containing the domains, file given with -D option.")
    print("                                tld       Remove the TLD of given domain and test against all TLDs registered in IANA.")
    print("                                zonewalk  Perform a DNSSEC zone walk using NSEC records.")
    print("   -a                           Perform AXFR with standard enumeration.")
    print("   -s                           Perform a reverse lookup of IPv4 ranges in the SPF record with standard enumeration.")
    print("   -g                           Perform Google enumeration with standard enumeration.")
    print("   -w                           Perform deep whois record analysis and reverse lookup of IP ranges found through")
    print("                                Whois when doing a standard enumeration.")
    print("   -z                           Performs a DNSSEC zone walk with standard enumeration.")
    print("   --threads         <number>   Number of threads to use in reverse lookups, forward lookups, brute force and SRV")
    print("                                record enumeration.")
    print("   --lifetime        <number>   Time to wait for a server to response to a query.")
    print("   --db              <file>     SQLite 3 file to save found records.")
    print("   --xml             <file>     XML file to save found records.")
    print("   --iw                         Continue brute forcing a domain even if a wildcard records are discovered.")
    print("   -c, --csv         <file>     Comma separated value file.")
    print("   -j, --json        <file>     JSON file.")
    print("   -v                           Show attempts in the brute force modes.")



# Main
#-------------------------------------------------------------------------------
def main():
    #
    # Option Variables
    #

    returned_records = []
    domain = None
    ns_server = None
    output_file = None
    dict = None
    type = None
    xfr = None
    goo = None
    spf_enum = None
    do_whois = None
    thread_num = 10
    request_timeout = 3.0
    ip_range = None
    ip_list = []
    results_db = None
    zonewalk = None
    csv_file = None
    json_file = None
    wildcard_filter = False
    verbose = False
    ignore_wildcardrr = False

    #
    # Global Vars
    #

    global pool

    #
    # Define options
    #
    parser = argparse.ArgumentParser()
    try:
        parser.add_argument('-d', '--domain', type=str, dest="domain", help="Target domain.")
        parser.add_argument('-n', '--name_server',type=str, dest="ns_server", help="Domain server to use. If none is given,    the SOA of the target will be used.")
        parser.add_argument('-r', '--range',type=str, dest="range", help="IP range for reverse lookup brute force in formats   (first-last) or in (range/bitmask).")
        parser.add_argument('-D', '--dictionary',type=str, dest="dictionary", help="Dictionary file of subdomain and          hostnames to use for brute force. Filter out of brute force domain lookup, records that resolve to the wildcard        defined IP address when saving records.")
        parser.add_argument('-f', help="Filter out of brute force domain lookup, records that resolve to the wildcard defined  IP address when saving records.", action="store_true")
        parser.add_argument('-t', '--type', type=str, dest="type", help="Type of enumeration to perform.")
        parser.add_argument('-a', help="Perform AXFR with standard enumeration.", action="store_true")
        parser.add_argument('-s', help="Perform a reverse lookup of IPv4 ranges in the SPF record with standard enumeration.   ", action="store_true")
        parser.add_argument('-g', help="Perform Google enumeration with standard enumeration.", action="store_true")
        parser.add_argument('-w', help="Perform deep whois record analysis and reverse lookup of IP ranges found through       Whois when doing a standard enumeration.", action="store_true")
        parser.add_argument('-z', help='Performs a DNSSEC zone walk with standard enumeration.', action="store_true")
        parser.add_argument('--threads', type=int, dest="threads", help="Number of threads to use in reverse lookups, forward  lookups, brute force and SRV record enumeration.")
        parser.add_argument('--lifetime', type=int, dest="lifetime", help="Time to wait for a server to response to a query.")
        parser.add_argument('--db', type=str, dest="db", help="SQLite 3 file to save found records.")
        parser.add_argument('-x', '--xml', type=str, dest="xml", help="XML file to save found records.")
        parser.add_argument('-c', '--csv', type=str, dest="csv", help="Comma separated value file.")
        parser.add_argument('-j', '--json', type=str, dest="json", help="JSON file.")
        parser.add_argument('--iw', help="Continue brute forcing a domain even if a wildcard records are discovered.",         action="store_true")
        parser.add_argument('-v', help="Enable verbose", action="store_true")
        arguments = parser.parse_args()

    except:
        print_error("Wrong Option Provided!")
        parser.print_help()
        sys.exit(0)
    #
    # Parse options
    #
    type = arguments.type
    domain = arguments.domain

    if arguments.ns_server:
        if netaddr.valid_glob(arguments.ns_server):
            ns_server = arguments.ns_server
        else:
            #Resolve in the case if FQDN
            answer = socket_resolv(arguments.ns_server)
            # Check we actually got a list
            if len(answer) > 0:
                # We will use the first IP found as the NS
                ns_server = answer[0][2]
            else:
                # Exit if we cannot resolve it
                print_error("Could not resolve NS server provided")
                sys.exit(1)

    output_file = arguments.xml

    if arguments.dictionary:
        # print(arguments.dictionary)
        if os.path.isfile(arguments.dictionary.strip()):
            dict = arguments.dictionary.strip()
        else:
            print_error("File {0} does not exist!".format(arguments.dictionary.strip()))
            exit(1)


    if arguments.range:
        ip_list = process_range(arguments.range)
        if len(ip_list) > 0:
            if type is None:
                type = "rvl"
            elif not re.search(r'rvl', type):
                type = "rvl," + type
        else:
            print_error('Failed CIDR or Range is Required for type rvl')

    if arguments.threads:
        thread_num = int(arguments.threads)

    if arguments.lifetime:
        request_timeout = float(arguments.lifetime)

    results_db = arguments.db
    csv_file = arguments.csv
    json_file = arguments.json
    verbose = arguments.v
    ignore_wildcardrr = arguments.iw

    xfr = arguments.a
    goo = arguments.g
    do_whois = arguments.w
    zonewalk = arguments.z
    spf_enum = arguments.s
    wildcard_filter = arguments.f

    # Setting the number of threads to 10
    pool = ThreadPool(thread_num)

    # Set the resolver
    res = DnsHelper(domain, ns_server, request_timeout)

    domain_req = ['axfr', 'std', 'srv', 'tld', 'goo', 'zonewalk']
    scan_info = [" ".join(sys.argv), str(datetime.datetime.now())]

    if type is not None:

        # Check for any illegal enumeration types from the user
        valid_types = ['axfr','std','rvl','brt','srv','tld','goo','snoop','zonewalk']
        incorrect_types = [t for t in type.split(',') if t not in valid_types]
        if incorrect_types:
            print_error("This type of scan is not in the list: {0}".format(','.join(incorrect_types)))
            sys.exit(1)

        for r in type.split(','):
            if r in domain_req and domain is None:
                print_error('No Domain to target specified!')
                sys.exit(1)

            try:
                if r == 'axfr':
                    print_status('Testing NS Servers for Zone Transfer')
                    zonercds = res.zone_transfer()
                    if zonercds:
                        returned_records.extend(zonercds)
                    else:
                        print_error("No records were returned in the zone transfer attempt.")

                elif r == 'std':
                    print_status("Performing General Enumeration of Domain:".format(domain))
                    std_enum_records = general_enum(res, domain, xfr, goo,
                                                    spf_enum, do_whois, zonewalk)

                    if (output_file is not None) or (results_db is not None) or (csv_file is not None) or (json_file is not None):
                        returned_records.extend(std_enum_records)

                elif r == 'rvl':
                    if len(ip_list) > 0:
                        print_status('Reverse Look-up of a Range')
                        rvl_enum_records = brute_reverse(res, ip_list, verbose)

                        if (output_file is not None) or (results_db is not None) or (csv_file is not None) or (json_file is not None):
                            returned_records.extend(rvl_enum_records)
                    else:
                        print_error('Failed CIDR or Range is Required for type rvl')

                elif r == 'brt':
                    if (dict is not None) and (domain is not None):
                        print_status('Performing host and subdomain brute force against {0}'.format(domain))
                        brt_enum_records = brute_domain(res, dict, domain, wildcard_filter, verbose, ignore_wildcardrr)

                        if (output_file is not None) or (results_db is not None) or (csv_file is not None) or (json_file is not None):
                            returned_records.extend(brt_enum_records)
                    elif (domain is not None):
                        script_dir = os.path.dirname(os.path.realpath(__file__)) + os.sep
                        print_status("No file was specified with domains to check.")
                        name_list_dic = script_dir + "namelist.txt"
                        if os.path.isfile(name_list_dic):
                            print_status("Using file provided with tool: " + name_list_dic)
                            brt_enum_records = brute_domain(res, name_list_dic, domain, wildcard_filter, verbose,
                                                            ignore_wildcardrr)
                        else:
                            print_error("File {0} does not exist!".format(name_list_dic))
                            exit(1)
                    else:
                        print_error('Could not execute a brute force enumeration. A domain was not given.')
                        sys.exit(1)

                elif r == 'srv':
                    print_status('Enumerating Common SRV Records against {0}'.format(domain))
                    srv_enum_records = brute_srv(res, domain, verbose)

                    if (output_file is not None) or (results_db is not None) or (csv_file is not None) or (json_file is not None):
                        returned_records.extend(srv_enum_records)

                elif r == 'tld':
                    print_status("Performing TLD Brute force Enumeration against {0}".format(domain))
                    tld_enum_records = brute_tlds(res, domain, verbose)
                    if (output_file is not None) or (results_db is not None) or (csv_file is not None) or (json_file is not None):
                        returned_records.extend(tld_enum_records)

                elif r == 'goo':
                    print_status("Performing Google Search Enumeration against {0}".format(domain))
                    goo_enum_records = goo_result_process(res, scrape_google(domain))
                    if (output_file is not None) or (results_db is not None) or (csv_file is not None) or (json_file is not None):
                        returned_records.extend(goo_enum_records)

                elif r == "snoop":
                    if (dict is not None) and (ns_server is not None):
                        print_status("Performing Cache Snooping against NS Server: {0}".format(ns_server))
                        cache_enum_records = in_cache(dict, ns_server)
                        if (output_file is not None) or (results_db is not None) or (csv_file is not None) or (json_file is not None):
                            returned_records.extend(cache_enum_records)

                    else:
                        print_error('No Domain or Name Server to target specified!')
                        sys.exit(1)

                elif r == "zonewalk":
                    if (output_file is not None) or (results_db is not None) or (csv_file is not None) or (json_file is not None):
                        returned_records.extend(ds_zone_walk(res, domain))
                    else:
                        ds_zone_walk(res, domain)

                else:
                    print_error("This type of scan is not in the list: {0}".format(r))

            except dns.resolver.NXDOMAIN:
                print_error("Could not resolve domain: {0}".format(domain))
                sys.exit(1)

            except dns.exception.Timeout:
                print_error("A timeout error occurred please make sure you can reach the target DNS Servers")
                print_error("directly and requests are not being filtered. Increase the timeout from {0} second".format(
                    request_timeout))
                print_error("to a higher number with --lifetime <time> option.")
                sys.exit(1)

        # if an output xml file is specified it will write returned results.
        if (output_file is not None):
            print_status("Saving records to XML file: {0}".format(output_file, scan_info))
            xml_enum_doc = dns_record_from_dict(returned_records, scan_info, domain)
            write_to_file(xml_enum_doc, output_file)

        # if an output db file is specified it will write returned results.
        if (results_db is not None):
            print_status("Saving records to SQLite3 file: {0}".format(results_db))
            create_db(results_db)
            write_db(results_db, returned_records)

        # if an output csv file is specified it will write returned results.
        if (csv_file is not None):
            print_status("Saving records to CSV file: {0}".format(csv_file))
            write_to_file(make_csv(returned_records), csv_file)

        # if an output json file is specified it will write returned results.
        if (json_file is not None):
            print_status("Saving records to JSON file: {0}".format(json_file))
            write_json(json_file, returned_records, scan_info)

        sys.exit(0)

    elif domain is not None:
        try:
            print_status("Performing General Enumeration of Domain: {0}".format(domain))
            std_enum_records = general_enum(res, domain, xfr, goo,
                                            spf_enum, do_whois, zonewalk)

            returned_records.extend(std_enum_records)

            # if an output xml file is specified it will write returned results.
            if (output_file is not None):
                print_status("Saving records to XML file: {0}".format(output_file, scan_info))
                xml_enum_doc = dns_record_from_dict(returned_records, scan_info, domain)
                write_to_file(xml_enum_doc, output_file)

            # if an output db file is specified it will write returned results.
            if (results_db is not None):
                print_status("Saving records to SQLite3 file: {0}".format(results_db))
                create_db(results_db)
                write_db(results_db, returned_records)

            # if an output csv file is specified it will write returned results.
            if (csv_file is not None):
                print_status("Saving records to CSV file: {0}".format(csv_file))
                write_to_file(make_csv(returned_records), csv_file)

                # if an output json file is specified it will write returned results.
            if (json_file is not None):
                print_status("Saving records to JSON file: {0}".format(json_file))
                write_json(json_file, returned_records, scan_info)

            sys.exit(0)
        except dns.resolver.NXDOMAIN:
            print_error("Could not resolve domain: {0}".format(domain))
            sys.exit(1)

        except dns.exception.Timeout:
            print_error("A timeout error occurred please make sure you can reach the target DNS Servers")
            print_error("directly and requests are not being filtered. Increase the timeout")
            print_error("to a higher number with --lifetime <time> option.")
            sys.exit(1)
    else:
        usage()
        sys.exit(0)


if __name__ == "__main__":
    main()
