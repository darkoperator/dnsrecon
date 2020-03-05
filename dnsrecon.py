#!/usr/bin/env python
# -*- coding: utf-8 -*-

#    DNSRecon
#
#    Copyright (C) 2012  Carlos Perez
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

__version__ = '0.6.5'
__author__ = 'Carlos Perez, Carlos_Perez@darkoperator.com'

__doc__ = """
DNSRecon http://www.darkoperator.com

 by Carlos Perez, Darkoperator

requires dnspython http://www.dnspython.org/
requires netaddr https://github.com/drkjam/netaddr/

"""
import getopt
import os
import re
import string
import sys
import time
import sqlite3

# Manage the change in Python3 of the name of the Queue Library
try:
    from Queue import Queue
except ImportError:
    from queue import Queue
    
from random import Random
from threading import Lock, Thread
from xml.dom import minidom
from xml.etree import ElementTree
from xml.etree.ElementTree import Element, SubElement

import dns.message
import dns.query
import dns.rdatatype
import dns.resolver
import dns.reversename
import dns.zone
import dns.message
import dns.rdata
import dns.rdatatype
from dns.dnssec import algorithm_to_text

from netaddr import *

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

        found_recrd = []
        while True:
            (func, args, kargs) = self.tasks.get()
            try:
                found_recrd = func(*args, **kargs)
                if found_recrd:
                    Worker.lck.acquire()
                    brtdata.append(found_recrd)
                    for r in found_recrd:
                        if type(r).__name__ == "dict":
                            for k,v in r.iteritems():
                                print_status("\t{0}:{1}".format(k,v))
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

    def add_task(
        self,
        func,
        *args,
        **kargs
        ):
        """Add a task to the queue"""

        self.tasks.put((func, args, kargs))
        
    def wait_completion(self):
        """Wait for completion of all the tasks in the queue"""

        self.tasks.join()

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

        range_vals.extend(arg.split("-"))
        if len(range_vals) == 2:
            ip_list = IPRange(range_vals[0],range_vals[1])
    except:
        print_error("Range provided is not valid: {0}".format(arg()))
        return []
    return [str(ip) for ip in ip_list]

def process_spf_data(res, data):
    """
    This function will take the text info of a TXT or SPF record, extract the
    IPv4, IPv6 addresses and ranges, request process include records and return
    a list of IP Addresses for the records specified in the SPF Record.
    """
    # Declare lists that will be used in the function.
    ipv4=[]
    ipv6 = []
    includes = []
    ip_list = []

    # check first if it is a sfp record
    if not re.search(r'v\=spf', data):
        return

    # Parse the record for IPv4 Ranges, individual IPs and include TXT Records.
    ipv4.extend(re.findall(\
            'ip4:(\S*) ',"".join(data)))
    ipv6.extend(re.findall(\
            'ip6:(\S*)',"".join(data)))

    # Create a list of IPNetwork objects.
    for ip in ipv4:
        for i in IPNetwork(ip):
            ip_list.append(i)

    for ip in ipv6:
        for i in IPNetwork(ip):
            ip_list.append(i)

    # Extract and process include values.
    includes.extend(re.findall(\
            'include:(\S*)',"".join(data)))
    for inc_ranges in includes:
        for spr_rec in res.get_txt(inc_ranges):
            ip_list.extend(process_spf_data(res, spr_rec[2]))

    # Return a list of IP Addresses
    return [str(ip) for ip in ip_list]

def expand_cidr(cidr_to_expand):
    """
    Function to expand a given CIDR and return an Array of IP Addresses that
    form the range covered by the CIDR.
    """
    ip_list = []
    c1 = IPNetwork(cidr_to_expand)
    for x in ([str(c) for c in c1.iter_hosts()]):
        ip_list.append(str(x))
    return ip_list


def expand_range(startip,endip):
    """
    Function to expand a given range and return an Array of IP Addresses that
    form the range.
    """
    ip_list = []
    ipr = iter_iprange(startip,endip)
    for i in ipr:
        ip_list.append(str(i))
    return ip_list

def range2cidr(ip1,ip2):
    """
    Function to return the maximum CIDR given a range of IP's
    """
    r1 = IPRange(ip1, ip2)
    return str(r1.cidrs()[-1])

def write_to_file(data,target_file):
    """
    Function for writing returned data to a file
    """
    f = open(target_file, "w")
    f.write(data)
    f.close


    
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
        print_debug('It is resolving to'.format(''.join(ips)))
        print_debug("All queries will resolve to this address!!")
        wildcard = ''.join(ips)
    
    return wildcard


def brute_tlds(res, domain):
    """
    This function performs a check of a given domain for known TLD values.
    prints and returns a dictionary of the results.
    """
    global brtdata
    brtdata = []
    
    # tlds taken from http://data.iana.org/TLD/tlds-alpha-by-domain.txt
    gtld = ['co','com','net','biz','org']
    tlds = ['ac', 'ad', 'aeaero', 'af', 'ag', 'ai', 'al', 'am', 'an', 'ao', 'aq', 'ar',
    'arpa', 'as', 'asia', 'at', 'au', 'aw', 'ax', 'az', 'ba', 'bb', 'bd', 'be', 'bf', 'bg',
    'bh', 'bi', 'biz', 'bj', 'bm', 'bn', 'bo', 'br', 'bs', 'bt', 'bv', 'bw', 'by', 'bzca',
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
    print_status("The operation could take up to: {0}".format(time.strftime('%H:%M:%S', \
    time.gmtime(len(tlds)/4))))
    
    try:
        for t in tlds:
            pool.add_task(res.get_ip, domain_main + "." + t)
            for g in gtld:
                pool.add_task(res.get_ip, domain_main+ "." + g + "." + t)

        # Wait for threads to finish.
        pool.wait_completion()
        
    except (KeyboardInterrupt):
        print_error("You have pressed Ctrl-C. Saving found records.")
        
    # Process the output of the threads.
    for rcd_found in brtdata:
        for rcd in rcd_found:
            if re.search(r'^A',rcd[0]):
                print_status("\t{0}".format("".join(rcd)))
                found_tlds.extend([{'type':rcd[0],'name':rcd[1],'address':rcd[2]}])
    
    print_good("{0} Records Found".format(len(found_tlds)))

    return found_tlds


def brute_srv(res, domain):
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
        '_h323be._tcp.', '_h323be._udp.', '_h323ls._tcp.',
        '_h323ls._udp.', '_sipinternal._tcp.', '_sipinternaltls._tcp.',
        '_sip._tls.', '_sipfederationtls._tcp.', '_jabber._tcp.',
        '_xmpp-server._tcp.', '_xmpp-client._tcp.', '_imap.tcp.',
        '_certificates._tcp.', '_crls._tcp.', '_pgpkeys._tcp.',
        '_pgprevokations._tcp.', '_cmp._tcp.', '_svcp._tcp.', '_crl._tcp.',
        '_ocsp._tcp.', '_PKIXREP._tcp.', '_smtp._tcp.', '_hkp._tcp.',
        '_hkps._tcp.', '_jabber._udp.','_xmpp-server._udp.', '_xmpp-client._udp.',
        '_jabber-client._tcp.', '_jabber-client._udp.','_kerberos.tcp.dc._msdcs.',
        '_ldap._tcp.ForestDNSZones.', '_ldap._tcp.dc._msdcs.', '_ldap._tcp.pdc._msdcs.',
        '_ldap._tcp.gc._msdcs.','_kerberos._tcp.dc._msdcs.','_kpasswd._tcp.','_kpasswd._udp.'
        ]

    
    try:
        for srvtype in srvrcd:
            pool.add_task(res.get_srv, srvtype + domain)
            
            # Wait for threads to finish.
        pool.wait_completion()
    
    except (KeyboardInterrupt):
        print_error("You have pressed Crtl-C. Saving found records.")
    
        
    
    # Make sure we clear the variable
    
    if len(brtdata) > 0:
        for rcd_found in brtdata:
            for rcd in rcd_found:
                returned_records.extend([{'type':rcd[0],\
                'name':rcd[1],'target':rcd[2],'address':rcd[3],'port':rcd[4]
                }])
    
    else:
        print_error("No SRV Records Found for {0}".format(domain))

    print_good("{0} Records Found".format(len(returned_records)))
    
    return returned_records


def brute_reverse(res,ip_list):
    """
    Reverse look-up brute force for given CIDR example 192.168.1.1/24. Returns an
    Array of found records.
    """
    global brtdata
    brtdata = []
    
    returned_records = []
    print_status("Performing Reverse Lookup from {0} to {1}".format(ip_list[0],ip_list[-1]))

    # Resolve each IP in a separate thread.
    try:
        for x in ip_list:
            pool.add_task(res.get_ptr, x)

        # Wait for threads to finish.
        pool.wait_completion()
    except (KeyboardInterrupt):
        print_error("You have pressed Crtl-C. Saving found records.")
    
    for rcd_found in brtdata:
        for rcd in rcd_found:
            returned_records.extend([{'type':rcd[0],\
            "name":rcd[1],'address':rcd[2]
            }])

    print_good("{0} Records Found".format(len(returned_records)))

    return returned_records

def brute_domain(res, dict, dom, filter = None):
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
    if wildcard_ip:
        continue_brt = input('[*] Do you wish to continue? y/n ')
    if continue_brt == 'y':
        # Check if Dictionary file exists

        if os.path.isfile(dict):
            f = open(dict, 'r+')

            # Thread brute-force.
            try:
                for line in f:
                    target = line.strip() + '.' + dom.strip()
                    pool.add_task(res.get_ip, target)
            except (KeyboardInterrupt):
                print_error("You have pressed Crtl-C. Saving found records.")
                
        # Wait for threads to finish
        pool.wait_completion()
        
        # Process the output of the threads.
        for rcd_found in brtdata:
            for rcd in rcd_found:
                if re.search(r'^A',rcd[0]):
               
                    # Filter Records if filtering was enabled
                    if filter:
                        if not filter == rcd[2]:
                            found_hosts.extend([{'type':rcd[0],'name':rcd[1],'address':rcd[2]}])
                    else:
                        found_hosts.extend([{'type':rcd[0],'name':rcd[1],'address':rcd[2]}])
        
        # Clear Global variable
        brtdata = []
        
    print_good("{0} Records Found".format(len(found_hosts)))
    return found_hosts



def in_cache(dict_file,ns):
    """
    Function for Cache Snooping, it will check a given NS server for specific
    type of records for a given domain are in it's cache. 
    """
    found_records = []
    f = open(dict_file, 'r+')
    for zone in f:
        dom_to_query = str.strip(zone)
        query = dns.message.make_query(dom_to_query, dns.rdatatype.A, dns.rdataclass.IN)
        query.flags ^= dns.flags.RD
        answer = dns.query.udp(query,ns)
        if len(answer.answer) > 0:
            for an in answer.answer:
                for rcd in an:
                    if rcd.rdtype == 1:
                        print_status("\tName: {0} TTL: {1} Address: {2} Type: A".format(an.name,an.ttl,rcd.address))
                        
                        found_records.extend([{'type':"A",'name':an.name,\
                        'address':rcd.address,'ttl':an.ttl}])
                    
                    elif rcd.rdtype == 5:
                        print_status("\tName: {0} TTL: {1} Target: {2} Type: CNAME".format(an.name, an.ttl, rcd.target))
                        found_records.extend([{'type':"CNAME",'name':an.name,\
                        'target':rcd.target,'ttl':an.ttl}])
                    
                    else:
                        print_status()
    return found_records

def goo_result_process(res, found_hosts):
    """
    This function processes the results returned from the Google Search and does
    an A and AAAA query for the IP of the found host. Prints and returns a dictionary
    with all the results found.
    """
    returned_records = []
    for sd in found_hosts:
        for sdip in res.get_ip(sd):
            if re.search(r'^A',sdip[0]):
                print_status('\t {0} {1} {2}'.format(sdip[0], sdip[1], sdip[2]))
            
                returned_records.extend([{'type':sdip[0], 'name':sdip[1], \
                'address':sdip[2]
                }])
    print_good("{0} Records Found".format(len(returned_records)))
    return returned_records

def get_whois_nets_iplist(ip_list):
    """
    This function will perform whois queries against a list of IP's and extract
    the net ranges and if available the organization list of each and remover any
    duplicate entries.
    """
    seen = {}
    idfun=repr
    found_nets = []
    for ip in ip_list:
        if ip != "no_ip":
            # Find appropiate Whois Server for the IP
            whois_server = get_whois(ip)
            # If we get a Whois server Process get the whois and process.
            if whois_server:
                whois_data = whois(ip,whois_server )
                net = get_whois_nets(whois_data)
                if net:
                    org = get_whois_orgname(whois_data)
                    found_nets.append({'start':net[0][0],'end':net[0][1],'orgname':"".join(org)})
    #Remove Duplicates
    return [seen.setdefault(idfun(e),e) for e in found_nets if idfun(e) not in seen]

def whois_ips(res,ip_list):
    """
    This function will process the results of the whois lookups and present the 
    user with the list of net ranges found and ask the user if he wishes to perform
    a reverse lookup on any of the ranges or all the ranges.
    """
    answer = ""
    found_records = []
    print_status("Performing Whois lookup against records found.")
    list = get_whois_nets_iplist(unique(ip_list))
    print_status("The following IP Ranges where found:")
    for i in range(len(list)):
        print_status("\t {0} {1}-{2} {3}".format(str(i)+")", list[i]['start'], list[i]['end'], list[i]['orgname']))
    print_status('What Range do you wish to do a Revers Lookup for?')
    print_status('number, comma separated list, a for all or n for none')
    val = sys.stdin.readline()[:-1]
    answer = str(val).split(",")

    if "a" in answer:
        for i in range(len(list)):
            print_status("Performing Reverse Lookup of range {0}-{1}".format(list[i]['start'],list[i]['end']))
            found_records.append(brute_reverse(res, \
                expand_range(list[i]['start'],list[i]['end'])))

    elif "n" in answer:
        print_status("No Reverse Lookups will be performed.")
        pass
    else:
        for a in answer:
            net_selected = list[int(a)]
            print_status(net_selected['orgname'])
            print_status("Performing Reverse Lookup of range {0}-{1}".format(net_selected['start'],net_selected['end']))
            found_records.append(brute_reverse(res, \
                expand_range(net_selected['start'],net_selected['end'])))
    
    return found_records

def prettify(elem):
    """
    Return a pretty-printed XML string for the Element.
    """
    rough_string = ElementTree.tostring(elem, 'utf-8')
    reparsed = minidom.parseString(rough_string)
    return reparsed.toprettyxml(indent="", newl= "")

def dns_record_from_dict(record_dict_list):
    """
    Saves DNS Records to XML Given a a list of dictionaries each representing
    a record to be saved, returns the XML Document formatted.
    """
    xml_doc = Element("records")
    for r in record_dict_list:
        xml_record = Element('record')
        for n,v in r.iteritems():
            record_field = SubElement(xml_record,n)
            record_field.text = v
        xml_doc.append(xml_record)

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
    if cur.fetchone() == None:
        cur.execute(make_table)
        con.commit()
    else:
        pass

def make_csv(data):
    csv_data = ""
    for n in data:

        if re.search(r'PTR|^[A]$|AAAA',n['type']):
            csv_data += n['type']+","+n['name']+","+n['address']+"\n"

        elif re.search(r'NS',n['type']):
            csv_data += n['type']+","+n['target']+","+n['address']+"\n"

        elif re.search(r'SOA',n['type']):
            csv_data += n['type']+","+n['mname']+","+n['address']+"\n"

        elif re.search(r'MX',n['type']):
            csv_data += n['type']+","+n['exchange']+","+n['address']+"\n"

        elif re.search(r'TXT|SPF',n['type']):
            csv_data += n['type']+","+n['name']+",,,,\'"+n['text']+"\'\n"

        elif re.search(r'SRV',n['type']):
            csv_data += n['type']+","+n['name']+","+n['address']+","+n['target']+","+n['port']+"\n"

        else:
            # Handle not common records
            t = n['type']
            del n['type']
            record_data =  "".join([' %s=%s,' % (key, value) for key, value in n.items()])
            records = [t,record_data]
            csv_data + records[0] + ",,,,," + records[1] +"\n"

    return csv_data
                
def write_db(db,data):
    """
    Function to write DNS Records SOA, PTR, NS, A, AAAA, MX, TXT, SPF and SRV to
    DB.
    """

    con = sqlite3.connect(db)
    # Set the cursor for connection
    con.isolation_level = None
    cur = con.cursor()
    records = []


    # Normalize the dictionary data
    for n in data:

        if re.match(r'PTR|^[A]$|AAAA',n['type']):
            query = 'insert into data( type, name, address ) '+\
            'values( "%(type)s", "%(name)s","%(address)s" )' % n

        elif re.match(r'NS',n['type']):
            query = 'insert into data( type, name, address ) '+\
            'values( "%(type)s", "%(target)s", "%(address)s" )' % n

        elif re.match(r'SOA',n['type']):
            query = 'insert into data( type, name, address ) '+\
            'values( "%(type)s", "%(mname)s", "%(address)s" )' % n

        elif re.match(r'MX',n['type']):
            query = 'insert into data( type, name, address ) '+\
            'values( "%(type)s", "%(exchange)s", "%(address)s" )' % n

        elif re.match(r'TXT|SPF',n['type']):
            query = 'insert into data( type, name, text) '+\
            'values( "%(type)s", "%(text)s" ,"%(text)s" )' % n

        elif re.match(r'SRV',n['type']):
            query = 'insert into data( type, name, target, address, port ) '+\
            'values( "%(type)s", "%(name)s" , "%(target)s", "%(address)s" ,"%(port)s" )' % n

        else:
            # Handle not common records
            t = n['type']
            del n['type']
            record_data =  "".join([' %s=%s,' % (key, value) for key, value in n.items()])
            records = [t,record_data]
            query = "insert into data(type,text) values ('"+\
                records[0] + "','" + records[1] +"')"

        # Execute Query and commit
        cur.execute(query)
        con.commit()
        
def dns_sec_check(domain,res):
    nsec_algos = [1,2,3,4,5]
    nsec3_algos = [6,7]
    try:
        answer = res.resolve(domain, 'DNSKEY')
        print_status("DNSSEC is configured for {0}".format(domain))
        print_status("DNSKEYs:")
        for rdata in answer:
            if rdata.flags == 256:
                key_type = "ZSK"

            if rdata.flags == 257:
                key_type = "KSk"

            if rdata.algorithm in nsec_algos:
                print_status("\tNSEC {0} {1} {2}".format(key_type, algorithm_to_text(rdata.algorithm), dns.rdata._hexify(rdata.key)))
            if rdata.algorithm in nsec3_algos:
                print_status("\tNSEC3 {0} {1} {2}".format(key_type, algorithm_to_text(rdata.algorithm), dns.rdata._hexify(rdata.key)))

    except dns.resolver.NXDOMAIN:
        print_error("Could not resolve domain: {0}".format(domain))
        sys.exit(1)

    except dns.exception.Timeout:
        print_error("A timeout error occurred please make sure you can reach the target DNS Servers")
        print_error("directly and requests are not being filtered. Increase the timeout from {0} second".format(request_timeout))
        print_error("to a higher number with --lifetime <time> option.")
        sys.exit(1)
    except dns.resolver.NoAnswer:
        print_error("DNSSEC is not configured for".format(domain))

def zone_walk(domain, res):
    """
    Function to perform DNSSEC Zone Walk to enumerate an entire zone using NSEC
    Records.
    """
    returned_records = []
    found_records = []
    print_status("Performing NSEC Zone Walk for".format(domain))
    
    # Check for the presense of a NSEC record, if none exit.
    try:
        answer = res.get_nsec(domain)
    except dns.resolver.NoAnswer:
        print_error("This Zone can not be walked!")
        return

    # Process initial information from request
    for arc in answer.response.authority:
        for ns in arc:
            name = ns.target.to_text()
            for ip in res.get_ip(name):
                print_status("\tNS {0}".format(name,ip[-1]))
                returned_records.extend([{'type':"NS",\
                "target":name,'address':ip[2]
                }])

    while answer:
        try:
            for rdata in answer:
                # Make sure we do not end up in a loop where the the NSEC record
                # keeps repeating the zone.
                if rdata.next in found_records:
                    answer = None
                    break
                #print rdata.to_text()
                rcd_type = None
                rcd_type = re.search('( A | AAAA)',rdata.to_text())
                if rcd_type:
                    ip_info = res.get_ip(rdata.next.to_text())
                    if len(ip_info) > 0:
                        for a_rcrd in ip_info:
                            if a_rcrd[0] == "A":
                                print_status('\t {0} {1} {2}'.format(a_rcrd[0], a_rcrd[1], a_rcrd[2]))
                                returned_records.extend([{'type':a_rcrd[0],'name':a_rcrd[1],'address':a_rcrd[2]}])
                            elif a_rcrd[0] == "CNAME":
                                print_status('\t {0} {1} {2}'.format(a_rcrd[0], a_rcrd[1], a_rcrd[2]))
                                returned_records.extend([{'type':a_rcrd[0],'name':a_rcrd[1],'target':a_rcrd[2]}])
                    else:
                        print_status("\t {0} {1} no_ip".format(rcd_type.group(0).strip(), rdata.next.to_text()))

                elif re.search(' SRV ',rdata.to_text()):
                    for rcd in res.get_srv(rdata.next.to_text()):
                        print_status("\t {0}".format(" ".join(rcd)))
                        returned_records.extend([{'type':rcd[0],\
                        'name':rcd[1],'target':rcd[2],'address':rcd[3],'port':rcd[4]
                        }])

                elif re.search('( TXT|SPF)',rdata.to_text()):
                    try:
                        for rcd in res.get_txt(rdata.next.to_text()):
                            print_status("\t {0}".format(" ".join(rcd)))
                            returned_records.extend([{'type':rcd[0],\
                            'name':rcd[1],'text':rcd[2]
                            }])
                    except:
                        print_status("\t {0}".format(rdata.to_text()))
                # Save record in list of found hosts
                found_records.append(rdata.next.to_text())

                # Get the next record
                #answer = None
                answer = res.get_nsec(rdata.next.to_text())
        # Break out of the loop once there are no more records given for the
        # Zone
        except dns.resolver.NoAnswer:
            print_status("Finished")
            break
        except (KeyboardInterrupt):
            print_error("You have pressed Crtl-C. Saving found records.")
            print_good("{0} Records Found".format(len(found_records)))
            return found_records
        except:
            print_good("{0} Records Found".format(len(found_records)))
            return returned_records
    print_good("{0} Records Found".format(len(found_records)))
    return returned_records

def general_enum(res, domain, do_axfr, do_google, do_spf, do_whois, zw):
    """
    Function for performing general enumeration of a domain. It gets SOA, NS, MX
    A, AAA and SRV records for a given domain.It Will first try a Zone Transfer
    if not successful it will try individual record type enumeration. If chosen
    it will also perform a Google Search and scrape the results for host names and
    perform an A and AAA query against them.
    """
    returned_records = []

    # Var for SPF Record Range Reverse Look-up
    found_spf_ranges = []
    ip_spf_list = []
    
    # Var to hold the IP Addresses that will be queried in Whois
    ip_for_whois = []
    
    # Check if wildcards are enabled on the target domain 
    check_wildcard(res, domain)

    # To identify when the records come from a Zone Transfer
    from_zt =  None
    
    # Perform test for Zone Transfer against all NS servers of a Domain
    if do_axfr is not None:
        returned_records.extend(res.zone_transfer())
        if len(returned_records) == 0:
            from_zt = True

    # If a Zone Trasfer was possible there is no need to enumerate the rest
    if from_zt == None:
        
        # Check if DNSSEC is configured
        dns_sec_check(domain,res)

        # Enumerate SOA Record

        try:
            found_soa_record = res.get_soa()
            print_status('\t {0} {1} {2}'.format(found_soa_record[0], found_soa_record[1], found_soa_record[2]))

            # Save dictionary of returned record
            returned_records.extend([{'type':found_soa_record[0],\
            "mname":found_soa_record[1],'address':found_soa_record[2]
            }])

            ip_for_whois.append(found_soa_record[2])

        except:
            print_error("Could not Resolve SOA Recor for {0}".format(domain))

        # Enumerate Name Servers
        try:
            for ns_rcrd in res.get_ns():
                print_status('\t {0} {1} {2}'.format(ns_rcrd[0], ns_rcrd[1], ns_rcrd[2]))

                # Save dictionary of returned record
                returned_records.extend([{'type':ns_rcrd[0],\
                "target":ns_rcrd[1],'address':ns_rcrd[2]
                }])

                ip_for_whois.append(ns_rcrd[2])

        except dns.resolver.NoAnswer:
            print_error("Could not Resolve NS Records for {0}".format(domain))

        # Enumerate MX Records
        try:
            for mx_rcrd in res.get_mx():
                print_status('\t {0} {1} {2}'.format(mx_rcrd[0], mx_rcrd[1], mx_rcrd[2]))

                # Save dictionary of returned record
                returned_records.extend([{'type':mx_rcrd[0],\
                "exchange":mx_rcrd[1],'address':mx_rcrd[2]
                }])

                ip_for_whois.append(mx_rcrd[2])

        except dns.resolver.NoAnswer:
            print_error("Could not Resolve MX Records for {0}".format(domain))

        # Enumerate A Record for the targeted Domain
        for a_rcrd in res.get_ip(domain):
            print_status('\t {0} {1} {2}'.format(a_rcrd[0], a_rcrd[1], a_rcrd[2]))

            # Save dictionary of returned record
            returned_records.extend([{'type':a_rcrd[0],\
            "name":a_rcrd[1],'address':a_rcrd[2]
            }])

            ip_for_whois.append(a_rcrd[2])

        # Enumerate SFP and TXT Records for the target domain
        text_data = ""
        spf_text_data = res.get_spf()

        # Save dictionary of returned record
        if spf_text_data is not None:
            for s in spf_text_data:
                print_status('\t {0} {1} {2}'.format(s[0], s[1], s[2]))
                text_data += s[2]
                returned_records.extend([{'type':s[0], 'name':s[1],\
                "text":s[1]
                }])

        txt_text_data = res.get_txt()

        # Save dictionary of returned record
        if txt_text_data is not None:
            for t in txt_text_data:
                print_status('\t {0} {1} {2}'.format(t[0], t[1], t[2]))
                text_data += t[2]
                returned_records.extend([{'type':t[0], 'name':t[1],\
                "text":t[2]
                }])

        # Process SPF records if selected
        if do_spf is not None:
            print_status("Expanding IP ranges found in DNS and TXT records for Reverse Look-up")
            found_spf_ranges.extend(process_spf_data(res, text_data))
            if len(found_spf_ranges) > 0:
                print_status("Performing Reverse Look-up of SPF Ranges")
                returned_records.extend(brute_reverse(res,unique(found_spf_ranges)))
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
                    ip_for_whois.append(r['address'])
                    returned_records.extend(r)

        if do_whois:
            whois_rcd = whois_ips(res, ip_for_whois)
            returned_records.extend(whois_rcd)

        if zw:
            zone_info = zone_walk(domain, res)
            if zone_info:
                returned_records.extend(zone_info)
        
        return returned_records 

        #sys.exit(0)

    return returned_records 


def usage():
    print("Version: {0}".format(__version__))
    print("Usage: dnsrecon.py <options>\n")
    print("Options:")
    print("   -h, --help                  Show this help message and exit")
    print("   -d, --domain      <domain>  Domain to Target for enumeration.")
    print("   -c, --cidr        <range>   CIDR for reverse look-up brute force (range/bitmask).")
    print("   -r, --range       <range>   IP Range for reverse look-up brute force in formats (first-last)")
    print("                               or in (range/bitmask).")
    print("   -n, --name_server <name>    Domain server to use, if none is given the SOA of the")
    print("                               target will be used")
    print("   -D, --dictionary  <file>    Dictionary file of sub-domain and hostnames to use for")
    print("                               brute force.")
    print("   -f                          Filter out of Brute Force Domain lookup records that resolve to")
    print("                               the wildcard defined IP Address when saving records.")
    print("   -t, --type        <types>   Specify the type of enumeration to perform:")
    print("                               std      To Enumerate general record types, enumerates.")
    print("                                        SOA, NS, A, AAAA, MX and SRV if AXRF on the")
    print("                                        NS Servers fail.\n")
    print("                               rvl      To Reverse Look Up a given CIDR IP range.\n")
    print("                               brt      To Brute force Domains and Hosts using a given")
    print("                                        dictionary.\n")
    print("                               srv      To Enumerate common SRV Records for a given \n")
    print("                                        domain.\n")
    print("                               axfr     Test all NS Servers in a domain for misconfigured")
    print("                                        zone transfers.\n")
    print("                               goo      Perform Google search for sub-domains and hosts.\n")
    print("                               snoop    To Perform a Cache Snooping against all NS ")
    print("                                        servers for a given domain, testing all with")
    print("                                        file containing the domains, file given with -D")
    print("                                        option.\n")
    print("                               tld      Will remove the TLD of given domain and test against")
    print("                                        all TLD's registered in IANA\n")
    print("                               zonewalk Will perform a DNSSEC Zone Walk using NSEC Records.\n")
    print("   -a                          Perform AXFR with the standard enumeration.")
    print("   -s                          Perform Reverse Look-up of ipv4 ranges in the SPF Record of the")
    print("                               targeted domain with the standard enumeration.")
    print("   -g                          Perform Google enumeration with the standard enumeration.")
    print("   -w                          Do deep whois record analysis and reverse look-up of IP")
    print("                               ranges found thru whois when doing standard query.")
    print("   -z                          Performs a DNSSEC Zone Walk with the standard enumeration.")
    print("   --threads          <number> Number of threads to use in Range Reverse Look-up, Forward")
    print("                               Look-up Brute force and SRV Record Enumeration")
    print("   --lifetime         <number> Time to wait for a server to response to a query.")
    print("   --db               <file>   SQLite 3 file to save found records.")
    print("   --xml              <file>   XML File to save found records.")
    print("   --csv              <file>   Comma separated value file.")
    sys.exit(0)


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
    ip_list = []
    ip_range = None
    results_db = None
    zonewalk = None
    csv_file = None
    wildcard_filter = None
    
    #
    # Global Vars
    #

    global pool
    
    #
    # Define options
    #
    try:
        options, args = getopt.getopt(sys.argv[1:], 'hzd:n:x:D:t:aq:gwr:fsc:',
                                           ['help',
                                           'zone_walk'
                                           'domain=',
                                           'name_server=',
                                           'xml=',
                                           'dictionary=',
                                           'type=',
                                           'axfr',
                                           'google',
                                           'do_whois',
                                           'range=',
                                           'do_spf',
                                           'csv=',
                                           'lifetime=',
                                           'threads=',
                                           'db='
                                           ])
    except getopt.GetoptError:
        print_error("Wrong Option Provided!")
        usage()
    #
    # Parse options
    #
    for opt, arg in options:
        if opt in ('-t','--type'):
            type = arg
            
        elif opt in ('-d','--domain'):
            domain = arg
                        
        elif opt in ('-n','--name_server'):
            ns_server = arg
            
        elif opt in ('-x','--xml'):
            output_file = arg
            
        elif opt in ('-D','--dictionary'):
            #Check if the dictionary file exists
            if os.path.isfile(arg):
                dict = arg
            else:
                print_error("File {0} does not exist!".format(arg))
                exit(1)
                
        elif opt in ('-a','--axfr'):
            xfr = True
            
        elif opt in ('-g','--google'):
            goo = True
            
        elif opt in ('-w','--do_whois'):
            do_whois = True
            
        elif opt in ('-z', '--zone_walk'):
            zonewalk = True

        elif opt in ('-s', '--do_spf'):
            spf_enum = True
            
        elif opt in ('-r','--range'):
            ip_range = process_range(arg)
            if len(ip_range) > 0:
                ip_list.extend(ip_range)
            else:
                sys.exit(1)
        elif opt in ('-f'):
            wildcard_filter = True

        elif opt in ('--theads'):
            thread_num = int(arg)
            
        elif opt in ('--lifetime'):
            request_timeout = float(arg)
            
        elif opt in ('--db'):
            results_db = arg
            
        elif opt in ('-c', '--csv'):
            csv_file = arg
            
        elif opt in ('-h'):
            usage()
            
    # Setting the number of threads to 10
    pool = ThreadPool(thread_num)
    
    # Set the resolver
    res = DnsHelper(domain, ns_server, request_timeout)
        
    if type is not None:
        for r in type.split(','):
            try:
                if r == 'axfr':
                    if domain is not None:
                        print_status('Testing NS Servers for Zone Transfer')
                        returned_records.extend(res.zone_transfer())

                    else:
                        print_error('No Domain to target specified!')
                        sys.exit(1)
                    
                elif r == 'std':
                    if domain is not None:
                        print_status("Performing General Enumeration of Domain:".format(domain))
                        std_enum_records = general_enum(res, domain, xfr, goo,\
                        spf_enum, do_whois, zonewalk)
                        
                        if (output_file is not None) or (results_db is not None) or (csv_file is not None):
                            returned_records.extend(std_enum_records)
                    else:
                        print_error('No Domain to target specified!')
                        sys.exit(1)
                    
                elif r == 'rvl':
                    if len(ip_list) > 0:
                        print_status('Reverse Look-up of a Range')
                        rvl_enum_records = brute_reverse(res, ip_list)

                        if (output_file is not None) or (results_db is not None) or (csv_file is not None):
                            returned_records.extend(rvl_enum_records)
                    else:
                        print_error('Failed CIDR or Range is Required for type rvl')
                        
                elif r == 'brt':
                    if (dict is not None) and (domain is not None):
                        print_status('Performing host and subdomain brute force against {0}'.format(domain))
                        brt_enum_records = brute_domain(res, dict, domain, wildcard_filter)

                        if (output_file is not None) or (results_db is not None) or (csv_file is not None):
                            returned_records.extend(brt_enum_records)
                    else:
                        print_error('No Dictionary file specified!')
                        sys.exit(1)
                        
                elif r == 'srv':
                    if domain is not None:
                        print_status('Enumerating Common SRV Records against {0}'.format(domain))
                        srv_enum_records = brute_srv(res, domain)

                        if (output_file is not None) or (results_db is not None) or (csv_file is not None):
                            returned_records.extend(srv_enum_records)
                    else:
                        print('[-] No Domain to target specified!')
                        sys.exit(1)
                    
                elif r == 'tld':
                    if domain is not None:
                        print_status("Performing TLD Brute force Enumeration against {0}".format(domain))
                        tld_enum_records = brute_tlds(res, domain)
                        if (output_file is not None) or (results_db is not None) or (csv_file is not None):
                            returned_records.extend(tld_enum_records)
                    else:
                        print('[-] No Domain to target specified!')
                        sys.exit(1)
                        
                elif r == 'goo':
                    if domain is not None:
                        print_status("Performing Google Search Enumeration against{0}".format(domain))
                        goo_enum_records = goo_result_process(res, scrape_google(domain))
                        if (output_file is not None) or (results_db is not None) or (csv_file is not None):
                            returned_records.extend(goo_enum_records)
                    else:
                        print('[-] No Domain to target specified!')
                        sys.exit(1)
                        
                elif r == "snoop":
                    if (dict is not None) and (ns_server is not None):
                        print_status("Performing Cache Snooping against NS Server: {0}".format(ns_server))
                        cache_enum_records = in_cache(dict,ns_server)
                        if (output_file is not None) or (results_db is not None) or (csv_file is not None):
                            returned_records.extend(cache_enum_records)
                            
                    else:
                        print_error('No Domain or Name Server to target specified!')
                        sys.exit(1)

                elif r == "zonewalk":
                    if domain is not None:
                        if (output_file is not None) or (results_db is not None) or (csv_file is not None):
                            returned_records.extend(zone_walk(domain, res))
                        else:
                            zone_walk(domain, res)
                    else:
                        print_error('No Domain or Name Server to target specified!')
                        sys.exit(1)

                else:
                    print_error("This type of scan is not in the list {0}".format(r))
                    usage()
            
                    
            except dns.resolver.NXDOMAIN:
                print_error("Could not resolve domain: {0}".format(domain))
                sys.exit(1)

            except dns.exception.Timeout:
                print_error("A timeout error occurred please make sure you can reach the target DNS Servers")
                print_error("directly and requests are not being filtered. Increase the timeout from {0} second".format(request_timeout))
                print_error("to a higher number with --lifetime <time> option.")
                sys.exit(1)
        
        # if an output xml file is specified it will write returned results.
        if (output_file is not None):
            print_status("Saving records to XML file: {0}".format(output_file))
            xml_enum_doc = dns_record_from_dict(returned_records)
            write_to_file(xml_enum_doc,output_file)

        # if an output db file is specified it will write returned results.
        if (results_db is not None):
            print_status("Saving records to SQLite3 file: {0}".format(results_db))
            create_db(results_db)
            write_db(results_db,returned_records)
            
        # if an output csv file is specified it will write returned results.
        if (csv_file is not None):
            print_status("Saving records to CSV file: {0}".format(csv_file))
            write_to_file(make_csv(returned_records),csv_file)
            
        sys.exit(0)
        
    elif domain is not None:
        try:
            print_status("Performing General Enumeration of Domain: {0}".format(domain))
            std_enum_records = std_enum_records = general_enum(res, domain, xfr, goo,\
                                                               spf_enum, do_whois, zonewalk)

            returned_records.extend(std_enum_records)

            # if an output xml file is specified it will write returned results.
            if (output_file is not None):
                xml_enum_doc = dns_record_from_dict(returned_records)
                write_to_file(xml_enum_doc,output_file)

            # if an output db file is specified it will write returned results.
            if (results_db is not None):
                create_db(results_db)
                write_db(results_db,returned_records)
            
            # if an output csv file is specified it will write returned results.
            if (csv_file is not None):
                write_to_file(make_csv(returned_records),csv_file)

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
        
if __name__ == "__main__":
    main()
