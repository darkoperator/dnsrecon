#!/usr/bin/env python
# -*- coding: utf-8 -*-

#    DNSRecon
#
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

__version__ = '0.3'
__author__ = 'Carlos Perez, Carlos_Perez@darkoperator.com'

__doc__ = """
DNSRecon http://www.darkoperator.com

 by Carlos Perez, Darkoperator

requires bonjour for Mac, Windows, Linux
requires pybonjour http://code.google.com/p/pybonjour/
requires dnspython http://www.dnspython.org/
requires netaddr https://github.com/drkjam/netaddr/

"""
import Queue
import getopt
import os
import re
import string
import sys
import time


from Queue import Queue
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

from netaddr import *

sys.path.append("lib/")

from gooenum import *
from whois import *
from mdnsenum import *
from dnshelper import DnsHelper

# Global Variables for Brute force Threads
brtdata = []



# Function Definitions
# -------------------------------------------------------------------------------

# Worker & Threadpool classes ripped from
# http://code.activestate.com/recipes/577187-python-thread-pool/


class Worker(Thread):

    """Thread executing tasks from a given tasks queue"""

    def __init__(self, tasks):
        Thread.__init__(self)
        self.tasks = tasks
        self.daemon = True
        self.start()
        # Global variable that will hold the results
        global brtdata
    def run(self):
        lck = Lock()
        found_recrd = []
        while True:
            (func, args, kargs) = self.tasks.get()
            try:
                found_recrd = func(*args, **kargs)
                if found_recrd:
                    lck.acquire()
                    brtdata.append(found_recrd)
                    lck.release()

            except Exception, e:
                print e
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


def write_to_file(data,target_file):
    """
    Function for writing returned data to a file
    """
    f = open(target_file, "a")
    f.write(data)
    f.close


    
def check_wildcard(res, domain_trg):
    """
    Function for checking if Wildcard resolution is configured for a Domain
    """
    wildcard = None
    test_name = ''.join(Random().sample(string.letters + string.digits,
                        12)) + '.' + domain_trg
    ips = res.get_a(test_name)
    
    if len(ips) > 0:
        print '[-] Wildcard resolution is enabled on this domain'
        print '[-] It is resolving to', ''.join(ips)
        print '[-] All queries will resolve to this address!!'
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
    print "[*] The operation could take up to:", time.strftime('%H:%M:%S', \
    time.gmtime(len(tlds)/4))
    
    try:
        for t in tlds:
            pool.add_task(res.get_ip, domain_main + "." + t)
            for g in gtld:
                pool.add_task(res.get_ip, domain_main+ "." + g + "." + t)

        # Wait for threads to finish.
        pool.wait_completion()
        
    except (KeyboardInterrupt):
        print "[-] You have pressed Crtl-C. Saving found records."
        
    # Process the output of the threads.
    for rcd_found in brtdata:
        for rcd in rcd_found:
            print "[*]\t"," ".join(rcd)
            found_tlds.extend([{'type':rcd[0],'name':rcd[1],'address':rcd[2]}])
    
    
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
        '_gc._tcp.', '_kerberos._tcp.', '_kerberos._udp.', '_ldap._tcp',
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
        '_jabber-client._tcp.', '_jabber-client._udp.',
        ]
#    print "[*] The operation could take up to:", time.strftime('%H:%M:%S', \
#    time.gmtime(len(srvrcd)/4))
    
    try:
        for srvtype in srvrcd:
            pool.add_task(res.get_srv, srvtype + domain)
            
            # Wait for threads to finish.
        pool.wait_completion()
    
    except (KeyboardInterrupt):
        print "[-] You have pressed Crtl-C. Saving found records."
    
        
    
    # Make sure we clear the variable
    
    if len(brtdata) > 0:
        for rcd_found in brtdata:
            for rcd in rcd_found:
                returned_records.extend([{'type':rcd[0],\
                'name':rcd[1],'target':rcd[2],'address':rcd[3],'port':rcd[2],\
                'weight':rcd[2]
                }])
                print "[*]\t", " ".join(rcd)
    else:
        print "[-] No SRV Records Found for",domain
    
    
    return returned_records


def brute_reverse(res,ip_list):
    """
    Reverse look-up brute force for given CIDR example 192.168.1.1/24. Returns an
    Array of found records.
    """
    global brtdata
    brtdata = []
    
    returned_records = []

    
#    # Give an estimated time to finish
#    print "[*] The operation could take up to:", time.strftime('%H:%M:%S', \
#    time.gmtime(len(ip_list)/2))
    
    # Resolve each IP in a separate thread.
    try:
        for x in ip_list:
            pool.add_task(res.get_ptr, x)

        # Wait for threads to finish.
        pool.wait_completion()
    except (KeyboardInterrupt):
        print "[-] You have pressed Crtl-C. Saving found records."
    
    for rcd_found in brtdata:
        for rcd in rcd_found:
            returned_records.extend([{'type':rcd[0],\
            "name":rcd[1],'address':rcd[2]
            }])
            print "[*]\t"," ".join(rcd)
    
    return returned_records

def brute_domain(res, dict, dom):
    """
    Main Function for domain brute forcing
    """
    global brtdata
    brtdata = []
    
    found_hosts = []
    continue_brt = 'y'
   
    # Check if wildcard resolution is enabled

    if check_wildcard(res, dom):
        continue_brt = raw_input('[*] Do you wish to continue? y/n ')
    if continue_brt == 'y':
        # Check if Dictionary file exists

        if os.path.isfile(dict):
            f = open(dict, 'r+')

            # Thread brute-force.

            for line in f:
                target = line.strip() + '.' + dom.strip()
                pool.add_task(res.get_ip, target)
                
        # Wait for threads to finish
        pool.wait_completion()
        
        # Process the output of the threads.
        for rcd_found in brtdata:
            for rcd in rcd_found:
                print "[*]\t"," ".join(rcd)
                
                found_hosts.extend([{'type':rcd[0],'name':rcd[1],'address':rcd[2]}])
        
        # Clear Global variable
        brtdata = []
        
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
                        print "[*]\tName:",an.name, "TTL:",an.ttl, "Address:",\
                        rcd.address, "Type: A"
                        
                        found_records.extend([{'type':"A",'name':an.name,\
                        'address':rcd.address,'ttl':an.ttl}])
                    
                    elif rcd.rdtype == 5:
                        print "[*]\tName:",an.name, "TTL:",an.ttl,"Target:",\
                        rcd.target, "Type: CNAME"
                        
                        found_records.extend([{'type':"CNAME",'name':an.name,\
                        'target':rcd.target,'ttl':an.ttl}])
                    
                    else:
                        print ""
    return found_records



def mdns_enum():
    """
    Function for enumerating several know types of mDNS records in the local
    subnet.
    """
    global brtdata
    brtdata = []
    found_results = []
    mdns_types = [
        '_appletv-itunes._tcp', '_touch-able._tcp', '_sleep-proxy._tcp',
        '_raop._tcp', '_touch-remote._tcp', '_appletv-pair._tcp', '_appletv._tcp',
        '_rfb._tcp', '_adisk._tcp', '_daap._tcp', '_presence._tcp', '_ichat._tcp',
        '_http._tcp', '_ftp._tcp', '_rtsp._tcp', '_distcc._tcp',
        '_tivo_servemedia._tcp', '_airport._tcp', '_afpovertcp._tcp',
        '_printer._tcp', '_ipp._tcp', '_pdl-datastream._tcp', '_eppc._tcp',
        '_workstation._tcp', '_ssh._tcp', '_telnet._tcp', '_tftp._udp',
        '_smb._tcp', '_netbios-ns._udp', '_netbios-ssn._tcp', '_apple-sasl._tcp',
        '_ssscreenshare._tcp', '_postgresql._tcp', '_pop3._tcp', '_imaps._tcp',
        '_imap._tcp', '_pop3s._tcp', '_bootps._udp', '_shell._tcp', '_login._tcp',
        '_teleport._udp', '_dacp._tcp', '_dpap._tcp', '_auth._tcp',
        '_fmpro-internal._tcp', '_h323._tcp', '_iwork._tcp', '_nfs._tcp',
        '_ptp._tcp', '_spl-itunes._tcp', '_spr-itunes._tcp', '_upnp._tcp',
        '_webdav._tcp', '_ws._tcp', '_exec._tcp', '_net-assistant._udp',
        '_raop._tcp', '_servermgr._tcp', '_sftp-ssh._tcp', '_asr._tcp',
        '_dacp._tcp', '_domain._udp', '_dns-llq._udp', '_iax._udp',
        '_kerberos-adm._tcp', '_kerberos._tcp', '_ntp._tcp', '_rsync._tcp',
        '_sip._udp', '_xmpp-client._tcp', '_xmpp-server._tcp', '_skype._tcp',
        '_ica-networking._tcp', '_presence._tcp', '_ofocus-sync._tcp',
        '_zuul1000205._udp', '_sub._ipp._tcp','_raop._tcp','_rfb._tcp','_growl._tcp',
        '_home-sharing._tcp','_odisk._tcp','_remote-jukebox._tcp',"_eppc._tcp",
        '_scanner._tcp', '_couchdb_location._tcp','_udisks-ssh._tcp','_presence._tcp'
        ]
    
    n = re.compile(u'(\x00|\x07|\x1A|\x16|\x06|\x08|\x1f|\xdb|\xb2|\xb0|\xb1'
                   u'\xc9|\xb9|\xcd|\u2019|\u2018|\u2019|\u201c|\u201d|\u2407)')
    
    t = re.compile(r'[\x00-\x1f|\x7f|\x0e]')
    
    for m in mdns_types:
        pool.add_task(mdns_browse, m)
    
    pool.wait_completion()
    for i in brtdata:
        for e in i:
            print "[*]\tHost:",e['host']
            host = e['host']
            print "[*]\tName:",n.sub(" ",e['name'])
            name = n.sub(" ",e['name'])
            print "[*]\tPort:",e['port']
            port = e['port']
            print "[*]\tTXTRecord:",t.sub(" ",e['txtRecord'])
            txtrecord = t.sub(" ",e['txtRecord'])
            print "[*]"
            found_results.extend([{'host':host,'name':name,'port':port,
                                   'txtrecord':txtrecord}])
    brtdata = []
    return found_results


def goo_result_process(res, found_hosts):
    """
    This function processes the results returned from the Google Search and does
    an A and AAAA query for the IP of the found host. Prints and returns a dictionary
    with all the results found.
    """
    returned_records = []
    for sd in found_hosts:
        for sdip in res.get_ip(sd):
            print '[*]\t', sdip[0], sdip[1], sdip[2]
            
            returned_records.extend([{'type':sdip[0], 'name':sdip[1], \
            'address':sdip[2]
            }])
    return returned_records

def get_whois_nets_iplist(ip_list):
    """
    This function will perform whois queries against a list of IP's and extract
    the net ranges and if available the orgasation list of each and remover any
    duplicate entries.
    """
    seen = {}
    idfun=repr
    found_nets = []
    for ip in ip_list:
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
    This function will proess the results of the whois lookups and present the 
    user with the list of net ranges found and ask the user if he wishes to perform
    a reverse lookup on any of the ranges or all the ranges.
    """
    answer = ""
    found_records = []
    print "[*] Performing Whois lookup against records found."
    list = get_whois_nets_iplist(unique(ip_list))
    print "[*] The following IP Ranges where found:"
    for i in range(len(list)):
        print "[*]\t",str(i)+")", list[i]['start'],"-",list[i]['end'],list[i]['orgname']
    print '[*] What Range do you wish to do a Revers Lookup for?' 
    print '(number, comma separated list, a for all or n for none)',
    answer = raw_input().split(",")

    if "a" in answer:
        for i in range(len(list)):
             print "[*] Performing Reverse Lookup of range", list[i]['start'],'-',list[i]['end']
             found_records.append(brute_reverse(res, \
                expand_range(list[i]['start'],list[i]['end'])))

    elif "n" in answer:
        print "[*] No Reverse Lookups will be performed."
        pass
    else:
        for a in answer:
            net_selected = list[int(a)]
            print net_selected['orgname']
            print "[*] Performing Reverse Lookup of range", net_selected['start'],'-',net_selected['end']
            found_records.append(brute_reverse(res, \
                expand_range(net_selected['start'],net_selected['end'])))
    
    return found_records


def general_enum(res, domain, do_axfr,do_google,do_spf, do_whois):
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
    
    # Perform test for Zone Transfer against all NS servers of a Domain
    if do_axfr is not None:
        returned_records.extend(res.zone_transfer())
        
    # Enumerate SOA Record
    
    try:
        found_soa_record = res.get_soa()
        print '[*]\t', found_soa_record[0], found_soa_record[1], found_soa_record[2]

        # Save dictionary of returned record
        returned_records.extend([{'type':found_soa_record[0],\
        "mname":found_soa_record[1],'address':found_soa_record[2]
        }])
        
        ip_for_whois.append(found_soa_record[2])
        
    except:
        print "[-] Could not Resolve SOA Recor for",domain

    # Enumerate Name Servers
    try:
        for ns_rcrd in res.get_ns():
            print '[*]\t', ns_rcrd[0], ns_rcrd[1], ns_rcrd[2]

            # Save dictionary of returned record
            returned_records.extend([{'type':ns_rcrd[0],\
            "target":ns_rcrd[1],'address':ns_rcrd[2]
            }])
            
            ip_for_whois.append(ns_rcrd[2])
            
    except dns.resolver.NoAnswer:
        print "[-] Could not Resolve NS Records for",domain
        
    # Enumerate MX Records
    try:
        for mx_rcrd in res.get_mx():
            print '[*]\t', mx_rcrd[0], mx_rcrd[1], mx_rcrd[2]

            # Save dictionary of returned record
            returned_records.extend([{'type':mx_rcrd[0],\
            "exchange":mx_rcrd[1],'address':mx_rcrd[2]
            }])
            
            ip_for_whois.append(mx_rcrd[2])
            
    except dns.resolver.NoAnswer:
        print "[-] Could not Resolve MX Records for",domain
    
    # Enumerate A Record for the targeted Domain
    for a_rcrd in res.get_ip(domain):
        print '[*]\t', a_rcrd[0], a_rcrd[1], a_rcrd[2]
        
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
        returned_records.extend([{'type':spf_text_data[0],\
        "text":spf_text_data[1]
        }])
    
    txt_text_data = res.get_txt()
    
    # Save dictionary of returned record
    if txt_text_data is not None:
        returned_records.extend([{'type':txt_text_data[0],\
        "text":txt_text_data[1]
        }])
    
    if spf_text_data is not None: text_data += spf_text_data[1]
    if txt_text_data is not None: text_data += txt_text_data[1]
    
    # Process ipv4 SPF records if selected
    if do_spf is not None:
        found_spf_ranges.extend(re.findall(\
        '([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/\d*)',"".join(text_data)))
        if len(found_spf_ranges) > 0:
            print "[*] Performing Reverse Look-up of SPF ipv4 Ranges"
            for c in found_spf_ranges:
                ip = IPNetwork(c)
                ip_list = list(ip)
                for i in ip_list:
                    ip_spf_list.append(str(i))
            returned_records.extend(brute_reverse(res,unique(ip_spf_list)))
        
        
    # Enumerate SRV Records for the targeted Domain
    print '[*] Enumerating SRV Records'
    srv_rcd = brute_srv(res, domain)
    if srv_rcd:
        for r in srv_rcd:
            ip_for_whois.append(r['address'])
            returned_records.extend(r)
    
    # Do Google Search enumeration if selected
    if do_google is not None:
        print '[*] Performing Google Search Enumeration'
        goo_rcd = goo_result_process(res, scrape_google(domain))
        if goo_rcd:
            for r in goo_rcd:
                ip_for_whois.append(r['address'])
                returned_records.extend(r)
                
    if do_whois:
        whois_ips(res, ip_for_whois)
        
        
    return returned_records


def prettify(elem):
    """
    Return a pretty-printed XML string for the Element.
    """
    rough_string = ElementTree.tostring(elem, 'utf-8')
    reparsed = minidom.parseString(rough_string)
    return reparsed.toprettyxml(indent="  ")


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


def usage():
    print "Usage: dnsrecon.py <options>\n"
    print "Options:"
    print "  -h, --help                  Show this help message and exit"
    print "  -d, --domain      <domain>  Domain to Target for enumeration."
    print "  -c, --cidr        <range>   CIDR for reverse look-up brute force (range/bitmask)."
    print "  -r, --range       <range>   IP Range for reverse look-up brute force (first-last)."
    print "  -n, --name_server <name>    Domain server to use, if none is given the SOA of the"
    print "                              target will be used"
    print "  -f, --output_file <file>    File to save found records."
    print "  -D, --dictionary  <file>    Dictionary file of sub-domain and hostnames to use for"
    print "                              brute force."
    print "  -t, --type        <types>   Specify the type of enumeration to perform:"
    print "                              mdns    To Enumerate local subnet with mDNS.\n"
    print "                              std     To Enumerate general record types, enumerates."
    print "                                      SOA, NS, A, AAAA, MX and SRV if AXRF on the"
    print "                                      NS Servers fail.\n"
    print "                              rvl     To Reverse Look Up a given CIDR IP range.\n"
    print "                              brt     To Brute force Domains and Hosts using a given"
    print "                                      dictionary.\n"
    print "                              srv     To Enumerate common SRV Records for a given \n"
    print "                                      domain.\n"
    print "                              axfr    Test all NS Servers in a domain for misconfigured"
    print "                                      zone transfers.\n"
    print "                              goo     Perform Google search for sub-domains and hosts.\n"
    print "                              snoop   To Perform a Cache Snooping against all NS "
    print "                                      servers for a given domain, testing all with"
    print "                                      file containing the domains, file given with -D"
    print "                                      option.\n"
    print "                              tld     Will remove the TLD of given domain and test against"
    print "                                      all TLD's registered in IANA\n"
    print "  -x, --axfr                  Perform AXFR with the standard enumeration."
    print "  -s, --do_spf                Perform Reverse Look-up of ipv4 ranges in the SPF Record of the"
    print "                              targeted domain with the standard enumeration."
    print "  -g, --google                Perform Google enumeration with the standard enumeration."
    print "  -w, --do_whois              Do deep whois record analysis and reverse look-up of IP"
    print "                              ranges found thru whois when doing standard query."
    print "  --threads          <number> Number of threads to use in Range Reverse Look-up, Forward"
    print "                              Look-up Brute force and SRV Record Enumeration"
    print "  --lifetime         <number> Time to wait for a server to response to a query."
    exit(0)


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
    request_timeout = 1.5
    ip_list = []
    ip_range = None
    ip_range_pattern ='([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})-([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})'
    
    #
    # Global Vars
    #

    global pool
    
    #
    # Define options
    #
    try:
        options, remainder = getopt.getopt(sys.argv[1:], 'hd:c:n:f:D:t:xq:gwr:s',
                                           ['help',
                                           'domain=',
                                           'cidr=',
                                           'name_server=',
                                           'output_file=',
                                           'dictionary=',
                                           'type=',
                                           'axfr',
                                           'google',
                                           'do_whois',
                                           'range=',
                                           'do_spf',
                                           'lifetime=',
                                           'threads='])
    except getopt.GetoptError:
        print "[-] Wrong Option Provided!"
        usage()
    #
    # Parse options
    #
    
    for opt, arg in options:
        
        if opt in ('-t','--type'):
            type = arg
            
        elif opt in ('-d','--domain'):
            domain = arg
            
        elif opt in ('-c','--cidr'):
            ip_list.extend(expand_cidr(arg))
            
        elif opt in ('-n','--name_server'):
            ns_server = arg
            
        elif opt in ('-f','--output_file'):
            output_file = arg
            
        elif opt in ('-D','--dictionary'):
            #Check if the dictionary file exists
            if os.path.isfile(arg):
                dict = arg
            else:
                print "[-] File",arg,"does not exist!"
                exit(1)
                
        elif opt in ('-x','--axfr'):
            xfr = True
            
        elif opt in ('-g','--google'):
            goo = True
            
        elif opt in ('-w','--do_whois'):
            do_whois = True
            
        elif opt in ('-s','--do_spf'):
            spf_enum = True
            
        elif opt in ('-r','--range'):
            ip_range = re.findall(ip_range_pattern,arg)
            ip_list.extend(expand_range(ip_range[0][0],ip_range[0][1]))
            
        elif opt in ('--theads'):
            thread_num = int(arg)
            
        elif opt in ('--lifetime'):
            request_timeout = float(arg)
            
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
                        print '[*] Testing NS Servers for Zone Transfer'
                        returned_records.extend(res.zone_transfer())

                    else:
                        print '[-] No Domain to target specified!'
                        exit(1)
                    
                elif r == 'std':
                    if domain is not None:
                        print "[*] Performing General Enumeration of Domain:",domain
                        std_enum_records = general_enum(res, domain, xfr, goo, spf_enum, do_whois)
                        if (output_file is not None): returned_records.extend(std_enum_records)
                    else:
                        print '[-] No Domain to target specified!'
                        exit(1)
                    
                elif r == 'rvl':
                    if len(ip_list) > 0:
                        print '[*] Reverse Look-up of a Range'
                        rvl_enum_records = brute_reverse(res, ip_list)
                        if (output_file is not None): returned_records.extend(rvl_enum_records)
                    else:
                        print '[-] Failed CIDR or Range is Required for type rvl'
                        
                elif r == 'brt':
                    if (dict is not None) and (domain is not None):
                        print '[*] Performing host and subdomain brute force against', \
                            domain
                        brt_enum_records = brute_domain(res, dict, domain)
                        if (output_file is not None): returned_records.extend(brt_enum_records)
                    else:
                        print '[-] No Dictionary file specified!'
                        exit(1)
                        
                elif r == 'srv':
                    if domain is not None:
                        print '[*] Enumerating Common SRV Records against', \
                            domain
                        srv_enum_records = brute_srv(res, domain)
                        if (output_file is not None): returned_records.extend(srv_enum_records)
                    else:
                        print '[-] No Domain to target specified!'
                        exit(1)
                    
                elif r == 'mdns':
                    print '[*] Enumerating most common mDNS Records on Subnet'
                    mdns_enum_records = mdns_enum()
                    if (output_file is not None): returned_records.extend(mdns_enum_records)
                    
                elif r == 'tld':
                    if domain is not None:
                        print "[*] Performing TLD Brute force Enumeration against", domain
                        tld_enum_records = brute_tlds(res, domain)
                        if (output_file is not None): returned_records.extend(tld_enum_records)
                    else:
                        print '[-] No Domain to target specified!'
                        exit(1)
                        
                elif r == 'goo':
                    if domain is not None:
                        print "[*] Performing Google Search Enumeration against", domain
                        goo_enum_records = goo_result_process(res, scrape_google(domain))
                        if (output_file is not None): returned_records.extend(goo_enum_records)
                    else:
                        print '[-] No Domain to target specified!'
                        exit(1)
                        
                elif r == "snoop":
                    if (dict is not None) and (ns_server is not None):
                        print "[*] Performing Cache Snooping against NS Server:", ns_server
                        cache_enum_records = in_cache(dict,ns_server)
                        if (output_file is not None): returned_records.extend(cache_enum_records)
                    else:
                        print '[-] No Domain or Name Server to target specified!'
                        exit(1)
                    
                else:
                    print "[-] This type of scan is not in the list", r
                    usage()
            
                    
            except dns.resolver.NXDOMAIN:
                print "[-] Could not resolve domain:",domain
                exit(1)
            except dns.exception.Timeout:
                print "[-] A timeout error occurred please make sure you can reach the target DNS Servers"
                print "[-] directly and requests are not being filtered. Increase the timeout from 1.0 second"
                print "[-] to a higher number with --lifetime <time> option."
                exit(1)
        
        # if an output xml file is specified it will write returned results.
        if (output_file is not None): 
            xml_enum_doc = dns_record_from_dict(returned_records)
            write_to_file(xml_enum_doc,output_file)
        exit(0)
    elif domain is not None:
        print "[*] Performing General Enumeration of Domain:",domain
        std_enum_records = general_enum(res, domain, xfr, goo, spf_enum, do_whois)
        if (output_file is not None): returned_records.extend(std_enum_records)
        
        # if an output xml file is specified it will write returned results.
        if (output_file is not None): 
            xml_enum_doc = dns_record_from_dict(returned_records)
            write_to_file(xml_enum_doc,output_file)
        exit(0)
    else:
        usage()
        
if __name__ == "__main__":
    main()