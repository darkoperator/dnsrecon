#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#    reconDNS
#
#    Copyright (C) 2020  SecurityShrimp
#
#    python module version of dnsrecon by Carlos Perez
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

__version__ = '0.0.2'
__author__ = 'securityshrimp, https://twitter.com/securityshrimp'

__doc__ = """
reconDNS, python module version of DNSrecon by Carlos Perez

maintained by SecurityShrimp, https://twitter.com/securityshrimp

requires dnspython http://www.dnspython.org/
requires netaddr https://github.com/drkjam/netaddr/

"""

import os
import string
import datetime
import netaddr
from random import Random
from xml.dom import minidom
from xml.etree import ElementTree
from xml.etree.ElementTree import Element
import dns.message
import dns.query
import dns.rdatatype
import dns.resolver
import dns.reversename
import dns.zone
import dns.rdata
import dns.flags
from dns.dnssec import algorithm_to_text
from lib.crtenum import scrape_crtsh
from lib.bingenum import *
from lib.yandexenum import *
from lib.whois import *
from lib.dnshelper import DnsHelper
from lib.msf_print import *

from concurrent import futures

# Global Variables for Brute force Threads
brtdata = []

CONFIG = {
    "disable_check_recursion": False,
    "disable_check_bindversion": False
}


# Function Definitions
# -------------------------------------------------------------------------------

def process_range(arg):
    """
    Function will take a string representation of a range for IPv4 or IPv6 in
    CIDR or Range format and return a list of IPs.
    """
    try:
        ip_list = None
        range_vals = []
        if re.match(r"\S*/\S*", arg):
            ip_list = IPNetwork(arg)

        elif re.match(r"\S*-\S*", arg):
            range_vals.extend(arg.split("-"))
            if len(range_vals) == 2:
                ip_list = IPRange(range_vals[0], range_vals[1])
        else:
            print_error("Range provided is not valid")
            return []
    except Exception:
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
    if not re.search(r"v=spf", data):
        return

    # Parse the record for IPv4 Ranges, individual IPs and include TXT Records.
    ipv4.extend(re.findall(r"ip4:(\S*)", "".join(data)))
    ipv6.extend(re.findall(r"ip6:(\S*)", "".join(data)))

    # Create a list of IPNetwork objects.
    for ip in ipv4:
        for i in IPNetwork(ip):
            ip_list.append(i)

    for ip in ipv6:
        for i in IPNetwork(ip):
            ip_list.append(i)

    # Extract and process include values.
    includes.extend(re.findall(r"include:(\S*)", "".join(data)))
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


def check_wildcard(res, domain_trg):
    """
    Function for checking if Wildcard resolution is configured for a Domain
    """
    wildcard = None
    test_name = ''.join(Random().sample(string.hexdigits + string.digits,
                                        12)) + "." + domain_trg
    ips = res.get_a(test_name)

    if len(ips) > 0:
        print_debug("Wildcard resolution is enabled on this domain")
        print_debug("It is resolving to {0}".format("".join(ips[0][2])))
        print_debug("All queries will resolve to this address!!")
        wildcard = "".join(ips[0][2])

    return wildcard


def check_nxdomain_hijack(nameserver):
    """
    Function for checking if a name server performs NXDOMAIN hijacking
    """

    test_name = ''.join(Random().sample(string.hexdigits + string.digits,
                                        20)) + ".com"

    res = dns.resolver.Resolver(configure=False)
    res.nameservers = [nameserver]
    res.timeout = 5.0

    address = []

    for record_type in ('A', 'AAAA'):
        try:
            answers = res.resolve(test_name, record_type, tcp=True)
        except (
                dns.resolver.NoNameservers, dns.resolver.NXDOMAIN, dns.exception.Timeout, dns.resolver.NoAnswer,
                socket.error,
                dns.query.BadResponse):
            continue

        if answers:
            for ardata in answers.response.answer:
                for rdata in ardata:
                    if rdata.rdtype == 5:
                        if rdata.target.to_text().endswith('.'):
                            address.append(rdata.target.to_text()[:-1])
                        else:
                            address.append(rdata.target.to_text())
                    else:
                        address.append(rdata.address)

    if len(address) > 0:
        print_error("Nameserver {} performs NXDOMAIN hijacking".format(nameserver))
        print_error("It resolves nonexistent domains to {}".format(", ".join(address)))
        print_error("This server has been removed from the name server list!")
        return True

    return False


def brute_tlds(res, domain, verbose=False, thread_num=None):
    """
    This function performs a check of a given domain for known TLD values.
    prints and returns a dictionary of the results.
    """
    global brtdata
    brtdata = []

    # https://en.wikipedia.org/wiki/Country_code_top-level_domain#Types
    # https://www.iana.org/domains
    # Taken from http://data.iana.org/TLD/tlds-alpha-by-domain.txt
    itld = ['arpa']

    # Generic TLD
    gtld = ['co', 'com', 'info', 'net', 'org']

    # Generic restricted TLD
    grtld = ['biz', 'name', 'online', 'pro', 'shop', 'site', 'top', 'xyz']

    # Sponsored TLD
    stld = ['aero', 'app', 'asia', 'cat', 'coop', 'dev', 'edu', 'gov', 'int', 'jobs', 'mil', 'mobi', 'museum', 'post',
            'tel', 'travel', 'xxx']

    # Country Code TLD
    cctld = ['ac', 'ad', 'ae', 'af', 'ag', 'ai', 'al', 'am', 'an', 'ao', 'aq', 'ar', 'as', 'at', 'au', 'aw', 'ax', 'az',
             'ba', 'bb', 'bd', 'be', 'bf', 'bg', 'bh', 'bi', 'bj', 'bl', 'bm', 'bn', 'bo', 'bq', 'br', 'bs', 'bt', 'bv',
             'bw', 'by', 'bz', 'ca', 'cc', 'cd', 'cf', 'cg', 'ch', 'ci', 'ck', 'cl', 'cm', 'cn', 'co', 'cr', 'cu', 'cv',
             'cw', 'cx', 'cy', 'cz', 'de', 'dj', 'dk', 'dm', 'do', 'dz', 'ec', 'ee', 'eg', 'eh', 'er', 'es', 'et', 'eu',
             'fi', 'fj', 'fk', 'fm', 'fo', 'fr', 'ga', 'gb', 'gd', 'ge', 'gf', 'gg', 'gh', 'gi', 'gl', 'gm', 'gn', 'gp',
             'gq', 'gr', 'gs', 'gt', 'gu', 'gw', 'gy', 'hk', 'hm', 'hn', 'hr', 'ht', 'hu', 'id', 'ie', 'il', 'im', 'in',
             'io', 'iq', 'ir', 'is', 'it', 'je', 'jm', 'jo', 'jp', 'ke', 'kg', 'kh', 'ki', 'km', 'kn', 'kp', 'kr', 'kw',
             'ky', 'kz', 'la', 'lb', 'lc', 'li', 'lk', 'lr', 'ls', 'lt', 'lu', 'lv', 'ly', 'ma', 'mc', 'md', 'me', 'mf',
             'mg', 'mh', 'mk', 'ml', 'mm', 'mn', 'mo', 'mp', 'mq', 'mr', 'ms', 'mt', 'mu', 'mv', 'mw', 'mx', 'my', 'mz',
             'na', 'nc', 'ne', 'nf', 'ng', 'ni', 'nl', 'no', 'np', 'nr', 'nu', 'nz', 'om', 'pa', 'pe', 'pf', 'pg', 'ph',
             'pk', 'pl', 'pm', 'pn', 'pr', 'ps', 'pt', 'pw', 'py', 'qa', 're', 'ro', 'rs', 'ru', 'rw', 'sa', 'sb', 'sc',
             'sd', 'se', 'sg', 'sh', 'si', 'sj', 'sk', 'sl', 'sm', 'sn', 'so', 'sr', 'ss', 'st', 'su', 'sv', 'sx', 'sy',
             'sz', 'tc', 'td', 'tf', 'tg', 'th', 'tj', 'tk', 'tl', 'tm', 'tn', 'to', 'tp', 'tr', 'tt', 'tv', 'tw', 'tz',
             'ua', 'ug', 'uk', 'um', 'us', 'uy', 'uz', 'va', 'vc', 've', 'vg', 'vi', 'vn', 'vu', 'wf', 'ws', 'yt', 'za',
             'zm', 'zw']

    domain_main = domain.split(".")[0]

    # Let the user know how long it could take
    #print_status("The operation could take up to: {0}".format(
        #time.strftime('%H:%M:%S', time.gmtime((len(itld) + len(gtld) + len(grtld) + len(stld) + len(cctld)) / 3))))

    total_tlds = list(set(itld + gtld + grtld + stld))

    if verbose:
        for tld in total_tlds:
            #print_status(f'Trying: {domain_main}.{tld}')
        for cc in cctld:
            #print_status(f'Trying: {domain_main}.{cc}')
        for cc, tld in zip(cctld, total_tlds):
            #print_status(f'Trying: {domain_main}.{cc}.{tld}')
    try:
        with futures.ThreadPoolExecutor(max_workers=thread_num) as executor:
            future_results = {**{executor.submit(res.get_ip, f'{domain_main}.{tld}'): tld for tld in total_tlds},
                              **{executor.submit(res.get_ip, f'{domain_main}.{cc}'): cc for cc in cctld},
                              **{executor.submit(res.get_ip, f'{domain_main}.{cc}.{tld}'): (cc, tld) for (cc, tld) in
                                 zip(cctld, total_tlds)}}

            brtdata = [future.result() for future in futures.as_completed(future_results)]
            brtdata = [result for result in brtdata if len(result) > 0]

    except Exception as e:
        print_error(e)
    found_tlds = []
    for rcd_found in brtdata:
        for rcd in rcd_found:
            if re.search(r"^A", rcd[0]):
                #print_good({"type": rcd[0], "name": rcd[1], "address": rcd[2]})
                found_tlds.append([{"type": rcd[0], "name": rcd[1], "address": rcd[2]}])
    #print_good(f"{len(found_tlds)} Records Found")
    return found_tlds


def brute_reverse(res, ip_list, verbose=False, thread_num=None):
    """
    Reverse look-up brute force for given CIDR example 192.168.1.1/24. Returns an
    Array of found records.
    """
    global brtdata
    brtdata = []

    #print_status("Performing Reverse Lookup from {0} to {1}".format(ip_list[0], ip_list[-1]))

    # Resolve each IP in a separate thread.

    ip_range = range(len(ip_list) - 1)

    try:

        with futures.ThreadPoolExecutor(max_workers=thread_num) as executor:
            future_results = {executor.submit(res.get_ptr, str(ip_list[x])): x for x in ip_range}
            brtdata = [future.result() for future in futures.as_completed(future_results)]
            brtdata = [result for result in brtdata if result]
            # Filter out results that are None
        if verbose:
            for x in ip_range:
                ipaddress = str(ip_list[x])
                #print_status("Trying {0}".format(ipaddress))
    except Exception as ex:
        print_error(ex)

    returned_records = []
    for rcd_found in brtdata:
        for rcd in rcd_found:
            returned_records.append([{'type': rcd[0], 'name': rcd[1], 'address': rcd[2]}])

    print_good("{0} Records Found".format(len(returned_records)))

    return returned_records


def brute_domain(res, dict, dom, filter=None, verbose=False, ignore_wildcard=False, thread_num=None):
    """
    Main Function for domain brute forcing
    """
    global brtdata
    brtdata = []
    wildcard_ip = None
    found_hosts = []
    continue_brt = "y"

    # Check if wildcard resolution is enabled
    wildcard_ip = check_wildcard(res, dom)
    if wildcard_ip and not ignore_wildcard:
        #print_status("Do you wish to continue? y/n")
        continue_brt = str(sys.stdin.readline()[:-1])
    if re.search(r"y", continue_brt, re.I):
        # Check if Dictionary file exists
        if os.path.isfile(dict):
            with open(dict) as file:
                targets = [f'{line.strip()}.{dom.strip()}' for line in file]
                if verbose:
                    for target in targets:
                        #print_status(f'Trying: {target}')
            with futures.ThreadPoolExecutor(max_workers=thread_num) as executor:
                future_results = {executor.submit(res.get_ip, target): target for target in targets}
                brtdata = [future.result() for future in futures.as_completed(future_results)]

        # Process the output of the threads.
        for rcd_found in brtdata:
            for rcd in rcd_found:
                if re.search(r"^A", rcd[0]):
                    # Filter Records if filtering was enabled
                    if filter:
                        if not wildcard_ip == rcd[2]:
                            found_hosts.extend([{"type": rcd[0], "name": rcd[1], "address": rcd[2]}])
                    else:
                        found_hosts.extend([{"type": rcd[0], "name": rcd[1], "address": rcd[2]}])
                elif re.search(r"^CNAME", rcd[0]):
                    found_hosts.extend([{"type": rcd[0], "name": rcd[1], "target": rcd[2]}])

        # Clear Global variable
        brtdata = []

    print_good("{0} Records Found".format(len(found_hosts)))
    return found_hosts


def in_cache(res, dict_file, ns):
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
            answer = res.query(query, ns)
            if len(answer.answer) > 0:
                for an in answer.answer:
                    for rcd in an:
                        if rcd.rdtype == 1:
                            #print_status(f"\tName: {an.name} TTL: {an.ttl} Address: {rcd.address} Type: A")

                            found_records.extend([{"type": "A", "name": an.name,
                                                   "address": rcd.address, "ttl": an.ttl}])

                        elif rcd.rdtype == 5:
                            #print_status(f"\tName: {an.name} TTL: {an.ttl} Target: {rcd.target} Type: CNAME")
                            found_records.extend([{"type": "CNAME", "name": an.name,
                                                   "target": rcd.target, "ttl": an.ttl}])

                        else:
                            #print_status()
    return found_records


def se_result_process(res, found_hosts):
    """
    This function processes the results returned from a Search Engine and does
    an A and AAAA query for the IP of the found host. Prints and returns a dictionary
    with all the results found.
    """
    returned_records = []
    if found_hosts is None:
        return None
    for sd in found_hosts:
        for sdip in res.get_ip(sd):
            if re.search(r"^A|CNAME", sdip[0]):
                if re.search(r"^A", sdip[0]):
                    returned_records.extend([{"type": sdip[0], "name": sdip[1],
                                              "address": sdip[2]}])
                else:
                    returned_records.extend([{"type": sdip[0], "name": sdip[1],
                                              "target": sdip[2]}])

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
                arin_style = re.search("NetRange", whois_data)
                ripe_apic_style = re.search("netname", whois_data)
                if arin_style or ripe_apic_style:
                    net = get_whois_nets(whois_data)
                    if net:
                        for network in net:
                            org = get_whois_orgname(whois_data)
                            found_nets.append({"start": network[0], "end": network[1], "orgname": "".join(org)})
                else:
                    for line in whois_data.splitlines():
                        recordentrie = re.match(r"^(.*)\s\S*-\w*\s\S*\s(\S*\s-\s\S*)", line)
                        if recordentrie:
                            org = recordentrie.group(1)
                            net = get_whois_nets(recordentrie.group(2))
                            for network in net:
                                found_nets.append({"start": network[0], "end": network[1], "orgname": "".join(org)})
    # Remove Duplicates
    return [seen.setdefault(idfun(e), e) for e in found_nets if idfun(e) not in seen]


def whois_ips(res, ip_list):
    """
    This function will process the results of the whois lookups and present the
    user with the list of net ranges found and ask the user if he wishes to perform
    a reverse lookup on any of the ranges or all the ranges.
    """
    found_records = []
    #print_status("Performing Whois lookup against records found.")
    list = get_whois_nets_iplist(unique(ip_list))
    if len(list) > 0:
        #print_status("The following IP Ranges were found:")
        for i in range(len(list)):
            #print_status(
                "\t {0} {1}-{2} {3}".format(str(i) + ")", list[i]["start"], list[i]["end"], list[i]["orgname"]))
        #print_status("What Range do you wish to do a Reverse Lookup for?")
        #print_status("number, comma separated list, a for all or n for none")
        val = sys.stdin.readline()[:-1]
        answer = str(val).split(",")

        if "a" in answer:
            for i in range(len(list)):
                #print_status("Performing Reverse Lookup of range {0}-{1}".format(list[i]['start'], list[i]['end']))
                found_records.append(brute_reverse(res, expand_range(list[i]['start'], list[i]['end'])))

        elif "n" in answer:
            #print_status("No Reverse Lookups will be performed.")
            pass
        else:
            for a in answer:
                net_selected = list[int(a)]
                #print_status(net_selected['orgname'])
                found_records.append(brute_reverse(res, expand_range(net_selected['start'], net_selected['end'])))
    else:
        print_error("No IP Ranges were found in the Whois query results")

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
                        k = str(k)
                        v = str(v)
                        elem.attrib[k] = v
                    except Exception:
                        print_error("Could not convert key or value to unicode: '{0} = {1}'".format((repr(k)), (repr(v))))
                        print_error("In element: {0}".format(repr(elem.attrib)))
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


def get_nsec_type(domain, res):
    target = "0." + domain

    answer = get_a_answer(res, target, res._res.nameservers[0], res._res.timeout)
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
        answer = res.resolve(domain, 'DNSKEY')
        #print_status("DNSSEC is configured for {0}".format(domain))
        nsectype = get_nsec_type(domain, res)
        #print_status("DNSKEYs:")
        for rdata in answer:
            if rdata.flags == 256:
                key_type = "ZSK"

            if rdata.flags == 257:
                key_type = "KSk"

            #print_status("\t{0} {1} {2} {3}".format(nsectype, key_type, algorithm_to_text(rdata.algorithm),
                                                    #dns.rdata._hexify(rdata.key)))

    except dns.resolver.NXDOMAIN:
        print_error(f"Could not resolve domain: {domain}")
        sys.exit(1)

    except dns.resolver.NoNameservers:
        print_error(f"All nameservers failed to answer the DNSSEC query for {domain}")

    except dns.exception.Timeout:
        print_error("A timeout error occurred please make sure you can reach the target DNS Servers")
        print_error("directly and requests are not being filtered. Increase the timeout from {0} second".format(
            res._res.timeout))
        print_error("to a higher number with --lifetime <time> option.")
        sys.exit(1)
    except dns.resolver.NoAnswer:
        print_error(f"DNSSEC is not configured for {domain}")


def check_bindversion(res, ns_server, timeout):
    """
    Check if the version of Bind can be queried for.
    """
    version = ""

    if not CONFIG or not CONFIG.get("disable_check_bindversion", False):
        request = dns.message.make_query('version.bind', 'txt', 'ch')
        try:
            response = res.query(request, ns_server, timeout=timeout, one_rr_per_rrset=True)
            if len(response.answer) > 0 and 'items' in response.answer[0]:
                #print_status(f"\t Bind Version for {ns_server} {response.answer[0].items[0].strings[0]}")
                version = response.answer[0].items[0].strings[0]
        except (dns.resolver.NXDOMAIN, dns.exception.Timeout, dns.resolver.NoAnswer, socket.error,
                dns.query.BadResponse):
            pass

    return version


def check_recursive(res, ns_server, timeout):
    """
    Check if a NS Server is recursive.
    """
    is_recursive = False

    if not CONFIG or not CONFIG.get("disable_check_recursion", False):
        query = dns.message.make_query('www.google.com.', dns.rdatatype.NS)
        try:
            response = res.query(query, ns_server, timeout)
            recursion_flag_pattern = r"\.*RA\.*"
            flags = dns.flags.to_text(response.flags)
            result = re.findall(recursion_flag_pattern, flags)
            if result:
                print_error(f"\t Recursion enabled on NS Server {ns_server}")
            is_recursive = True
        except (socket.error, dns.exception.Timeout):
            pass

    return is_recursive


def general_enum(res, domain, do_axfr, do_bing, do_yandex, do_spf, do_whois, do_crt, zw, thread_num=None):
    """
    Function for performing general enumeration of a domain. It gets SOA, NS, MX
    A, AAAA and SRV records for a given domain. It will first try a Zone Transfer
    if not successful it will try individual record type enumeration.
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
    if do_axfr:
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
                # Save dictionary of returned record
                returned_records.extend([{"type": found_soa_record[0],
                                          "mname": found_soa_record[1], "address": found_soa_record[2]}])

                ip_for_whois.append(found_soa_record[2])

        except Exception:
            print_error(f"Could not Resolve SOA Record for {domain}")

        # Enumerate Name Servers
        try:
            for ns_rcrd in res.get_ns():

                # Save dictionary of returned record
                recursive = check_recursive(res, ns_rcrd[2], res._res.timeout)
                bind_ver = check_bindversion(res, ns_rcrd[2], res._res.timeout)
                returned_records.extend([
                    {"type": ns_rcrd[0], "target": ns_rcrd[1], "address": ns_rcrd[2], "recursive": str(recursive),
                     "Version": bind_ver}])
                ip_for_whois.append(ns_rcrd[2])

        except dns.resolver.NoAnswer:
            print_error("Could not Resolve NS Records for {0}".format(domain))
        except dns.resolver.NoNameservers:
            print_error("All nameservers failed to answer the NS query for {0}".format(domain))
            sys.exit(1)

        # Enumerate MX Records
        try:
            for mx_rcrd in res.get_mx():
                # Save dictionary of returned record
                returned_records.extend([{"type": mx_rcrd[0], "exchange": mx_rcrd[1], 'address': mx_rcrd[2]}])

                ip_for_whois.append(mx_rcrd[2])

        except dns.resolver.NoAnswer:
            print_error(f"Could not Resolve MX Records for {domain}")
        except dns.resolver.NoNameservers:
            print_error(f"All nameservers failed to answer the MX query for {domain}")

        # Enumerate A Record for the targeted Domain
        for a_rcrd in res.get_ip(domain):

            # Save dictionary of returned record
            returned_records.extend([{"type": a_rcrd[0], "name": a_rcrd[1], "address": a_rcrd[2]}])

            ip_for_whois.append(a_rcrd[2])

        # Enumerate SFP and TXT Records for the target domain
        text_data = ""
        spf_text_data = res.get_spf()

        # Save dictionary of returned record
        if spf_text_data is not None:
            for s in spf_text_data:
                text_data = s[1]
                returned_records.extend([{"type": s[0], "strings": s[1]}])

        txt_text_data = res.get_txt()

        # Save dictionary of returned record
        if txt_text_data is not None:
            for t in txt_text_data:
                text_data += t[2]
                returned_records.extend([{"type": t[0], "name": t[1], "strings": t[2]}])

        domainkey_text_data = res.get_txt("_domainkey." + domain)

        # Save dictionary of returned record
        if domainkey_text_data is not None:
            for t in domainkey_text_data:
                text_data += t[2]
                returned_records.extend([{"type": t[0], "name": t[1], "strings": t[2]}])

        # Process SPF records if selected
        if do_spf and len(text_data) > 0:
            #print_status("Expanding IP ranges found in DNS and TXT records for Reverse Look-up")
            processed_spf_data = process_spf_data(res, text_data)
            if processed_spf_data is not None:
                found_spf_ranges.extend(processed_spf_data)
            if len(found_spf_ranges) > 0:
                #print_status("Performing Reverse Look-up of SPF Ranges")
                returned_records.extend(brute_reverse(res, unique(found_spf_ranges)))
            else:
                #print_status("No IP Ranges were found in SPF and TXT Records")

        # Enumerate SRV Records for the targeted Domain
        #print_status("Enumerating SRV Records")
        srv_rcd = brute_srv(res, domain, thread_num=thread_num)
        if srv_rcd:
            for r in srv_rcd:
                ip_for_whois.append(r["address"])
                returned_records.append(r)

        # Do Bing Search enumeration if selected
        if do_bing:
            #print_status("Performing Bing Search Enumeration")
            bing_rcd = se_result_process(res, scrape_bing(domain))
            if bing_rcd:
                for r in bing_rcd:
                    if "address" in bing_rcd:
                        ip_for_whois.append(r["address"])
                returned_records.extend(bing_rcd)

        # Do Yandex Search enumeration if selected
        if do_yandex:
            #print_status("Performing Yandex Search Enumeration")
            yandex_rcd = se_result_process(res, scrape_bing(domain))
            if yandex_rcd:
                for r in yandex_rcd:
                    if "address" in yandex_rcd:
                        ip_for_whois.append(r["address"])
                returned_records.extend(yandex_rcd)

        if do_crt:
            #print_status("Performing Crt.sh Search Enumeration")
            crt_rcd = se_result_process(res, scrape_crtsh(domain))
            for r in crt_rcd:
                if "address" in crt_rcd:
                    ip_for_whois.append(r["address"])
            returned_records.extend(crt_rcd)

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


def query_ds(res, target, ns, timeout=5.0):
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
        answer = res.query(query, ns, timeout)
    except dns.exception.Timeout:
        print_error("A timeout error occurred please make sure you can reach the target DNS Servers")
        print_error(
            "directly and requests are not being filtered. Increase the timeout from {0} second".format(timeout))
        print_error("to a higher number with --lifetime <time> option.")
        sys.exit(1)
    except Exception:
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
    families = get_constants("AF_")
    types = get_constants("SOCK_")
    try:
        for response in socket.getaddrinfo(target, 0):
            # Unpack the response tuple
            family, socktype, proto, canonname, sockaddr = response
            if families[family] == "AF_INET" and types[socktype] == "SOCK_DGRAM":
                found_recs.append(["A", target, sockaddr[0]])
            elif families[family] == "AF_INET6" and types[socktype] == "SOCK_DGRAM":
                found_recs.append(["AAAA", target, sockaddr[0]])
    except Exception:
        return found_recs
    return found_recs


def lookup_next(target, res):
    """
    Try to get the most accurate information for the record found.
    """
    DnsHelper(target)
    returned_records = []

    if re.search(r"^_[A-Za-z0-9_-]*._[A-Za-z0-9_-]*.", target, re.I):
        srv_answer = res.get_srv(target)
        if len(srv_answer) > 0:
            for r in srv_answer:
                ##print_status("\t {0}".format(" ".join(r)))
                returned_records.append({"type": r[0],
                                         "name": r[1],
                                         "target": r[2],
                                         "address": r[3],
                                         "port": r[4]})

    elif re.search(r"(_autodiscover\\.|_spf\\.|_domainkey\\.)", target, re.I):
        txt_answer = res.get_txt(target)
        if len(txt_answer) > 0:
            for r in txt_answer:
                ##print_status("\t {0}".format(" ".join(r)))
                returned_records.append({'type': r[0],
                                         'name': r[1], 'strings': r[2]})
        else:
            txt_answer = res.get_txt(target)
            if len(txt_answer) > 0:
                for r in txt_answer:
                    ##print_status("\t {0}".format(" ".join(r)))
                    returned_records.append({'type': r[0],
                                             'name': r[1], 'strings': r[2]})
            else:
                #print_status("\t A {0} no_ip".format(target))
                returned_records.append({"type": "A", "name": target, "address": "no_ip"})

    else:
        a_answer = res.get_ip(target)
        if len(a_answer) > 0:
            for r in a_answer:
                ##print_status("\t {0} {1} {2}".format(r[0], r[1], r[2]))
                if r[0] == "CNAME":
                    returned_records.append({"type": r[0], "name": r[1], "target": r[2]})
                else:
                    returned_records.append({"type": r[0], "name": r[1], "address": r[2]})
        else:
            a_answer = socket_resolv(target)
            if len(a_answer) > 0:
                for r in a_answer:
                    ##print_status("\t {0} {1} {2}".format(r[0], r[1], r[2]))
                    returned_records.append({"type": r[0], "name": r[1], "address": r[2]})
            else:
                #print_status("\t A {0} no_ip".format(target))
                returned_records.append({"type": "A", "name": target, "address": "no_ip"})

    return returned_records


def get_a_answer(res, target, ns, timeout):
    query = dns.message.make_query(target, dns.rdatatype.A, dns.rdataclass.IN)
    query.flags += dns.flags.CD
    query.use_edns(edns=True, payload=4096)
    query.want_dnssec(True)
    answer = res.query(query, ns, timeout)
    return answer


def get_next(res, target, ns, timeout):
    next_host = None
    response = get_a_answer(res, target, ns, timeout)
    for a in response.authority:
        if a.rdtype == 47:
            for r in a:
                next_host = r.next.to_text()[:-1]
    return next_host


def ds_zone_walk(res, domain):
    """
    Perform DNSSEC Zone Walk using NSEC records found in the error additional
    records section of the message to find the next host to query in the zone.
    """

    nameserver = ''

    try:
        soa_rcd = res.get_soa()[0][2]

        #print_status("Name Server {0} will be used".format(soa_rcd))
        res = DnsHelper(domain, soa_rcd, 3)
        nameserver = soa_rcd
    except Exception:
        print_error("This zone appears to be misconfigured, no SOA record found.")

    timeout = res._res.timeout

    records = []

    transformations = [
        # Send the hostname as-is
        lambda h, hc, dc: h,

        # Prepend a zero as a subdomain
        lambda h, hc, dc: "0.{0}".format(h),

        # Append a hyphen to the host portion
        lambda h, hc, dc: "{0}-.{1}".format(hc, dc) if hc else None,

        # Double the last character of the host portion
        lambda h, hc, dc: "{0}{1}.{2}".format(hc, hc[-1], dc) if hc else None
    ]

    pending = {domain}
    finished = set()

    try:
        while pending:
            # Get the next pending hostname
            hostname = pending.pop()
            finished.add(hostname)

            # Get all the records we can for the hostname
            records.extend(lookup_next(hostname, res))

            # Arrange the arguments for the transformations
            fields = re.search(r"^(^[^.]*)\.(\S+\.\S*)$", hostname)

            domain_portion = hostname
            if fields and fields.group(2):
                domain_portion = fields.group(2)

            host_portion = ""
            if fields and fields.group(1):
                host_portion = fields.group(1)

            params = [hostname, host_portion, domain_portion]

            walk_filter = "." + domain_portion
            walk_filter_offset = len(walk_filter) + 1

            for transformation in transformations:
                # Apply the transformation
                target = transformation(*params)
                if not target:
                    continue

                # Perform a DNS query for the target and process the response
                if not nameserver:
                    response = get_a_answer(res, target, res._res.nameservers[0], timeout)
                else:
                    response = get_a_answer(res, target, nameserver, timeout)
                for a in response.authority:
                    if a.rdtype != 47:
                        continue

                    # NSEC records give two results:
                    #   1) The previous existing hostname that is signed
                    #   2) The subsequent existing hostname that is signed
                    # Add the latter to our list of pending hostnames
                    for r in a:

                        # As an optimization Cloudflare (and perhaps others)
                        # return '\000.' instead of NODATA when a record doesn't
                        # exist. Detect this and avoid becoming tarpitted while
                        # permuting the namespace.
                        if r.next.to_text()[:5] == '\\000.':
                            continue

                        # Avoid walking outside of the target domain. This
                        # happens with certain misconfigured domains.
                        if r.next.to_text()[-walk_filter_offset:-1] == walk_filter:
                            pending.add(r.next.to_text()[:-1])

            # Ensure nothing pending has already been queried
            pending -= finished

    except KeyboardInterrupt:
        print_error("You have pressed Ctrl + C. Saving found records.")

    except dns.exception.Timeout:
        print_error("A timeout error occurred while performing the zone walk please make ")
        print_error("sure you can reach the target DNS Servers directly and requests")
        print_error("are not being filtered. Increase the timeout to a higher number")
        print_error("with --lifetime <time> option.")

    except EOFError:
        print_error(f"SoA nameserver {nameserver} failed to answer the DNSSEC query for {target}")

    except socket.error:
        print_error(f"SoA nameserver {nameserver} failed to answer the DNSSEC query for {domain}")

    # Give a summary of the walk
    if len(records) > 0:
        print_good("{0} records found".format(len(records)))
    else:
        print_error("Zone could not be walked")

    return records
