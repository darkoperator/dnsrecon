#!/usr/bin/env python3
#    DNSRecon
#
#    Copyright (C) 2023 Carlos Perez
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; Applies version 2 of the License.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#    See the GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program; if not, write to the Free Software
#    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

__version__ = '1.3.1'
__author__ = 'Carlos Perez, Carlos_Perez@darkoperator.com'
__name__ = 'cli'

__doc__ = """
DNSRecon https://www.darkoperator.com

 by Carlos Perez, Darkoperator
"""

import datetime
import json
import os
import sqlite3
import sys
from argparse import ArgumentError, ArgumentParser, RawTextHelpFormatter
from concurrent import futures
from pathlib import Path
from random import SystemRandom
from string import ascii_letters, digits
from xml.dom import minidom
from xml.etree import ElementTree
from xml.etree.ElementTree import Element

import dns.flags
import dns.message
import dns.query
import dns.rdata
import dns.rdatatype
import dns.resolver
import dns.reversename
import dns.zone
import netaddr
import requests
from dns.dnssec import algorithm_to_text
from loguru import logger

from dnsrecon.lib.bingenum import *
from dnsrecon.lib.crtenum import scrape_crtsh
from dnsrecon.lib.dnshelper import DnsHelper
from dnsrecon.lib.whois import *
from dnsrecon.lib.yandexenum import *

# Global Variables for Brute force Threads
brtdata = []

CONFIG = {'disable_check_recursion': False, 'disable_check_bindversion': False}
DATA_DIR = Path(__file__).parent / 'data'


def process_range(arg):
    """
    This function will take a string representation of a range for IPv4 or IPv6 in
    CIDR or Range format and return a list of individual IP addresses.
    """
    ip_list = []

    ranges_raw_list = list(set(arg.strip().split(',')))
    for entry in ranges_raw_list:
        try:
            if re.match(r'\S*/\S*', entry):
                # If CIDR, expand to individual IPs
                ip_list.extend(list(netaddr.IPNetwork(entry)))

            elif re.match(r'\S*-\S*', entry):
                # If range, expand to individual IPs
                start, end = entry.split('-')
                ip_list.extend(list(netaddr.iter_iprange(start, end)))
            else:
                logger.error(f'Range: {entry} provided is not valid')
        except Exception as e:
            logger.error(f'Error processing range: {entry} - {e}')

    return ip_list


def process_spf_data(res, data):
    """
    This function will take the text info of a TXT or SPF record, extract the
    IPv4, IPv6 addresses and ranges, a request process includes records and returns
    a list of IP Addresses for the records specified in the SPF Record.
    """
    # Declare lists that will be used in the function.
    ipv4 = []
    ipv6 = []
    includes = []
    ip_list = []

    # check first if it is a sfp record
    if not re.search(r'v=spf', data):
        return

    # Parse the record for IPv4 Ranges, individual IPs and include TXT Records.
    ipv4.extend(re.findall(r'ip4:(\S*)', ''.join(data)))
    ipv6.extend(re.findall(r'ip6:(\S*)', ''.join(data)))

    # Create a list of IPNetwork objects.
    for ip in ipv4:
        for i in netaddr.IPNetwork(ip):
            ip_list.append(i)

    for ip in ipv6:
        for i in netaddr.IPNetwork(ip):
            ip_list.append(i)

    # Extract and process include values.
    includes.extend(re.findall(r'include:(\S*)', ''.join(data)))
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
    return netaddr.IPNetwork(cidr_to_expand)


def expand_range(startip, endip):
    """
    Function to expand a given range and return an Array of IP Addresses that
    form the range.
    """
    return netaddr.IPRange(startip, endip)


def range2cidr(ip1, ip2):
    """
    Function to return the maximum CIDR given a range of IP's
    """
    r1 = netaddr.IPRange(ip1, ip2)
    return str(r1.cidrs()[-1])


def write_to_file(data, target_file):
    """
    Function for writing returned data to a file
    """
    with open(target_file, 'w') as fd:
        fd.write(data)


def generate_testname(name_len, name_suffix):
    """
    This function easily allows generating a testname
    to be used within the wildcard resolution and
    the NXDOMAIN hijacking checks
    """
    testname = SystemRandom().sample(ascii_letters + digits, name_len)
    return ''.join(testname) + '.' + name_suffix


def check_wildcard(res, domain_trg):
    """
    Function for checking if Wildcard resolution is configured for a Domain
    """
    testname = generate_testname(12, domain_trg)

    ips = res.get_a(testname)
    if not ips:
        return None

    wildcard_set = set()
    logger.debug('Wildcard resolution is enabled on this domain')
    for ip in ips:
        logger.debug(f'It is resolving to {ip[2]}')
        wildcard_set.add(ip[2])
    logger.debug('All queries will resolve to this list of addresses!!')
    return wildcard_set


def check_nxdomain_hijack(nameserver):
    """
    Function for checking if a name server performs NXDOMAIN hijacking
    """
    testname = generate_testname(20, 'com')

    res = dns.resolver.Resolver(configure=False)
    res.nameservers = [nameserver]
    res.timeout = 5.0

    address = []

    for record_type in ('A', 'AAAA'):
        try:
            answers = res.resolve(testname, record_type, tcp=True)
        except (
            dns.resolver.NoNameservers,
            dns.resolver.NXDOMAIN,
            dns.exception.Timeout,
            dns.resolver.NoAnswer,
            socket.error,
            dns.query.BadResponse,
        ):
            continue

        if answers:
            for ardata in answers.response.answer:
                for rdata in ardata:
                    if rdata.rdtype == 5:
                        target_ = rdata.target.to_text()
                        if target_.endswith('.'):
                            target_ = target_[:-1]
                        address.append(target_)
                    else:
                        address.append(rdata.address)

    if not address:
        return False

    addresses = ', '.join(address)
    logger.error(f'Nameserver {nameserver} performs NXDOMAIN hijacking')
    logger.error(f'It resolves nonexistent domains to {addresses}')
    logger.error('This server has been removed from the name server list!')
    return True


def brute_tlds(res, domain, verbose=False, thread_num=None):
    """
    This function performs a check of a given domain for known TLD values.
    Prints and returns a dictionary of the results.
    """

    total_tlds = []
    try:
        tlds_list = requests.get(
            'https://raw.githubusercontent.com/publicsuffix/list/master/public_suffix_list.dat', timeout=30
        ).text
    except Exception as e:
        tlds_list = ''
        logger.error(f'Error {e} retrieving TLDs list')

    for tld in tlds_list.split('\n'):
        if '/' not in tld.strip() and tld.strip() != '':
            total_tlds.append(tld.strip().lower().replace('*.', ''))

    # Let the user know how long it could take
    total_combinations = len(total_tlds)
    duration = time.strftime('%H:%M:%S', time.gmtime(total_combinations / 3))
    logger.info(f'The operation could take up to: {duration}')

    found_tlds = []

    try:
        with futures.ThreadPoolExecutor(max_workers=thread_num) as executor:
            future_results = {}

            for tld in total_tlds:
                full_domain = f'{domain}.{tld}'
                future_results[executor.submit(res.get_ip, full_domain)] = full_domain

                if verbose:
                    logger.info(f'Queuing: {full_domain}')

            # Display results as soon as threads are completed
            for future in futures.as_completed(future_results):
                full_domain = future_results[future]
                try:
                    res_ = future.result()
                    if res_:
                        for type_, name_, addr_ in res_:
                            if type_ in ['A', 'AAAA']:
                                logger.info(f'\t {type_} {name_} {addr_}')
                                found_tlds.append({'type': type_, 'name': name_, 'address': addr_})
                except Exception as e:
                    logger.error(f'Error resolving domain {full_domain}: {e}')

    except Exception as e:
        logger.error(f'Error during brute force: {e}')

    logger.info(f'{len(found_tlds)} Records Found')
    return found_tlds


def brute_srv(res, domain, verbose=False, thread_num=None):
    """
    Brute-force most common SRV records for a given Domain. Returns an Array with
    records found.
    """
    global brtdata
    brtdata = []
    returned_records = []
    srvrcd = [
        '_gc._tcp.',
        '_kerberos._tcp.',
        '_kerberos._udp.',
        '_ldap._tcp.',
        '_test._tcp.',
        '_sips._tcp.',
        '_sip._udp.',
        '_sip._tcp.',
        '_aix._tcp.',
        '_aix._tcp.',
        '_finger._tcp.',
        '_ftp._tcp.',
        '_http._tcp.',
        '_nntp._tcp.',
        '_telnet._tcp.',
        '_whois._tcp.',
        '_h323cs._tcp.',
        '_h323cs._udp.',
        '_h323be._tcp.',
        '_h323be._udp.',
        '_h323ls._tcp.',
        '_https._tcp.',
        '_h323ls._udp.',
        '_sipinternal._tcp.',
        '_sipinternaltls._tcp.',
        '_sip._tls.',
        '_sipfederationtls._tcp.',
        '_jabber._tcp.',
        '_xmpp-server._tcp.',
        '_xmpp-client._tcp.',
        '_imap.tcp.',
        '_certificates._tcp.',
        '_crls._tcp.',
        '_pgpkeys._tcp.',
        '_pgprevokations._tcp.',
        '_cmp._tcp.',
        '_svcp._tcp.',
        '_crl._tcp.',
        '_ocsp._tcp.',
        '_PKIXREP._tcp.',
        '_smtp._tcp.',
        '_hkp._tcp.',
        '_hkps._tcp.',
        '_jabber._udp.',
        '_xmpp-server._udp.',
        '_xmpp-client._udp.',
        '_jabber-client._tcp.',
        '_jabber-client._udp.',
        '_kerberos.tcp.dc._msdcs.',
        '_ldap._tcp.ForestDNSZones.',
        '_ldap._tcp.dc._msdcs.',
        '_ldap._tcp.pdc._msdcs.',
        '_ldap._tcp.gc._msdcs.',
        '_kerberos._tcp.dc._msdcs.',
        '_kpasswd._tcp.',
        '_kpasswd._udp.',
        '_imap._tcp.',
        '_imaps._tcp.',
        '_submission._tcp.',
        '_pop3._tcp.',
        '_pop3s._tcp.',
        '_caldav._tcp.',
        '_caldavs._tcp.',
        '_carddav._tcp.',
        '_carddavs._tcp.',
        '_x-puppet._tcp.',
        '_x-puppet-ca._tcp.',
        '_autodiscover._tcp.',
    ]

    try:
        with futures.ThreadPoolExecutor(max_workers=thread_num) as executor:
            if verbose:
                for srvtype in srvrcd:
                    srvtype_domain = srvtype + domain
                    logger.info(f'Trying {srvtype_domain}...')
            future_results = {executor.submit(res.get_srv, srvtype + domain): srvtype for srvtype in srvrcd}
            # Display logs as soon as a thread is finished
            for future in futures.as_completed(future_results):
                result = future.result()
                for type_, name_, target_, addr_, port_, priority_ in result:
                    returned_records.append(
                        {
                            'type': type_,
                            'name': name_,
                            'target': target_,
                            'address': addr_,
                            'port': port_,
                        }
                    )
                    logger.info(f'\t {type_} {name_} {target_} {addr_} {port_}')
    except Exception as e:
        logger.error(e)

    if len(returned_records) > 0:
        logger.info(f'{len(returned_records)} Records Found')
    else:
        logger.error(f'No SRV Records Found for {domain}')

    return returned_records


def brute_reverse(res, ip_list, verbose=False, thread_num=None):
    """
    Reverse look-up brute force for given CIDR example 192.168.1.1/24. Returns an
    Array of found records.
    """
    global brtdata
    brtdata = []
    returned_records = []

    # Ensure that ip_list contains individual IPs instead of IPNetwork or IPRange objects.
    expanded_ips = []
    for entry in ip_list:
        if isinstance(entry, netaddr.IPNetwork) or isinstance(entry, netaddr.IPRange):
            expanded_ips.extend(list(entry))
        else:
            expanded_ips.append(entry)

    start_ip = expanded_ips[0]
    end_ip = expanded_ips[-1]
    logger.info(f'Performing Reverse Lookup from {start_ip} to {end_ip}')

    ip_group_size = 255
    for ip_group in [expanded_ips[j : j + ip_group_size] for j in range(0, len(expanded_ips), ip_group_size)]:
        try:
            if verbose:
                for ip in ip_group:
                    logger.info(f'Trying {ip}')

            with futures.ThreadPoolExecutor(max_workers=thread_num) as executor:
                # Submit each IP for reverse lookup, converting to string as necessary
                future_results = {executor.submit(res.get_ptr, str(ip)): ip for ip in ip_group}

                # Display logs as soon as a thread is finished
                for future in futures.as_completed(future_results):
                    ip_address = future_results[future]
                    try:
                        res_ = future.result()
                        if res_:
                            for type_, name_, addr_ in res_:
                                returned_records.append({'type': type_, 'name': name_, 'address': addr_})
                                logger.info(f'\t {type_} {name_} {addr_}')
                    except Exception as e:
                        logger.error(f'Error resolving IP {ip_address}: {e}')

        except Exception as e:
            logger.error(f'Error with thread executor: {e}')

    logger.info(f'{len(returned_records)} Records Found')
    return returned_records


def brute_domain(
    res,
    dictfile,
    dom,
    filter_=None,
    verbose=False,
    ignore_wildcard=False,
    thread_num=None,
):
    """
    Main Function for domain brute forcing
    """
    global brtdata
    brtdata = []

    # Check if wildcard resolution is enabled
    wildcard_set = check_wildcard(res, dom)
    if wildcard_set and not ignore_wildcard:
        logger.info('Do you wish to continue? [Y/n]')
        i = input().lower().strip()
        if i not in ['y', 'yes']:
            logger.error('Domain bruteforcing aborted.')
            return None

    found_hosts = []

    # Check if the Dictionary file exists
    if os.path.isfile(dictfile):
        with open(dictfile) as fd:
            targets = [f'{line.strip()}.{dom.strip()}' for line in fd]
            if verbose:
                for target in targets:
                    logger.info(f'Trying {target}')
        with futures.ThreadPoolExecutor(max_workers=thread_num) as executor:
            future_results = {executor.submit(res.get_ip, target): target for target in targets}
            # Display logs as soon as a thread is finished
            for future in futures.as_completed(future_results):
                result = future.result()
                for type_, name_, address_or_target_ in result:
                    print_and_append = False
                    found_dict = {'type': type_, 'name': name_}
                    if type_ in ['A', 'AAAA']:
                        # Filter Records if filtering was enabled
                        if filter_:
                            if not wildcard_set or address_or_target_ not in wildcard_set:
                                print_and_append = True
                                found_dict['address'] = address_or_target_
                        else:
                            print_and_append = True
                            found_dict['address'] = address_or_target_
                    elif type_ == 'CNAME':
                        print_and_append = True
                        found_dict['target'] = address_or_target_

                    if print_and_append:
                        logger.info(f'\t {type_} {name_} {address_or_target_}')
                        found_hosts.append(found_dict)

                brtdata.append(res)

    logger.info(f'{len(found_hosts)} Records Found')
    return found_hosts


def in_cache(res, dict_file, ns):
    """
    Function for Cache Snooping, it will check a given NS server for a specific
    type of records for a given domain are in its cache.
    """
    found_records = []
    with open(dict_file) as f:
        for zone in f:
            dom_to_query = zone.strip()
            query = dns.message.make_query(dom_to_query, dns.rdatatype.A, dns.rdataclass.IN)
            query.flags ^= dns.flags.RD
            answer = res.query(query, ns)

            for an in answer.answer:
                for rcd in an:
                    if rcd.rdtype not in [1, 5]:
                        continue

                    found_record = {'name': an.name, 'ttl': an.ttl}
                    status = f'\tName: {an.name} TTL: {an.ttl} '

                    if rcd.rdtype == 1:
                        found_record['type'] = 'A'
                        found_record['address'] = rcd.address
                        status += f'Address: {rcd.address} Type: A'
                    elif rcd.rdtype == 5:
                        found_record['type'] = 'CNAME'
                        found_record['target'] = rcd.target
                        status += f'Target: {rcd.target} Type: CNAME'

                    logger.info(status)
                    found_records.append(found_record)

    return found_records


def se_result_process(res, se_entries):
    """
    This function processes the results returned from a Search Engine and does
    an A and AAAA query for the IP of the found host. Prints and returns a dictionary
    with all the results found.
    """
    if not se_entries:
        return None

    resolved_se_entries = []
    for se_entry in se_entries:
        for type_, name_, address_or_target_ in res.get_ip(se_entry):
            if type_ not in ['A', 'CNAME']:
                continue

            logger.info(f'\t {type_} {name_} {address_or_target_}')
            resolved_se_entry = {'type': type_, 'name': name_}

            if type_ == 'A':
                resolved_se_entry['address'] = address_or_target_
            elif type_ == 'CNAME':
                resolved_se_entry['target'] = address_or_target_

            resolved_se_entries.append(resolved_se_entry)

    logger.info(f'{len(resolved_se_entries)} Records Found')
    return resolved_se_entries


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
        if ip != 'no_ip':
            # Find appropriate Whois Server for the IP
            whois_server = get_whois(ip)
            # If we get a Whois server Process get the whois and process.
            if whois_server:
                whois_data = whois(ip, whois_server)
                arin_style = re.search('NetRange', whois_data)
                ripe_apic_style = re.search('netname', whois_data)
                if arin_style or ripe_apic_style:
                    net = get_whois_nets(whois_data)
                    if net:
                        for network in net:
                            org = get_whois_orgname(whois_data)
                            found_nets.append(
                                {
                                    'start': network[0],
                                    'end': network[1],
                                    'orgname': ''.join(org),
                                }
                            )
                else:
                    for line in whois_data.splitlines():
                        recordentrie = re.match(r'^(.*)\s\S*-\w*\s\S*\s(\S*\s-\s\S*)', line)
                        if recordentrie:
                            org = recordentrie.group(1)
                            net = get_whois_nets(recordentrie.group(2))
                            for network in net:
                                found_nets.append(
                                    {
                                        'start': network[0],
                                        'end': network[1],
                                        'orgname': ''.join(org),
                                    }
                                )
    # Remove Duplicates
    return [seen.setdefault(idfun(e), e) for e in found_nets if idfun(e) not in seen]


def whois_ips(res, ip_list):
    """
    This function will process the results of the whois lookups and present the
    user with the list of net ranges found and ask the user if he wishes to perform
    a reverse lookup on any of the ranges or all the ranges.
    """
    found_records = []
    logger.info('Performing Whois lookup against records found.')
    list_whois = get_whois_nets_iplist(unique(ip_list))
    if len(list_whois) > 0:
        logger.info('The following IP Ranges were found:')
        for i in range(len(list_whois)):
            logger.info(
                '\t {0} {1}-{2} {3}'.format(
                    str(i) + ')',
                    list_whois[i]['start'],
                    list_whois[i]['end'],
                    list_whois[i]['orgname'],
                )
            )
        logger.info('What Range do you wish to do a Reverse Lookup for?')
        logger.info('number, comma separated list, a for all or n for none')
        val = sys.stdin.readline()[:-1]
        answer = str(val).split(',')

        if 'a' in answer:
            for i in range(len(list_whois)):
                logger.info('Performing Reverse Lookup of range {0}-{1}'.format(list_whois[i]['start'], list_whois[i]['end']))
                found_records.append(brute_reverse(res, expand_range(list_whois[i]['start'], list_whois[i]['end'])))

        elif 'n' in answer:
            logger.info('No Reverse Lookups will be performed.')
        else:
            for a in answer:
                net_selected = list_whois[int(a)]
                logger.info(net_selected['orgname'])
                logger.info('Performing Reverse Lookup of range {0}-{1}'.format(net_selected['start'], net_selected['end']))
                found_records.append(brute_reverse(res, expand_range(net_selected['start'], net_selected['end'])))
    else:
        logger.error('No IP Ranges were found in the Whois query results')

    return found_records


def prettify(elem):
    """
    Return a pretty-printed XML string for the Element.
    """
    rough_string = ElementTree.tostring(elem, 'utf-8')
    reparsed = minidom.parseString(rough_string)
    return reparsed.toprettyxml(indent='    ')


def dns_record_from_dict(record_dict_list, scan_info, domains):
    """
    Saves DNS Records to XML Given a list of dictionaries each representing
    a record to be saved, returns the XML Document formatted.
    """
    xml_doc = Element('dnsrecon')

    # Add scan information
    scanelem = Element('scaninfo')
    scanelem.attrib['arguments'] = scan_info[0]
    scanelem.attrib['time'] = scan_info[1]
    xml_doc.append(scanelem)

    for domain in domains:
        domelem = Element('domain')
        domelem.attrib['domain_name'] = domain
        xml_doc.append(domelem)

        # Filter records for the current domain
        domain_records = [r for r in record_dict_list if r.get('domain') == domain]

        for r in domain_records:
            elem = Element('record')
            for k, v in r.items():
                if k != 'domain':  # Domain already represented by domelem
                    elem.attrib[k] = str(v)
            domelem.append(elem)

    return prettify(xml_doc)


def create_db(db):
    """
    This function will create the specified database if not present, and it will create
    the table needed for storing the data returned by the modules.
    """

    # Connect to the DB
    con = sqlite3.connect(db)

    # Create SQL Queries to be used in the script
    make_table = """CREATE TABLE data (
    serial integer  Primary Key Autoincrement,
    domain TEXT(256),
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
    csv_data = 'Domain,Type,Name,Address,Target,Port,String\n'
    for record_tmp in data:
        record = record_tmp
        # make sure that we are working with a dictionary.
        if not isinstance(record, dict):
            # the representation of data[i] is a list of one dictionary
            # we want to exploit this dictionary
            record = record_tmp[0]

        domain = record.get('domain', '')
        type_ = record['type'].upper()
        csv_data += f'{domain},{type_},'

        if type_ in ['PTR', 'A', 'AAAA', 'NS', 'SOA', 'MX']:
            if type_ in ['PTR', 'A', 'AAAA']:
                csv_data += record.get('name', '')
            elif type_ == 'NS':
                csv_data += record.get('target', '')
            elif type_ == 'SOA':
                csv_data += record.get('mname', '')
            elif type_ == 'MX':
                csv_data += record.get('exchange', '')

            csv_data += ',' + record.get('address', '') + (',' * 3) + '\n'

        elif type_ in ['TXT', 'SPF']:
            if 'zone_server' not in record:
                if type_ == 'SPF':
                    csv_data += record.get('domain', '')
                else:
                    csv_data += record.get('name', '')

            csv_data += (',' * 4) + f"'{record.get('strings', '')}'\n"

        elif type_ == 'SRV':
            items = [
                record.get('name', ''),
                record.get('address', ''),
                record.get('target', ''),
                record.get('port', ''),
            ]
            csv_data += ','.join(items) + ',\n'

        elif type_ == 'CNAME':
            csv_data += record.get('name', '') + (',' * 2)
            if 'target' in record:
                csv_data += record['target']

            csv_data += (',' * 2) + '\n'

        else:
            # Handle not common records
            del record['type']
            s = '; '.join([f'{k}={v}' for k, v in record.items()])
            csv_data += (',' * 4) + f"'{s}'\n"

    return csv_data


def write_json(jsonfile, data, scan_info):
    """
    Function to write DNS Records SOA, PTR, NS, A, AAAA, MX, TXT, SPF and SRV to
    JSON file.
    """
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
            query = (
                'insert into data( domain, type, name, address ) '
                + 'values( "{domain}", "{type}", "{name}","{address}" )'.format(**n)
            )

        elif re.match(r'NS$', n['type']):
            query = (
                'insert into data( domain, type, name, address ) '
                + 'values( "{domain}", "{type}", "{target}", "{address}" )'.format(**n)
            )

        elif re.match(r'SOA', n['type']):
            query = (
                'insert into data( domain, type, name, address ) '
                + 'values( "{domain}", "{type}", "{mname}", "{address}" )'.format(**n)
            )

        elif re.match(r'MX', n['type']):
            query = (
                'insert into data( domain, type, name, address ) '
                + 'values( "{domain}", "{type}", "{exchange}", "{address}" )'.format(**n)
            )

        elif re.match(r'TXT', n['type']):
            query = 'insert into data( domain, type, text) ' + 'values( "{domain}", "{type}","{strings}" )'.format(**n)

        elif re.match(r'SPF', n['type']):
            query = 'insert into data( domain, type, text) ' + 'values( "{domain}", "{type}","{strings}" )'.format(**n)

        elif re.match(r'SRV', n['type']):
            query = (
                'insert into data( domain, type, name, target, address, port ) '
                + 'values( "{domain}", "{type}", "{name}" , "{target}", "{address}" ,"{port}" )'.format(**n)
            )

        elif re.match(r'CNAME', n['type']):
            query = (
                'insert into data( domain, type, name, target ) '
                + 'values( "{domain}", "{type}", "{name}" , "{target}" )'.format(**n)
            )

        else:
            # Handle not common records
            t = n['type']
            del n['type']
            record_data = ''.join([f'{key}={value},' for key, value in n.items()])
            records = [t, record_data]
            query = 'insert into data(domain,type,text) values ("%(domain)", \'' + records[0] + "','" + records[1] + "')"

        # Execute Query and commit
        cur.execute(query)
        con.commit()


def get_nsec_type(domain, res):
    target = '0.' + domain

    answer = get_a_answer(res, target, res._res.nameservers[0], res._res.timeout)
    for a in answer.authority:
        if a.rdtype == 50:
            return 'NSEC3'
        elif a.rdtype == 47:
            return 'NSEC'


def dns_sec_check(domain, res):
    """
    Check if a zone is configured for DNSSEC and if so is NSEC or NSEC3 is used.
    """
    try:
        answer = res.resolve(domain, 'DNSKEY', res._res.nameservers[0])
        logger.info(f'DNSSEC is configured for {domain}')
        nsectype = get_nsec_type(domain, res)
        logger.info('DNSKEYs:')
        for rdata in answer:
            if rdata.flags == 256:
                key_type = 'ZSK'
            if rdata.flags == 257:
                key_type = 'KSk'
            logger.info(f'\t{nsectype} {key_type} {algorithm_to_text(rdata.algorithm)} {dns.rdata._hexify(rdata.key)}')
    except dns.resolver.NXDOMAIN:
        logger.error(f'Could not resolve domain: {domain}')
        sys.exit(1)
    except dns.resolver.NoNameservers:
        logger.error(f'All nameservers failed to answer the DNSSEC query for {domain}')
    except dns.exception.Timeout:
        logger.error('A timeout error occurred please make sure you can reach the target DNS Servers')
        logger.error(f'directly and requests are not being filtered. Increase the timeout from {res._res.timeout} second')
        logger.error('to a higher number with --lifetime <time> option.')
        sys.exit(1)
    except dns.resolver.NoAnswer:
        logger.error(f'No answer for DNSSEC query for {domain}')


def check_bindversion(res, ns_server, timeout):
    """
    Check if the version of Bind can be queried for.
    """
    version = ''

    if not CONFIG or not CONFIG.get('disable_check_bindversion', False):
        request = dns.message.make_query('version.bind', 'txt', 'ch')
        try:
            response = res.query(request, ns_server, timeout=timeout, one_rr_per_rrset=True)
            if len(response.answer) > 0:
                version = response.answer[0].to_text().split(' ')[-1]
                logger.info(f'\t Bind Version for {ns_server} {version}')

        except (
            dns.resolver.NXDOMAIN,
            dns.exception.Timeout,
            dns.resolver.NoAnswer,
            socket.error,
            dns.query.BadResponse,
        ):
            pass

    return version


def check_recursive(res, ns_server, timeout):
    """
    Check if an NS Server is recursive.
    """
    is_recursive = False

    if not CONFIG or not CONFIG.get('disable_check_recursion', False):
        query = dns.message.make_query('www.google.com.', dns.rdatatype.NS)
        try:
            response = res.query(query, ns_server, timeout)
            recursion_flag_pattern = r'\.*RA\.*'
            flags = dns.flags.to_text(response.flags)
            result = re.findall(recursion_flag_pattern, flags)
            if result:
                logger.error(f'\t Recursion enabled on NS Server {ns_server}')
            is_recursive = True
        except (socket.error, dns.exception.Timeout):
            pass

    return is_recursive


def general_enum(
    res,
    domain,
    do_axfr,
    do_bing,
    do_yandex,
    do_spf,
    do_whois,
    do_crt,
    zw,
    request_timeout,
    thread_num=None,
):
    """
    Function for performing general enumeration of a domain. It gets SOA, NS, MX
    A, AAAA and SRV records for a given domain. It will first try a Zone Transfer
    if not successful, it will try individual record type enumeration.
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

    # If a Zone Transfer was possible there is no need to enumerate the rest
    if from_zt is None:
        # Check if DNSSEC is configured
        dns_sec_check(domain, res)

        # Enumerate SOA Record
        try:
            found_soa_records = res.get_soa()
            for found_soa_record in found_soa_records:
                logger.info(f'\t {found_soa_record[0]} {found_soa_record[1]} {found_soa_record[2]}')

                # Save dictionary of returned record
                returned_records.extend(
                    [
                        {
                            'domain': domain,
                            'type': found_soa_record[0],
                            'mname': found_soa_record[1],
                            'address': found_soa_record[2],
                        }
                    ]
                )

                ip_for_whois.append(found_soa_record[2])

        except Exception:
            logger.info(found_soa_records)
            if found_soa_records == []:
                logger.error(f'No SOA records found for {domain}')
            else:
                logger.error(f'Could not Resolve SOA Record for {domain}')

        # Enumerate Name Servers
        try:
            for ns_rcrd in res.get_ns():
                logger.info(f'\t {ns_rcrd[0]} {ns_rcrd[1]} {ns_rcrd[2]}')

                # Save dictionary of returned record
                recursive = check_recursive(res, ns_rcrd[2], res._res.timeout)
                bind_ver = check_bindversion(res, ns_rcrd[2], res._res.timeout)
                returned_records.extend(
                    [
                        {
                            'domain': domain,
                            'type': ns_rcrd[0],
                            'target': ns_rcrd[1],
                            'address': ns_rcrd[2],
                            'recursive': str(recursive),
                            'Version': bind_ver,
                        }
                    ]
                )
                ip_for_whois.append(ns_rcrd[2])

        except dns.resolver.NoAnswer:
            logger.error(f'Could not Resolve NS Records for {domain}')
        except dns.resolver.NoNameservers:
            logger.error(f'All nameservers failed to answer the NS query for {domain}')
            sys.exit(1)

        # Enumerate MX Records
        try:
            for mx_rcrd in res.get_mx():
                logger.info(f'\t {mx_rcrd[0]} {mx_rcrd[1]} {mx_rcrd[2]}')

                # Save dictionary of returned record
                returned_records.extend(
                    [
                        {
                            'domain': domain,
                            'type': mx_rcrd[0],
                            'exchange': mx_rcrd[1],
                            'address': mx_rcrd[2],
                        }
                    ]
                )

                ip_for_whois.append(mx_rcrd[2])

        except dns.resolver.NoAnswer:
            logger.error(f'Could not Resolve MX Records for {domain}')
        except dns.resolver.NoNameservers:
            logger.error(f'All nameservers failed to answer the MX query for {domain}')

        # Enumerate A Record for the targeted Domain
        for a_rcrd in res.get_ip(domain):
            logger.info(f'\t {a_rcrd[0]} {a_rcrd[1]} {a_rcrd[2]}')

            # Save dictionary of returned record
            returned_records.extend(
                [
                    {
                        'domain': domain,
                        'type': a_rcrd[0],
                        'name': a_rcrd[1],
                        'address': a_rcrd[2],
                    }
                ]
            )

            ip_for_whois.append(a_rcrd[2])

        # Enumerate SFP and TXT Records for the target domain
        text_data = ''
        spf_text_data = res.get_spf()

        # Save dictionary of returned record
        if spf_text_data is not None:
            for s in spf_text_data:
                logger.info(f'\t {s[0]} {s[1]}')
                text_data = s[1]
                returned_records.extend([{'domain': domain, 'type': s[0], 'strings': s[1]}])

        txt_text_data = res.get_txt()

        # Save dictionary of returned record
        if txt_text_data is not None:
            for t in txt_text_data:
                logger.info(f'\t {t[0]} {t[1]} {t[2]}')
                text_data += t[2]
                returned_records.extend([{'domain': domain, 'type': t[0], 'name': t[1], 'strings': t[2]}])

        domainkey_text_data = res.get_txt('_domainkey.' + domain)

        # Save dictionary of returned record
        if domainkey_text_data is not None:
            for t in domainkey_text_data:
                logger.info(f'\t {t[0]} {t[1]} {t[2]}')
                text_data += t[2]
                returned_records.extend([{'domain': domain, 'type': t[0], 'name': t[1], 'strings': t[2]}])

        # Process SPF records if selected
        if do_spf and len(text_data) > 0:
            logger.info('Expanding IP ranges found in DNS and TXT records for Reverse Look-up')
            processed_spf_data = process_spf_data(res, text_data)
            if processed_spf_data is not None:
                found_spf_ranges.extend(processed_spf_data)
            if len(found_spf_ranges) > 0:
                logger.info('Performing Reverse Look-up of SPF Ranges')
                returned_records.extend(brute_reverse(res, unique(found_spf_ranges)))
            else:
                logger.info('No IP Ranges were found in SPF and TXT Records')

        # Enumerate SRV Records for the targeted Domain
        logger.info('Enumerating SRV Records')
        srv_rcd = brute_srv(res, domain, thread_num=thread_num)
        if srv_rcd:
            for r in srv_rcd:
                ip_for_whois.append(r['address'])
                returned_records.extend(
                    [
                        {
                            'domain': domain,
                            'type': r['type'],
                            'name': r['name'],
                            'target': r['target'],
                            'address': r['address'],
                            'port': r['port'],
                        }
                    ]
                )

        # Do Bing Search enumeration if selected
        if do_bing:
            logger.info('Performing Bing Search Enumeration')
            bing_rcd = se_result_process(res, scrape_bing(domain))
            if bing_rcd:
                for r in bing_rcd:
                    if 'address' in bing_rcd:
                        ip_for_whois.append(r['address'])
                returned_records.extend(bing_rcd)

        # Do Yandex Search enumeration if selected
        if do_yandex:
            logger.info('Performing Yandex Search Enumeration')
            yandex_rcd = se_result_process(res, scrape_bing(domain))
            if yandex_rcd:
                for r in yandex_rcd:
                    if 'address' in yandex_rcd:
                        ip_for_whois.append(r['address'])
                returned_records.extend(yandex_rcd)

        if do_crt:
            logger.info('Performing Crt.sh Search Enumeration')
            crt_rcd = se_result_process(res, scrape_crtsh(domain))
            if crt_rcd:
                for r in crt_rcd:
                    if 'address' in crt_rcd:
                        ip_for_whois.append(r['address'])
                returned_records.extend(crt_rcd)

        if do_whois:
            whois_rcd = whois_ips(res, ip_for_whois)
            if whois_rcd:
                for r in whois_rcd:
                    returned_records.extend(r)

        if zw:
            zone_info = ds_zone_walk(res, domain, request_timeout)
            if zone_info:
                returned_records.extend(zone_info)

        return returned_records


def query_ds(res, target, ns, timeout=5.0):
    """
    Function for performing DS Record queries. Returns answer object. Since a
    timeout will break the DS NSEC chain of a zone walk, it will exit if a timeout
    happens.
    """
    try:
        query = dns.message.make_query(target, dns.rdatatype.DS, dns.rdataclass.IN)
        query.flags += dns.flags.CD
        query.use_edns(edns=True, payload=4096)
        query.want_dnssec(True)
        answer = res.query(query, ns, timeout)
    except dns.exception.Timeout:
        logger.error('A timeout error occurred please make sure you can reach the target DNS Servers')
        logger.error(f'directly and requests are not being filtered. Increase the timeout from {timeout} second')
        logger.error('to a higher number with --lifetime <time> option.')
        sys.exit(1)
    except Exception:
        logger.error(f'Unexpected error: {sys.exc_info()[0]}')
        raise
    return answer


def get_constants(prefix):
    """
    Create a dictionary mapping socket module constants to their names.
    """
    return dict((getattr(socket, n), n) for n in dir(socket) if n.startswith(prefix))


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
            if families[family] == 'AF_INET' and types[socktype] == 'SOCK_DGRAM':
                found_recs.append(['A', target, sockaddr[0]])
            elif families[family] == 'AF_INET6' and types[socktype] == 'SOCK_DGRAM':
                found_recs.append(['AAAA', target, sockaddr[0]])
    except Exception:
        return found_recs
    return found_recs


def lookup_next(target, res):
    """
    Try to get the most accurate information for the record found.
    """
    DnsHelper(target)
    returned_records = []

    if re.search(r'^_[A-Za-z0-9_-]*._[A-Za-z0-9_-]*.', target, re.I):
        srv_answer = res.get_srv(target)
        if len(srv_answer) > 0:
            for r in srv_answer:
                logger.info('\t {0}'.format(' '.join(r)))
                returned_records.append(
                    {
                        'type': r[0],
                        'name': r[1],
                        'target': r[2],
                        'address': r[3],
                        'port': r[4],
                    }
                )

    elif re.search(r'(_autodiscover\\.|_spf\\.|_domainkey\\.)', target, re.I):
        txt_answer = res.get_txt(target)
        if len(txt_answer) > 0:
            for r in txt_answer:
                logger.info('\t {0}'.format(' '.join(r)))
                returned_records.append({'type': r[0], 'name': r[1], 'strings': r[2]})
        else:
            txt_answer = res.get_txt(target)
            if len(txt_answer) > 0:
                for r in txt_answer:
                    logger.info('\t {0}'.format(' '.join(r)))
                    returned_records.append({'type': r[0], 'name': r[1], 'strings': r[2]})
            else:
                logger.info(f'\t A {target} no_ip')
                returned_records.append({'type': 'A', 'name': target, 'address': 'no_ip'})

    else:
        a_answer = res.get_ip(target)
        if len(a_answer) > 0:
            for r in a_answer:
                logger.info(f'\t {r[0]} {r[1]} {r[2]}')
                if r[0] == 'CNAME':
                    returned_records.append({'type': r[0], 'name': r[1], 'target': r[2]})
                else:
                    returned_records.append({'type': r[0], 'name': r[1], 'address': r[2]})
        else:
            a_answer = socket_resolv(target)
            if len(a_answer) > 0:
                for r in a_answer:
                    logger.info(f'\t {r[0]} {r[1]} {r[2]}')
                    returned_records.append({'type': r[0], 'name': r[1], 'address': r[2]})
            else:
                logger.info(f'\t A {target} no_ip')
                returned_records.append({'type': 'A', 'name': target, 'address': 'no_ip'})

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


def ds_zone_walk(res, domain, lifetime):
    """
    Perform DNSSEC Zone Walk using NSEC records found in the error an additional
    records section of the message to find the next host to query in the zone.
    """
    logger.info(f'Performing NSEC Zone Walk for {domain}')
    logger.info(f'Getting SOA record for {domain}')

    nameserver = ''

    try:
        target_soas = res.get_soa()
        if target_soas:
            first_ns = target_soas[0]
            if first_ns:
                nameserver = first_ns[2]
                if nameserver:
                    logger.info(f'Name Server {nameserver} will be used')
                    res = DnsHelper(domain, nameserver, lifetime)

        if not nameserver:
            logger.error('This zone appears to be misconfigured, no SOA record found.')

    except Exception as err:
        logger.error(f'Exception while trying to determine the SOA records for domain {domain}: {err}')

    timeout = res._res.timeout

    records = []

    transformations = [
        # Send the hostname as-is
        lambda h, hc, dc: h,
        # Prepend a zero as a subdomain
        lambda h, hc, dc: f'0.{h}',
        # Append a hyphen to the host portion
        lambda h, hc, dc: f'{hc}-.{dc}' if hc else None,
        # Double the last character of the host portion
        lambda h, hc, dc: f'{hc}{hc[-1]}.{dc}' if hc else None,
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
            fields = re.search(r'^(^[^.]*)\.(\S+\.\S*)$', hostname)

            domain_portion = hostname
            if fields and fields.group(2):
                domain_portion = fields.group(2)

            host_portion = ''
            if fields and fields.group(1):
                host_portion = fields.group(1)

            params = [hostname, host_portion, domain_portion]

            walk_filter = '.' + domain_portion
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
        logger.error('You have pressed Ctrl + C. Saving found records.')

    except dns.exception.Timeout:
        logger.error('A timeout error occurred while performing the zone walk please make ')
        logger.error('sure you can reach the target DNS Servers directly and requests')
        logger.error('are not being filtered. Increase the timeout to a higher number')
        logger.error('with --lifetime <time> option.')

    except EOFError:
        logger.error(f'SoA nameserver {nameserver} failed to answer the DNSSEC query for {target}')

    except socket.error:
        logger.error(f'SoA nameserver {nameserver} failed to answer the DNSSEC query for {domain}')

    # Give a summary of the walk
    if len(records) > 0:
        logger.info(f'{len(records)} records found')
    else:
        logger.error('Zone could not be walked')

    return records


def main():
    #
    # Option Variables
    #

    output_file = None
    xfr = None
    bing = False
    yandex = False
    spf_enum = False
    do_whois = False
    do_crt = False

    # By default, thread_num will be None
    thread_num = None

    results_db = None
    zonewalk = False
    csv_file = None
    json_file = None
    wildcard_filter = False
    verbose = False
    ignore_wildcardrr = False

    # Initialize ns_server as an empty list
    ns_server = []

    #
    # Define options
    #
    parser = ArgumentParser(formatter_class=RawTextHelpFormatter)
    try:
        parser.add_argument('-d', '--domain', type=str, dest='domain', help='Target domain.')
        parser.add_argument(
            '-iL',
            '--input-list',
            type=str,
            dest='input_list',
            help='File containing a list of domains to perform DNS enumeration on, one per line.',
        )
        parser.add_argument(
            '-n',
            '--name_server',
            type=str,
            dest='ns_server',
            help='Domain server to use. If none is given, the SOA of the target will be used. Multiple servers can be specified using a comma separated list.',
        )
        parser.add_argument(
            '-r',
            '--range',
            type=str,
            dest='range',
            help='IP range for reverse lookup brute force in formats (first-last) or in (range/bitmask).',
        )
        parser.add_argument(
            '-D',
            '--dictionary',
            type=str,
            dest='dictionary',
            help='Dictionary file of subdomain and hostnames to use for brute force.',
        )
        parser.add_argument(
            '-f',
            help='Filter out of brute force domain lookup, records that resolve to the wildcard defined IP address when saving records.',
            action='store_true',
        )
        parser.add_argument('-a', help='Perform AXFR with standard enumeration.', action='store_true')
        parser.add_argument(
            '-s',
            help='Perform a reverse lookup of IPv4 ranges in the SPF record with standard enumeration.',
            action='store_true',
        )
        parser.add_argument(
            '-b',
            help='Perform Bing enumeration with standard enumeration.',
            action='store_true',
        )
        parser.add_argument(
            '-y',
            help='Perform Yandex enumeration with standard enumeration.',
            action='store_true',
        )
        parser.add_argument(
            '-k',
            help='Perform crt.sh enumeration with standard enumeration.',
            action='store_true',
        )
        parser.add_argument(
            '-w',
            help='Perform deep whois record analysis and reverse lookup of IP ranges found through Whois when doing a standard enumeration.',
            action='store_true',
        )
        parser.add_argument(
            '-z',
            help='Performs a DNSSEC zone walk with standard enumeration.',
            action='store_true',
        )
        parser.add_argument(
            '--threads',
            type=int,
            dest='threads',
            help='Number of threads to use in reverse lookups, forward lookups, brute force and SRV record enumeration.',
        )
        parser.add_argument(
            '--lifetime',
            type=float,
            dest='lifetime',
            default=3.0,
            help='Time to wait for a server to respond to a query. default is 3.0',
        )

        parser.add_argument(
            '--loglevel',
            type=str,
            choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
            default='INFO',
            help='Log level to use. default is INFO',
        )

        parser.add_argument(
            '--tcp',
            dest='tcp',
            help='Use TCP protocol to make queries.',
            action='store_true',
        )
        parser.add_argument('--db', type=str, dest='db', help='SQLite 3 file to save found records.')
        parser.add_argument('-x', '--xml', type=str, dest='xml', help='XML file to save found records.')
        parser.add_argument(
            '-c',
            '--csv',
            type=str,
            dest='csv',
            help='Save output to a comma separated value file.',
        )
        parser.add_argument('-j', '--json', type=str, dest='json', help='save output to a JSON file.')
        parser.add_argument(
            '--iw',
            help='Continue brute forcing a domain even if a wildcard record is discovered.',
            action='store_true',
        )
        parser.add_argument(
            '--disable_check_nxdomain', help='Disables check for NXDOMAIN hijacking on name servers.', action='store_true'
        )
        parser.add_argument(
            '--disable_check_recursion',
            help='Disables check for recursion on name servers',
            action='store_true',
        )
        parser.add_argument(
            '--disable_check_bindversion',
            help='Disables check for BIND version on name servers',
            action='store_true',
        )
        parser.add_argument('-V', '--version', help='DNSrecon version', action='store_true')
        parser.add_argument('-v', '--verbose', help='Enable verbosity', action='store_true')
        parser.add_argument(
            '-t',
            '--type',
            type=str,
            dest='type',
            help="""Type of enumeration to perform.
Possible types:
    std:      SOA, NS, A, AAAA, MX and SRV.
    rvl:      Reverse lookup of a given CIDR or IP range.
    brt:      Brute force domains and hosts using a given dictionary.
    srv:      SRV records.
    axfr:     Test all NS servers for a zone transfer.
    bing:     Perform Bing search for subdomains and hosts.
    yand:     Perform Yandex search for subdomains and hosts.
    crt:      Perform crt.sh search for subdomains and hosts.
    snoop:    Perform cache snooping against all NS servers for a given domain, testing
              all with file containing the domains, file given with -D option.

    tld:      Remove the TLD of given domain and test against all TLDs registered in IANA.
    zonewalk: Perform a DNSSEC zone walk using NSEC records.""",
        )
        arguments = parser.parse_args()
        logger.remove()
        logger.add(sys.stderr, format='{time} {level} {message}', level=arguments.loglevel)
        logger.add(Path(Path.home(), '.config/dnsrecon/dnsrecon.log'), rotation='100 MB', compression='tar.gz')

    except SystemExit:
        # Handle exit() from passing --help
        raise
    except ArgumentError as e:
        logger.error(f'Wrong Option Provided!: {e}')
        parser.print_help()
        sys.exit(1)

    # Ensure that both --domain and --input-list are not used simultaneously
    if arguments.domain and arguments.input_list:
        logger.error('Cannot specify both --domain and --input-list options simultaneously.')
        sys.exit(1)

    # if no arguments have been provided,
    # we exit and print program usage
    if not len(sys.argv) > 1:
        parser.print_usage()
        sys.exit(0)

    # a "map" that specifies if a type of scan needs
    # the domain and the dictionary
    type_map = {
        'axfr': {'domain': True, 'dictionary': False},
        'std': {'domain': True, 'dictionary': False},
        'srv': {'domain': True, 'dictionary': False},
        'tld': {'domain': True, 'dictionary': False},
        'bing': {'domain': True, 'dictionary': False},
        'yand': {'domain': True, 'dictionary': False},
        'crt': {'domain': True, 'dictionary': False},
        'rvl': {'domain': False, 'dictionary': False},
        'zonewalk': {'domain': True, 'dictionary': False},
        'brt': {'domain': True, 'dictionary': True},
        'snoop': {'domain': False, 'dictionary': True},
    }
    valid_types = type_map.keys()

    #
    # Parse options
    #

    # if user requests tool version, we print it and exit
    if arguments.version:
        print(f'DNSRecon version {__version__} https://www.darkoperator.com')
        sys.exit(0)

    # validating type param which is in the form: type1,type2,...,typeN
    # if the pattern is not correct or if there is an unknown type we exit
    type_arg = arguments.type
    types = []
    if type_arg:
        type_arg = type_arg.lower().strip()

        # we create a dynamic regex specifying min and max type length
        # and max number of possible scan types
        min_type_len = len(min(valid_types, key=len))
        max_type_len = len(max(valid_types, key=len))
        type_len = len(valid_types)
        dynamic_regex = f'^([a-z]{{{min_type_len},{max_type_len}}},?){{,{type_len}}}$'

        type_match = re.match(dynamic_regex, type_arg)
        if not type_match:
            logger.error('This type of scan is not valid')
            sys.exit(1)

        incorrect_types = [t for t in type_arg.split(',') if t not in valid_types]
        if incorrect_types:
            incorrect_types_str = ','.join(incorrect_types)
            logger.error(f'This type of scan is not in the list: {incorrect_types_str}')
            sys.exit(1)

        types = list(set(type_arg.split(',')))

    # validating range
    rvl_ip_list = []
    if arguments.range:
        rvl_ip_list = process_range(arguments.range)
        # if the provided range is not valid, we exit
        if not rvl_ip_list:
            logger.error('Invalid Address/CIDR or Address Range provided.')
            sys.exit(1)

        # otherwise, we update a type list
        if 'rvl' not in types:
            types.append('rvl')

    # Read list of domains if input_list is provided
    domain_list = []
    if arguments.input_list:
        if not os.path.isfile(arguments.input_list):
            logger.error(f"Input list file '{arguments.input_list}' does not exist.")
            sys.exit(1)
        with open(arguments.input_list) as f:
            domain_list = [line.strip() for line in f if line.strip()]
        if not domain_list:
            logger.error(f"No domains found in the input list file '{arguments.input_list}'.")
            sys.exit(1)
    elif arguments.domain:
        domain_list = [arguments.domain]
    else:
        # If no domain or input list is provided, exit
        logger.error('A domain name or an input list of domains is required.')
        sys.exit(1)

    # if types are empty but domain_list is not, default to 'std'
    if not types and domain_list:
        types = ['std']

    # Check if the Dictionary file exists
    dictionary_required = []
    if types:
        # combining the types and the type_map, we obtain
        # dictionary_required, which is a list of bool
        # where True means that a dictionary file is required
        dictionary_required = [type_map[t]['dictionary'] for t in types]
    else:
        # Handle cases where types might not be defined
        dictionary_required = [False]

    dictionary = ''
    if any(dictionary_required):
        # we generate a list of possible dictionary files
        dictionaries = ['/etc/dnsrecon/namelist.txt', str(DATA_DIR / 'namelist.txt')]

        # if the user has provided a custom dictionary file,
        # we insert it as the first entry of the list
        if arguments.dictionary:
            arguments.dictionary = arguments.dictionary.strip()
            dictionaries.insert(0, arguments.dictionary)
        else:
            logger.info('No dictionary file has been specified.')

        # we individuate the first valid dictionary file,
        # among those in the list
        for dict_ in dictionaries:
            if os.path.isfile(dict_):
                dictionary = dict_
                break

        # if we don't have a valid dictionary file, we exit
        if not dictionary:
            logger.error('No valid dictionary files have been specified or found within the tool')
            sys.exit(1)

        dict_type = 'user' if arguments.dictionary == dictionary else 'tool'
        logger.info(f'Using the dictionary file: {dictionary} (provided by {dict_type})')

    if arguments.threads:
        thread_num = int(arguments.threads)

    request_timeout = float(arguments.lifetime)

    output_file = arguments.xml
    results_db = arguments.db
    csv_file = arguments.csv
    json_file = arguments.json

    # this flag summarizes if the program has to output
    do_output = bool(output_file or results_db or csv_file or json_file)

    verbose = arguments.verbose
    ignore_wildcardrr = arguments.iw
    CONFIG['disable_check_recursion'] = arguments.disable_check_recursion
    CONFIG['disable_check_bindversion'] = arguments.disable_check_bindversion

    xfr = arguments.a
    bing = arguments.b
    yandex = arguments.y
    do_crt = arguments.k
    do_whois = arguments.w
    zonewalk = arguments.z
    spf_enum = arguments.s
    wildcard_filter = arguments.f
    proto = 'tcp' if arguments.tcp else 'udp'
    ns_server = arguments.ns_server.split(',') if arguments.ns_server else []

    # Initialize an empty list to hold all records
    all_returned_records = []

    # Iterate over each domain and perform enumeration
    for domain in domain_list:
        logger.info(f'Starting enumeration for domain: {domain}')

        # Initialize the resolver for the current domain
        res = DnsHelper(domain, ns_server, request_timeout, proto)

        scan_info = [' '.join(sys.argv), str(datetime.datetime.now())]

        for type_ in types:
            # Check if the scan type requires a domain
            if type_map[type_]['domain'] and not domain:
                logger.error(f'{type_}: No Domain to target specified!')
                sys.exit(1)

            try:
                # Perform the scan based on type_
                if type_ == 'axfr':
                    zonercds = res.zone_transfer()
                    if not zonercds:
                        logger.error(f'{type_}: No records were returned.')
                        continue
                    all_returned_records.extend(zonercds)

                elif type_ == 'std':
                    logger.info(f'{type_}: Performing General Enumeration against: {domain}...')
                    std_enum_records = general_enum(
                        res,
                        domain,
                        xfr,
                        bing,
                        yandex,
                        spf_enum,
                        do_whois,
                        do_crt,
                        zonewalk,
                        request_timeout,
                        thread_num=thread_num,
                    )
                    if do_output and std_enum_records:
                        all_returned_records.extend(std_enum_records)

                elif type_ == 'rvl':
                    if not rvl_ip_list:
                        logger.error(f'{type_}: Invalid Address/CIDR or Address Range provided.')
                        continue
                    rvl_enum_records = brute_reverse(res, rvl_ip_list, verbose, thread_num=thread_num)
                    if do_output:
                        all_returned_records.extend(rvl_enum_records)

                elif type_ == 'brt':
                    logger.info(f'{type_}: Performing host and subdomain brute force against {domain}...')
                    brt_enum_records = brute_domain(
                        res,
                        dictionary,
                        domain,
                        wildcard_filter,
                        verbose,
                        ignore_wildcardrr,
                        thread_num=thread_num,
                    )
                    if do_output and brt_enum_records:
                        all_returned_records.extend(brt_enum_records)

                elif type_ == 'srv':
                    logger.info(f'{type_}: Enumerating Common SRV Records against {domain}...')
                    srv_enum_records = brute_srv(res, domain, verbose, thread_num=thread_num)
                    if do_output:
                        all_returned_records.extend(srv_enum_records)

                elif type_ == 'tld':
                    logger.info(f'{type_}: Performing TLD Brute force Enumeration against {domain}...')
                    tld_enum_records = brute_tlds(res, domain, verbose, thread_num=thread_num)
                    if do_output:
                        all_returned_records.extend(tld_enum_records)

                elif type_ == 'bing':
                    logger.info(f'{type_}: Performing Bing Search Enumeration against {domain}...')
                    bing_enum_records = se_result_process(res, scrape_bing(domain))
                    if bing_enum_records is not None and do_output:
                        all_returned_records.extend(bing_enum_records)

                elif type_ == 'yand':
                    logger.info(f'{type_}: Performing Yandex Search Enumeration against {domain}...')
                    yandex_enum_records = se_result_process(res, scrape_yandex(domain))
                    if yandex_enum_records is not None and do_output:
                        all_returned_records.extend(yandex_enum_records)

                elif type_ == 'crt':
                    logger.info(f'{type_}: Performing Crt.sh Search Enumeration against {domain}...')
                    crt_enum_records = se_result_process(res, scrape_crtsh(domain))
                    if crt_enum_records is not None and do_output:
                        all_returned_records.extend(crt_enum_records)
                    else:
                        print('[-] No records returned from crt.sh enumeration')

                elif type_ == 'snoop':
                    if not (dictionary and ns_server):
                        logger.error(f'{type_}: A dictionary file and at least one Name Server have to be specified!')
                        continue
                    logger.info(f'{type_}: Performing Cache Snooping against NS Server: {ns_server[0]}...')
                    cache_enum_records = in_cache(res, dictionary, ns_server[0])
                    if do_output:
                        all_returned_records.extend(cache_enum_records)

                elif type_ == 'zonewalk':
                    zonewalk_result = ds_zone_walk(res, domain, request_timeout)
                    if do_output:
                        all_returned_records.extend(zonewalk_result)

                else:
                    logger.error(f'{type_}: This type of scan is not in the list.')

            except dns.resolver.NXDOMAIN:
                logger.error(f'Could not resolve domain: {domain}')
                continue  # Continue with the next domain

            except dns.exception.Timeout:
                logger.error(
                    f"""A timeout error occurred.
Please make sure you can reach the target DNS Servers directly and requests are not being filtered.
Increase the timeout from {request_timeout} seconds to a higher number with --lifetime <time> option."""
                )
                continue  # Continue with the next domain

        logger.info(f'Completed enumeration for domain: {domain}\n')

    # After processing all domains, handle output
    if do_output:
        # XML Output
        if output_file:
            logger.info(f'Saving records to XML file: {output_file}')
            xml_enum_doc = dns_record_from_dict(all_returned_records, scan_info, domain_list)
            write_to_file(xml_enum_doc, output_file)

        # SQLite DB Output
        if results_db:
            logger.info(f'Saving records to SQLite3 file: {results_db}')
            create_db(results_db)
            write_db(results_db, all_returned_records)

        # CSV Output
        if csv_file:
            logger.info(f'Saving records to CSV file: {csv_file}')
            write_to_file(make_csv(all_returned_records), csv_file)

        # JSON Output
        if json_file:
            logger.info(f'Saving records to JSON file: {json_file}')
            write_json(json_file, all_returned_records, scan_info)

    sys.exit(0)
