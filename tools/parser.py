#!/usr/bin/env python
# -*- coding: utf-8 -*-

#    DNSRecon Data Parser
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

__version__ = '0.0.7'
__author__ = 'Carlos Perez, Carlos_Perez@darkoperator.com'

import xml.etree.cElementTree as cElementTree
import csv
import os
import getopt
import sys
import re

from netaddr import *

# Function Definitions
# ------------------------------------------------------------------------------


def print_status(message=""):
    print("\033[1;34m[*]\033[1;m {0}".format(message))


def print_good(message=""):
    print("\033[1;32m[*]\033[1;m {0}".format(message))


def print_error(message=""):
    print("\033[1;31m[-]\033[1;m {0}".format(message))


def print_debug(message=""):
    print("\033[1;31m[!]\033[1;m {0}".format(message))


def print_line(message=""):
    print("{0}".format(message))


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
            ip_list = IPNetwork(IPRange(range_vals[0], range_vals[1])).cidrs()[-1]
    except:
        print_error("Range provided is not valid: {0}".format(arg()))
        return []
    return ip_list


def xml_parse(xm_file, ifilter, tfilter, nfilter, list):
    """
    Function for parsing XML files created by DNSRecon and apply filters.
    """
    iplist = []
    for event, elem in cElementTree.iterparse(xm_file):
        # Check if it is a record
        if elem.tag == "record":
            # Check that it is a RR Type that has an IP Address
            if "address" in elem.attrib:
                # Check if the IP is in the filter list of IPs to ignore
                if (len(ifilter) == 0 or IPAddress(elem.attrib['address']) in ifilter) and (elem.attrib['address'] != "no_ip"):
                    # Check if the RR Type against the types
                    if re.match(tfilter, elem.attrib['type'], re.I):
                        # Process A, AAAA and PTR Records
                        if re.search(r'PTR|^[A]$|AAAA', elem.attrib['type']) \
                        and re.search(nfilter, elem.attrib['name'], re.I):
                            if list:
                                if elem.attrib['address'] not in iplist:
                                    print elem.attrib['address']
                            else:
                                print_good("{0} {1} {2}".format(elem.attrib['type'], elem.attrib['name'], elem.attrib['address']))

                        # Process NS Records
                        elif re.search(r'NS', elem.attrib['type']) and \
                        re.search(nfilter, elem.attrib['target'], re.I):
                            if list:
                                if elem.attrib['address'] not in iplist:
                                    iplist.append(elem.attrib['address'])
                            else:
                                print_good("{0} {1} {2}".format(elem.attrib['type'], elem.attrib['target'], elem.attrib['address']))

                        # Process SOA Records
                        elif re.search(r'SOA', elem.attrib['type']) and \
                        re.search(nfilter, elem.attrib['mname'], re.I):
                            if list:
                                if elem.attrib['address'] not in iplist:
                                    iplist.append(elem.attrib['address'])
                            else:
                                print_good("{0} {1} {2}".format(elem.attrib['type'], elem.attrib['mname'], elem.attrib['address']))

                        # Process MS Records
                        elif re.search(r'MX', elem.attrib['type']) and \
                        re.search(nfilter, elem.attrib['exchange'], re.I):
                            if list:
                                if elem.attrib['address'] not in iplist:
                                    iplist.append(elem.attrib['address'])
                            else:
                                print_good("{0} {1} {2}".format(elem.attrib['type'], elem.attrib['exchange'], elem.attrib['address']))

                        # Process SRV Records
                        elif re.search(r'SRV', elem.attrib['type']) and \
                        re.search(nfilter, elem.attrib['target'], re.I):
                            if list:
                                if elem.attrib['address'] not in iplist:
                                    iplist.append(elem.attrib['address'])
                            else:
                                print_good("{0} {1} {2} {3}".format(elem.attrib['type'], elem.attrib['name'], elem.attrib['address'], elem.attrib['target'], elem.attrib['port']))
            else:
                if re.match(tfilter, elem.attrib['type'], re.I):
                    # Process TXT and SPF Records
                    if re.search(r'TXT|SPF', elem.attrib['type']):
                        if not list:
                            print_good("{0} {1}".format(elem.attrib['type'], elem.attrib['strings']))
    # Process IPs in list
    if len(iplist) > 0:
        try:
            for ip in filter(None, iplist):
                print_line(ip)
        except IOError:
            sys.exit(0)


def csv_parse(csv_file, ifilter, tfilter, nfilter, list):
    """
    Function for parsing CSV files created by DNSRecon and apply filters.
    """
    iplist = []
    reader = csv.reader(open(csv_file, 'r'), delimiter=',')
    reader.next()
    for row in reader:
        # Check if IP is in the filter list of addresses to ignore
        if ((len(ifilter) == 0) or (IPAddress(row[2]) in ifilter)) and (row[2] != "no_ip"):
            # Check Host Name regex and type list
            if re.search(tfilter, row[0], re.I) and re.search(nfilter, row[1], re.I):
                if list:
                    if row[2] not in iplist:
                        print(row[2])
                else:
                    print_good(" ".join(row))
    # Process IPs for target list if available
    #if len(iplist) > 0:
    #    for ip in filter(None, iplist):
    #        print_line(ip)


def extract_hostnames(file):
    host_names = []
    hostname_pattern = re.compile("(^[^.]*)")
    file_type = detect_type(file)
    if file_type == "xml":
        for event, elem in cElementTree.iterparse(file):
            # Check if it is a record
            if elem.tag == "record":
                # Check that it is a RR Type that has an IP Address
                if "address" in elem.attrib:
                    # Process A, AAAA and PTR Records
                    if re.search(r'PTR|^[A]$|AAAA', elem.attrib['type']):
                        host_names.append(re.search(hostname_pattern, elem.attrib['name']).group(1))

                    # Process NS Records
                    elif re.search(r'NS', elem.attrib['type']):
                        host_names.append(re.search(hostname_pattern, elem.attrib['target']).group(1))

                    # Process SOA Records
                    elif re.search(r'SOA', elem.attrib['type']):
                        host_names.append(re.search(hostname_pattern, elem.attrib['mname']).group(1))

                    # Process MX Records
                    elif re.search(r'MX', elem.attrib['type']):
                        host_names.append(re.search(hostname_pattern, elem.attrib['exchange']).group(1))

                    # Process SRV Records
                    elif re.search(r'SRV', elem.attrib['type']):
                        host_names.append(re.search(hostname_pattern, elem.attrib['target']).group(1))

    elif file_type == "csv":
        reader = csv.reader(open(file, 'r'), delimiter=',')
        reader.next()
        for row in reader:
            host_names.append(re.search(hostname_pattern, row[1]).group(1))

    host_names = list(set(host_names))
    # Return list with no empty values
    return filter(None, host_names)


def detect_type(file):
    """
    Function for detecting the file type by checking the first line of the file.
    Returns xml, csv or None.
    """
    ftype = None

    # Get the fist lile of the file for checking
    f = open(file, 'r')
    firs_line = f.readline()

    # Determine file type based on the fist line content
    import re
    if re.search("(xml version)", firs_line):
        ftype = "xml"
    elif re.search(r'\w*,[^,]*,[^,]*', firs_line):
        ftype = "csv"
    else:
        raise Exception("Unsupported File Type")
    return ftype


def usage():
    print("Version: {0}".format(__version__))
    print("DNSRecon output file parser")
    print("Usage: parser.py <options>\n")
    print("Options:")
    print("   -h, --help               Show this help message and exit")
    print("   -f, --file    <file>     DNSRecon XML or CSV output file to parse.")
    print("   -l, --list               Output an unique IP List that can be used with other tools.")
    print("   -i, --ips     <ranges>   IP Ranges in a comma separated list each in formats (first-last)")
    print("                            or in (range/bitmask) for ranges to be included from output.")
    print("                            For A, AAAA, NS, MX, SOA, SRV and PTR Records.")
    print("   -t, --type    <type>     Resource Record Types as a regular expression to filter output.")
    print("                            For A, AAAA, NS, MX, SOA, TXT, SPF, SRV and PTR Records.")
    print("   -s, --str     <regex>    Regular expression between quotes for filtering host names on.")
    print("                            For A, AAAA, NS, MX, SOA, SRV and PTR Records.")
    print("   -n, --name               Return list of unique host names.")
    print("                            For A, AAAA, NS, MX, SOA, SRV and PTR Records.")
    sys.exit(0)

# Main
#-------------------------------------------------------------------------------


def main():
    #
    # Option Variables
    #
    ip_filter = []
    name_filter = "(.*)"
    type_filter = "(.*)"
    target_list = False
    file = None
    names = False
    #ip_set = []

    #
    # Define options
    #
    try:
        options, args = getopt.getopt(sys.argv[1:], 'hi:t:s:lf:n',
                                           ['help',
                                           'ips='
                                           'type=',
                                           'str=',
                                           'list',
                                           'file=',
                                           'name'
                                           ])

    except getopt.GetoptError as error:
        print_error("Wrong Option Provided!")
        print_error(error)
        return

    #
    # Parse options
    #
    for opt, arg in options:
        if opt in ('-t', '--type'):
            type_filter = arg

        elif opt in ('-i', '--ips'):
            ipranges = arg.split(",")
            for r in ipranges:
                ip_filter.extend(process_range(r))
            #ip_set = IPSet(ip_filter)

        elif opt in ('-s', '--str'):
            name_filter = "({0})".format(arg)

        elif opt in ('-l', '--list'):
            target_list = True

        elif opt in ('-f', '--file'):

            #Check if the dictionary file exists
            if os.path.isfile(arg):
                file = arg
            else:
                print_error("File {0} does not exist!".format(arg))
                exit(1)

        elif opt in ('-r', '--range'):
            ip_range = process_range(arg)
            if len(ip_range) > 0:
                ip_list.extend(ip_range)
            else:
                sys.exit(1)
        elif opt in ('-n', '--name'):
            names = True

        elif opt in ('-h'):
            usage()

    # start execution based on options
    if file:
        if names:
            try:
                found_names = extract_hostnames(file)
                found_names.sort()
                for n in found_names:
                    print_line(n)
            except IOError:
                sys.exit(0)
        else:
            file_type = detect_type(file)
            if file_type == "xml":
                xml_parse(file, ip_filter, type_filter, name_filter, target_list)
            elif file_type == "csv":
                csv_parse(file, ip_filter, type_filter, name_filter, target_list)
    else:
        print_error("A DNSRecon XML or CSV output file must be provided to be parsed")
        usage()

if __name__ == "__main__":
    main()
