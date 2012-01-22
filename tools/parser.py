#!/usr/bin/env python
# -*- coding: utf-8 -*-

import xml.etree.cElementTree as cElementTree
import csv
import os
import getopt
import sys
import re

from netaddr import *

# Function Definitions
# -------------------------------------------------------------------------------

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
            ip_list = IPRange(range_vals[0],range_vals[1])
    except:
        print_error("Range provided is not valid: {0}".format(arg()))
        return []
    return [str(ip) for ip in ip_list]
    
def xml_parse(xm_file, ifilter, tfilter, nfilter, list):
    for event, elem in cElementTree.iterparse(xm_file):
        if elem.tag == "record":
            print elem.attrib['type']
            break
        
def csv_parse(csv_file, ifilter, tfilter, nfilter, list):
    iplist = []
    reader = csv.reader(open(csv_file, 'rb'), delimiter=',')
    for row in reader:
        if row[2] not in  ifilter:
            if re.search(tfilter, row[0], re.I) and re.search(nfilter, row[1], re.I):
                if list:
                    if row[2] not in iplist: iplist.append(row[2])
                else:
                    print_good(" ".join(row))
    if len(iplist ) > 0:
        for ip in iplist:
            print_line(ip)
    
def detect_type(file):
    ftype = None
    
    # Get the fist lile of the file for checking
    f = open(file, 'rb')
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
    
    #
    # Define options
    #
    try:
        options, args = getopt.getopt(sys.argv[1:], 'hi:t:s:lf:',
                                           ['help',
                                           'ips='
                                           'type=',
                                           'str=',
                                           'list',
                                           'file='
                                           ])
        
    except getopt.GetoptError as error:
        print_error("Wrong Option Provided!")
        print_error(error)
        return
 
    #
    # Parse options
    #
    for opt, arg in options:
        if opt in ('-t','--type'):
            type_filter = arg

        elif opt in ('-i','--ips'):
            ipranges = arg.split(",")
            for r in ipranges:
                ip_filter.extend(process_range(r))

        elif opt in ('-s','--str'):
            name_filter = "({0})".format(arg)

        elif opt in ('-l','--list'):
            target_list = True

        elif opt in ('-f','--file'):

            #Check if the dictionary file exists
            if os.path.isfile(arg):
                file = arg
            else:
                print_error("File {0} does not exist!".format(arg))
                exit(1)

        elif opt in ('-r','--range'):
            ip_range = process_range(arg)
            if len(ip_range) > 0:
                ip_list.extend(ip_range)
            else:
                sys.exit(1)
        elif opt in ('-h'):
            print usage
    
    # start execution based on options
    if file:
        file_type = detect_type(file)
        if file_type == "xml":
            xml_parse(file, ip_filter, type_filter, name_filter,target_list)
        elif file_type == "csv":
            csv_parse(file, ip_filter, type_filter, name_filter,target_list)
    else:
        print_error("A DNSRecon XML or CSV output file must be provided to be parsed")
            
        
if __name__ == "__main__":
    main()