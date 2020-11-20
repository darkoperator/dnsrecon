#!/usr/bin/env python3

import csv
import sqlite3
import json


def write_to_file(data, target_file):
    """
    Function for writing returned data to a file
    """
    f = open(target_file, "w")
    f.write(data)
    f.close()


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
            print(n)
            if n['type'] in ['PTR', 'A', 'AAAA']:
                csv_data += n["type"] + "," + n["name"] + "," + n["address"] + "\n"

            elif re.search(r"NS$", n["type"]):
                csv_data += n["type"] + "," + n["target"] + "," + n["address"] + "\n"

            elif re.search(r"SOA", n["type"]):
                csv_data += n["type"] + "," + n["mname"] + "," + n["address"] + "\n"

            elif re.search(r"MX", n["type"]):
                csv_data += n["type"] + "," + n["exchange"] + "," + n["address"] + "\n"

            elif re.search(r"SPF", n["type"]):
                if "zone_server" in n:
                    csv_data += n["type"] + ",,,,,\'" + n["strings"] + "\'\n"
                else:
                    csv_data += n["type"] + ",,,,,\'" + n["strings"] + "\'\n"

            elif re.search(r"TXT", n["type"]):
                if "zone_server" in n:
                    csv_data += n["type"] + ",,,,,\'" + n["strings"] + "\'\n"
                else:
                    csv_data += n["type"] + "," + n["name"] + ",,,,\'" + n["strings"] + "\'\n"

            elif re.search(r"SRV", n["type"]):
                csv_data += n["type"] + "," + n["name"] + "," + n["address"] + "," + n["target"] + "," + n["port"] + "\n"

            elif re.search(r"CNAME", n["type"]):
                if "target" not in n.keys():
                    n["target"] = ""
                csv_data += n["type"] + "," + n["name"] + ",," + n["target"] + ",\n"

            else:
                # Handle not common records
                t = n["type"]
                del n["type"]
                record_data = "".join(["%s =%s," % (key, value) for key, value in n.items()])
                records = [t, record_data]
                csv_data + records[0] + ",,,,," + records[1] + "\n"

    return csv_data


def write_json(jsonfile, data, scan_info):
    """
    Function to write DNS Records SOA, PTR, NS, A, AAAA, MX, TXT, SPF and SRV to
    JSON file.
    """
    scaninfo = {"type": "ScanInfo", "arguments": scan_info[0], "date": scan_info[1]}
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
