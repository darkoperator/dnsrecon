#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#    Unit test for DNSRecon's dnshelper library
#    Author: Filippo Lauria (@filippolauria)
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

from dnsrecon.lib.dnshelper import DnsHelper
from netaddr import IPAddress
from re import match


class Test_Lib_dnshelper:
    def test_get_a(self):
        helper = DnsHelper("google.com")
        records = helper.get_a("ipv4.google.com")
        for record in records:
            assert record[0] in ["A", "CNAME"]

    def test_get_aaaa(self):
        helper = DnsHelper("google.com")
        records = helper.get_aaaa("ipv6.google.com")
        for record in records:
            assert record[0] in ["AAAA", "CNAME"]

    def test_get_mx(self):
        helper = DnsHelper("google.com")
        records = helper.get_mx()
        for record in records:
            assert record[0] == "MX"

    def test_get_ip(self):
        helper = DnsHelper("google.com")
        records = helper.get_ip("google.com")
        for record in records:
            ip = IPAddress(record[2])
            assert ip.version in [4, 6]  # ~ redundant

    def test_get_txt(self):
        helper = DnsHelper("gmail.com")
        records = helper.get_txt()
        for record in records:
            assert record[0] == "TXT"

    def test_get_ns(self):
        helper = DnsHelper("zonetransfer.me")
        records = helper.get_ns()
        for record in records:
            assert record[0] == "NS"

    def test_get_soa(self):
        helper = DnsHelper("zonetransfer.me")
        records = helper.get_soa()
        for record in records:
            assert record[0] == "SOA"

    def test_get_srv(self):
        helper = DnsHelper("nsztm1.digi.ninja")
        records = helper.get_srv("_sip._tcp.zonetransfer.me")
        for record in records:
            assert record[0] == "SRV"

    def test_zone_transfer(self):
        helper = DnsHelper("zonetransfer.me")
        records = helper.zone_transfer()
        assert len(records) >= 135

    def test_get_ptr(self):
        helper = DnsHelper("zonetransfer.me")
        records = helper.get_ptr("51.79.37.18")
        assert len(records) == 1 and match(r"^.+\.megacorpone\.com$", records[0][1])
