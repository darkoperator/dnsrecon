#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#    Unit test for DNSRecon main functions
#    Author: Filippo Lauria (@filippolauria)
#
#    Copyright (C) 2021  Carlos Perez
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

from dnsrecon import cli
from dnsrecon.lib.dnshelper import DnsHelper
import os


class Test_dnsrecon():

    def test_in_cache(self):
        namelist_filename = 'namelist.tmp'
        namelist = ['localhost', 'test', 'www', 'mail']
        with open(namelist_filename, 'w') as fd:
            fd.writelines([f"{name}\n" for name in namelist])
        helper = DnsHelper('zonetransfer.me')
        ns = '81.4.108.41'
        result = cli.in_cache(helper, namelist_filename, ns)
        os.remove(namelist_filename)
        assert len(result) == 1 and result[0]['type'] == 'A'

    def test_se_result_process(self):
        helper = DnsHelper('zonetransfer.me')
        hosts = ['www.megacorpone.com', 'www.zonetransfer.me']
        result = cli.se_result_process(helper, hosts)
        assert len(result) >= 2
