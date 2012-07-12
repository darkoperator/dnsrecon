#!/usr/bin/env python
# -*- coding: utf-8 -*-

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

import pybonjour
import select
import re

def mdns_browse(regtype):
    """
    Function for resolving a specific mDNS record in the Local Subnet.
    """
    found_mdns_records = []
    domain = None
    browse_timeout = 1
    resolve_timeout = 1
    results = []
    resolved = []

    def resolve_callback(
        sdRef,
        flags,
        interfaceIndex,
        errorCode,
        fullname,
        hosttarget,
        port,
        txtRecord,
        ):

        n = re.compile(u'(\x00|\x07|\x1A|\x16|\x06|\x08|\x1f|\xdb|\xb2|\xb0|\xb1'
                   u'\xc9|\xb9|\xcd|\u2019|\u2018|\u2019|\u201c|\u201d|\u2407)')

        t = re.compile(r'[\x00-\x1f|\x7f|\x0e]')

        if errorCode == pybonjour.kDNSServiceErr_NoError:
            results.append({
                'type': 'MDNS',
                'name': n.sub(" ",fullname),
                'host': str(hosttarget).replace('\032'," "),
                'port': str(port),
                'txtRecord': t.sub(" ",txtRecord.strip())
                })
            resolved.append(True)

    def browse_callback(
        sdRef,
        flags,
        interfaceIndex,
        errorCode,
        serviceName,
        regtype,
        replyDomain,
        ):
        if errorCode != pybonjour.kDNSServiceErr_NoError:
            return

        if not flags & pybonjour.kDNSServiceFlagsAdd:

            # Service removed

            return

        resolve_sdRef = pybonjour.DNSServiceResolve(
            0,
            interfaceIndex,
            serviceName,
            regtype,
            replyDomain,
            resolve_callback,
            )

        try:
            while not resolved:
                ready = select.select([resolve_sdRef], [], [],
                        resolve_timeout)

                if resolve_sdRef not in ready[0]:

                    # Resolve timed out

                    break

                pybonjour.DNSServiceProcessResult(resolve_sdRef)
            else:

                resolved.pop()
        finally:

            resolve_sdRef.close()

    browse_sdRef = pybonjour.DNSServiceBrowse(regtype=regtype,
            domain=domain, callBack=browse_callback)

    try:
        while True:
            ready = select.select([browse_sdRef], [], [],
                                  browse_timeout)

            if not ready[0]:
                break

            if browse_sdRef in ready[0]:
                pybonjour.DNSServiceProcessResult(browse_sdRef)

            _results = results

            for result in _results:
                found_mdns_records = [result]
    finally:

        browse_sdRef.close()
    return found_mdns_records
