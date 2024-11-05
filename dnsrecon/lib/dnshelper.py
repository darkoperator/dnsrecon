#!/usr/bin/env python3

#    Copyright (C) 2020  Carlos Perez
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


import random
import socket

import dns.message
import dns.query
import dns.resolver
import dns.reversename
from dns.dnssec import algorithm_to_text
from dns.zone import *
from loguru import logger

DNS_PORT_NUMBER = 53
DNS_QUERY_TIMEOUT = 4.0


def strip_last_dot(addr_):
    """
    Util function that strips the last dot from an address (if any)
    """
    return addr_[:-1] if addr_.endswith('.') else addr_


class DnsHelper:
    def __init__(self, domain, ns_server=None, request_timeout=3.0, proto='tcp'):
        self._domain = domain
        self._proto = proto
        self._is_tcp = proto == 'tcp'

        configure = not ns_server
        self._res = dns.resolver.Resolver(configure=configure)

        if ns_server:
            if isinstance(ns_server, str):
                ns_server = [ns_server]
            self._res.nameservers = ns_server
            if len(ns_server) > 1:
                self._res.rotate = True

        # Set timing
        self._res.timeout = request_timeout
        self._res.lifetime = request_timeout

    def check_tcp_dns(self, address):
        """
        Function to check if a server is listening at port 53 TCP. This will aid
        in IDS/IPS detection since a AXFR will not be tried if port 53 is found to
        be closed.
        """
        try:
            sock = socket.socket()
            sock.settimeout(DNS_QUERY_TIMEOUT)
            sock.connect((address, DNS_PORT_NUMBER))
        except Exception:
            return False

        return True

    def get_answers(self, type_, addr_):
        """
        Function that wraps the resolve() function with all the specific
        exceptions it could raise and the socket.error exception
        https://dnspython.readthedocs.io/en/latest/resolver-class.html#dns.resolver.Resolver.resolve
        """
        try:
            return self._res.resolve(addr_, type_, tcp=self._is_tcp)
        except (
            OSError,
            dns.exception.Timeout,
            dns.resolver.NXDOMAIN,
            dns.resolver.YXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.name.EmptyLabel,
        ):
            return None

    def resolve(self, target, type_, ns=None):
        """
        Function for performing general resolution types returning the RDATA
        """
        configure = not ns
        res = dns.resolver.Resolver(configure=configure)
        if ns:
            res.nameservers = [ns]

        answers = res.query(target, type_, tcp=self._is_tcp)
        return answers

    def query(
        self,
        q,
        where,
        timeout=DNS_QUERY_TIMEOUT,
        port=53,
        af=None,
        source=None,
        source_port=0,
        one_rr_per_rrset=False,
    ):
        if isinstance(where, list):
            random.shuffle(where)
            target_server = where[0]
        else:
            target_server = where

        if self._is_tcp:
            return dns.query.tcp(
                q,
                target_server,
                timeout,
                port,
                af,
                source,
                source_port,
                one_rr_per_rrset,
            )
        else:
            return dns.query.udp(
                q,
                target_server,
                timeout,
                port,
                af,
                source,
                source_port,
                False,
                one_rr_per_rrset,
            )

    def get_a(self, host_trg):
        """
        Function for resolving the A Record for a given host. Returns an Array of
        the IP Address it resolves to. It will also return CNAME data.
        """
        answers = self.get_answers('A', host_trg)
        if not answers:
            return []

        result = []
        for answer in answers.response.answer:
            for rdata in answer:
                if rdata.rdtype == 5:
                    target_ = strip_last_dot(rdata.target.to_text())
                    result.append(['CNAME', host_trg, target_])
                    host_trg = target_

                else:
                    result.append(['A', host_trg, rdata.address])

        return result

    def get_aaaa(self, host_trg):
        """
        Function for resolving the AAAA Record for a given host. Returns an Array of
        the IP Address it resolves to. It will also return CNAME data.
        """
        answers = self.get_answers('AAAA', host_trg)
        if not answers:
            return []

        result = []
        for answer in answers.response.answer:
            for rdata in answer:
                if rdata.rdtype == 5:
                    target_ = strip_last_dot(rdata.target.to_text())
                    result.append(['CNAME', host_trg, target_])
                    host_trg = target_

                else:
                    result.append(['AAAA', host_trg, rdata.address])

        return result

    def get_ip(self, hostname):
        """
        Function resolves a host name to its given A and/or AAAA record.
        Returns Array of found hosts and IPv4 or IPv6 Address.
        """
        found_ip_add = []
        found_ip_add.extend(self.get_a(hostname))
        found_ip_add.extend(self.get_aaaa(hostname))
        return found_ip_add

    def get_mx(self):
        """
        Function for MX Record resolving. Returns all MX records. Returns also the IP
        address of the host both in IPv4 and IPv6. Returns an Array
        """
        answers = self.get_answers('MX', self._domain)
        if not answers:
            return []

        answer_types = ['A', 'AAAA']
        result = []
        for answer_type in answer_types:
            for answer in answers:
                exchange_ = strip_last_dot(answer.exchange.to_text())

                a_or_aaaa_answers = self.get_answers(answer_type, exchange_)
                if not a_or_aaaa_answers:
                    continue

                for a_or_aaaa_answer in a_or_aaaa_answers:
                    result.append(['MX', exchange_, a_or_aaaa_answer.address, answer.preference])

        return result

    def get_ns(self):
        """
        Function for NS Record resolving. Returns all NS records. Returns also the IP
        address of the host both in IPv4 and IPv6. Returns an Array.
        """
        answers = self.get_answers('NS', self._domain)
        if not answers:
            return []

        result = []
        for answer in answers:
            target_ = strip_last_dot(answer.target.to_text())
            addresses = self.get_ip(target_)
            for type_, name_, addr_ in addresses:
                if type_ in ['A', 'AAAA']:
                    result.append(['NS', target_, addr_])

        return result

    def get_soa(self):
        """
        Function for SOA Record resolving. Returns all SOA records. Returns also the IP
        address of the host both in IPv4 and IPv6. Returns an Array.
        """
        queryfunc = dns.query.tcp if self._is_tcp else dns.query.udp

        try:
            querymsg = dns.message.make_query(self._domain, dns.rdatatype.SOA)
            response = queryfunc(querymsg, self._res.nameservers[0], self._res.timeout)
        except (
            OSError,
            dns.exception.Timeout,
            dns.resolver.NXDOMAIN,
            dns.resolver.YXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.query.BadResponse,
        ) as e:
            logger.error(f'Exception "{e}" while resolving SOA record.')
            logger.error(f'Error while resolving SOA while using {self._res.nameservers[0]} as nameserver.')
            return []

        # ~ we consider both response sections
        sections = []
        if len(response.authority) > 0:
            sections.append(response.authority)
        if len(response.answer) > 0:
            sections.append(response.answer)
        else:
            return []

        result = []
        record_types = ['A', 'AAAA']
        for section in sections:
            for record in section:
                if not isinstance(record[0], dns.rdtypes.ANY.SOA.SOA):
                    continue

                mname_ = strip_last_dot(record[0].mname.to_text())

                for record_type in record_types:
                    a_or_aaaa_answers = self.get_answers(record_type, mname_)

                    if not a_or_aaaa_answers:
                        continue

                    for a_or_aaaa_answer in a_or_aaaa_answers:
                        result.append(['SOA', mname_, a_or_aaaa_answer.address])

        return result

    def get_spf(self):
        """
        Function for SPF Record resolving returns the string with the SPF definition.
        Prints the string for the SPF Record and Returns the string
        """
        answers = self.get_answers('SPF', self._domain)
        if not answers:
            return []

        result = []
        for answer in answers:
            strings_ = bytes.join(b'', answer.strings).decode('utf-8', errors='ignore')
            result.append(['SPF', strings_])

        return result

    def get_txt(self, target=None):
        """
        Function for TXT Record resolving returns the string.
        """
        if target is None:
            target = self._domain

        targets = [target, '_dmarc.' + target]
        result = []
        for target_ in targets:
            answers = self.get_answers('TXT', target_)
            if not answers:
                continue

            for answer in answers:
                strings_ = bytes.join(b'', answer.strings).decode('utf-8', errors='ignore')
                result.append(['TXT', target_, strings_])

        return result

    def get_ptr(self, ipaddress):
        """
        Function for resolving PTR Record given it's IPv4 or IPv6 Address.
        """
        reversename_ = dns.reversename.from_address(ipaddress)
        answers = self.get_answers('PTR', reversename_)
        if not answers:
            return []

        result = []
        for answer in answers:
            target_ = strip_last_dot(answer.target.to_text())
            result.append(['PTR', target_, ipaddress])

        return result

    def get_srv(self, host):
        """
        Function for resolving SRV Records.
        """
        answers = self.get_answers('SRV', host)
        if not answers:
            return []

        result = []
        for answer in answers:
            target_ = strip_last_dot(answer.target.to_text())
            a_or_aaaa_answers = self.get_ip(target_)
            for type_, hostname_, addr_ in a_or_aaaa_answers:
                if type_ in ['A', 'AAAA']:
                    result.append(
                        [
                            'SRV',
                            host,
                            target_,
                            addr_,
                            str(answer.port),
                            str(answer.weight),
                        ]
                    )

        return result

    def get_nsec(self, host):
        """
        Function for querying for a NSEC record and retrieving the rdata object.
        This function is used mostly for performing a Zone Walk against a zone.
        """
        return self.get_answers('NSEC', host)

    def from_wire(self, xfr, zone_factory=Zone, relativize=True):
        """
        Method for turning returned data from a DNS AXFR in to RRSET, this method will not perform a
        check origin on the zone data as the method included with dnspython
        """
        z = None
        for r in xfr:
            if z is None:
                if relativize:
                    origin = r.origin
                else:
                    origin = r.answer[0].name
                rdclass = r.answer[0].rdclass
                z = zone_factory(origin, rdclass, relativize=relativize)
            for rrset in r.answer:
                znode = z.nodes.get(rrset.name)
                if not znode:
                    znode = z.node_factory()
                    z.nodes[rrset.name] = znode
                zrds = znode.find_rdataset(rrset.rdclass, rrset.rdtype, rrset.covers, True)
                zrds.update_ttl(rrset.ttl)
                for rd in rrset:
                    try:
                        rd.choose_relativity(z.origin, relativize)
                    except AttributeError:
                        pass
                    zrds.add(rd)

        return z

    def zone_transfer(self):
        """
        Function for testing for zone transfers for a given Domain, it will parse the
        output by record type.
        """
        # if anyone reports a record not parsed, I will add it; the list is long
        # I tried to include those I thought where the most common.

        zone_records = []
        ns_records = []
        logger.info(f'Checking for Zone Transfer for {self._domain} name servers')

        # Find SOA for Domain
        logger.info('Resolving SOA Record')
        try:
            soa_srvs = self.get_soa()
            for type_, name_, addr_ in soa_srvs:
                logger.info(f'\t {type_} {name_} {addr_}')
                ns_records.append(addr_)
        except Exception:
            logger.error('Could not obtain the domains SOA Record.')
            return

        # Find NS for Domain
        logger.info('Resolving NS Records')
        try:
            ns_srvs = []
            ns_srvs = self.get_ns()
            logger.info('NS Servers found:')
            for type_, name_, addr_ in ns_srvs:
                logger.info(f'\t {type_} {name_} {addr_}')
                ns_records.append(addr_)
        except Exception as e:
            logger.error(f'Could not Resolve NS Records: {e}')

        # Remove duplicates
        logger.info('Removing any duplicate NS server IP Addresses...')
        ns_records = list(set(ns_records))

        # Test each NS Server
        for ns_srv in ns_records:
            logger.info(' ')
            logger.info(f'Trying NS server {ns_srv}')

            if not self.check_tcp_dns(ns_srv):
                logger.error(f'Zone Transfer Failed for {ns_srv}!')
                logger.error('Port 53 TCP is being filtered')
                zone_records.append({'type': 'info', 'zone_transfer': 'failed', 'ns_server': ns_srv})
                continue

            logger.info(f'{ns_srv} Has port 53 TCP Open')
            try:
                zone = self.from_wire(dns.query.xfr(ns_srv, self._domain, timeout=DNS_QUERY_TIMEOUT))
                logger.info('Zone Transfer was successful!!')
                zone_records.append({'type': 'info', 'zone_transfer': 'success', 'ns_server': ns_srv})

                for name, rdataset in zone.iterate_rdatasets(dns.rdatatype.SOA):
                    for rdata in rdataset:
                        mname = strip_last_dot(rdata.mname.to_text())

                        for type_, name_, addr_ in self.get_ip(mname):
                            if type_ in ['A', 'AAAA']:
                                logger.info(f'\t SOA {mname} {addr_}')
                                zone_records.append(
                                    {
                                        'zone_server': ns_srv,
                                        'type': 'SOA',
                                        'mname': mname,
                                        'address': addr_,
                                    }
                                )

                for name, rdataset in zone.iterate_rdatasets(dns.rdatatype.NS):
                    for rdata in rdataset:
                        # Check if target is only the host name or a full FQDN.
                        # If only a hostname we will append the domain name of the
                        # Zone being transfered.
                        target = rdata.target.to_text()
                        if target.count('.') == 0:
                            target = target + '.' + self._domain
                        else:
                            target = strip_last_dot(target)

                        for type_, name_, addr_ in self.get_ip(target):
                            if type_ in ['A', 'AAAA']:
                                logger.info(f'\t NS {target} {addr_}')
                                zone_records.append(
                                    {
                                        'zone_server': ns_srv,
                                        'type': 'NS',
                                        'target': target,
                                        'address': addr_,
                                    }
                                )

                for name, rdataset in zone.iterate_rdatasets(dns.rdatatype.TXT):
                    for rdata in rdataset:
                        s = '; '.join([string.decode() for string in rdata.strings])
                        logger.info(f'\t TXT {s}')
                        zone_records.append({'zone_server': ns_srv, 'type': 'TXT', 'strings': s})

                for name, rdataset in zone.iterate_rdatasets(dns.rdatatype.SPF):
                    for rdata in rdataset:
                        s = '; '.join([string.decode() for string in rdata.strings])
                        logger.info(f'\t SPF {s}')
                        zone_records.append({'zone_server': ns_srv, 'type': 'SPF', 'strings': s})

                for name, rdataset in zone.iterate_rdatasets(dns.rdatatype.PTR):
                    for rdata in rdataset:
                        target = rdata.target.to_text() + '.' + self._domain
                        for type_, name_, addr_ in self.get_ip(target):
                            if type_ in ['A', 'AAAA']:
                                logger.info(f'\t PTR {target} {addr_}')
                                zone_records.append(
                                    {
                                        'zone_server': ns_srv,
                                        'type': 'PTR',
                                        'name': target,
                                        'address': addr_,
                                    }
                                )

                for name, rdataset in zone.iterate_rdatasets(dns.rdatatype.MX):
                    for rdata in rdataset:
                        exchange = strip_last_dot(rdata.exchange.to_text())

                        for type_, name_, addr_ in self.get_ip(exchange):
                            fqdn_ = str(name) + '.' + self._domain
                            if type_ in ['A', 'AAAA']:
                                logger.info(f'\t MX {fqdn_} {exchange} {addr_}')
                                zone_records.append(
                                    {
                                        'zone_server': ns_srv,
                                        'type': 'MX',
                                        'name': fqdn_,
                                        'exchange': exchange,
                                        'address': addr_,
                                    }
                                )

                for name, rdataset in zone.iterate_rdatasets(dns.rdatatype.AAAA):
                    fqdn_ = str(name) + '.' + self._domain
                    for rdata in rdataset:
                        logger.info(f'\t AAAA {fqdn_} {rdata.address}')
                        zone_records.append(
                            {
                                'zone_server': ns_srv,
                                'type': 'AAAA',
                                'name': fqdn_,
                                'address': rdata.address,
                            }
                        )

                for name, rdataset in zone.iterate_rdatasets(dns.rdatatype.A):
                    fqdn_ = str(name) + '.' + self._domain
                    for rdata in rdataset:
                        logger.info(f'\t A {fqdn_} {rdata.address}')
                        zone_records.append(
                            {
                                'zone_server': ns_srv,
                                'type': 'A',
                                'name': fqdn_,
                                'address': rdata.address,
                            }
                        )

                for name, rdataset in zone.iterate_rdatasets(dns.rdatatype.CNAME):
                    fqdn_ = str(name) + '.' + self._domain
                    for rdata in rdataset:
                        target = strip_last_dot(rdata.target.to_text())

                        for type_, name_, addr_ in self.get_ip(target):
                            if type_ in ['A', 'AAAA']:
                                logger.info(f'\t CNAME {fqdn_} {target} {addr_}')
                                zone_records.append(
                                    {
                                        'zone_server': ns_srv,
                                        'type': 'CNAME',
                                        'name': fqdn_,
                                        'target': target,
                                        'address': addr_,
                                    }
                                )

                for name, rdataset in zone.iterate_rdatasets(dns.rdatatype.SRV):
                    fqdn_ = str(name) + '.' + self._domain

                    for rdata in rdataset:
                        target = strip_last_dot(rdata.target.to_text())
                        weight_ = str(rdata.weight)
                        port_ = str(rdata.port)

                        ip_list = self.get_ip(rdata.target.to_text())
                        if not ip_list:
                            logger.info(f'\t SRV {fqdn_} {target} {port_} {weight_} no_ip')
                            zone_records.append(
                                {
                                    'zone_server': ns_srv,
                                    'type': 'SRV',
                                    'name': fqdn_,
                                    'target': target,
                                    'address': 'no_ip',
                                    'port': port_,
                                    'weight': weight_,
                                }
                            )
                            continue

                        for type_, name_, addr_ in ip_list:
                            if type_ in ['A', 'AAAA']:
                                logger.info(f'\t SRV {fqdn_} {target} {port_} {weight_} {addr_}')
                                zone_records.append(
                                    {
                                        'zone_server': ns_srv,
                                        'type': 'SRV',
                                        'name': fqdn_,
                                        'target': target,
                                        'address': addr_,
                                        'port': port_,
                                        'weight': weight_,
                                    }
                                )

                for name, rdataset in zone.iterate_rdatasets(dns.rdatatype.HINFO):
                    for rdata in rdataset:
                        cpu_ = rdata.cpu.decode()
                        os_ = rdata.os.decode()
                        logger.info(f'\t HINFO {cpu_} {os_}')
                        zone_records.append(
                            {
                                'zone_server': ns_srv,
                                'type': 'HINFO',
                                'cpu': cpu_,
                                'os': os_,
                            }
                        )

                for name, rdataset in zone.iterate_rdatasets(dns.rdatatype.WKS):
                    for rdata in rdataset:
                        addr_ = rdata.address
                        bitmap_ = rdata.bitmap
                        proto_ = rdata.protocol
                        logger.info(f'\t WKS {addr_} {bitmap_} {proto_}')
                        zone_records.append(
                            {
                                'zone_server': ns_srv,
                                'type': 'WKS',
                                'address': addr_,
                                'bitmap': bitmap_,
                                'protocol': proto_,
                            }
                        )

                for name, rdataset in zone.iterate_rdatasets(dns.rdatatype.RP):
                    for rdata in rdataset:
                        mbox_ = rdata.mbox.to_text()
                        txt_ = rdata.txt.to_text()
                        logger.info(f'\t RP {mbox_} {txt_}')
                        zone_records.append(
                            {
                                'zone_server': ns_srv,
                                'type': 'RP',
                                'mbox': mbox_,
                                'txt': txt_,
                            }
                        )

                for name, rdataset in zone.iterate_rdatasets(dns.rdatatype.AFSDB):
                    for rdata in rdataset:
                        subtype_ = str(rdata.subtype)
                        hostname_ = rdata.hostname.to_text()
                        logger.info(f'\t AFSDB {subtype_} {hostname_}')
                        zone_records.append(
                            {
                                'zone_server': ns_srv,
                                'type': 'AFSDB',
                                'subtype': subtype_,
                                'hostname': hostname_,
                            }
                        )

                for name, rdataset in zone.iterate_rdatasets(dns.rdatatype.LOC):
                    for rdata in rdataset:
                        coordinates_ = rdata.to_text()
                        logger.info(f'\t LOC {coordinates_}')
                        zone_records.append(
                            {
                                'zone_server': ns_srv,
                                'type': 'LOC',
                                'coordinates': coordinates_,
                            }
                        )

                for name, rdataset in zone.iterate_rdatasets(dns.rdatatype.X25):
                    for rdata in rdataset:
                        addr_ = rdata.address
                        logger.info(f'\t X25 {addr_}')
                        zone_records.append({'zone_server': ns_srv, 'type': 'X25', 'address': addr_})

                for name, rdataset in zone.iterate_rdatasets(dns.rdatatype.ISDN):
                    for rdata in rdataset:
                        addr_ = rdata.address
                        logger.info(f'\t ISDN {addr_}')
                        zone_records.append({'zone_server': ns_srv, 'type': 'ISDN', 'address': addr_})

                for name, rdataset in zone.iterate_rdatasets(dns.rdatatype.RT):
                    for rdata in rdataset:
                        addr_ = rdata.address
                        exchange = strip_last_dot(rdata.exchange.to_text())
                        pref_ = str(rdata.preference)

                        logger.info(f'\t RT {exchange} {pref_}')
                        zone_records.append(
                            {
                                'zone_server': ns_srv,
                                'type': 'X25',
                                'address': addr_,
                                'preference': pref_,
                            }
                        )

                for name, rdataset in zone.iterate_rdatasets(dns.rdatatype.NSAP):
                    for rdata in rdataset:
                        addr_ = rdata.address
                        logger.info(f'\t NSAP {addr_}')
                        zone_records.append({'zone_server': ns_srv, 'type': 'NSAP', 'address': addr_})

                for name, rdataset in zone.iterate_rdatasets(dns.rdatatype.NAPTR):
                    for rdata in rdataset:
                        flags_ = rdata.flags.decode()
                        order_ = str(rdata.order)
                        pref_ = str(rdata.preference)
                        regexp_ = rdata.regexp.decode()
                        replacement_ = rdata.replacement.to_text()
                        service_ = rdata.service.decode()

                        logger.info(f'\t NAPTR {flags_} {order_} {pref_} {regexp_} {replacement_} {service_}')
                        zone_records.append(
                            {
                                'zone_server': ns_srv,
                                'type': 'NAPTR',
                                'order': order_,
                                'preference': pref_,
                                'regex': regexp_,
                                'replacement': replacement_,
                                'service': service_,
                            }
                        )

                for name, rdataset in zone.iterate_rdatasets(dns.rdatatype.CERT):
                    for rdata in rdataset:
                        algo_ = algorithm_to_text(rdata.algorithm)
                        cert_ = rdata.certificate
                        cert_type_ = rdata.certificate_type
                        key_tag_ = rdata.key_tag

                        logger.info(f'\t CERT {rdata.to_text()}')
                        zone_records.append(
                            {
                                'zone_server': ns_srv,
                                'type': 'CERT',
                                'algorithm': algo_,
                                'certificate': cert_,
                                'certificate_type': cert_type_,
                                'key_tag': key_tag_,
                            }
                        )

                for name, rdataset in zone.iterate_rdatasets(dns.rdatatype.SIG):
                    for rdata in rdataset:
                        algo_ = algorithm_to_text(rdata.algorithm)
                        expiration_ = rdata.expiration
                        inception_ = (rdata.inception,)
                        key_tag_ = rdata.key_tag
                        labels_ = rdata.labels
                        original_ttl_ = rdata.original_ttl
                        signature_ = rdata.signature
                        signer_ = str(rdata.signer)
                        type_covered_ = rdata.type_covered

                        logger.info(
                            f'\t SIG {algo_} {expiration_} {inception_} {key_tag_} {labels_} {original_ttl_} {signature_} {signer_} {type_covered_}'
                        )
                        zone_records.append(
                            {
                                'zone_server': ns_srv,
                                'type': 'SIG',
                                'algorithm': algo_,
                                'expiration': expiration_,
                                'inception': inception_,
                                'key_tag': key_tag_,
                                'labels': labels_,
                                'original_ttl': original_ttl_,
                                'signature': signature_,
                                'signer': signer_,
                                'type_covered': type_covered_,
                            }
                        )

                for name, rdataset in zone.iterate_rdatasets(dns.rdatatype.RRSIG):
                    for rdata in rdataset:
                        algo_ = algorithm_to_text(rdata.algorithm)
                        expiration_ = rdata.expiration
                        inception_ = (rdata.inception,)
                        key_tag_ = rdata.key_tag
                        labels_ = rdata.labels
                        original_ttl_ = rdata.original_ttl
                        signature_ = rdata.signature
                        signer_ = str(rdata.signer)
                        type_covered_ = rdata.type_covered

                        logger.info(
                            f'\t RRSIG {algo_} {expiration_} {inception_} {key_tag_} {labels_} {original_ttl_} {signature_} {signer_} {type_covered_}'
                        )
                        zone_records.append(
                            {
                                'zone_server': ns_srv,
                                'type': 'RRSIG',
                                'algorithm': algo_,
                                'expiration': expiration_,
                                'inception': inception_,
                                'key_tag': key_tag_,
                                'labels': labels_,
                                'original_ttl': original_ttl_,
                                'signature': signature_,
                                'signer': signer_,
                                'type_covered': type_covered_,
                            }
                        )

                for name, rdataset in zone.iterate_rdatasets(dns.rdatatype.DNSKEY):
                    for rdata in rdataset:
                        algo_ = algorithm_to_text(rdata.algorithm)
                        flags_ = rdata.flags
                        key_ = dns.rdata._hexify(rdata.key)
                        proto_ = rdata.protocol

                        logger.info(f'\t DNSKEY {algo_} {flags_} {key_} {proto_}')
                        zone_records.append(
                            {
                                'zone_server': ns_srv,
                                'type': 'DNSKEY',
                                'algorithm': algo_,
                                'flags': flags_,
                                'key': key_,
                                'protocol': proto_,
                            }
                        )

                for name, rdataset in zone.iterate_rdatasets(dns.rdatatype.DS):
                    for rdata in rdataset:
                        algo_ = algorithm_to_text(rdata.algorithm)
                        digest_ = dns.rdata._hexify(rdata.digest)
                        digest_type_ = rdata.digest_type
                        key_tag_ = rdata.key_tag

                        logger.info(f'\t DS {algo_} {digest_} {digest_type_} {key_tag_}')
                        zone_records.append(
                            {
                                'zone_server': ns_srv,
                                'type': 'DS',
                                'algorithm': algo_,
                                'digest': digest_,
                                'digest_type': digest_type_,
                                'key_tag': key_tag_,
                            }
                        )

                for name, rdataset in zone.iterate_rdatasets(dns.rdatatype.NSEC):
                    for rdata in rdataset:
                        next_ = rdata.next.to_text()
                        logger.info(f'\t NSEC {next_}')
                        zone_records.append({'zone_server': ns_srv, 'type': 'NSEC', 'next': next_})

                for name, rdataset in zone.iterate_rdatasets(dns.rdatatype.NSEC3):
                    for rdata in rdataset:
                        algo_ = algorithm_to_text(rdata.algorithm)
                        flags_ = rdata.flags
                        iterations_ = rdata.iterations
                        salt_ = dns.rdata._hexify(rdata.salt)

                        logger.info(f'\t NSEC3 {algo_} {flags_} {iterations_} {salt_}')
                        zone_records.append(
                            {
                                'zone_server': ns_srv,
                                'type': 'NSEC3',
                                'algorithm': algo_,
                                'flags': flags_,
                                'iterations': iterations_,
                                'salt': salt_,
                            }
                        )

                for name, rdataset in zone.iterate_rdatasets(dns.rdatatype.NSEC3PARAM):
                    for rdata in rdataset:
                        algo_ = algorithm_to_text(rdata.algorithm)
                        flags_ = rdata.flags
                        iterations_ = rdata.iterations
                        salt_ = dns.rdata._hexify(rdata.salt)

                        logger.info(f'\t NSEC3PARAM {algo_} {flags_} {iterations_} {salt_}')
                        zone_records.append(
                            {
                                'zone_server': ns_srv,
                                'type': 'NSEC3PARAM',
                                'algorithm': algo_,
                                'flags': flags_,
                                'iterations': iterations_,
                                'salt': salt_,
                            }
                        )

                for name, rdataset in zone.iterate_rdatasets(dns.rdatatype.IPSECKEY):
                    for rdata in rdataset:
                        algo_ = algorithm_to_text(rdata.algorithm)
                        key_ = dns.rdata._hexify(rdata.key)
                        gw_ = rdata.gateway
                        gw_type_ = rdata.gateway_type
                        prec_ = rdata.precedence

                        logger.info(f'\t IPSECKEY {algo_} {gw_} {gw_type_} {key_} {prec_}')
                        zone_records.append(
                            {
                                'zone_server': ns_srv,
                                'type': 'IPSECKEY',
                                'algorithm': algo_,
                                'gateway': gw_,
                                'gateway_type': gw_type_,
                                'key': key_,
                                'precedence': prec_,
                            }
                        )
            except Exception as e:
                logger.error(f'Zone Transfer Failed ({e})')
                zone_records.append({'type': 'info', 'zone_transfer': 'failed', 'ns_server': ns_srv})

        return zone_records
