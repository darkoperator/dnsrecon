
from time import sleep

def get_a(host_trg):
    """
    Function for resolving the A Record for a given host. Returns an Array of
    the IP Address it resolves to.
    """
    address = []
    try:
        ipv4_answers = res.query(host_trg, 'A')
        for ardata in ipv4_answers:
            address.append(ardata.address)
            return address
    except:
        return address


def get_aaaa(host_trg):
    """
    Function for resolving the AAAA Record for a given host. Returns an Array of
    the IP Address it resolves to.
    """
    address = []
    try:
        ipv6_answers = res.query(host_trg, 'AAAA')
        for ardata in ipv6_answers:
            address.append(ardata.address)
            return address
    except:
        return address


def get_mx(domain):
    """
    Function for MX Record resolving. Returns all MX records. Returns also the IP
    address of the host both in IPv4 and IPv6. Returns an Array
    """
    mx_records = []
    answers = res.query(domain, 'MX')
    for rdata in answers:
        try:
            name = rdata.exchange.to_text()
            ipv4_answers = res.query(name, 'A')
            for ardata in ipv4_answers:
                mx_records.append(['MX', name[:-1], ardata.address,
                                rdata.preference])
        except:
            pass
    try:
        for rdata in answers:
            name = rdata.exchange.to_text()
            ipv6_answers = res.query(name, 'AAAA')
            for ardata in ipv6_answers:
                mx_records.append(['MX', name[:-1], ardata.address,
                                  rdata.preference])
        return mx_records
    except:
        return mx_records


def get_ns(domain):
    """
    Function for NS Record resolving. Returns all NS records. Returns also the IP
    address of the host both in IPv4 and IPv6. Returns an Array.
    """
    ns_srvs = []
    answers = res.query(domain, 'NS')
    for rdata in answers:
        name = rdata.target.to_text()
        ipv4_answers = res.query(name, 'A')
        for ardata in ipv4_answers:
            ns_srvs.append(['NS', name[:-1], ardata.address])
            
    try:
        for rdata in answers:
            name = rdata.target.to_text()
            ipv6_answers = res.query(name, 'AAAA')
            for ardata in ipv6_answers:
                ns_srvs.append(['NS', name[:-1], ardata.address])
                
        return ns_srvs
    except:
        return ns_srvs


def get_soa(domain):
    """
    Function for SOA Record resolving. Returns all SOA records. Returns also the IP
    address of the host both in IPv4 and IPv6. Returns an Array.
    """
    soa_records = []
    answers = res.query(domain, 'SOA')
    for rdata in answers:
        name = rdata.mname.to_text()
        ipv4_answers = res.query(name, 'A')
        for ardata in ipv4_answers:
            soa_records.extend(['SOA', name[:-1], ardata.address])
            
    try:
        for rdata in answers:
            name = rdata.mname.to_text()
            ipv4_answers = res.query(name, 'AAAA')
            for ardata in ipv4_answers:
                soa_records.extend(['SOA', name[:-1], ardata.address])
                
        return soa_records
    except:
        return soa_records


def get_spf(domain):
    """
    Function for SPF Record resolving returns the string with the SPF definition.
    Prints the string for the SPF Record and Returns the string
    """
    spf_record = []
    
    try:
        answers = res.query(domain, 'SPF')
        for rdata in answers:
            name = rdata.strings
            spf_record.extend(['SPF', name])
            print '[*]', 'SPF', name
    except:
        return None
    
    return spf_record

def get_txt(domain):
    """
    Function for TXT Record resolving returns the string.
    """
    txt_record = []
    try:
        answers = res.query(domain, 'TXT')
        for rdata in answers:
            name = "".join(rdata.strings)
            print '[*]\t', 'TXT', name
            txt_record.extend(['TXT', name])
    except:
        return None
    
    return txt_record

def get_ptr(ipaddress):
    """
    Function for resolving PTR Record given it's IPv4 or IPv6 Address.
    """
    found_ptr = []
    n = dns.reversename.from_address(ipaddress)
    try:
        answers = res.query(n, 'PTR')
        for a in answers:
            found_ptr.append(['PTR', a.target.to_text(),ipaddress])
        return found_ptr
    except:
        return None
    
def get_srv(host):
    """
    Function for resolving SRV Records.
    """
    record = []
    try:
        answers = res.query(host, 'SRV')
        for a in answers:
            target = a.target.to_text()
            for ip in get_a(target):
                record.append(['SRV', host, a.target.to_text(), ip,
                              str(a.port), str(a.weight)])
    except:
        return record
    return record

def get_ip(hostname):
    """
    Function resolves a host name to its given A and/or AAA record. Returns Array
    of found hosts and IPv4 or IPv6 Address.
    """
    found_ip_add = []
    ipv4 = get_a(hostname)
    sleep(0.2)
    if ipv4:
        for ip in ipv4:
            found_ip_add.append(["A",hostname,ip])
    ipv6 = get_aaaa(hostname)
    
    if ipv6:
        for ip in ipv6:
            found_ip_add.append(["AAAA",hostname,ip])
    
    return found_ip_add

