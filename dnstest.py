from recondns import general_enum, DnsHelper, write_to_file, make_csv

domain = 'baxter.com'

returned_records = []

def dnsrecon( domain, out_dir):

    ns_server = ['8.8.8.8']
    request_timeout = 10
    proto = 'udp'

    res = DnsHelper(domain, ns_server, request_timeout, proto)
    std_records = general_enum(res, domain, False, False, False, True, False, False, True, 10)
    write_to_file(make_csv(std_records), out_dir, '/dnsrecon/' + domain +'.txt')

dnsrecon('baxter.com','/tmp')
