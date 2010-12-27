import pybonjour
import select

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
        if errorCode == pybonjour.kDNSServiceErr_NoError:
            results.append({
                'name': fullname,
                'host': str(hosttarget).replace('\032'," "),
                'port': str(port),
                'txtRecord':txtRecord.strip()
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