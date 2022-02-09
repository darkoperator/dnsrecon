import pkg_resources


def version() -> str:
    return pkg_resources.require("dnsrecon")[0].version
