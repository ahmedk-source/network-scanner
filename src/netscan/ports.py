"""Port specifications, presets and service names.

The service names are intentionally a small, curated table instead of a full
port database: they are the ports a network scanner encounters in practice, and
they give the same answer on Windows, macOS and Linux.  Anything outside the
table falls back to the operating system's ``services`` database.
"""

from __future__ import annotations

import socket
from functools import cache

from .errors import PortSpecError

MAX_PORT = 65535

#: Curated port-to-service table.  The ``common`` preset is derived from it, so
#: the preset and the names can never disagree.
SERVICES: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "domain",
    67: "dhcp",
    68: "dhcp",
    69: "tftp",
    80: "http",
    81: "http-alt",
    88: "kerberos",
    110: "pop3",
    111: "rpcbind",
    123: "ntp",
    135: "msrpc",
    137: "netbios-ns",
    138: "netbios-dgm",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    162: "snmptrap",
    179: "bgp",
    389: "ldap",
    443: "https",
    445: "microsoft-ds",
    465: "smtps",
    500: "isakmp",
    514: "syslog",
    515: "printer",
    548: "afp",
    554: "rtsp",
    587: "submission",
    631: "ipp",
    636: "ldaps",
    646: "ldp",
    873: "rsync",
    990: "ftps",
    993: "imaps",
    995: "pop3s",
    1025: "nfs-or-iis",
    1080: "socks",
    1194: "openvpn",
    1433: "ms-sql-s",
    1434: "ms-sql-m",
    1521: "oracle",
    1723: "pptp",
    1755: "wms",
    1812: "radius",
    1813: "radius-acct",
    1883: "mqtt",
    1900: "ssdp",
    2000: "cisco-sccp",
    2049: "nfs",
    2121: "ftp-alt",
    2222: "ssh-alt",
    2323: "telnet-alt",
    2375: "docker",
    2376: "docker-tls",
    2379: "etcd-client",
    2380: "etcd-server",
    3000: "grafana",
    3128: "squid",
    3260: "iscsi",
    3306: "mysql",
    3389: "ms-wbt-server",
    3690: "svn",
    4000: "terabase",
    4443: "https-alt",
    4505: "salt-publish",
    4506: "salt-request",
    5000: "upnp",
    5060: "sip",
    5061: "sips",
    5222: "xmpp-client",
    5353: "mdns",
    5432: "postgresql",
    5555: "adb",
    5601: "kibana",
    5632: "pcanywhere",
    5672: "amqp",
    5900: "vnc",
    5901: "vnc-1",
    5984: "couchdb",
    6000: "x11",
    6379: "redis",
    6443: "kubernetes",
    7001: "weblogic",
    7002: "weblogic-ssl",
    8000: "http-alt",
    8008: "http-alt",
    8009: "ajp13",
    8080: "http-proxy",
    8081: "http-alt",
    8088: "http-alt",
    8090: "http-alt",
    8161: "activemq",
    8443: "https-alt",
    8883: "mqtt-tls",
    8888: "http-alt",
    9000: "http-alt",
    9001: "http-alt",
    9042: "cassandra",
    9090: "prometheus",
    9092: "kafka",
    9200: "elasticsearch",
    9300: "elasticsearch",
    9418: "git",
    9999: "abyss",
    10000: "webmin",
    11211: "memcached",
    15672: "rabbitmq-mgmt",
    27017: "mongodb",
    27018: "mongodb",
    50000: "db2",
    50070: "hdfs",
    61616: "activemq",
}

#: A curated list of around a hundred ports that are worth checking first.
COMMON_PORTS: tuple[int, ...] = tuple(sorted(SERVICES))

WEB_PORTS: tuple[int, ...] = (80, 443, 3000, 8000, 8080, 8443, 8888)

#: Named presets accepted by ``--ports``.
PRESETS: dict[str, tuple[int, ...]] = {
    "common": COMMON_PORTS,
    "web": WEB_PORTS,
}


def parse_ports(spec: str) -> tuple[int, ...]:
    """Expand a port specification into a sorted tuple of unique ports.

    Accepted forms, combinable with commas::

        80
        22,80,443
        1-1024
        common
        web
        all
    """
    text = spec.strip().lower()
    if not text:
        raise PortSpecError("no ports specified")

    if text == "all":
        return tuple(range(1, MAX_PORT + 1))
    if text in PRESETS:
        return PRESETS[text]

    ports: set[int] = set()
    for chunk in text.split(","):
        part = chunk.strip()
        if not part:
            raise PortSpecError(f"invalid port specification: {spec!r}")
        start_text, separator, end_text = part.partition("-")
        if separator:
            start = _parse_number(start_text.strip(), spec)
            end = _parse_number(end_text.strip(), spec)
            if start > end:
                raise PortSpecError(f"invalid range {part!r}: start is greater than end")
            ports.update(range(start, end + 1))
        else:
            ports.add(_parse_number(part, spec))

    if not ports:
        raise PortSpecError("no ports specified")
    return tuple(sorted(ports))


def _parse_number(value: str, spec: str) -> int:
    try:
        port = int(value)
    except ValueError:
        raise PortSpecError(f"invalid port {value!r} in {spec!r}") from None
    if not 1 <= port <= MAX_PORT:
        raise PortSpecError(f"port {port} is outside 1-{MAX_PORT}")
    return port


@cache
def service_name(port: int) -> str:
    """Return a short service name for *port*.

    The curated table wins; otherwise the platform service database is asked.
    """
    known = SERVICES.get(port)
    if known is not None:
        return known
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"
