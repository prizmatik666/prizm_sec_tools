#!/usr/bin/env python3
"""
lanwatch.py v2.2.0
Passive multicast LAN service observer.

Designed for:
  - Termux / Android (non-root)
  - Regular Linux shells (non-root)
  - Other Unix-like Python environments where multicast UDP works

Passively listens for:
  - mDNS / DNS-SD       224.0.0.251:5353
  - SSDP / UPnP        239.255.255.250:1900

Parses:
  - DNS questions
  - PTR
  - SRV
  - TXT
  - A
  - AAAA
  - SSDP NOTIFY
  - SSDP M-SEARCH
  - SSDP responses

Behavior:
  - DOES NOT transmit discovery probes
  - DOES NOT port scan
  - DOES NOT ping sweep
  - DOES NOT connect to discovered services
  - Detects Termux vs regular Linux vs other environments
  - Detects the preferred local IPv4 used for multicast routing
  - Attempts to identify the active interface on regular Linux
  - Uses pure Python socket behavior in Termux
  - Marks self-originating traffic
  - Deduplicates repetitive display output
  - Correlates DNS-SD service records
  - Separates reverse-DNS PTRs from services
  - Distinguishes service advertisers from query-only clients
  - Infers simple device roles
  - Prints a clean inventory on Ctrl+C
  - Optionally saves TXT + JSON reports

Requirements:
  Python 3 only.
  No pip packages required.

Termux:
  pkg install python
  python3 lanwatch.py

Linux:
  python3 lanwatch.py
"""

import json
import os
import platform
import select
import shutil
import socket
import struct
import subprocess
import sys
import time
from collections import defaultdict
from datetime import datetime


VERSION = "2.2.0"

MDNS_GROUP = "224.0.0.251"
MDNS_PORT = 5353

SSDP_GROUP = "239.255.255.250"
SSDP_PORT = 1900

DISPLAY_DEDUPE_SECONDS = 30


# ============================================================
# Utility
# ============================================================

def now():
    return datetime.now().strftime("%H:%M:%S")


def iso_now():
    return datetime.now().isoformat(timespec="seconds")


def safe_decode(data):
    return data.decode("utf-8", errors="replace")


def ip_sort_key(ip):
    try:
        return tuple(int(part) for part in ip.split("."))
    except Exception:
        return (999, 999, 999, 999)


# ============================================================
# Runtime / environment detection
# ============================================================

def detect_environment():
    """Detect Termux, regular Linux, macOS, or generic Python runtime."""

    system_name = platform.system() or "Unknown"
    prefix = os.environ.get("PREFIX", "")
    termux_version = os.environ.get("TERMUX_VERSION")
    termux_prefix = "/data/data/com.termux/files/usr"

    info = {
        "type": "other",
        "platform": system_name,
        "system": system_name,
        "distro": None,
        "prefix": prefix or None,
        "python": platform.python_version(),
        "kernel": platform.release() or None,
    }

    if (
        termux_version
        or prefix.startswith(termux_prefix)
        or os.path.exists(termux_prefix)
    ):
        info["type"] = "termux"
        info["system"] = "Android / Termux"
        info["distro"] = "Termux"
        return info

    if sys.platform.startswith("linux"):
        info["type"] = "linux"
        info["system"] = "Linux"

        os_release = "/etc/os-release"

        if os.path.exists(os_release):
            try:
                values = {}

                with open(
                    os_release,
                    "r",
                    encoding="utf-8",
                    errors="replace",
                ) as f:
                    for line in f:
                        line = line.strip()

                        if (
                            not line
                            or line.startswith("#")
                            or "=" not in line
                        ):
                            continue

                        key, value = line.split("=", 1)

                        values[key] = value.strip().strip('"')

                info["distro"] = (
                    values.get("PRETTY_NAME")
                    or values.get("NAME")
                    or None
                )

            except OSError:
                pass

        return info

    if sys.platform == "darwin":
        info["type"] = "macos"
        info["system"] = "macOS"
        info["distro"] = platform.mac_ver()[0] or None
        return info

    return info


def runtime_capabilities(env):
    """Report capabilities used by this portable, non-root branch."""

    caps = {
        "multicast_udp": True,
        "raw_socket": False,
        "sysfs_net": False,
        "proc_route": False,
        "ip_command": shutil.which("ip") is not None,
        "interface_names": False,
    }

    if env["type"] == "linux":
        caps["sysfs_net"] = os.path.isdir("/sys/class/net")
        caps["proc_route"] = os.path.exists("/proc/net/route")

        caps["interface_names"] = (
            caps["sysfs_net"]
            or caps["proc_route"]
            or caps["ip_command"]
        )

    elif env["type"] == "macos":
        caps["interface_names"] = True

    elif env["type"] == "termux":
        # Deliberately keep the portable Termux path conservative.
        caps["interface_names"] = False

    return caps


def local_ipv4():
    """
    Ask the kernel which local IPv4 it would use for mDNS multicast.

    UDP connect() does not send application data; it only selects a route
    and local address for the socket.
    """

    s = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM
    )

    try:
        s.connect(
            (MDNS_GROUP, MDNS_PORT)
        )

        return s.getsockname()[0]

    except Exception:
        return None

    finally:
        s.close()


def linux_interface_for_ip(local_ip):
    """
    Best-effort interface-name lookup for regular Linux.

    This is diagnostic only. Listener setup uses the local IPv4 directly,
    so failure here does not prevent collection.
    """

    if not local_ip:
        return None

    if shutil.which("ip"):
        try:
            result = subprocess.run(
                [
                    "ip",
                    "-o",
                    "-4",
                    "addr",
                    "show"
                ],
                capture_output=True,
                text=True,
                timeout=2,
                check=False,
            )

            for line in result.stdout.splitlines():
                parts = line.split()

                if len(parts) < 4:
                    continue

                iface = parts[1]
                address = parts[3].split("/", 1)[0]

                if address == local_ip:
                    return iface

        except Exception:
            pass

    return None


def detect_interface(env, local_ip):
    if env["type"] == "linux":
        return linux_interface_for_ip(local_ip)

    return None


def print_environment_banner(
    env,
    caps,
    own_ip,
    interface_name
):
    print(
        f"[*] Runtime      : "
        f"{env['system']}"
    )

    if env.get("distro"):
        print(
            f"[*] Distribution : "
            f"{env['distro']}"
        )

    print(
        f"[*] Python       : "
        f"{env['python']}"
    )

    if env.get("kernel"):
        print(
            f"[*] Kernel       : "
            f"{env['kernel']}"
        )

    if env["type"] == "termux":
        print(
            "[*] Mode         : "
            "Termux / non-root Android"
        )

        print(
            "[*] Network      : "
            "Android userspace multicast sockets"
        )

    elif env["type"] == "linux":
        print(
            "[*] Mode         : "
            "Standard Linux userspace"
        )

        print(
            "[*] Network      : "
            "Linux multicast sockets"
        )

    elif env["type"] == "macos":
        print(
            "[*] Mode         : "
            "macOS userspace"
        )

        print(
            "[*] Network      : "
            "BSD multicast sockets"
        )

    else:
        print(
            "[*] Mode         : "
            "Generic Python socket mode"
        )

    if own_ip:
        print(
            f"[*] Local IPv4   : "
            f"{own_ip}"
        )
    else:
        print(
            "[*] Local IPv4   : "
            "undetermined"
        )

    if interface_name:
        print(
            f"[*] Interface    : "
            f"{interface_name}"
        )

    elif env["type"] == "linux":
        print(
            "[*] Interface    : "
            "automatic / unresolved name"
        )

    elif env["type"] == "termux":
        print(
            "[*] Interface    : "
            "Android automatic selection"
        )

    else:
        print(
            "[*] Interface    : "
            "automatic"
        )

    if (
        env["type"] == "linux"
        and caps["ip_command"]
    ):
        print(
            "[*] Linux helper : "
            "ip command available"
        )


# ============================================================
# Multicast sockets
# ============================================================

def make_listener(
    group,
    port,
    interface_ip=None
):
    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM,
        socket.IPPROTO_UDP,
    )

    sock.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1,
    )

    try:
        sock.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_REUSEPORT,
            1,
        )

    except (AttributeError, OSError):
        pass

    try:
        sock.bind(
            ("", port)
        )

    except OSError:
        # Useful fallback on some Android /
        # BSD-derived stacks.
        sock.bind(
            (group, port)
        )

    iface = (
        interface_ip
        or "0.0.0.0"
    )

    membership = struct.pack(
        "=4s4s",
        socket.inet_aton(group),
        socket.inet_aton(iface),
    )

    try:
        sock.setsockopt(
            socket.IPPROTO_IP,
            socket.IP_ADD_MEMBERSHIP,
            membership,
        )

    except OSError:
        # If explicit interface membership fails,
        # retry using the OS default.
        if iface != "0.0.0.0":
            membership = struct.pack(
                "=4s4s",
                socket.inet_aton(group),
                socket.inet_aton(
                    "0.0.0.0"
                ),
            )

            sock.setsockopt(
                socket.IPPROTO_IP,
                socket.IP_ADD_MEMBERSHIP,
                membership,
            )

        else:
            raise

    sock.setblocking(False)

    return sock


# ============================================================
# DNS helpers
# ============================================================

def decode_dns_name(
    packet,
    offset,
    depth=0
):
    """Decode an RFC1035 compressed DNS name."""

    if depth > 20:
        return (
            "<compression-loop>",
            offset
        )

    labels = []
    original_next = None

    while offset < len(packet):
        length = packet[offset]

        if length == 0:
            offset += 1

            if original_next is None:
                original_next = offset

            break

        # RFC1035 compression pointer.
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(packet):
                break

            pointer = (
                ((length & 0x3F) << 8)
                | packet[offset + 1]
            )

            if original_next is None:
                original_next = (
                    offset + 2
                )

            pointed_name, _ = (
                decode_dns_name(
                    packet,
                    pointer,
                    depth + 1,
                )
            )

            if pointed_name:
                labels.append(
                    pointed_name
                )

            break

        offset += 1

        if offset + length > len(packet):
            break

        label = packet[
            offset:offset + length
        ]

        labels.append(
            label.decode(
                "utf-8",
                errors="replace"
            )
        )

        offset += length

    if original_next is None:
        original_next = offset

    return (
        ".".join(labels),
        original_next
    )


def parse_txt(rdata):
    values = []
    offset = 0

    while offset < len(rdata):
        length = rdata[offset]
        offset += 1

        value = rdata[
            offset:offset + length
        ]

        offset += length

        if value:
            values.append(
                value.decode(
                    "utf-8",
                    errors="replace"
                )
            )

    return values


def dns_type_name(rtype):
    names = {
        1: "A",
        12: "PTR",
        16: "TXT",
        28: "AAAA",
        33: "SRV",
        255: "ANY",
    }

    return names.get(
        rtype,
        f"TYPE{rtype}"
    )


def is_reverse_dns_name(name):
    lower = name.lower()

    return (
        lower.endswith(
            ".in-addr.arpa"
        )
        or lower.endswith(
            ".ip6.arpa"
        )
    )


def is_dns_sd_service_type(name):
    lower = name.lower()

    return (
        lower.endswith(
            "._tcp.local"
        )
        or lower.endswith(
            "._udp.local"
        )
        or lower
        == "_services._dns-sd._udp.local"
    )


def is_service_instance(name):
    lower = name.lower()

    if (
        "._tcp.local"
        not in lower
        and "._udp.local"
        not in lower
    ):
        return False

    parts = name.split(".")

    if len(parts) < 4:
        return False

    return not parts[0].startswith("_")


# ============================================================
# DNS record parsing
# ============================================================

def parse_dns_record(
    packet,
    offset
):
    name, offset = decode_dns_name(
        packet,
        offset
    )

    if offset + 10 > len(packet):
        raise ValueError(
            "truncated DNS record"
        )

    (
        rtype,
        rclass,
        ttl,
        rdlength
    ) = struct.unpack(
        "!HHIH",
        packet[offset:offset + 10],
    )

    offset += 10

    rdata_offset = offset
    rdata_end = (
        offset + rdlength
    )

    if rdata_end > len(packet):
        raise ValueError(
            "truncated DNS RDATA"
        )

    rdata = packet[
        rdata_offset:rdata_end
    ]

    record = {
        "name": name,
        "type": dns_type_name(rtype),
        "rtype": rtype,
        "class": rclass & 0x7FFF,
        "cache_flush": bool(
            rclass & 0x8000
        ),
        "ttl": ttl,
        "value": None,
    }

    if (
        rtype == 1
        and len(rdata) == 4
    ):
        record["value"] = (
            socket.inet_ntoa(
                rdata
            )
        )

    elif (
        rtype == 28
        and len(rdata) == 16
    ):
        try:
            record["value"] = (
                socket.inet_ntop(
                    socket.AF_INET6,
                    rdata
                )
            )

        except Exception:
            record["value"] = (
                rdata.hex()
            )

    elif rtype == 12:
        value, _ = decode_dns_name(
            packet,
            rdata_offset
        )

        record["value"] = value

    elif (
        rtype == 33
        and len(rdata) >= 6
    ):
        (
            priority,
            weight,
            port
        ) = struct.unpack(
            "!HHH",
            rdata[:6]
        )

        target, _ = decode_dns_name(
            packet,
            rdata_offset + 6
        )

        record["value"] = {
            "priority": priority,
            "weight": weight,
            "port": port,
            "target": target,
        }

    elif rtype == 16:
        record["value"] = (
            parse_txt(rdata)
        )

    else:
        record["value"] = (
            rdata.hex()[:128]
        )

    return (
        record,
        rdata_end
    )


def parse_mdns(packet):
    result = {
        "id": 0,
        "query": True,
        "questions": [],
        "answers": [],
        "authorities": [],
        "additional": [],
    }

    if len(packet) < 12:
        return result

    (
        dns_id,
        flags,
        qdcount,
        ancount,
        nscount,
        arcount,
    ) = struct.unpack(
        "!HHHHHH",
        packet[:12]
    )

    result["id"] = dns_id

    result["query"] = not bool(
        flags & 0x8000
    )

    offset = 12

    for _ in range(qdcount):
        name, offset = decode_dns_name(
            packet,
            offset
        )

        if offset + 4 > len(packet):
            break

        (
            qtype,
            qclass
        ) = struct.unpack(
            "!HH",
            packet[offset:offset + 4]
        )

        offset += 4

        result["questions"].append({
            "name": name,
            "type": dns_type_name(
                qtype
            ),
            "unicast_response": bool(
                qclass & 0x8000
            ),
        })

    sections = [
        ("answers", ancount),
        ("authorities", nscount),
        ("additional", arcount),
    ]

    for (
        section_name,
        count
    ) in sections:

        for _ in range(count):
            try:
                (
                    record,
                    offset
                ) = parse_dns_record(
                    packet,
                    offset
                )

                result[
                    section_name
                ].append(
                    record
                )

            except Exception:
                break

    return result


# ============================================================
# SSDP
# ============================================================

def parse_ssdp(packet):
    text = safe_decode(
        packet
    ).replace(
        "\r",
        ""
    )

    lines = text.split("\n")

    if not lines:
        return {}

    result = {
        "start": lines[0].strip(),
        "headers": {},
    }

    for line in lines[1:]:
        if ":" not in line:
            continue

        key, value = line.split(
            ":",
            1
        )

        result["headers"][
            key.strip().upper()
        ] = value.strip()

    return result


# ============================================================
# Inventory model
# ============================================================

def blank_device():
    return {
        "protocols": set(),
        "hostnames": set(),
        "addresses": set(),
        "reverse_dns": set(),
        "service_types": set(),
        "service_instances": set(),
        "ports": set(),
        "txt": set(),
        "queries": set(),
        "ssdp_types": set(),
        "locations": set(),
        "servers": set(),
        "mdns_queries": 0,
        "mdns_responses": 0,
        "ssdp_searches": 0,
        "ssdp_notifies": 0,
        "ssdp_responses": 0,
        "first_seen": None,
        "last_seen": None,
        "packets": 0,
        "self": False,
    }


inventory = defaultdict(
    blank_device
)


services = defaultdict(
    lambda: {
        "service_type": None,
        "target": None,
        "port": None,
        "txt": set(),
        "addresses": set(),
        "sources": set(),
    }
)


def touch_device(
    ip,
    protocol,
    own_ip
):
    d = inventory[ip]

    if d["first_seen"] is None:
        d["first_seen"] = (
            iso_now()
        )

    d["last_seen"] = (
        iso_now()
    )

    d["packets"] += 1

    d["protocols"].add(
        protocol
    )

    if (
        own_ip
        and ip == own_ip
    ):
        d["self"] = True

    return d


# ============================================================
# mDNS correlation
# ============================================================

def service_type_from_instance(
    instance
):
    parts = instance.split(".")

    for i, part in enumerate(parts):
        if (
            part.startswith("_")
            and i + 1 < len(parts)
            and parts[i + 1]
            in ("_tcp", "_udp")
        ):
            return ".".join(
                parts[i:]
            )

    return None


def learn_mdns(
    ip,
    parsed,
    own_ip
):
    d = touch_device(
        ip,
        "mDNS",
        own_ip
    )

    if parsed["query"]:
        d["mdns_queries"] += 1

    else:
        d["mdns_responses"] += 1

    for q in parsed["questions"]:
        qname = q["name"]

        if qname:
            d["queries"].add(
                f"{q['type']} "
                f"{qname}"
            )

    records = (
        parsed["answers"]
        + parsed["authorities"]
        + parsed["additional"]
    )

    # First pass:
    # host addressing.
    for record in records:
        rtype = record["type"]
        name = record["name"]
        value = record["value"]

        if rtype in (
            "A",
            "AAAA"
        ):
            if name:
                d["hostnames"].add(
                    name
                )

            if value:
                d["addresses"].add(
                    str(value)
                )

                for svc in (
                    services.values()
                ):
                    if (
                        svc["target"]
                        == name
                    ):
                        svc[
                            "addresses"
                        ].add(
                            str(value)
                        )

    # Second pass:
    # PTR / SRV / TXT correlation.
    for record in records:
        rtype = record["type"]
        name = record["name"]
        value = record["value"]

        if rtype == "PTR":
            if is_reverse_dns_name(
                name
            ):
                target = (
                    value
                    if isinstance(
                        value,
                        str
                    )
                    else ""
                )

                if target:
                    d[
                        "reverse_dns"
                    ].add(
                        f"{name} "
                        f"-> {target}"
                    )

                else:
                    d[
                        "reverse_dns"
                    ].add(
                        name
                    )

                continue

            if is_dns_sd_service_type(
                name
            ):
                d[
                    "service_types"
                ].add(
                    name
                )

                if (
                    isinstance(
                        value,
                        str
                    )
                    and value
                ):
                    if is_service_instance(
                        value
                    ):
                        d[
                            "service_instances"
                        ].add(
                            value
                        )

                        svc = services[
                            value
                        ]

                        svc[
                            "service_type"
                        ] = name

                        svc[
                            "sources"
                        ].add(
                            ip
                        )

                continue

        elif rtype == "SRV":
            if not isinstance(
                value,
                dict
            ):
                continue

            target = value.get(
                "target"
            )

            port = value.get(
                "port"
            )

            if is_service_instance(
                name
            ):
                d[
                    "service_instances"
                ].add(
                    name
                )

                svc = services[
                    name
                ]

                svc[
                    "sources"
                ].add(
                    ip
                )

                inferred_type = (
                    service_type_from_instance(
                        name
                    )
                )

                if inferred_type:
                    svc[
                        "service_type"
                    ] = inferred_type

                if target:
                    svc[
                        "target"
                    ] = target

                    d[
                        "hostnames"
                    ].add(
                        target
                    )

                if port:
                    svc[
                        "port"
                    ] = port

                    d[
                        "ports"
                    ].add(
                        port
                    )

        elif rtype == "TXT":
            if not isinstance(
                value,
                list
            ):
                continue

            if is_service_instance(
                name
            ):
                d[
                    "service_instances"
                ].add(
                    name
                )

                svc = services[
                    name
                ]

                svc[
                    "sources"
                ].add(
                    ip
                )

                inferred_type = (
                    service_type_from_instance(
                        name
                    )
                )

                if inferred_type:
                    svc[
                        "service_type"
                    ] = inferred_type

                for item in value:
                    svc[
                        "txt"
                    ].add(
                        item
                    )

                    d[
                        "txt"
                    ].add(
                        item
                    )

    # Third pass:
    # Attach A/AAAA records from this packet
    # to service target hostnames.
    host_address_map = (
        defaultdict(set)
    )

    for record in records:
        if record["type"] in (
            "A",
            "AAAA"
        ):
            if (
                record["name"]
                and record["value"]
            ):
                host_address_map[
                    record["name"]
                ].add(
                    str(
                        record["value"]
                    )
                )

    for svc in services.values():
        target = svc["target"]

        if target in host_address_map:
            svc[
                "addresses"
            ].update(
                host_address_map[
                    target
                ]
            )


# ============================================================
# SSDP learning
# ============================================================

def learn_ssdp(
    ip,
    parsed,
    own_ip
):
    d = touch_device(
        ip,
        "SSDP",
        own_ip
    )

    start = parsed.get(
        "start",
        ""
    ).upper()

    headers = parsed.get(
        "headers",
        {}
    )

    if start.startswith(
        "M-SEARCH"
    ):
        d[
            "ssdp_searches"
        ] += 1

    elif start.startswith(
        "NOTIFY"
    ):
        d[
            "ssdp_notifies"
        ] += 1

    elif start.startswith(
        "HTTP/"
    ):
        d[
            "ssdp_responses"
        ] += 1

    for field in (
        "ST",
        "NT",
        "USN"
    ):
        value = headers.get(
            field
        )

        if value:
            d[
                "ssdp_types"
            ].add(
                value
            )

    location = headers.get(
        "LOCATION"
    )

    if location:
        d[
            "locations"
        ].add(
            location
        )

    server = headers.get(
        "SERVER"
    )

    if server:
        d[
            "servers"
        ].add(
            server
        )


# ============================================================
# Role inference
# ============================================================

def infer_role(ip, d):
    joined_services = " ".join(
        list(
            d["service_types"]
        )
        + list(
            d["service_instances"]
        )
    ).lower()

    joined_ssdp = " ".join(
        d["ssdp_types"]
    ).lower()

    joined_txt = " ".join(
        d["txt"]
    ).lower()

    joined_names = " ".join(
        d["hostnames"]
    ).lower()

    evidence = " ".join([
        joined_services,
        joined_ssdp,
        joined_txt,
        joined_names,
    ])

    roles = []

    if (
        "_ipp._tcp" in evidence
        or "_ipps._tcp" in evidence
        or "printer" in evidence
        or "epson" in evidence
    ):
        roles.append(
            "Printer / IPP"
        )

    if (
        "_googlecast._tcp"
        in evidence
        or "googlecast"
        in evidence
    ):
        roles.append(
            "Google Cast"
        )

    if (
        "_airplay._tcp"
        in evidence
        or "airplay"
        in evidence
    ):
        roles.append(
            "AirPlay"
        )

    if (
        "_viziocast._tcp"
        in evidence
        or "vizio"
        in evidence
    ):
        roles.append(
            "VIZIO TV"
        )

    if (
        "roku:ecp"
        in evidence
        or "roku"
        in evidence
    ):
        roles.append(
            "Roku"
        )

    if (
        "mediaserver"
        in evidence
        or "contentdirectory"
        in evidence
        or "twonky"
        in evidence
    ):
        roles.append(
            "UPnP/DLNA Media Server"
        )

    if (
        "_hap._tcp"
        in evidence
        or "homekit"
        in evidence
    ):
        roles.append(
            "HomeKit/HAP"
        )

    if (
        "android.local"
        in evidence
        or "android"
        in evidence
    ):
        roles.append(
            "Android"
        )

    advertises_mdns = (
        d["mdns_responses"] > 0
        or bool(
            d["service_instances"]
        )
        or bool(
            d["service_types"]
        )
    )

    advertises_ssdp = (
        d["ssdp_notifies"] > 0
        or d["ssdp_responses"] > 0
    )

    searches_only = (
        (
            d["mdns_queries"] > 0
            or d["ssdp_searches"] > 0
        )
        and not advertises_mdns
        and not advertises_ssdp
    )

    if searches_only:
        roles.append(
            "Discovery client"
        )

    if not roles:
        if (
            d["mdns_queries"] > 0
            or d["mdns_responses"] > 0
        ):
            roles.append(
                "Unknown mDNS participant"
            )

        elif "SSDP" in d["protocols"]:
            roles.append(
                "Unknown SSDP participant"
            )

        else:
            roles.append(
                "Unknown"
            )

    result = []

    for role in roles:
        if role not in result:
            result.append(
                role
            )

    return result


# ============================================================
# Live display
# ============================================================

def print_mdns(
    ip,
    parsed,
    own_ip
):
    marker = (
        " [SELF]"
        if (
            own_ip
            and ip == own_ip
        )
        else ""
    )

    kind = (
        "QUERY"
        if parsed["query"]
        else "RESPONSE"
    )

    print(
        f"[{now()}] "
        f"mDNS {kind} "
        f"{ip}:5353"
        f"{marker}"
    )

    for q in parsed["questions"]:
        print(
            f"    Q "
            f"{q['type']:<5} "
            f"{q['name']}"
        )

    records = (
        parsed["answers"]
        + parsed["additional"]
    )

    shown = set()

    for record in records:
        key = (
            record["name"],
            record["type"],
            str(
                record["value"]
            ),
        )

        if key in shown:
            continue

        shown.add(
            key
        )

        rtype = record["type"]
        name = record["name"]
        value = record["value"]

        if (
            rtype == "SRV"
            and isinstance(
                value,
                dict
            )
        ):
            print(
                f"    SRV {name}"
            )

            print(
                f"        -> "
                f"{value['target']}:"
                f"{value['port']}"
            )

        elif (
            rtype == "TXT"
            and isinstance(
                value,
                list
            )
        ):
            print(
                f"    TXT {name}"
            )

            for item in value:
                print(
                    f"        {item}"
                )

        elif rtype == "PTR":
            print(
                f"    PTR {name}"
            )

            if value:
                print(
                    f"        -> "
                    f"{value}"
                )

        else:
            print(
                f"    "
                f"{rtype:<4} "
                f"{name}"
            )

            if (
                value is not None
                and value != ""
                and value != name
            ):
                print(
                    f"        -> "
                    f"{value}"
                )

    print()


def print_ssdp(
    ip,
    parsed,
    port,
    own_ip
):
    marker = (
        " [SELF]"
        if (
            own_ip
            and ip == own_ip
        )
        else ""
    )

    print(
        f"[{now()}] "
        f"SSDP "
        f"{ip}:{port}"
        f"{marker}"
    )

    print(
        f"    "
        f"{parsed.get('start', '')}"
    )

    headers = parsed.get(
        "headers",
        {}
    )

    interesting = (
        "HOST",
        "ST",
        "NT",
        "NTS",
        "USN",
        "SERVER",
        "LOCATION",
        "CACHE-CONTROL",
    )

    for key in interesting:
        if key in headers:
            print(
                f"    {key}: "
                f"{headers[key]}"
            )

    print()


# ============================================================
# Report formatting
# ============================================================

def service_objects_for_ip(ip):
    result = []

    for (
        instance,
        svc
    ) in services.items():

        if ip not in svc["sources"]:
            continue

        result.append({
            "instance": instance,
            "service_type":
                svc["service_type"],
            "target":
                svc["target"],
            "port":
                svc["port"],
            "txt":
                sorted(
                    svc["txt"]
                ),
            "addresses":
                sorted(
                    svc["addresses"]
                ),
        })

    return sorted(
        result,
        key=lambda x:
            x["instance"].lower()
    )


def serializable_inventory():
    result = {}

    for (
        ip,
        d
    ) in inventory.items():

        item = {}

        for (
            key,
            value
        ) in d.items():

            if isinstance(
                value,
                set
            ):
                item[key] = sorted(
                    value,
                    key=lambda x:
                        str(x)
                )

            else:
                item[key] = value

        item["roles"] = infer_role(
            ip,
            d
        )

        item[
            "dns_sd_services"
        ] = service_objects_for_ip(
            ip
        )

        result[ip] = item

    return result


def print_summary():
    print()

    print(
        "=" * 72
    )

    print(
        " PASSIVE LAN INVENTORY"
    )

    print(
        "=" * 72
    )

    if not inventory:
        print(
            "No devices observed."
        )
        return

    for ip in sorted(
        inventory.keys(),
        key=ip_sort_key
    ):
        d = inventory[ip]

        self_marker = (
            " [SELF]"
            if d["self"]
            else ""
        )

        print()

        print(
            f"[{ip}]"
            f"{self_marker}"
        )

        roles = infer_role(
            ip,
            d
        )

        print(
            "  Role      : "
            + ", ".join(
                roles
            )
        )

        if d["protocols"]:
            print(
                "  Protocols : "
                + ", ".join(
                    sorted(
                        d[
                            "protocols"
                        ]
                    )
                )
            )

        if d["hostnames"]:
            print(
                "  Hostnames:"
            )

            for name in sorted(
                d["hostnames"]
            ):
                print(
                    f"    {name}"
                )

        if d["reverse_dns"]:
            print(
                "  Reverse DNS:"
            )

            for item in sorted(
                d["reverse_dns"]
            ):
                print(
                    f"    {item}"
                )

        if d["service_types"]:
            print(
                "  Service types:"
            )

            for item in sorted(
                d["service_types"]
            ):
                print(
                    f"    {item}"
                )

        service_objects = (
            service_objects_for_ip(
                ip
            )
        )

        if service_objects:
            print(
                "  DNS-SD services:"
            )

            for svc in service_objects:
                print(
                    f"    "
                    f"{svc['instance']}"
                )

                if svc[
                    "service_type"
                ]:
                    print(
                        f"      type : "
                        f"{svc['service_type']}"
                    )

                if svc["target"]:
                    print(
                        f"      host : "
                        f"{svc['target']}"
                    )

                if svc["port"]:
                    print(
                        f"      port : "
                        f"{svc['port']}"
                    )

                if svc["addresses"]:
                    print(
                        "      addr : "
                        + ", ".join(
                            svc[
                                "addresses"
                            ]
                        )
                    )

                if svc["txt"]:
                    print(
                        "      TXT:"
                    )

                    for item in svc[
                        "txt"
                    ]:
                        print(
                            f"        "
                            f"{item}"
                        )

        if d["ports"]:
            print(
                "  Advertised ports: "
                + ", ".join(
                    str(x)
                    for x in sorted(
                        d["ports"]
                    )
                )
            )

        if d["ssdp_types"]:
            print(
                "  SSDP types:"
            )

            for item in sorted(
                d["ssdp_types"]
            ):
                print(
                    f"    {item}"
                )

        if d["servers"]:
            print(
                "  Server strings:"
            )

            for item in sorted(
                d["servers"]
            ):
                print(
                    f"    {item}"
                )

        if d["locations"]:
            print(
                "  Description locations:"
            )

            for item in sorted(
                d["locations"]
            ):
                print(
                    f"    {item}"
                )

        if d["queries"]:
            print(
                "  Discovery queries:"
            )

            for item in sorted(
                d["queries"]
            )[:20]:
                print(
                    f"    {item}"
                )

            if (
                len(
                    d["queries"]
                )
                > 20
            ):
                print(
                    f"    ... "
                    f"{len(d['queries']) - 20} "
                    f"more"
                )

        print(
            "  Activity:"
        )

        print(
            f"    mDNS queries    : "
            f"{d['mdns_queries']}"
        )

        print(
            f"    mDNS responses  : "
            f"{d['mdns_responses']}"
        )

        print(
            f"    SSDP searches   : "
            f"{d['ssdp_searches']}"
        )

        print(
            f"    SSDP NOTIFY     : "
            f"{d['ssdp_notifies']}"
        )

        print(
            f"    SSDP responses  : "
            f"{d['ssdp_responses']}"
        )

        print(
            f"    total packets   : "
            f"{d['packets']}"
        )

        print(
            f"    first seen      : "
            f"{d['first_seen']}"
        )

        print(
            f"    last seen       : "
            f"{d['last_seen']}"
        )


# ============================================================
# Saving
# ============================================================

def save_reports():
    answer = input(
        "\nSave inventory reports? [y/N]: "
    ).strip().lower()

    if answer not in (
        "y",
        "yes"
    ):
        return

    stamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    json_name = (
        f"lanwatch_{stamp}.json"
    )

    txt_name = (
        f"lanwatch_{stamp}.txt"
    )

    data = (
        serializable_inventory()
    )

    with open(
        json_name,
        "w",
        encoding="utf-8"
    ) as f:
        json.dump(
            data,
            f,
            indent=2
        )

    with open(
        txt_name,
        "w",
        encoding="utf-8"
    ) as f:

        for ip in sorted(
            data.keys(),
            key=ip_sort_key
        ):
            d = data[ip]

            f.write(
                "=" * 72
                + "\n"
            )

            f.write(
                ip
            )

            if d.get("self"):
                f.write(
                    " [SELF]"
                )

            f.write("\n")

            f.write(
                "=" * 72
                + "\n"
            )

            for (
                key,
                value
            ) in d.items():

                f.write(
                    f"{key}: "
                    f"{value}\n"
                )

            f.write("\n")

    print(
        f"[+] Saved "
        f"{txt_name}"
    )

    print(
        f"[+] Saved "
        f"{json_name}"
    )


# ============================================================
# Main
# ============================================================

def main():
    env = detect_environment()

    caps = runtime_capabilities(
        env
    )

    own_ip = local_ipv4()

    interface_name = (
        detect_interface(
            env,
            own_ip
        )
    )

    print(
        "=" * 72
    )

    print(
        f" Passive LAN Service Watch "
        f"v{VERSION}"
    )

    print(
        " mDNS + DNS-SD + SSDP"
    )

    print(
        " LISTEN ONLY — "
        "no discovery requests transmitted"
    )

    print(
        "=" * 72
    )

    print_environment_banner(
        env,
        caps,
        own_ip,
        interface_name,
    )

    listeners = {}

    try:
        mdns = make_listener(
            MDNS_GROUP,
            MDNS_PORT,
            own_ip,
        )

        listeners[
            mdns
        ] = "mDNS"

        print(
            f"[+] mDNS        : "
            f"{MDNS_GROUP}:"
            f"{MDNS_PORT}"
        )

    except Exception as e:
        print(
            f"[-] mDNS unavailable: "
            f"{e}"
        )

    try:
        ssdp = make_listener(
            SSDP_GROUP,
            SSDP_PORT,
            own_ip,
        )

        listeners[
            ssdp
        ] = "SSDP"

        print(
            f"[+] SSDP        : "
            f"{SSDP_GROUP}:"
            f"{SSDP_PORT}"
        )

    except Exception as e:
        print(
            f"[-] SSDP unavailable: "
            f"{e}"
        )

    if not listeners:
        print(
            "[!] No multicast "
            "listeners available."
        )

        return

    print()

    print(
        "[*] Listening for "
        "multicast traffic."
    )

    print(
        "[*] Passive collection depends "
        "on devices announcing themselves "
        "naturally."
    )

    print(
        "[*] For useful results, let this "
        "run for at least 2-5 minutes."
    )

    print(
        "[*] Longer captures may reveal "
        "devices and services that advertise "
        "less frequently."
    )

    print(
        "[*] Multicast visibility can be "
        "reduced by AP isolation, VPNs, "
        "containers,"
    )

    print(
        "    or multiple active network "
        "interfaces."
    )

    print(
        "[*] Ctrl+C to stop and summarize."
    )

    print()

    display_seen = {}

    try:
        while True:
            (
                readable,
                _,
                _
            ) = select.select(
                list(
                    listeners.keys()
                ),
                [],
                [],
                5,
            )

            cutoff = (
                time.time()
                - DISPLAY_DEDUPE_SECONDS
            )

            display_seen = {
                key: stamp
                for (
                    key,
                    stamp
                ) in display_seen.items()
                if stamp > cutoff
            }

            for sock in readable:
                try:
                    (
                        packet,
                        addr
                    ) = sock.recvfrom(
                        65535
                    )

                except Exception:
                    continue

                protocol = (
                    listeners[sock]
                )

                ip = addr[0]
                port = addr[1]

                fingerprint = (
                    protocol,
                    ip,
                    packet,
                )

                should_display = (
                    fingerprint
                    not in display_seen
                )

                display_seen[
                    fingerprint
                ] = time.time()

                if protocol == "mDNS":
                    try:
                        parsed = (
                            parse_mdns(
                                packet
                            )
                        )

                    except Exception:
                        continue

                    learn_mdns(
                        ip,
                        parsed,
                        own_ip
                    )

                    if should_display:
                        print_mdns(
                            ip,
                            parsed,
                            own_ip
                        )

                elif protocol == "SSDP":
                    parsed = parse_ssdp(
                        packet
                    )

                    learn_ssdp(
                        ip,
                        parsed,
                        own_ip
                    )

                    if should_display:
                        print_ssdp(
                            ip,
                            parsed,
                            port,
                            own_ip
                        )

    except KeyboardInterrupt:
        print_summary()

        try:
            save_reports()

        except (
            EOFError,
            KeyboardInterrupt
        ):
            pass

    finally:
        for sock in listeners:
            try:
                sock.close()

            except Exception:
                pass


if __name__ == "__main__":
    main()
