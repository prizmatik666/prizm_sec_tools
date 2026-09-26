#!/usr/bin/env python3
"""Portable PCAP Workbench: analyze, read, search, and correlate captures.

Run without arguments for the interactive interface. CLI examples:

  python3 pcap_workbench.py analyze capture.pcap
  python3 pcap_workbench.py directory ./captures
  python3 pcap_workbench.py correlate --left-dir ./sensor-a --right-dir ./sensor-b
  python3 pcap_workbench.py read capture.pcap --mode follow-http --stream 0
  python3 pcap_workbench.py search capture.pcap --text example.org

The program uses Wireshark/tcpdump command-line tools and has no third-party
Python dependencies. It does not upload packet data. Analysis is descriptive:
"findings" are noteworthy protocol or transport observations, not automatic
security verdicts.
"""

from __future__ import annotations

import argparse
import bisect
import csv
import curses
import hashlib
import io
import json
import math
import os
import re
import shutil
import socket
import statistics
import subprocess
import sys
import textwrap
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Sequence


VERSION = "3.0.0"
DEFAULT_PRIMARY_DIR = Path.cwd()
DEFAULT_SECONDARY_DIR = Path.cwd()
DEFAULT_CORRELATION_FILTER = ""
DEFAULT_WINDOW = 0.050
DEFAULT_EVENT_LIMIT = 250
CAPTURE_SUFFIXES = (".pcap", ".pcapng", ".cap", ".pcap.gz", ".pcapng.gz", ".cap.gz")
READ_MODES = {
    "summary": "Packet list / one-line summaries",
    "decoded": "Fully decoded protocol trees",
    "decoded-hex": "Decoded protocol trees plus packet hex",
    "ascii": "Raw packet bytes as ASCII",
    "hex": "Raw packet bytes as hex plus ASCII",
    "plaintext": "Extracted application payload as readable text",
    "follow-tcp-ascii": "Reassembled TCP stream as ASCII",
    "follow-tcp-hex": "Reassembled TCP stream as hex plus ASCII",
    "follow-http": "Reassembled HTTP stream as plaintext",
    "follow-tls": "Reassembled decrypted TLS stream as plaintext",
    "follow-udp-ascii": "Reassembled UDP stream as ASCII",
    "follow-udp-hex": "Reassembled UDP stream as hex plus ASCII",
}

FIELDS = [
    "frame.number",
    "frame.time_epoch",
    "frame.time",
    "frame.len",
    "frame.cap_len",
    "frame.protocols",
    "_ws.col.Protocol",
    "_ws.col.Info",
    "eth.src",
    "eth.dst",
    "arp.src.proto_ipv4",
    "arp.dst.proto_ipv4",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "ip.proto",
    "ip.id",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.stream",
    "tcp.seq_raw",
    "tcp.ack_raw",
    "tcp.len",
    "tcp.flags",
    "tcp.flags.syn",
    "tcp.flags.ack",
    "tcp.flags.reset",
    "tcp.flags.fin",
    "tcp.analysis.retransmission",
    "tcp.analysis.fast_retransmission",
    "tcp.analysis.spurious_retransmission",
    "tcp.analysis.duplicate_ack",
    "tcp.analysis.lost_segment",
    "tcp.analysis.out_of_order",
    "tcp.analysis.zero_window",
    "tcp.analysis.window_full",
    "tcp.analysis.keep_alive",
    "tcp.completeness",
    "udp.srcport",
    "udp.dstport",
    "udp.stream",
    "udp.length",
    "http.request.method",
    "http.host",
    "http.request.uri",
    "http.response.code",
    "http.response.phrase",
    "http.user_agent",
    "http.content_type",
    "http.content_length",
    "http.request_in",
    "http.response_in",
    "dns.id",
    "dns.flags.response",
    "dns.flags.rcode",
    "dns.qry.name",
    "dns.a",
    "dns.aaaa",
    "tls.handshake.type",
    "tls.handshake.extensions_server_name",
    "tls.handshake.ja3",
    "tls.handshake.ja4",
    "dhcp.option.dhcp",
    "dhcp.option.hostname",
    "ftp.request.command",
    "ftp.request.arg",
    "smtp.req.command",
    "ssh.protocol",
    "smb2.cmd",
    "icmp.type",
    "icmp.code",
    "icmpv6.type",
    "icmpv6.code",
    "_ws.expert.message",
]


class WorkbenchError(RuntimeError):
    """A user-facing workbench error."""


def safe_int(value: str, default: int = 0) -> int:
    try:
        return int(value, 0)
    except (TypeError, ValueError):
        return default


def safe_float(value: str, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def is_true(value: str) -> bool:
    return value.lower() in {"1", "true", "yes", "set"}


def human_bytes(value: int | float) -> str:
    amount = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(amount) < 1024.0 or unit == "TiB":
            return f"{amount:.0f} {unit}" if unit == "B" else f"{amount:.1f} {unit}"
        amount /= 1024.0
    return f"{amount:.1f} TiB"


def human_duration(seconds: float) -> str:
    if seconds < 0.001:
        return f"{seconds * 1_000_000:.0f} us"
    if seconds < 1:
        return f"{seconds * 1000:.1f} ms"
    if seconds < 60:
        return f"{seconds:.3f} s"
    minutes, sec = divmod(seconds, 60)
    if minutes < 60:
        return f"{int(minutes)}m {sec:.1f}s"
    hours, minutes = divmod(minutes, 60)
    return f"{int(hours)}h {int(minutes)}m {sec:.0f}s"


def short_time(display_time: str, epoch: float = 0.0) -> str:
    if "T" in display_time:
        return display_time.split("T", 1)[1][:15]
    if epoch:
        return datetime.fromtimestamp(epoch).astimezone().strftime("%H:%M:%S.%f")[:-3]
    return "?"


def clip(text: str, width: int) -> str:
    if width <= 0:
        return ""
    return text if len(text) <= width else text[: max(0, width - 1)] + "…"


SENSITIVE_NAME = re.compile(
    r"(?i)(?:^|[_\-.])(?:auth(?:orization|entication)?|api[_-]?key|access[_-]?key|"
    r"password|passwd|pwd|passphrase|psk|private[_-]?key|secret|session[_-]?id|"
    r"token|credential|cookie|set[_-]?cookie)(?:$|[_\-.])"
)


def redact_sensitive_text(value: str) -> str:
    """Best-effort redaction for reports and textual packet views.

    This deliberately leaves capture files and extracted objects untouched. Generic
    protocol decoding is open-ended, so callers should not treat this as a DLP tool.
    """
    value = re.sub(
        r"(?im)^(\s*(?:authorization|proxy-authorization|cookie|set-cookie|"
        r"x-api-key|api-key)\s*:\s*).+$",
        r"\1<REDACTED>",
        value,
    )
    value = re.sub(r"(?im)^(\s*PASS\s+).+$", r"\1<REDACTED>", value)
    value = re.sub(
        r'''(?ix)(["']?(?:api[_-]?key|access[_-]?key|auth(?:key|token)?|password|passwd|pwd|'''
        r'''passphrase|psk|private[_-]?key|secret|session[_-]?id|token|credential)["']?\s*[:=]\s*)'''
        r'''("[^"\r\n]*"|'[^'\r\n]*'|[^&;\s,}\]\r\n]+)''',
        r"\1<REDACTED>",
        value,
    )
    return value


def redact_sensitive_data(value: Any) -> Any:
    """Return a redacted copy suitable for JSON/report output."""
    if isinstance(value, dict):
        return {
            key: "<REDACTED>" if SENSITIVE_NAME.search(str(key)) else redact_sensitive_data(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_sensitive_data(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_sensitive_data(item) for item in value)
    if isinstance(value, str):
        return redact_sensitive_text(value)
    return value


def protect_text(value: str, show_sensitive: bool) -> str:
    return value if show_sensitive else redact_sensitive_text(value)


def list_pcaps(directory: Path) -> list[Path]:
    try:
        return sorted(
            (
                path
                for path in directory.iterdir()
                if path.is_file() and path.name.lower().endswith(CAPTURE_SUFFIXES)
            ),
            key=lambda p: (p.stat().st_mtime, p.name),
        )
    except OSError as exc:
        raise WorkbenchError(f"Cannot read capture directory {directory}: {exc}") from exc


def require_program(name: str) -> str:
    path = shutil.which(name)
    if not path:
        raise WorkbenchError(f"Required program '{name}' is not installed or not in PATH")
    return path


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def capture_metadata(capture: Path) -> dict[str, str]:
    """Collect portable metadata; enrich it with capinfos when available."""
    metadata = {
        "File name": str(capture),
        "File size (bytes)": str(capture.stat().st_size),
        "SHA256": sha256_file(capture),
    }
    capinfos = shutil.which("capinfos")
    if not capinfos:
        metadata["Metadata note"] = "capinfos not installed; showing basic metadata only"
        return metadata
    result = subprocess.run(
        [capinfos, "-T", "-m", "-Q", str(capture)],
        check=False,
        capture_output=True,
        text=True,
        errors="replace",
    )
    if result.returncode:
        metadata["Metadata note"] = result.stderr.strip().splitlines()[-1] if result.stderr.strip() else "capinfos failed"
        return metadata
    rows = list(csv.reader(io.StringIO(result.stdout)))
    if len(rows) >= 2 and len(rows[0]) == len(rows[1]):
        metadata.update(dict(zip(rows[0], rows[1])))
    return metadata


def tshark_prefix(
    capture: Path,
    tls_keylog: Path | None = None,
    tshark_options: Sequence[str] = (),
) -> list[str]:
    command = [require_program("tshark"), "-n"]
    if tls_keylog:
        keylog = tls_keylog.expanduser()
        if not keylog.is_file():
            raise WorkbenchError(f"TLS key-log file not found: {keylog}")
        command.extend(["-o", f"tls.keylog_file:{keylog}"])
    for option in tshark_options:
        if ":" not in option or option.startswith("-"):
            raise WorkbenchError(f"Invalid TShark preference {option!r}; expected name:value")
        command.extend(["-o", option])
    command.extend(["-r", str(capture)])
    return command


@dataclass(slots=True)
class Packet:
    capture: str
    values: dict[str, str]
    number: int
    epoch: float
    length: int

    def get(self, key: str) -> str:
        return self.values.get(key, "")

    @property
    def src(self) -> str:
        return self.get("ip.src") or self.get("ipv6.src") or self.get("arp.src.proto_ipv4") or self.get("eth.src")

    @property
    def dst(self) -> str:
        return self.get("ip.dst") or self.get("ipv6.dst") or self.get("arp.dst.proto_ipv4") or self.get("eth.dst")

    @property
    def transport(self) -> str:
        if self.get("tcp.srcport"):
            return "TCP"
        if self.get("udp.srcport"):
            return "UDP"
        if self.get("icmp.type"):
            return "ICMP"
        if self.get("icmpv6.type"):
            return "ICMPv6"
        return self.get("_ws.col.Protocol") or "OTHER"

    @property
    def src_port(self) -> str:
        return self.get("tcp.srcport") or self.get("udp.srcport")

    @property
    def dst_port(self) -> str:
        return self.get("tcp.dstport") or self.get("udp.dstport")

    @property
    def protocol(self) -> str:
        return self.get("_ws.col.Protocol") or self.transport

    @property
    def endpoint_text(self) -> str:
        left = f"{self.src}:{self.src_port}" if self.src_port else self.src
        right = f"{self.dst}:{self.dst_port}" if self.dst_port else self.dst
        return f"{left} -> {right}"

    def flow_key(self) -> tuple[str, str, str, str, str]:
        return self.transport, self.src, self.src_port, self.dst, self.dst_port

    def conversation_key(self) -> tuple[tuple[str, str], tuple[str, str], str]:
        a = (self.src, self.src_port)
        b = (self.dst, self.dst_port)
        return (a, b, self.transport) if a <= b else (b, a, self.transport)

    def identity_key(self) -> tuple[str, ...]:
        base = self.flow_key()
        if self.transport == "TCP":
            return base + (
                self.get("tcp.seq_raw"),
                self.get("tcp.ack_raw"),
                self.get("tcp.len"),
                self.get("tcp.flags"),
                self.get("ip.id"),
                str(self.length),
            )
        if self.transport == "UDP":
            return base + (
                self.get("udp.length"),
                self.get("ip.id"),
                self.get("dns.id"),
                str(self.length),
            )
        return base + (self.get("ip.id"), self.get("icmp.type"), str(self.length), self.get("_ws.col.Info"))

    def event(self) -> tuple[str, str] | None:
        method = self.get("http.request.method")
        if method:
            host = self.get("http.host")
            uri = self.get("http.request.uri") or "/"
            return "HTTP", f"{method} {host}{uri}"
        status = self.get("http.response.code")
        if status:
            phrase = self.get("http.response.phrase")
            return "HTTP", f"response {status} {phrase}".strip()
        query = self.get("dns.qry.name")
        if query:
            if is_true(self.get("dns.flags.response")):
                answers = ", ".join(x for x in (self.get("dns.a"), self.get("dns.aaaa")) if x)
                return "DNS", f"answer {query}" + (f" -> {answers}" if answers else "")
            return "DNS", f"query {query}"
        sni = self.get("tls.handshake.extensions_server_name")
        if sni:
            fingerprints = " ".join(
                value
                for value in (
                    f"JA3={self.get('tls.handshake.ja3')}" if self.get("tls.handshake.ja3") else "",
                    f"JA4={self.get('tls.handshake.ja4')}" if self.get("tls.handshake.ja4") else "",
                )
                if value
            )
            return "TLS", f"ClientHello SNI={sni}" + (f" {fingerprints}" if fingerprints else "")
        dhcp_type = self.get("dhcp.option.dhcp")
        if dhcp_type:
            names = {"1": "Discover", "2": "Offer", "3": "Request", "5": "ACK", "6": "NAK", "7": "Release", "8": "Inform"}
            hostname = self.get("dhcp.option.hostname")
            return "DHCP", f"{names.get(dhcp_type, 'message ' + dhcp_type)}" + (f" hostname={hostname}" if hostname else "")
        ftp_command = self.get("ftp.request.command")
        if ftp_command:
            return "FTP", f"{ftp_command} {self.get('ftp.request.arg')}".strip()
        smtp_command = self.get("smtp.req.command")
        if smtp_command:
            return "SMTP", smtp_command
        ssh_banner = self.get("ssh.protocol")
        if ssh_banner:
            return "SSH", ssh_banner
        smb_command = self.get("smb2.cmd")
        if smb_command:
            return "SMB2", f"command {smb_command}"
        if is_true(self.get("tcp.flags.reset")):
            return "TCP", "reset"
        if self.get("tcp.analysis.retransmission") or self.get("tcp.analysis.fast_retransmission"):
            return "TCP", "retransmission"
        if self.get("icmp.type") or self.get("icmpv6.type"):
            return self.transport, self.get("_ws.col.Info") or "control message"
        return None


def extract_packets(
    captures: Sequence[Path],
    display_filter: str = "",
    *,
    tls_keylog: Path | None = None,
    tshark_options: Sequence[str] = (),
    progress: Callable[[int, int, Path], None] | None = None,
) -> list[Packet]:
    packets: list[Packet] = []
    for index, capture in enumerate(captures, 1):
        if not capture.is_file():
            raise WorkbenchError(f"Capture not found: {capture}")
        if progress:
            progress(index, len(captures), capture)
        command = tshark_prefix(capture, tls_keylog, tshark_options)
        if display_filter:
            command.extend(["-Y", display_filter])
        command.extend(
            [
                "-T",
                "fields",
                "-E",
                "header=n",
                "-E",
                "separator=\t",
                "-E",
                "quote=d",
                "-E",
                "occurrence=f",
            ]
        )
        for field_name in FIELDS:
            command.extend(["-e", field_name])
        result = subprocess.run(command, check=False, capture_output=True, text=True, errors="replace")
        if result.returncode not in (0, 1):
            detail = result.stderr.strip().splitlines()[-1] if result.stderr.strip() else "unknown error"
            raise WorkbenchError(f"TShark failed for {capture.name}: {detail}")
        reader = csv.reader(io.StringIO(result.stdout), delimiter="\t", quotechar='"')
        for row in reader:
            if len(row) < len(FIELDS):
                row.extend([""] * (len(FIELDS) - len(row)))
            elif len(row) > len(FIELDS):
                continue
            values = dict(zip(FIELDS, row))
            epoch = safe_float(values["frame.time_epoch"], math.nan)
            if math.isnan(epoch):
                continue
            packets.append(
                Packet(
                    capture=str(capture),
                    values=values,
                    number=safe_int(values["frame.number"]),
                    epoch=epoch,
                    length=safe_int(values["frame.len"]),
                )
            )
    return packets


@dataclass
class Finding:
    severity: str
    category: str
    time: str
    frame: int
    summary: str


@dataclass
class CaptureAnalysis:
    capture: str
    metadata: dict[str, str]
    file_size: int
    packet_count: int
    wire_bytes: int
    first_time: str
    last_time: str
    duration_seconds: float
    protocols: dict[str, int]
    services: list[dict[str, Any]]
    tcp_health: dict[str, int]
    endpoints: list[dict[str, Any]]
    conversations: list[dict[str, Any]]
    http: list[dict[str, Any]]
    dns: list[dict[str, Any]]
    tls: list[dict[str, Any]]
    findings: list[Finding]
    timeline: list[dict[str, Any]]
    filter_used: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def analyze_capture(
    capture: Path,
    display_filter: str = "",
    tls_keylog: Path | None = None,
    tshark_options: Sequence[str] = (),
) -> CaptureAnalysis:
    packets = extract_packets(
        [capture], display_filter, tls_keylog=tls_keylog, tshark_options=tshark_options
    )
    protocol_counts: Counter[str] = Counter()
    service_counts: dict[tuple[str, int], dict[str, int]] = defaultdict(lambda: defaultdict(int))
    tcp_health: Counter[str] = Counter()
    endpoint_stats: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    conversations: dict[tuple[Any, ...], dict[str, Any]] = {}
    requests: dict[int, dict[str, Any]] = {}
    http_rows: list[dict[str, Any]] = []
    dns_rows: list[dict[str, Any]] = []
    tls_rows: list[dict[str, Any]] = []
    timeline: list[dict[str, Any]] = []
    findings: list[Finding] = []

    for packet in packets:
        protocol_counts[packet.protocol] += 1
        numeric_ports = [safe_int(value) for value in (packet.src_port, packet.dst_port) if safe_int(value) > 0]
        if numeric_ports and packet.transport in {"TCP", "UDP"}:
            service_port = min(numeric_ports)
            service_counts[(packet.transport, service_port)]["packets"] += 1
            service_counts[(packet.transport, service_port)]["bytes"] += packet.length
        health_fields = {
            "retransmissions": ("tcp.analysis.retransmission", "tcp.analysis.fast_retransmission", "tcp.analysis.spurious_retransmission"),
            "duplicate ACKs": ("tcp.analysis.duplicate_ack",),
            "lost segments": ("tcp.analysis.lost_segment",),
            "out-of-order segments": ("tcp.analysis.out_of_order",),
            "zero windows": ("tcp.analysis.zero_window",),
            "full windows": ("tcp.analysis.window_full",),
            "keep-alives": ("tcp.analysis.keep_alive",),
            "resets": ("tcp.flags.reset",),
        }
        for label, field_names in health_fields.items():
            present = (
                any(is_true(packet.get(field_name)) for field_name in field_names)
                if label == "resets"
                else any(packet.get(field_name) for field_name in field_names)
            )
            if present:
                tcp_health[label] += 1
        if packet.src:
            endpoint_stats[packet.src]["sent_packets"] += 1
            endpoint_stats[packet.src]["sent_bytes"] += packet.length
        if packet.dst:
            endpoint_stats[packet.dst]["received_packets"] += 1
            endpoint_stats[packet.dst]["received_bytes"] += packet.length

        conv_key = packet.conversation_key()
        conv = conversations.setdefault(
            conv_key,
            {
                "endpoint_a": f"{conv_key[0][0]}:{conv_key[0][1]}" if conv_key[0][1] else conv_key[0][0],
                "endpoint_b": f"{conv_key[1][0]}:{conv_key[1][1]}" if conv_key[1][1] else conv_key[1][0],
                "protocol": conv_key[2],
                "packets": 0,
                "bytes": 0,
                "first_epoch": packet.epoch,
                "last_epoch": packet.epoch,
            },
        )
        conv["packets"] += 1
        conv["bytes"] += packet.length
        conv["last_epoch"] = packet.epoch

        method = packet.get("http.request.method")
        status = packet.get("http.response.code")
        if method:
            item = {
                "time": packet.get("frame.time"),
                "frame": packet.number,
                "stream": packet.get("tcp.stream"),
                "source": packet.endpoint_text,
                "method": method,
                "host": packet.get("http.host"),
                "uri": packet.get("http.request.uri"),
                "user_agent": packet.get("http.user_agent"),
                "response_frame": safe_int(packet.get("http.response_in")),
                "status": "",
                "content_type": "",
                "content_length": "",
            }
            requests[packet.number] = item
            http_rows.append(item)
        elif status:
            request_frame = safe_int(packet.get("http.request_in"))
            if request_frame in requests:
                item = requests[request_frame]
                item.update(
                    status=status,
                    response_frame=packet.number,
                    content_type=packet.get("http.content_type"),
                    content_length=packet.get("http.content_length"),
                )
            else:
                http_rows.append(
                    {
                        "time": packet.get("frame.time"),
                        "frame": packet.number,
                        "stream": packet.get("tcp.stream"),
                        "source": packet.endpoint_text,
                        "method": "",
                        "host": "",
                        "uri": "",
                        "user_agent": "",
                        "response_frame": packet.number,
                        "status": status,
                        "content_type": packet.get("http.content_type"),
                        "content_length": packet.get("http.content_length"),
                    }
                )
            if status.startswith(("4", "5")):
                severity = "high" if status.startswith("5") else "medium"
                findings.append(
                    Finding(severity, "HTTP", short_time(packet.get("frame.time"), packet.epoch), packet.number, f"HTTP {status} {packet.get('http.response.phrase')} from {packet.endpoint_text}")
                )

        query = packet.get("dns.qry.name")
        if query:
            dns_rows.append(
                {
                    "time": packet.get("frame.time"),
                    "frame": packet.number,
                    "direction": "response" if is_true(packet.get("dns.flags.response")) else "query",
                    "name": query,
                    "answers": ", ".join(x for x in (packet.get("dns.a"), packet.get("dns.aaaa")) if x),
                    "rcode": packet.get("dns.flags.rcode"),
                    "source": packet.endpoint_text,
                }
            )
            rcode = packet.get("dns.flags.rcode")
            if is_true(packet.get("dns.flags.response")) and rcode not in ("", "0"):
                findings.append(Finding("low", "DNS", short_time(packet.get("frame.time"), packet.epoch), packet.number, f"DNS response code {rcode} for {query}"))

        sni = packet.get("tls.handshake.extensions_server_name")
        if sni:
            tls_rows.append(
                {
                    "time": packet.get("frame.time"),
                    "frame": packet.number,
                    "server_name": sni,
                    "source": packet.endpoint_text,
                }
            )

        anomaly = ""
        if packet.get("tcp.analysis.spurious_retransmission"):
            anomaly = "spurious retransmission"
        elif packet.get("tcp.analysis.fast_retransmission"):
            anomaly = "fast retransmission"
        elif packet.get("tcp.analysis.retransmission"):
            anomaly = "retransmission"
        elif packet.get("tcp.analysis.lost_segment"):
            anomaly = "previous TCP segment not captured"
        elif packet.get("tcp.analysis.out_of_order"):
            anomaly = "out-of-order TCP segment"
        elif packet.get("tcp.analysis.zero_window"):
            anomaly = "TCP zero window"
        elif packet.get("tcp.analysis.window_full"):
            anomaly = "TCP receive window full"
        elif is_true(packet.get("tcp.flags.reset")):
            anomaly = "TCP reset"
        if anomaly:
            severity = "medium" if anomaly == "TCP reset" else "low"
            findings.append(Finding(severity, "TCP", short_time(packet.get("frame.time"), packet.epoch), packet.number, f"{anomaly}: {packet.endpoint_text}"))

        event = packet.event()
        if event:
            timeline.append(
                {
                    "time": short_time(packet.get("frame.time"), packet.epoch),
                    "epoch": packet.epoch,
                    "frame": packet.number,
                    "protocol": event[0],
                    "endpoint": packet.endpoint_text,
                    "summary": event[1],
                }
            )

    endpoints = []
    for address, stats in endpoint_stats.items():
        endpoints.append(
            {
                "address": address,
                "sent_packets": stats["sent_packets"],
                "received_packets": stats["received_packets"],
                "sent_bytes": stats["sent_bytes"],
                "received_bytes": stats["received_bytes"],
                "total_packets": stats["sent_packets"] + stats["received_packets"],
                "total_bytes": stats["sent_bytes"] + stats["received_bytes"],
            }
        )
    endpoints.sort(key=lambda item: (item["total_packets"], item["total_bytes"]), reverse=True)
    conversation_rows = sorted(conversations.values(), key=lambda item: (item["packets"], item["bytes"]), reverse=True)
    for item in conversation_rows:
        item["duration_seconds"] = item["last_epoch"] - item["first_epoch"]

    services = []
    for (transport, port), stats in service_counts.items():
        try:
            name = socket.getservbyport(port, transport.lower())
        except OSError:
            name = "unknown"
        services.append(
            {
                "transport": transport,
                "port": port,
                "service": name,
                "packets": stats["packets"],
                "bytes": stats["bytes"],
            }
        )
    services.sort(key=lambda item: (item["packets"], item["bytes"]), reverse=True)

    first = packets[0] if packets else None
    last = packets[-1] if packets else None
    return CaptureAnalysis(
        capture=str(capture),
        metadata=capture_metadata(capture),
        file_size=capture.stat().st_size,
        packet_count=len(packets),
        wire_bytes=sum(p.length for p in packets),
        first_time=first.get("frame.time") if first else "",
        last_time=last.get("frame.time") if last else "",
        duration_seconds=(last.epoch - first.epoch) if first and last else 0.0,
        protocols=dict(protocol_counts.most_common()),
        services=services,
        tcp_health=dict(tcp_health),
        endpoints=endpoints,
        conversations=conversation_rows,
        http=http_rows,
        dns=dns_rows,
        tls=tls_rows,
        findings=findings,
        timeline=timeline,
        filter_used=display_filter,
    )


def section(title: str) -> list[str]:
    return ["", title, "-" * len(title)]


def render_analysis(
    analysis: CaptureAnalysis,
    event_limit: int = DEFAULT_EVENT_LIMIT,
    show_sensitive: bool = False,
) -> str:
    lines = [
        "PCAP WORKBENCH — CAPTURE ANALYSIS",
        f"Capture: {analysis.capture}",
        f"File size: {human_bytes(analysis.file_size)}",
        f"Packets: {analysis.packet_count:,}    On-wire bytes: {human_bytes(analysis.wire_bytes)}",
        f"Time range: {analysis.first_time or 'no packets'}",
        f"            {analysis.last_time or 'no packets'}",
        f"Duration: {human_duration(analysis.duration_seconds)}",
    ]
    if analysis.filter_used:
        lines.append(f"Display filter: {analysis.filter_used}")

    lines += section("Capture metadata and integrity")
    metadata_labels = (
        "File type",
        "File encapsulation",
        "File time precision",
        "Packet size limit",
        "Data size (bytes)",
        "Average packet size (bytes)",
        "Average packet rate (packets/sec)",
        "Strict time order",
        "Number of decryption secrets",
        "Capture hardware",
        "Capture oper-sys",
        "Capture application",
        "Capture comment",
        "SHA256",
        "SHA1",
        "Metadata note",
    )
    for label in metadata_labels:
        value = analysis.metadata.get(label, "")
        if value:
            lines.append(f"  {label:<36} {value}")

    lines += section("Protocol summary")
    if analysis.protocols:
        total = max(1, analysis.packet_count)
        for proto, count in list(analysis.protocols.items())[:20]:
            lines.append(f"  {proto:<16} {count:>8,}  {count / total:>6.1%}")
    else:
        lines.append("  No decoded packets.")

    lines += section("Likely services / ports")
    for item in analysis.services[:20]:
        lines.append(
            f"  {item['transport']:<4} {item['port']:>5}  {item['service']:<16} "
            f"{item['packets']:>8,} packets  {human_bytes(item['bytes']):>10}"
        )
    if not analysis.services:
        lines.append("  None")

    lines += section("TCP health")
    if analysis.tcp_health:
        for label, count in sorted(analysis.tcp_health.items(), key=lambda pair: pair[1], reverse=True):
            lines.append(f"  {label:<28} {count:>8,}")
    else:
        lines.append("  No TCP analysis indicators reported.")

    lines += section("Top endpoints")
    lines.append("  Address                              Sent       Received      Total")
    for item in analysis.endpoints[:20]:
        lines.append(
            f"  {item['address']:<36} {item['sent_packets']:>6,}/{human_bytes(item['sent_bytes']):>9} "
            f"{item['received_packets']:>6,}/{human_bytes(item['received_bytes']):>9} {item['total_packets']:>7,}"
        )
    if not analysis.endpoints:
        lines.append("  None")

    lines += section("Top conversations")
    for item in analysis.conversations[:20]:
        lines.append(
            f"  {item['protocol']:<6} {item['endpoint_a']} <-> {item['endpoint_b']}  "
            f"{item['packets']:,} packets, {human_bytes(item['bytes'])}, {human_duration(item['duration_seconds'])}"
        )
    if not analysis.conversations:
        lines.append("  None")

    lines += section(f"HTTP activity ({len(analysis.http)})")
    for item in analysis.http[:event_limit]:
        request = " ".join(x for x in (item["method"], f"{item['host']}{item['uri']}" if item["host"] or item["uri"] else "") if x)
        response = f" -> {item['status']}" if item["status"] else ""
        metadata = ""
        if item["content_type"] or item["content_length"]:
            metadata = f" [{item['content_type'] or 'content'} {item['content_length'] or '?'} bytes]"
        lines.append(f"  {short_time(item['time'])} frame {item['frame']:<6} {request or 'unpaired response'}{response}{metadata}")
    if len(analysis.http) > event_limit:
        lines.append(f"  … {len(analysis.http) - event_limit} more HTTP entries omitted")
    elif not analysis.http:
        lines.append("  None")

    lines += section(f"DNS activity ({len(analysis.dns)})")
    for item in analysis.dns[:event_limit]:
        suffix = f" -> {item['answers']}" if item["answers"] else ""
        rcode = f" rcode={item['rcode']}" if item["rcode"] not in ("", "0") else ""
        lines.append(f"  {short_time(item['time'])} {item['direction']:<8} {item['name']}{suffix}{rcode}")
    if len(analysis.dns) > event_limit:
        lines.append(f"  … {len(analysis.dns) - event_limit} more DNS entries omitted")
    elif not analysis.dns:
        lines.append("  None")

    lines += section(f"TLS server names ({len(analysis.tls)})")
    for item in analysis.tls[:event_limit]:
        lines.append(f"  {short_time(item['time'])} {item['server_name']}  ({item['source']})")
    if len(analysis.tls) > event_limit:
        lines.append(f"  … {len(analysis.tls) - event_limit} more TLS entries omitted")
    elif not analysis.tls:
        lines.append("  None")

    lines += section(f"Noteworthy findings ({len(analysis.findings)})")
    lines.append("  These are observations for review, not automatic threat verdicts.")
    severity_order = {"high": 0, "medium": 1, "low": 2}
    ordered = sorted(analysis.findings, key=lambda x: (severity_order.get(x.severity, 9), x.frame))
    for item in ordered[:event_limit]:
        lines.append(f"  [{item.severity.upper():<6}] {item.time} frame {item.frame:<6} {item.category}: {item.summary}")
    if len(ordered) > event_limit:
        lines.append(f"  … {len(ordered) - event_limit} more findings omitted")
    elif not ordered:
        lines.append("  No noteworthy protocol/transport observations detected.")

    lines += section(f"Significant-event timeline ({len(analysis.timeline)})")
    for item in analysis.timeline[:event_limit]:
        lines.append(f"  {item['time']}  {item['protocol']:<6} frame {item['frame']:<6} {item['summary']}  [{item['endpoint']}]")
    if len(analysis.timeline) > event_limit:
        lines.append(f"  … {len(analysis.timeline) - event_limit} more events omitted")
    elif not analysis.timeline:
        lines.append("  None")
    return protect_text("\n".join(lines) + "\n", show_sensitive)


@dataclass
class CorrelationMatch:
    left_capture: str
    left_frame: int
    right_capture: str
    right_frame: int
    delta_seconds: float
    quality: str
    protocol: str
    endpoints: str
    event: str


@dataclass
class CorrelationReport:
    left_captures: list[str]
    right_captures: list[str]
    display_filter: str
    window_seconds: float
    clock_offset_seconds: float
    offset_method: str
    left_packets: int
    right_packets: int
    matched_packets: int
    exact_matches: int
    flow_matches: int
    left_only: int
    right_only: int
    protocol_overlap: dict[str, dict[str, int]]
    matches: list[CorrelationMatch]
    left_only_events: list[dict[str, Any]]
    right_only_events: list[dict[str, Any]]
    capture_coverage: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def estimate_clock_offset(left: Sequence[Packet], right: Sequence[Packet]) -> tuple[float, str]:
    left_by_identity: dict[tuple[str, ...], list[Packet]] = defaultdict(list)
    right_by_identity: dict[tuple[str, ...], list[Packet]] = defaultdict(list)
    for packet in left:
        left_by_identity[packet.identity_key()].append(packet)
    for packet in right:
        right_by_identity[packet.identity_key()].append(packet)

    deltas: list[float] = []
    for key in left_by_identity.keys() & right_by_identity.keys():
        left_items = left_by_identity[key]
        right_items = right_by_identity[key]
        if len(left_items) == 1 and len(right_items) == 1:
            deltas.append(right_items[0].epoch - left_items[0].epoch)
    if len(deltas) < 3:
        return 0.0, f"insufficient unique packet identities ({len(deltas)} candidates)"

    bins = Counter(round(delta, 2) for delta in deltas)
    winning_bin, count = bins.most_common(1)[0]
    cluster = [delta for delta in deltas if abs(delta - winning_bin) <= 0.02]
    if len(cluster) < 3 or count < 2:
        return 0.0, f"no stable offset cluster ({len(deltas)} candidates)"
    offset = statistics.median(cluster)
    spread = max(cluster) - min(cluster) if len(cluster) > 1 else 0.0
    return offset, f"auto, {len(cluster)} identity pairs, spread {human_duration(spread)}"


def correlation_display_filter(value: str) -> str:
    return value.strip() or "ip || ipv6 || arp"


def capture_coverage(packets: Sequence[Packet], side: str) -> list[dict[str, Any]]:
    grouped: dict[str, list[Packet]] = defaultdict(list)
    for packet in packets:
        grouped[packet.capture].append(packet)
    rows = []
    for name, items in grouped.items():
        rows.append(
            {
                "side": side,
                "capture": name,
                "packets": len(items),
                "first_epoch": items[0].epoch,
                "last_epoch": items[-1].epoch,
                "duration_seconds": items[-1].epoch - items[0].epoch,
            }
        )
    return sorted(rows, key=lambda x: x["first_epoch"])


def correlate_packets(
    left_captures: Sequence[Path],
    right_captures: Sequence[Path],
    display_filter: str,
    window: float,
    clock_offset: float | None,
    *,
    tls_keylog: Path | None = None,
    tshark_options: Sequence[str] = (),
    progress: Callable[[str], None] | None = None,
) -> CorrelationReport:
    display_filter = correlation_display_filter(display_filter)
    if progress:
        progress("Reading left-side captures")
    left = extract_packets(
        left_captures,
        display_filter,
        tls_keylog=tls_keylog,
        tshark_options=tshark_options,
        progress=(
            (lambda index, total, path: progress(f"Reading left {index}/{total}: {path.name}"))
            if progress
            else None
        ),
    )
    if progress:
        progress("Reading right-side captures")
    right = extract_packets(
        right_captures,
        display_filter,
        tls_keylog=tls_keylog,
        tshark_options=tshark_options,
        progress=(
            (lambda index, total, path: progress(f"Reading right {index}/{total}: {path.name}"))
            if progress
            else None
        ),
    )
    left.sort(key=lambda p: p.epoch)
    right.sort(key=lambda p: p.epoch)

    if clock_offset is None:
        offset, offset_method = estimate_clock_offset(left, right)
    else:
        offset, offset_method = clock_offset, "manual"

    right_exact: dict[tuple[str, ...], list[tuple[float, int]]] = defaultdict(list)
    right_fallback: dict[tuple[Any, ...], list[tuple[float, int]]] = defaultdict(list)
    for index, packet in enumerate(right):
        adjusted = packet.epoch - offset
        right_exact[packet.identity_key()].append((adjusted, index))
        right_fallback[packet.flow_key() + (str(packet.length),)].append((adjusted, index))
    for values in right_exact.values():
        values.sort()
    for values in right_fallback.values():
        values.sort()

    used_right: set[int] = set()
    matches: list[CorrelationMatch] = []
    matched_left: set[int] = set()
    exact_matches = 0
    flow_matches = 0

    def nearest(candidates: list[tuple[float, int]], center: float) -> tuple[float, int] | None:
        times = [item[0] for item in candidates]
        pos = bisect.bisect_left(times, center)
        options = candidates[max(0, pos - 3) : min(len(candidates), pos + 4)]
        options = [item for item in options if item[1] not in used_right and abs(item[0] - center) <= window]
        return min(options, key=lambda item: abs(item[0] - center)) if options else None

    for left_index, packet in enumerate(left):
        found = nearest(right_exact.get(packet.identity_key(), []), packet.epoch)
        quality = "exact"
        if found is None:
            found = nearest(right_fallback.get(packet.flow_key() + (str(packet.length),), []), packet.epoch)
            quality = "flow/time"
        if found is None:
            continue
        adjusted_epoch, right_index = found
        used_right.add(right_index)
        matched_left.add(left_index)
        if quality == "exact":
            exact_matches += 1
        else:
            flow_matches += 1
        right_packet = right[right_index]
        event = packet.event()
        matches.append(
            CorrelationMatch(
                left_capture=packet.capture,
                left_frame=packet.number,
                right_capture=right_packet.capture,
                right_frame=right_packet.number,
                delta_seconds=adjusted_epoch - packet.epoch,
                quality=quality,
                protocol=packet.protocol,
                endpoints=packet.endpoint_text,
                event=f"{event[0]} {event[1]}" if event else "",
            )
        )

    protocol_overlap: dict[str, dict[str, int]] = {}
    left_protocols = Counter(packet.protocol for packet in left)
    right_protocols = Counter(packet.protocol for packet in right)
    matched_protocols = Counter(match.protocol for match in matches)
    for protocol in sorted(left_protocols.keys() | right_protocols.keys()):
        protocol_overlap[protocol] = {
            "left": left_protocols[protocol],
            "right": right_protocols[protocol],
            "matched": matched_protocols[protocol],
        }

    def unmatched_events(items: Sequence[Packet], matched_indexes: set[int]) -> list[dict[str, Any]]:
        rows = []
        for index, packet in enumerate(items):
            if index in matched_indexes:
                continue
            event = packet.event()
            if event:
                rows.append(
                    {
                        "capture": packet.capture,
                        "frame": packet.number,
                        "time": short_time(packet.get("frame.time"), packet.epoch),
                        "protocol": event[0],
                        "summary": event[1],
                        "endpoint": packet.endpoint_text,
                    }
                )
        return rows

    coverage = capture_coverage(left, "left") + capture_coverage(right, "right")
    return CorrelationReport(
        left_captures=[str(path) for path in left_captures],
        right_captures=[str(path) for path in right_captures],
        display_filter=display_filter,
        window_seconds=window,
        clock_offset_seconds=offset,
        offset_method=offset_method,
        left_packets=len(left),
        right_packets=len(right),
        matched_packets=len(matches),
        exact_matches=exact_matches,
        flow_matches=flow_matches,
        left_only=len(left) - len(matches),
        right_only=len(right) - len(matches),
        protocol_overlap=protocol_overlap,
        matches=matches,
        left_only_events=unmatched_events(left, matched_left),
        right_only_events=unmatched_events(right, used_right),
        capture_coverage=coverage,
    )


def render_correlation(
    report: CorrelationReport,
    event_limit: int = DEFAULT_EVENT_LIMIT,
    show_sensitive: bool = False,
) -> str:
    denominator = min(report.left_packets, report.right_packets)
    rate = report.matched_packets / denominator if denominator else 0.0
    lines = [
        "PCAP WORKBENCH — CROSS-CAPTURE CORRELATION",
        f"Left side:  {len(report.left_captures)} capture(s)",
        f"Right side: {len(report.right_captures)} capture(s)",
        f"Correlation filter: {report.display_filter}",
        f"Match window: ±{human_duration(report.window_seconds)}",
        f"Clock offset (right - left): {report.clock_offset_seconds:+.6f} s ({report.offset_method})",
        "",
        f"Left packets:  {report.left_packets:,}",
        f"Right packets: {report.right_packets:,}",
        f"Matched:       {report.matched_packets:,} ({rate:.1%} of the smaller side)",
        f"               {report.exact_matches:,} exact identity, {report.flow_matches:,} flow/time fallback",
        f"Left only:     {report.left_only:,}",
        f"Right only:    {report.right_only:,}",
    ]

    lines += section("Capture coverage")
    for row in report.capture_coverage:
        start = datetime.fromtimestamp(row["first_epoch"]).astimezone().strftime("%Y-%m-%d %H:%M:%S")
        lines.append(
            f"  {row['side']:<5} {Path(row['capture']).name:<36} {row['packets']:>7,} packets  "
            f"{start}  {human_duration(row['duration_seconds'])}"
        )
    if not report.capture_coverage:
        lines.append("  No packets matched the target filter in the selected captures.")

    lines += section("Protocol visibility")
    lines.append("  Protocol              Left      Right    Matched")
    for protocol, counts in sorted(report.protocol_overlap.items(), key=lambda pair: max(pair[1]["left"], pair[1]["right"]), reverse=True):
        lines.append(f"  {protocol:<18} {counts['left']:>8,} {counts['right']:>10,} {counts['matched']:>10,}")
    if not report.protocol_overlap:
        lines.append("  None")

    significant = [match for match in report.matches if match.event]
    lines += section(f"Matched significant events ({len(significant)})")
    for match in significant[:event_limit]:
        lines.append(
            f"  {match.quality:<9} Δ={match.delta_seconds:+.6f}s  "
            f"{Path(match.left_capture).name}:#{match.left_frame} <-> {Path(match.right_capture).name}:#{match.right_frame}"
        )
        lines.append(f"             {match.protocol} {match.event} [{match.endpoints}]")
    if len(significant) > event_limit:
        lines.append(f"  … {len(significant) - event_limit} more matched events omitted")
    elif not significant:
        lines.append("  None")

    lines += section(f"Significant events visible only on the left ({len(report.left_only_events)})")
    for item in report.left_only_events[:event_limit]:
        lines.append(f"  {item['time']} {item['protocol']:<6} {Path(item['capture']).name}:#{item['frame']} {item['summary']} [{item['endpoint']}]")
    if len(report.left_only_events) > event_limit:
        lines.append(f"  … {len(report.left_only_events) - event_limit} more left-only events omitted")
    elif not report.left_only_events:
        lines.append("  None")

    lines += section(f"Significant events visible only on the right ({len(report.right_only_events)})")
    for item in report.right_only_events[:event_limit]:
        lines.append(f"  {item['time']} {item['protocol']:<6} {Path(item['capture']).name}:#{item['frame']} {item['summary']} [{item['endpoint']}]")
    if len(report.right_only_events) > event_limit:
        lines.append(f"  … {len(report.right_only_events) - event_limit} more right-only events omitted")
    elif not report.right_only_events:
        lines.append("  None")
    return protect_text("\n".join(lines) + "\n", show_sensitive)


def render_directory(
    directory: Path,
    analyses: Sequence[CaptureAnalysis],
    show_sensitive: bool = False,
) -> str:
    total_packets = sum(item.packet_count for item in analyses)
    total_wire = sum(item.wire_bytes for item in analyses)
    total_http = sum(len(item.http) for item in analyses)
    total_dns = sum(len(item.dns) for item in analyses)
    total_findings = sum(len(item.findings) for item in analyses)
    lines = [
        "PCAP WORKBENCH — DIRECTORY ANALYSIS",
        f"Directory: {directory}",
        f"Captures: {len(analyses)}    Packets: {total_packets:,}    Wire bytes: {human_bytes(total_wire)}",
        f"HTTP entries: {total_http:,}    DNS entries: {total_dns:,}    Findings: {total_findings:,}",
        "",
        "Capture                                  Packets       Bytes   Duration   HTTP   DNS  Findings",
        "-" * 94,
    ]
    for item in analyses:
        lines.append(
            f"{Path(item.capture).name:<40} {item.packet_count:>8,} {human_bytes(item.wire_bytes):>11} "
            f"{human_duration(item.duration_seconds):>10} {len(item.http):>6,} {len(item.dns):>5,} {len(item.findings):>9,}"
        )
    return protect_text("\n".join(lines) + "\n", show_sensitive)


@dataclass
class StreamInfo:
    number: int
    protocol: str
    endpoint_a: str
    endpoint_b: str
    packets: int = 0
    bytes: int = 0


def list_streams(
    capture: Path,
    protocol: str,
    tls_keylog: Path | None = None,
    tshark_options: Sequence[str] = (),
) -> list[StreamInfo]:
    """Return concise stream choices for the interactive reader."""
    if protocol not in {"tcp", "udp", "http", "tls"}:
        raise WorkbenchError(f"Unsupported stream protocol: {protocol}")
    stream_field = "udp.stream" if protocol == "udp" else ("tls.stream" if protocol == "tls" else "tcp.stream")
    transport = "udp" if protocol == "udp" else "tcp"
    fields = [stream_field, "ip.src", "ipv6.src", f"{transport}.srcport", "ip.dst", "ipv6.dst", f"{transport}.dstport", "frame.len"]
    command = tshark_prefix(capture, tls_keylog, tshark_options)
    command.extend(["-Y", protocol, "-T", "fields", "-E", "separator=\t", "-E", "quote=d", "-E", "occurrence=f"])
    for field_name in fields:
        command.extend(["-e", field_name])
    result = subprocess.run(command, check=False, capture_output=True, text=True, errors="replace")
    if result.returncode not in (0, 1):
        raise WorkbenchError(result.stderr.strip().splitlines()[-1] if result.stderr.strip() else "TShark stream discovery failed")
    streams: dict[int, StreamInfo] = {}
    for row in csv.reader(io.StringIO(result.stdout), delimiter="\t", quotechar='"'):
        if len(row) != len(fields) or not row[0]:
            continue
        number = safe_int(row[0], -1)
        if number < 0:
            continue
        src = row[1] or row[2]
        dst = row[4] or row[5]
        source = f"{src}:{row[3]}" if row[3] else src
        destination = f"{dst}:{row[6]}" if row[6] else dst
        item = streams.setdefault(number, StreamInfo(number, protocol.upper(), source, destination))
        item.packets += 1
        item.bytes += safe_int(row[7])
    return sorted(streams.values(), key=lambda item: item.number)


def decode_hex_payload(value: str) -> bytes:
    cleaned = "".join(character for character in value if character in "0123456789abcdefABCDEF")
    if len(cleaned) % 2:
        cleaned = cleaned[:-1]
    try:
        return bytes.fromhex(cleaned)
    except ValueError:
        return b""


def readable_payload(data: bytes) -> str:
    text = data.decode("utf-8", "replace")
    return "".join(character if character in "\r\n\t" or character.isprintable() else "." for character in text)


def extract_plaintext_payloads(
    capture: Path,
    display_filter: str = "",
    tls_keylog: Path | None = None,
    tshark_options: Sequence[str] = (),
) -> str:
    fields = [
        "frame.number",
        "frame.time",
        "_ws.col.Protocol",
        "ip.src",
        "ipv6.src",
        "tcp.srcport",
        "udp.srcport",
        "ip.dst",
        "ipv6.dst",
        "tcp.dstport",
        "udp.dstport",
        "tcp.stream",
        "udp.stream",
        "data.text",
        "http.file_data",
        "data.data",
        "tcp.payload",
        "udp.payload",
    ]
    payload_filter = "http.file_data || data.data || data.text || tcp.payload || udp.payload"
    combined_filter = f"({display_filter}) && ({payload_filter})" if display_filter else payload_filter
    command = tshark_prefix(capture, tls_keylog, tshark_options)
    command.extend(["-Y", combined_filter, "-T", "fields", "-E", "separator=\t", "-E", "quote=d", "-E", "occurrence=f"])
    for field_name in fields:
        command.extend(["-e", field_name])
    result = subprocess.run(command, check=False, capture_output=True, text=True, errors="replace")
    if result.returncode not in (0, 1):
        detail = result.stderr.strip().splitlines()[-1] if result.stderr.strip() else "TShark payload extraction failed"
        raise WorkbenchError(detail)
    lines = [
        "PCAP WORKBENCH — EXTRACTED PLAINTEXT/PAYLOADS",
        f"Capture: {capture}",
        f"TLS key log: {tls_keylog if tls_keylog else 'not configured'}",
        "Binary/non-printable bytes are represented with replacement characters or dots.",
        "",
    ]
    count = 0
    for row in csv.reader(io.StringIO(result.stdout), delimiter="\t", quotechar='"'):
        if len(row) != len(fields):
            continue
        values = dict(zip(fields, row))
        direct_text = values["data.text"]
        encoded = values["http.file_data"] or values["data.data"] or values["tcp.payload"] or values["udp.payload"]
        payload = direct_text if direct_text else readable_payload(decode_hex_payload(encoded))
        if not payload:
            continue
        src = values["ip.src"] or values["ipv6.src"]
        dst = values["ip.dst"] or values["ipv6.dst"]
        src_port = values["tcp.srcport"] or values["udp.srcport"]
        dst_port = values["tcp.dstport"] or values["udp.dstport"]
        stream = values["tcp.stream"] or values["udp.stream"]
        endpoint = f"{src}:{src_port} -> {dst}:{dst_port}" if src_port or dst_port else f"{src} -> {dst}"
        lines.extend(
            [
                f"--- frame {values['frame.number']}  {short_time(values['frame.time'])}  {values['_ws.col.Protocol']}  stream {stream or '-'}  {endpoint}",
                payload,
                "",
            ]
        )
        count += 1
    if not count:
        lines.append("No readable payload-bearing packets were found with the current filter/decryption settings.")
    else:
        lines.insert(4, f"Payload-bearing packets: {count}")
    return "\n".join(lines) + "\n"


def reader_command(
    capture: Path,
    mode: str,
    *,
    display_filter: str = "",
    stream: int = 0,
    tls_keylog: Path | None = None,
    tshark_options: Sequence[str] = (),
) -> list[str]:
    if mode not in READ_MODES or mode == "plaintext":
        raise WorkbenchError(f"Unsupported external reader mode: {mode}")
    if mode == "ascii":
        return [require_program("tcpdump"), "-nn", "-tttt", "-A", "-r", str(capture)]
    if mode == "hex":
        return [require_program("tcpdump"), "-nn", "-tttt", "-XX", "-r", str(capture)]
    command = tshark_prefix(capture, tls_keylog, tshark_options)
    if display_filter and not mode.startswith("follow-"):
        command.extend(["-Y", display_filter])
    if mode == "summary":
        return command
    if mode == "decoded":
        return command + ["-V"]
    if mode == "decoded-hex":
        return command + ["-V", "-x"]
    follow = {
        "follow-tcp-ascii": ("tcp", "ascii"),
        "follow-tcp-hex": ("tcp", "hex"),
        "follow-http": ("http", "ascii"),
        "follow-tls": ("tls", "ascii"),
        "follow-udp-ascii": ("udp", "ascii"),
        "follow-udp-hex": ("udp", "hex"),
    }
    protocol, representation = follow[mode]
    return command + ["-q", "-z", f"follow,{protocol},{representation},{stream}"]


def read_capture_content(
    capture: Path,
    mode: str,
    *,
    display_filter: str = "",
    stream: int = 0,
    tls_keylog: Path | None = None,
    tshark_options: Sequence[str] = (),
    show_sensitive: bool = False,
) -> str:
    if not capture.is_file():
        raise WorkbenchError(f"Capture not found: {capture}")
    if mode == "plaintext":
        return protect_text(
            extract_plaintext_payloads(capture, display_filter, tls_keylog, tshark_options),
            show_sensitive,
        )
    command = reader_command(
        capture,
        mode,
        display_filter=display_filter,
        stream=stream,
        tls_keylog=tls_keylog,
        tshark_options=tshark_options,
    )
    result = subprocess.run(command, check=False, capture_output=True, text=True, errors="replace")
    if result.returncode not in (0, 1):
        detail = result.stderr.strip().splitlines()[-1] if result.stderr.strip() else f"Reader exited with status {result.returncode}"
        raise WorkbenchError(detail)
    output = result.stdout
    if result.stderr.strip() and mode not in {"ascii", "hex"}:
        output += "\nDiagnostics:\n" + result.stderr
    return protect_text(
        output or "No output was produced for this capture, mode, stream, and filter.\n",
        show_sensitive,
    )


def search_capture(
    capture: Path,
    pattern: str,
    *,
    regex: bool = False,
    case_sensitive: bool = False,
    display_filter: str = "",
    tls_keylog: Path | None = None,
    tshark_options: Sequence[str] = (),
) -> list[dict[str, Any]]:
    if not pattern:
        raise WorkbenchError("Search pattern cannot be empty")
    flags = 0 if case_sensitive else re.IGNORECASE
    try:
        matcher = re.compile(pattern if regex else re.escape(pattern), flags)
    except re.error as exc:
        raise WorkbenchError(f"Invalid regular expression: {exc}") from exc
    fields = [
        "frame.number",
        "frame.time",
        "_ws.col.Protocol",
        "ip.src",
        "ipv6.src",
        "tcp.srcport",
        "udp.srcport",
        "ip.dst",
        "ipv6.dst",
        "tcp.dstport",
        "udp.dstport",
        "tcp.stream",
        "udp.stream",
        "_ws.col.Info",
        "data.text",
        "http.file_data",
        "data.data",
        "tcp.payload",
        "udp.payload",
    ]
    command = tshark_prefix(capture, tls_keylog, tshark_options)
    if display_filter:
        command.extend(["-Y", display_filter])
    command.extend(["-T", "fields", "-E", "separator=\t", "-E", "quote=d", "-E", "occurrence=f"])
    for field_name in fields:
        command.extend(["-e", field_name])
    result = subprocess.run(command, check=False, capture_output=True, text=True, errors="replace")
    if result.returncode not in (0, 1):
        detail = result.stderr.strip().splitlines()[-1] if result.stderr.strip() else "TShark search extraction failed"
        raise WorkbenchError(detail)
    matches = []
    for row in csv.reader(io.StringIO(result.stdout), delimiter="\t", quotechar='"'):
        if len(row) != len(fields):
            continue
        values = dict(zip(fields, row))
        encoded = values["http.file_data"] or values["data.data"] or values["tcp.payload"] or values["udp.payload"]
        payload = values["data.text"] or readable_payload(decode_hex_payload(encoded))
        haystack = f"{values['_ws.col.Info']}\n{payload}"
        found = matcher.search(haystack)
        if not found:
            continue
        src = values["ip.src"] or values["ipv6.src"]
        dst = values["ip.dst"] or values["ipv6.dst"]
        src_port = values["tcp.srcport"] or values["udp.srcport"]
        dst_port = values["tcp.dstport"] or values["udp.dstport"]
        start = max(0, found.start() - 100)
        end = min(len(haystack), found.end() + 200)
        excerpt = haystack[start:end].replace("\r", "\\r").replace("\n", "\\n")
        matches.append(
            {
                "frame": safe_int(values["frame.number"]),
                "time": values["frame.time"],
                "protocol": values["_ws.col.Protocol"],
                "source": f"{src}:{src_port}" if src_port else src,
                "destination": f"{dst}:{dst_port}" if dst_port else dst,
                "stream": values["tcp.stream"] or values["udp.stream"],
                "info": values["_ws.col.Info"],
                "excerpt": excerpt,
            }
        )
    return matches


def render_search(
    capture: Path,
    pattern: str,
    matches: Sequence[dict[str, Any]],
    regex: bool,
    show_sensitive: bool = False,
) -> str:
    lines = [
        "PCAP WORKBENCH — DECODED SEARCH",
        f"Capture: {capture}",
        f"Pattern: {pattern!r} ({'regular expression' if regex else 'literal text'})",
        f"Matches: {len(matches):,}",
        "",
    ]
    for item in matches:
        lines.append(
            f"frame {item['frame']:<7} {short_time(item['time'])} {item['protocol']:<8} "
            f"stream {item['stream'] or '-':<5} {item['source']} -> {item['destination']}"
        )
        lines.append(f"  {item['excerpt']}")
    if not matches:
        lines.append("No decoded packet summary or payload matched the search.")
    return protect_text("\n".join(lines) + "\n", show_sensitive)


OBJECT_PROTOCOLS = ("http", "smb", "tftp", "ftp-data", "imf", "dicom", "x509af")


def ensure_new_output(output: Path, inputs: Sequence[Path] = ()) -> Path:
    destination = output.expanduser().resolve()
    if any(destination == item.expanduser().resolve() for item in inputs):
        raise WorkbenchError("Output must not overwrite an input capture")
    if destination.exists():
        raise WorkbenchError(f"Output already exists: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    return destination


def export_objects(
    capture: Path,
    protocol: str,
    output_dir: Path,
    *,
    tls_keylog: Path | None = None,
    tshark_options: Sequence[str] = (),
) -> list[Path]:
    if protocol not in OBJECT_PROTOCOLS:
        raise WorkbenchError(f"Unsupported object protocol {protocol!r}")
    directory = output_dir.expanduser().resolve()
    if directory.exists() and any(directory.iterdir()):
        raise WorkbenchError(f"Object output directory must be empty: {directory}")
    directory.mkdir(parents=True, exist_ok=True)
    command = tshark_prefix(capture, tls_keylog, tshark_options)
    command.extend(["--export-objects", f"{protocol},{directory}"])
    result = subprocess.run(command, check=False, capture_output=True, text=True, errors="replace")
    if result.returncode not in (0, 1):
        detail = result.stderr.strip().splitlines()[-1] if result.stderr.strip() else "TShark object extraction failed"
        raise WorkbenchError(detail)
    return sorted(path for path in directory.iterdir() if path.is_file())


def export_filtered_capture(
    capture: Path,
    display_filter: str,
    output: Path,
    *,
    tls_keylog: Path | None = None,
    tshark_options: Sequence[str] = (),
) -> Path:
    if not display_filter.strip():
        raise WorkbenchError("A display filter is required for filtered export")
    destination = ensure_new_output(output, [capture])
    command = tshark_prefix(capture, tls_keylog, tshark_options)
    command.extend(["-Y", display_filter, "-w", str(destination)])
    result = subprocess.run(command, check=False, capture_output=True, text=True, errors="replace")
    if result.returncode not in (0, 1):
        detail = result.stderr.strip().splitlines()[-1] if result.stderr.strip() else "TShark filtered export failed"
        raise WorkbenchError(detail)
    return destination


def merge_captures(captures: Sequence[Path], output: Path) -> Path:
    if len(captures) < 2:
        raise WorkbenchError("At least two captures are required for merge")
    for capture in captures:
        if not capture.is_file():
            raise WorkbenchError(f"Capture not found: {capture}")
    destination = ensure_new_output(output, captures)
    command = [require_program("mergecap"), "-w", str(destination), *(str(path) for path in captures)]
    result = subprocess.run(command, check=False, capture_output=True, text=True, errors="replace")
    if result.returncode:
        detail = result.stderr.strip().splitlines()[-1] if result.stderr.strip() else "mergecap failed"
        raise WorkbenchError(detail)
    return destination


def tool_diagnostics() -> dict[str, Any]:
    tools = {}
    for name in ("tshark", "tcpdump", "capinfos", "mergecap", "editcap", "reordercap", "text2pcap"):
        path = shutil.which(name)
        version = ""
        if path:
            result = subprocess.run([path, "--version"], check=False, capture_output=True, text=True, errors="replace")
            version = (result.stdout or result.stderr).splitlines()[0] if (result.stdout or result.stderr) else "available"
        tools[name] = {"path": path or "", "version": version}
    return {
        "workbench_version": VERSION,
        "python": sys.version.splitlines()[0],
        "platform": sys.platform,
        "cwd": str(Path.cwd()),
        "tools": tools,
    }


def render_diagnostics(value: dict[str, Any]) -> str:
    lines = [
        "PCAP WORKBENCH — DIAGNOSTICS",
        f"Workbench: {value['workbench_version']}",
        f"Python: {value['python']}",
        f"Platform: {value['platform']}",
        f"Working directory: {value['cwd']}",
        "",
        "Tool status",
        "-----------",
    ]
    for name, item in value["tools"].items():
        status = f"{item['path']} — {item['version']}" if item["path"] else "NOT FOUND"
        required = "required" if name == "tshark" else "optional"
        lines.append(f"  {name:<12} [{required:<8}] {status}")
    lines.extend(
        [
            "",
            "Notes",
            "-----",
            "  TShark is required for analysis, search, correlation, and decoded reading.",
            "  tcpdump supplies raw ASCII/hex views; capinfos enriches metadata.",
            "  mergecap is required only for merge operations.",
            "  Offline capture reading does not require root when files are readable.",
        ]
    )
    return "\n".join(lines) + "\n"


def write_output(path: Path, content: str) -> None:
    path = path.expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def write_json(path: Path, value: Any) -> None:
    path = path.expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


@dataclass
class TuiSettings:
    primary_dir: Path = DEFAULT_PRIMARY_DIR
    secondary_dir: Path = DEFAULT_SECONDARY_DIR
    correlation_filter: str = DEFAULT_CORRELATION_FILTER
    window: float = DEFAULT_WINDOW
    auto_offset: bool = True
    manual_offset: float = 0.0
    event_limit: int = DEFAULT_EVENT_LIMIT
    display_filter: str = ""
    tls_keylog: Path | None = None
    tshark_options: list[str] = field(default_factory=list)
    show_sensitive: bool = False


def settings_to_dict(settings: TuiSettings) -> dict[str, Any]:
    return {
        "primary_dir": str(settings.primary_dir),
        "secondary_dir": str(settings.secondary_dir),
        "correlation_filter": settings.correlation_filter,
        "window": settings.window,
        "auto_offset": settings.auto_offset,
        "manual_offset": settings.manual_offset,
        "event_limit": settings.event_limit,
        "display_filter": settings.display_filter,
        "tls_keylog": str(settings.tls_keylog) if settings.tls_keylog else None,
        "tshark_options": list(settings.tshark_options),
        "show_sensitive": settings.show_sensitive,
    }


def load_settings(path: Path) -> TuiSettings:
    config_path = path.expanduser()
    try:
        value = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise WorkbenchError(f"Cannot load configuration {config_path}: {exc}") from exc
    if not isinstance(value, dict):
        raise WorkbenchError("Configuration root must be a JSON object")
    try:
        settings = TuiSettings(
            primary_dir=Path(value.get("primary_dir", Path.cwd())).expanduser(),
            secondary_dir=Path(value.get("secondary_dir", Path.cwd())).expanduser(),
            correlation_filter=str(value.get("correlation_filter", "")),
            window=float(value.get("window", DEFAULT_WINDOW)),
            auto_offset=bool(value.get("auto_offset", True)),
            manual_offset=float(value.get("manual_offset", 0.0)),
            event_limit=max(1, int(value.get("event_limit", DEFAULT_EVENT_LIMIT))),
            display_filter=str(value.get("display_filter", "")),
            tls_keylog=Path(value["tls_keylog"]).expanduser() if value.get("tls_keylog") else None,
            tshark_options=[str(item) for item in value.get("tshark_options", [])],
            show_sensitive=bool(value.get("show_sensitive", False)),
        )
    except (TypeError, ValueError) as exc:
        raise WorkbenchError(f"Invalid configuration value: {exc}") from exc
    if settings.window <= 0:
        raise WorkbenchError("Configured correlation window must be positive")
    return settings


def save_settings(path: Path, settings: TuiSettings) -> Path:
    config_path = path.expanduser()
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(json.dumps(settings_to_dict(settings), indent=2) + "\n", encoding="utf-8")
    try:
        os.chmod(config_path, 0o600)
    except OSError:
        pass
    return config_path


class WorkbenchTUI:
    def __init__(self, stdscr: "curses.window", settings: TuiSettings):
        self.screen = stdscr
        self.settings = settings
        curses.curs_set(0)
        self.screen.keypad(True)

    def add(self, row: int, column: int, text: str, attr: int = 0) -> None:
        height, width = self.screen.getmaxyx()
        if 0 <= row < height and column < width:
            try:
                self.screen.addstr(row, column, clip(text, width - column - 1), attr)
            except curses.error:
                pass

    def header(self, title: str, subtitle: str = "") -> None:
        self.screen.erase()
        self.add(0, 0, f"PCAP WORKBENCH {VERSION}  |  {title}", curses.A_BOLD)
        if subtitle:
            self.add(1, 0, subtitle)
        _, width = self.screen.getmaxyx()
        self.add(2, 0, "─" * max(1, width - 1))

    def menu(self, title: str, choices: Sequence[str], subtitle: str = "", footer: str = "Enter=select  Esc/q=back") -> int | None:
        selected = 0
        while True:
            self.header(title, subtitle)
            height, width = self.screen.getmaxyx()
            top = 4
            visible = max(1, height - top - 2)
            start = min(max(0, selected - visible + 1), max(0, len(choices) - visible))
            for display_row, index in enumerate(range(start, min(len(choices), start + visible)), top):
                label = f"  {choices[index]}"
                self.add(display_row, 0, label, curses.A_REVERSE if index == selected else 0)
            self.add(height - 1, 0, footer, curses.A_DIM)
            self.screen.refresh()
            key = self.screen.getch()
            if key in (27, ord("q")):
                return None
            if key in (curses.KEY_UP, ord("k")):
                selected = (selected - 1) % len(choices)
            elif key in (curses.KEY_DOWN, ord("j")):
                selected = (selected + 1) % len(choices)
            elif key in (curses.KEY_ENTER, 10, 13):
                return selected

    def input_text(self, title: str, prompt: str, initial: str = "") -> str | None:
        self.header(title)
        self.add(4, 0, prompt)
        if initial:
            self.add(5, 0, f"Current/default: {initial}", curses.A_DIM)
        self.add(7, 0, "> ")
        self.screen.move(7, 2)
        curses.curs_set(1)
        curses.echo()
        try:
            raw = self.screen.getstr(7, 2, 4096)
            value = raw.decode("utf-8", "replace").strip()
            return value if value else initial
        except (KeyboardInterrupt, curses.error):
            return None
        finally:
            curses.noecho()
            curses.curs_set(0)

    def message(self, title: str, message: str) -> None:
        self.header(title)
        row = 4
        width = max(20, self.screen.getmaxyx()[1] - 2)
        for paragraph in message.splitlines() or [""]:
            for line in textwrap.wrap(paragraph, width=width) or [""]:
                self.add(row, 0, line)
                row += 1
        self.add(self.screen.getmaxyx()[0] - 1, 0, "Press any key to continue", curses.A_DIM)
        self.screen.refresh()
        self.screen.getch()

    def busy(self, message: str) -> None:
        self.header("Working")
        self.add(4, 0, message, curses.A_BOLD)
        self.add(6, 0, "TShark is decoding the selected capture data. This may take a moment.")
        self.screen.refresh()

    def viewer(self, title: str, content: str, suggested_name: str) -> None:
        lines = content.splitlines()
        top = 0
        while True:
            self.header(title, f"{len(lines):,} lines")
            height, width = self.screen.getmaxyx()
            visible = max(1, height - 5)
            top = max(0, min(top, max(0, len(lines) - visible)))
            for row, line in enumerate(lines[top : top + visible], 3):
                self.add(row, 0, line)
            self.add(height - 1, 0, "↑↓/jk scroll  PgUp/PgDn  g/G ends  s=save report  q=back", curses.A_DIM)
            self.screen.refresh()
            key = self.screen.getch()
            if key in (ord("q"), 27):
                return
            if key in (curses.KEY_DOWN, ord("j")):
                top += 1
            elif key in (curses.KEY_UP, ord("k")):
                top -= 1
            elif key == curses.KEY_NPAGE:
                top += visible
            elif key == curses.KEY_PPAGE:
                top -= visible
            elif key == ord("g"):
                top = 0
            elif key == ord("G"):
                top = len(lines)
            elif key == ord("s"):
                default_path = str(Path.home() / suggested_name)
                chosen = self.input_text("Save report", "Output path:", default_path)
                if chosen:
                    try:
                        write_output(Path(chosen), content)
                        self.message("Saved", f"Report written to {chosen}")
                    except OSError as exc:
                        self.message("Save failed", str(exc))

    def choose_capture(self, title: str, directories: Sequence[Path]) -> Path | None:
        files_by_path: dict[Path, Path] = {}
        for directory in directories:
            for capture in list_pcaps(directory):
                files_by_path[capture.resolve()] = capture
        files = list(files_by_path.values())
        files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        choices = ["Enter a capture path…"]
        choices.extend(f"{path.name:<42} {human_bytes(path.stat().st_size):>10}  {path.parent}" for path in files)
        subtitle = f"{len(files)} configured capture(s); newest first" if files else "No configured captures; enter a path"
        selected = self.menu(title, choices, subtitle)
        if selected is None:
            return None
        if selected == 0:
            value = self.input_text(title, "Capture file or directory path:", "")
            if not value:
                return None
            entered_path = Path(value).expanduser()
            if entered_path.is_dir():
                directory_files = list_pcaps(entered_path)
                if not directory_files:
                    self.message(
                        "No captures",
                        f"No .pcap, .pcapng, .cap, or compressed capture files were found in {entered_path}",
                    )
                    return None
                directory_files.sort(key=lambda path: path.stat().st_mtime, reverse=True)
                directory_choices = [
                    f"{path.name:<48} {human_bytes(path.stat().st_size):>10}"
                    for path in directory_files
                ]
                directory_selected = self.menu(
                    f"Select a capture from {entered_path}",
                    directory_choices,
                    f"{len(directory_files)} capture(s); newest first",
                )
                return directory_files[directory_selected] if directory_selected is not None else None
            if not entered_path.is_file():
                self.message("Capture unavailable", f"File or directory not found or not readable: {entered_path}")
                return None
            return entered_path
        return files[selected - 1]

    def analyze_one(self) -> None:
        capture = self.choose_capture("Analyze one capture", [self.settings.primary_dir, self.settings.secondary_dir])
        if not capture:
            return
        self.busy(f"Analyzing {capture.name}")
        try:
            result = analyze_capture(
                capture,
                self.settings.display_filter,
                self.settings.tls_keylog,
                self.settings.tshark_options,
            )
            self.viewer(
                "Capture analysis",
                render_analysis(result, self.settings.event_limit, self.settings.show_sensitive),
                f"{capture.stem}-analysis.txt",
            )
        except (WorkbenchError, OSError) as exc:
            self.message("Analysis failed", str(exc))

    def analyze_directory(self) -> None:
        choice = self.menu(
            "Analyze a directory",
            [f"Primary source — {self.settings.primary_dir}", f"Secondary source — {self.settings.secondary_dir}"],
        )
        if choice is None:
            return
        directory = self.settings.primary_dir if choice == 0 else self.settings.secondary_dir
        captures = list_pcaps(directory)
        if not captures:
            self.message("No captures", f"No captures found in {directory}")
            return
        analyses = []
        try:
            for index, capture in enumerate(captures, 1):
                self.busy(f"Analyzing {index}/{len(captures)}: {capture.name}")
                analyses.append(
                    analyze_capture(
                        capture,
                        self.settings.display_filter,
                        self.settings.tls_keylog,
                        self.settings.tshark_options,
                    )
                )
            self.viewer(
                "Directory analysis",
                render_directory(directory, analyses, self.settings.show_sensitive),
                f"{directory.name}-analysis.txt",
            )
        except (WorkbenchError, OSError) as exc:
            self.message("Directory analysis failed", str(exc))

    def correlate(self) -> None:
        choice = self.menu(
            "Correlation scope",
            [
                "All primary captures vs all secondary captures (recommended)",
                "Choose one capture from each source",
                "Newest primary capture vs newest secondary capture",
            ],
            f"Filter={self.settings.correlation_filter or 'all IP/IPv6/ARP'}  window=±{human_duration(self.settings.window)}  offset={'auto' if self.settings.auto_offset else self.settings.manual_offset}",
        )
        if choice is None:
            return
        left = list_pcaps(self.settings.primary_dir)
        right = list_pcaps(self.settings.secondary_dir)
        if choice == 1:
            left_capture = self.choose_capture("Choose primary-side capture", [self.settings.primary_dir])
            if not left_capture:
                return
            right_capture = self.choose_capture("Choose secondary-side capture", [self.settings.secondary_dir])
            if not right_capture:
                return
            left, right = [left_capture], [right_capture]
        elif choice == 2:
            left, right = left[-1:], right[-1:]
        if not left or not right:
            self.message("Correlation unavailable", "One or both configured directories contain no captures.")
            return
        self.busy(f"Correlating {len(left)} left capture(s) with {len(right)} right capture(s)")
        try:
            report = correlate_packets(
                left,
                right,
                self.settings.correlation_filter,
                self.settings.window,
                None if self.settings.auto_offset else self.settings.manual_offset,
                tls_keylog=self.settings.tls_keylog,
                tshark_options=self.settings.tshark_options,
                progress=self.busy,
            )
            self.viewer(
                "Cross-capture correlation",
                render_correlation(report, self.settings.event_limit, self.settings.show_sensitive),
                "pcap-correlation.txt",
            )
        except (WorkbenchError, OSError) as exc:
            self.message("Correlation failed", str(exc))

    def raw_view(self) -> None:
        capture = self.choose_capture("Read capture contents", [self.settings.primary_dir, self.settings.secondary_dir])
        if not capture:
            return
        mode_names = list(READ_MODES)
        selected = self.menu(
            "Read capture contents",
            [READ_MODES[name] for name in mode_names],
            f"Capture: {capture.name}  TLS keys: {'configured' if self.settings.tls_keylog else 'none'}",
        )
        if selected is None:
            return
        mode = mode_names[selected]
        stream = 0
        follow_protocol = {
            "follow-tcp-ascii": "tcp",
            "follow-tcp-hex": "tcp",
            "follow-http": "http",
            "follow-tls": "tls",
            "follow-udp-ascii": "udp",
            "follow-udp-hex": "udp",
        }.get(mode)
        self.busy(f"Decoding {capture.name}")
        try:
            if follow_protocol:
                streams = list_streams(
                    capture,
                    follow_protocol,
                    self.settings.tls_keylog,
                    self.settings.tshark_options,
                )
                if not streams:
                    hint = " Configure a TLS key-log file in Settings." if follow_protocol == "tls" else ""
                    self.message("No streams", f"No {follow_protocol.upper()} streams were found in this capture.{hint}")
                    return
                choice = self.menu(
                    f"Choose {follow_protocol.upper()} stream",
                    [
                        f"stream {item.number:<5} {item.endpoint_a} <-> {item.endpoint_b}  "
                        f"{item.packets} packets, {human_bytes(item.bytes)}"
                        for item in streams
                    ],
                    f"Capture: {capture.name}",
                )
                if choice is None:
                    return
                stream = streams[choice].number
                self.busy(f"Reassembling {follow_protocol.upper()} stream {stream} from {capture.name}")
            content = read_capture_content(
                capture,
                mode,
                display_filter=self.settings.display_filter,
                stream=stream,
                tls_keylog=self.settings.tls_keylog,
                tshark_options=self.settings.tshark_options,
                show_sensitive=self.settings.show_sensitive,
            )
            self.viewer("Capture content reader", content, f"{capture.stem}-{mode}.txt")
        except (WorkbenchError, OSError) as exc:
            self.message("Reader failed", str(exc))

    def search_contents(self) -> None:
        capture = self.choose_capture("Search decoded contents", [self.settings.primary_dir, self.settings.secondary_dir])
        if not capture:
            return
        pattern = self.input_text("Search decoded contents", "Text or regular expression:")
        if not pattern:
            return
        mode = self.menu("Search mode", ["Literal text (case-insensitive)", "Regular expression (case-insensitive)"])
        if mode is None:
            return
        self.busy(f"Searching {capture.name}")
        try:
            matches = search_capture(
                capture,
                pattern,
                regex=mode == 1,
                display_filter=self.settings.display_filter,
                tls_keylog=self.settings.tls_keylog,
                tshark_options=self.settings.tshark_options,
            )
            self.viewer(
                "Decoded search",
                render_search(capture, pattern, matches, mode == 1, self.settings.show_sensitive),
                f"{capture.stem}-search.txt",
            )
        except (WorkbenchError, OSError) as exc:
            self.message("Search failed", str(exc))

    def capture_operations(self) -> None:
        choice = self.menu(
            "Capture operations",
            [
                "Extract transferred objects",
                "Export packets matching a display filter",
                "Merge every capture in the primary directory",
                "Merge every capture in the secondary directory",
            ],
            "Operations always write a new destination and never modify input captures",
        )
        if choice is None:
            return
        try:
            if choice == 0:
                capture = self.choose_capture("Extract transferred objects", [self.settings.primary_dir, self.settings.secondary_dir])
                if not capture:
                    return
                protocol_choice = self.menu("Object protocol", [name.upper() for name in OBJECT_PROTOCOLS])
                if protocol_choice is None:
                    return
                protocol = OBJECT_PROTOCOLS[protocol_choice]
                default_dir = Path.home() / f"{capture.stem}-{protocol}-objects"
                value = self.input_text("Object extraction", "New or empty output directory:", str(default_dir))
                if not value:
                    return
                self.busy(f"Extracting {protocol.upper()} objects from {capture.name}")
                files = export_objects(
                    capture,
                    protocol,
                    Path(value),
                    tls_keylog=self.settings.tls_keylog,
                    tshark_options=self.settings.tshark_options,
                )
                detail = "\n".join(f"{path.name} ({human_bytes(path.stat().st_size)})" for path in files[:100])
                if len(files) > 100:
                    detail += f"\n… {len(files) - 100} more files"
                self.message("Object extraction complete", f"Extracted {len(files)} file(s) to {value}\n{detail}")
            elif choice == 1:
                capture = self.choose_capture("Filtered capture export", [self.settings.primary_dir, self.settings.secondary_dir])
                if not capture:
                    return
                display_filter = self.input_text("Filtered capture export", "Required TShark display filter:", self.settings.display_filter)
                if not display_filter:
                    return
                default_output = Path.home() / f"{capture.stem}-filtered.pcapng"
                value = self.input_text("Filtered capture export", "New output capture path:", str(default_output))
                if not value:
                    return
                self.busy(f"Exporting filtered packets from {capture.name}")
                output = export_filtered_capture(
                    capture,
                    display_filter,
                    Path(value),
                    tls_keylog=self.settings.tls_keylog,
                    tshark_options=self.settings.tshark_options,
                )
                self.message("Filtered export complete", f"Wrote {output} ({human_bytes(output.stat().st_size)})")
            else:
                directory = self.settings.primary_dir if choice == 2 else self.settings.secondary_dir
                captures = list_pcaps(directory)
                if len(captures) < 2:
                    self.message("Merge unavailable", f"Fewer than two captures were found in {directory}")
                    return
                default_output = Path.home() / f"{directory.name or 'captures'}-merged.pcapng"
                value = self.input_text("Merge captures", f"Output path for {len(captures)} captures:", str(default_output))
                if not value:
                    return
                self.busy(f"Merging {len(captures)} captures")
                output = merge_captures(captures, Path(value))
                self.message("Merge complete", f"Wrote {output} ({human_bytes(output.stat().st_size)})")
        except (WorkbenchError, OSError) as exc:
            self.message("Operation failed", str(exc))

    def settings_menu(self) -> None:
        while True:
            choices = [
                f"Primary capture directory: {self.settings.primary_dir}",
                f"Secondary capture directory: {self.settings.secondary_dir}",
                f"Correlation display filter: {self.settings.correlation_filter or 'all IP/IPv6/ARP traffic'}",
                f"Match window: {self.settings.window:g} seconds",
                f"Clock offset: {'automatic' if self.settings.auto_offset else f'manual {self.settings.manual_offset:+g} seconds'}",
                f"Analysis display filter: {self.settings.display_filter or 'none'}",
                f"TLS key-log file: {self.settings.tls_keylog or 'not configured'}",
                f"Advanced TShark preferences: {len(self.settings.tshark_options)} configured",
                f"Show sensitive values in text/reports: {'YES' if self.settings.show_sensitive else 'no (redacted by default)'}",
                f"Report event limit: {self.settings.event_limit}",
                "Save settings to JSON",
                "Load settings from JSON",
                "Back",
            ]
            choice = self.menu("Settings", choices, "Changes apply for this run")
            if choice is None or choice == 12:
                return
            try:
                if choice == 0:
                    value = self.input_text("Settings", "Primary capture directory:", str(self.settings.primary_dir))
                    if value:
                        self.settings.primary_dir = Path(value).expanduser()
                elif choice == 1:
                    value = self.input_text("Settings", "Secondary capture directory:", str(self.settings.secondary_dir))
                    if value:
                        self.settings.secondary_dir = Path(value).expanduser()
                elif choice == 2:
                    value = self.input_text(
                        "Settings",
                        "TShark display filter for correlation (enter 'all' for IP/IPv6/ARP):",
                        self.settings.correlation_filter or "all",
                    )
                    if value is not None:
                        self.settings.correlation_filter = "" if value.lower() == "all" else value
                elif choice == 3:
                    value = self.input_text("Settings", "Correlation window in seconds:", str(self.settings.window))
                    if value:
                        parsed = float(value)
                        if parsed <= 0:
                            raise ValueError("window must be positive")
                        self.settings.window = parsed
                elif choice == 4:
                    value = self.input_text("Settings", "Enter 'auto' or a right-minus-left offset in seconds:", "auto" if self.settings.auto_offset else str(self.settings.manual_offset))
                    if value:
                        self.settings.auto_offset = value.lower() == "auto"
                        if not self.settings.auto_offset:
                            self.settings.manual_offset = float(value)
                elif choice == 5:
                    value = self.input_text("Settings", "Optional TShark display filter for capture analysis:", self.settings.display_filter)
                    if value is not None:
                        self.settings.display_filter = value
                elif choice == 6:
                    value = self.input_text(
                        "Settings",
                        "TLS SSLKEYLOGFILE path (enter 'none' to disable):",
                        str(self.settings.tls_keylog) if self.settings.tls_keylog else "none",
                    )
                    if value:
                        self.settings.tls_keylog = None if value.lower() == "none" else Path(value).expanduser()
                elif choice == 7:
                    value = self.input_text(
                        "Settings",
                        "Advanced TShark name:value preferences, separated by semicolons (or 'none'):",
                        ";".join(self.settings.tshark_options) if self.settings.tshark_options else "none",
                    )
                    if value:
                        self.settings.tshark_options = [] if value.lower() == "none" else [item.strip() for item in value.split(";") if item.strip()]
                elif choice == 8:
                    self.settings.show_sensitive = not self.settings.show_sensitive
                    if self.settings.show_sensitive:
                        self.message(
                            "Sensitive values enabled",
                            "Passwords, authorization values, cookies, and tokens may now appear in views and saved reports.",
                        )
                elif choice == 9:
                    value = self.input_text("Settings", "Maximum entries per report section:", str(self.settings.event_limit))
                    if value:
                        self.settings.event_limit = max(1, int(value))
                elif choice == 10:
                    value = self.input_text(
                        "Save settings",
                        "Configuration output path:",
                        str(Path.cwd() / "pcap-workbench.json"),
                    )
                    if value:
                        saved = save_settings(Path(value), self.settings)
                        self.message("Settings saved", f"Configuration written to {saved}")
                elif choice == 11:
                    value = self.input_text(
                        "Load settings",
                        "Configuration path:",
                        str(Path.cwd() / "pcap-workbench.json"),
                    )
                    if value:
                        loaded = load_settings(Path(value))
                        self.settings.__dict__.update(loaded.__dict__)
                        self.message("Settings loaded", f"Configuration loaded from {value}")
            except ValueError as exc:
                self.message("Invalid setting", str(exc))

    def help(self) -> None:
        self.viewer(
            "Help",
            textwrap.dedent(
                f"""
                PCAP Workbench {VERSION}

                Analyze one capture
                  Produces a human-readable overview of protocols, endpoints,
                  conversations, HTTP transactions, DNS, TLS server names,
                  transport observations, and a significant-event timeline.

                Analyze a directory
                  Decodes every capture and presents one comparable summary row
                  per file. Use Analyze one capture for full detail.

                Search decoded contents
                  Searches packet summaries and decoded application payloads as
                  literal text or a regular expression. An optional display filter
                  can narrow the packets before searching.

                Correlate capture systems
                  Matches packets using protocol, directional addresses/ports,
                  TCP sequence/acknowledgment information, lengths, flags, IP ID,
                  and timestamps. It can infer right-minus-left clock offset from
                  unique shared packets and falls back to flow/length/time matching.
                  The report highlights visibility differences and unmatched events.

                Capture content reader
                  Provides packet summaries, decoded protocol trees, decoded trees
                  with hex, raw ASCII, raw hex/ASCII, extracted plaintext payloads,
                  and selectable reconstructed TCP, UDP, HTTP, or TLS streams.

                Capture operations
                  Extract transferred objects, export packets selected by any
                  TShark display filter, or merge captures. Input files are never
                  modified and existing destinations are never overwritten.

                Decryption
                  Set a TLS SSLKEYLOGFILE path in Settings. When the matching session
                  secrets are present, TShark can decode TLS application protocols and
                  follow decrypted TLS streams. A PCAP alone generally cannot decrypt
                  modern TLS; the secrets must have been captured by the client/server.
                  Decryption-secret blocks embedded in pcapng are used automatically.
                  Advanced TShark preferences can configure other protocol keys/keytabs.

                Reports
                  Press s in a report viewer to save the currently displayed report.
                  CLI mode can also export structured JSON.

                Privacy
                  Captures, extracted payloads, stream views, object exports, and
                  key-log files may contain credentials or other private data.
                  Text views and reports redact common sensitive fields by default;
                  Settings can explicitly reveal them. Capture exports and extracted
                  objects remain byte-faithful and are never altered by redaction.
                  The workbench runs locally and does not upload packet data.

                Keyboard
                  Arrow keys or j/k move; Enter selects; q or Escape goes back.

                Important
                  Findings are protocol and transport observations for human review.
                  They are not automatic conclusions that traffic is malicious.
                """
            ).strip() + "\n",
            "pcap-workbench-help.txt",
        )

    def run(self) -> int:
        while True:
            choice = self.menu(
                "Main menu",
                [
                    "Analyze one capture",
                    "Analyze every capture in a directory",
                    "Read capture contents (raw, decoded, hex, plaintext, streams)",
                    "Search decoded summaries and payloads",
                    "Correlate primary and secondary capture sources",
                    "Capture operations (objects, filter, merge)",
                    "Settings",
                    "Diagnostics / dependency check",
                    "Help / methodology",
                    "Quit",
                ],
                f"PRIMARY={self.settings.primary_dir}  SECONDARY={self.settings.secondary_dir}",
            )
            if choice is None or choice == 9:
                return 0
            if choice == 0:
                self.analyze_one()
            elif choice == 1:
                self.analyze_directory()
            elif choice == 2:
                self.raw_view()
            elif choice == 3:
                self.search_contents()
            elif choice == 4:
                self.correlate()
            elif choice == 5:
                self.capture_operations()
            elif choice == 6:
                self.settings_menu()
            elif choice == 7:
                self.viewer("Diagnostics", render_diagnostics(tool_diagnostics()), "pcap-workbench-diagnostics.txt")
            elif choice == 8:
                self.help()


def add_common_output(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--output", type=Path, help="write the human-readable report to this file")
    parser.add_argument("--json", type=Path, help="write the complete structured result as JSON")
    parser.add_argument("--event-limit", type=int, default=DEFAULT_EVENT_LIMIT, help=f"maximum rows per report section (default: {DEFAULT_EVENT_LIMIT})")
    parser.add_argument("--tls-keylog", type=Path, help="TLS SSLKEYLOGFILE containing session secrets for decryption")
    parser.add_argument("--tshark-option", action="append", default=[], metavar="NAME:VALUE", help="advanced TShark -o preference; repeat as needed")
    parser.add_argument("--show-sensitive", action="store_true", help="do not redact common credentials, cookies, or tokens in text/JSON output")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    subparsers = parser.add_subparsers(dest="command")

    tui = subparsers.add_parser("tui", help="open the interactive interface")
    tui.add_argument("--config", type=Path, help="load TUI settings from an explicit JSON file")
    tui.add_argument("--primary-dir", type=Path)
    tui.add_argument("--secondary-dir", type=Path)
    tui.add_argument("--correlation-filter")
    tui.add_argument("--window", type=float)
    tui.add_argument("--tls-keylog", type=Path, help="TLS SSLKEYLOGFILE containing session secrets")
    tui.add_argument("--tshark-option", action="append", default=[], metavar="NAME:VALUE")
    tui.add_argument("--show-sensitive", action="store_true", help="start with sensitive-value redaction disabled")

    analyze = subparsers.add_parser("analyze", help="analyze one or more capture files")
    analyze.add_argument("captures", nargs="+", type=Path)
    analyze.add_argument("--display-filter", default="", help="optional TShark display filter")
    add_common_output(analyze)

    directory = subparsers.add_parser("directory", help="summarize every capture in a directory")
    directory.add_argument("directory", type=Path)
    directory.add_argument("--display-filter", default="", help="optional TShark display filter")
    add_common_output(directory)

    correlate = subparsers.add_parser("correlate", help="correlate captures from two capture systems")
    left = correlate.add_mutually_exclusive_group(required=True)
    left.add_argument("--left", nargs="+", type=Path, help="left-side capture file(s)")
    left.add_argument("--left-dir", type=Path, help="directory of left-side captures")
    right = correlate.add_mutually_exclusive_group(required=True)
    right.add_argument("--right", nargs="+", type=Path, help="right-side capture file(s)")
    right.add_argument("--right-dir", type=Path, help="directory of right-side captures")
    correlate.add_argument("--display-filter", default=DEFAULT_CORRELATION_FILTER, help="TShark filter applied to both sides (default: all IP/IPv6/ARP)")
    correlate.add_argument("--window", type=float, default=DEFAULT_WINDOW, help=f"timestamp tolerance in seconds (default: {DEFAULT_WINDOW})")
    correlate.add_argument("--clock-offset", type=float, help="manual right-minus-left clock offset; omitted means auto-detect")
    add_common_output(correlate)

    reader = subparsers.add_parser("read", help="read a capture as summaries, decoded fields, hex, plaintext, or streams")
    reader.add_argument("capture", type=Path)
    reader.add_argument("--mode", choices=READ_MODES, default="summary", help="content representation (default: summary)")
    reader.add_argument("--stream", type=int, default=0, help="stream number for follow-* modes (default: 0)")
    reader.add_argument("--display-filter", default="", help="optional TShark filter for non-stream modes")
    reader.add_argument("--tls-keylog", type=Path, help="TLS SSLKEYLOGFILE containing session secrets for decryption")
    reader.add_argument("--tshark-option", action="append", default=[], metavar="NAME:VALUE", help="advanced TShark -o preference; repeat as needed")
    reader.add_argument("--show-sensitive", action="store_true", help="do not redact common credentials, cookies, or tokens")
    reader.add_argument("--output", type=Path, help="write reader output to this file")

    search = subparsers.add_parser("search", help="search decoded summaries and payload text")
    search.add_argument("capture", type=Path)
    search.add_argument("--text", required=True, help="literal text or regular expression")
    search.add_argument("--regex", action="store_true", help="interpret --text as a regular expression")
    search.add_argument("--case-sensitive", action="store_true")
    search.add_argument("--display-filter", default="", help="optional TShark pre-filter")
    search.add_argument("--tls-keylog", type=Path)
    search.add_argument("--tshark-option", action="append", default=[], metavar="NAME:VALUE")
    search.add_argument("--show-sensitive", action="store_true", help="do not redact sensitive values in displayed matches or JSON")
    search.add_argument("--output", type=Path)
    search.add_argument("--json", type=Path)

    objects = subparsers.add_parser("extract-objects", help="extract transferred files from a capture")
    objects.add_argument("capture", type=Path)
    objects.add_argument("--protocol", required=True, choices=OBJECT_PROTOCOLS)
    objects.add_argument("--output-dir", required=True, type=Path)
    objects.add_argument("--tls-keylog", type=Path)
    objects.add_argument("--tshark-option", action="append", default=[], metavar="NAME:VALUE")

    filtered = subparsers.add_parser("filter", help="write packets matching a display filter to a new capture")
    filtered.add_argument("capture", type=Path)
    filtered.add_argument("--display-filter", required=True)
    filtered.add_argument("--output", required=True, type=Path)
    filtered.add_argument("--tls-keylog", type=Path)
    filtered.add_argument("--tshark-option", action="append", default=[], metavar="NAME:VALUE")

    merge = subparsers.add_parser("merge", help="merge capture files into a new capture")
    merge.add_argument("captures", nargs="+", type=Path)
    merge.add_argument("--output", required=True, type=Path)

    subparsers.add_parser("doctor", help="show dependency and environment diagnostics")

    raw = subparsers.add_parser("raw", help="print raw or verbose packet details")
    raw.add_argument("capture", type=Path)
    raw.add_argument("--hex", action="store_true", help="tcpdump hex plus ASCII")
    raw.add_argument("--verbose", action="store_true", help="verbose TShark dissection")
    raw.add_argument("--show-sensitive", action="store_true", help="do not redact common credentials, cookies, or tokens")
    return parser


def run_cli(args: argparse.Namespace) -> int:
    if args.command == "analyze":
        analyses = [
            analyze_capture(path.expanduser(), args.display_filter, args.tls_keylog, args.tshark_option)
            for path in args.captures
        ]
        reports = [render_analysis(item, args.event_limit, args.show_sensitive) for item in analyses]
        content = "\n\f\n".join(report.rstrip() for report in reports) + "\n"
        if args.output:
            write_output(args.output, content)
        else:
            print(content, end="")
        if args.json:
            data = [item.to_dict() for item in analyses] if len(analyses) > 1 else analyses[0].to_dict()
            write_json(args.json, data if args.show_sensitive else redact_sensitive_data(data))
        return 0

    if args.command == "directory":
        directory = args.directory.expanduser()
        captures = list_pcaps(directory)
        if not captures:
            raise WorkbenchError(f"No captures found in {directory}")
        analyses = [
            analyze_capture(path, args.display_filter, args.tls_keylog, args.tshark_option)
            for path in captures
        ]
        content = render_directory(directory, analyses, args.show_sensitive)
        if args.output:
            write_output(args.output, content)
        else:
            print(content, end="")
        if args.json:
            data = [item.to_dict() for item in analyses]
            write_json(args.json, data if args.show_sensitive else redact_sensitive_data(data))
        return 0

    if args.command == "correlate":
        if args.window <= 0:
            raise WorkbenchError("Correlation window must be positive")
        left_captures = [path.expanduser() for path in args.left] if args.left else list_pcaps(args.left_dir.expanduser())
        right_captures = [path.expanduser() for path in args.right] if args.right else list_pcaps(args.right_dir.expanduser())
        if not left_captures or not right_captures:
            raise WorkbenchError("One or both correlation sides contain no captures")
        report = correlate_packets(
            left_captures,
            right_captures,
            args.display_filter,
            args.window,
            args.clock_offset,
            tls_keylog=args.tls_keylog,
            tshark_options=args.tshark_option,
        )
        content = render_correlation(report, args.event_limit, args.show_sensitive)
        if args.output:
            write_output(args.output, content)
        else:
            print(content, end="")
        if args.json:
            data = report.to_dict()
            write_json(args.json, data if args.show_sensitive else redact_sensitive_data(data))
        return 0

    if args.command == "read":
        if args.stream < 0:
            raise WorkbenchError("Stream number cannot be negative")
        content = read_capture_content(
            args.capture.expanduser(),
            args.mode,
            display_filter=args.display_filter,
            stream=args.stream,
            tls_keylog=args.tls_keylog,
            tshark_options=args.tshark_option,
            show_sensitive=args.show_sensitive,
        )
        if args.output:
            write_output(args.output, content)
        else:
            print(content, end="")
        return 0

    if args.command == "search":
        capture = args.capture.expanduser()
        matches = search_capture(
            capture,
            args.text,
            regex=args.regex,
            case_sensitive=args.case_sensitive,
            display_filter=args.display_filter,
            tls_keylog=args.tls_keylog,
            tshark_options=args.tshark_option,
        )
        content = render_search(capture, args.text, matches, args.regex, args.show_sensitive)
        if args.output:
            write_output(args.output, content)
        else:
            print(content, end="")
        if args.json:
            write_json(args.json, matches if args.show_sensitive else redact_sensitive_data(matches))
        return 0

    if args.command == "extract-objects":
        files = export_objects(
            args.capture.expanduser(),
            args.protocol,
            args.output_dir,
            tls_keylog=args.tls_keylog,
            tshark_options=args.tshark_option,
        )
        print(f"Extracted {len(files)} object(s) to {args.output_dir.expanduser().resolve()}")
        for path in files:
            print(f"{path.name}\t{path.stat().st_size} bytes")
        return 0

    if args.command == "filter":
        output = export_filtered_capture(
            args.capture.expanduser(),
            args.display_filter,
            args.output,
            tls_keylog=args.tls_keylog,
            tshark_options=args.tshark_option,
        )
        print(f"Wrote {output} ({output.stat().st_size} bytes)")
        return 0

    if args.command == "merge":
        output = merge_captures([path.expanduser() for path in args.captures], args.output)
        print(f"Wrote {output} ({output.stat().st_size} bytes)")
        return 0

    if args.command == "doctor":
        print(render_diagnostics(tool_diagnostics()), end="")
        return 0

    if args.command == "raw":
        capture = args.capture.expanduser()
        mode = "decoded" if args.verbose else "hex" if args.hex else "ascii"
        print(read_capture_content(capture, mode, show_sensitive=args.show_sensitive), end="")
        return 0
    return 0


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        if not args.command:
            if not sys.stdin.isatty() or not sys.stdout.isatty():
                parser.print_help()
                return 0
            settings = TuiSettings()
            return curses.wrapper(lambda screen: WorkbenchTUI(screen, settings).run())
        if args.command == "tui":
            settings = load_settings(args.config) if args.config else TuiSettings()
            if args.primary_dir:
                settings.primary_dir = args.primary_dir.expanduser()
            if args.secondary_dir:
                settings.secondary_dir = args.secondary_dir.expanduser()
            if args.correlation_filter is not None:
                settings.correlation_filter = args.correlation_filter
            if args.window is not None:
                if args.window <= 0:
                    raise WorkbenchError("Correlation window must be positive")
                settings.window = args.window
            if args.tls_keylog:
                settings.tls_keylog = args.tls_keylog.expanduser()
            if args.tshark_option:
                settings.tshark_options = args.tshark_option
            if args.show_sensitive:
                settings.show_sensitive = True
            return curses.wrapper(lambda screen: WorkbenchTUI(screen, settings).run())
        return run_cli(args)
    except (WorkbenchError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
