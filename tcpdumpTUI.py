#!/usr/bin/env python3
"""
tcpdump TUI: guided live packet capture for the terminal.
"""

from __future__ import annotations

import argparse
import collections
import dataclasses
import datetime as dt
import ipaddress
import json
import os
import queue
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
from pathlib import Path
from typing import Iterable, Sequence

try:
    import curses
except ImportError:  # pragma: no cover - platform-specific import failure
    curses = None  # type: ignore[assignment]

try:
    import tomllib
except ImportError:  # pragma: no cover - Python < 3.11
    tomllib = None  # type: ignore[assignment]


VERSION = "1.0.1"
APP_NAME = "tcpdump-tui"
DEFAULT_CONFIG = Path(
    os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config"))
) / APP_NAME / "config.toml"
MIN_WIDTH = 76
MIN_HEIGHT = 20


class AppError(RuntimeError):
    """An error that can be shown directly to the user."""


CAPABILITY_BITS = {
    "cap_net_admin": 12,
    "cap_net_raw": 13,
}


def parse_capability_names(value: str) -> set[str]:
    """Extract Linux capability names from getcap-style output."""
    return set(re.findall(r"\bcap_[a-z0-9_]+\b", value.lower()))


def process_ambient_capabilities() -> set[str]:
    """Return capabilities that Linux will preserve across a normal exec."""
    try:
        status = Path("/proc/self/status").read_text(encoding="ascii")
    except OSError:
        return set()
    match = re.search(r"^CapAmb:\s*([0-9a-fA-F]+)$", status, re.MULTILINE)
    if not match:
        return set()
    mask = int(match.group(1), 16)
    return {name for name, bit in CAPABILITY_BITS.items() if mask & (1 << bit)}


def executable_capabilities(program: str) -> set[str]:
    """Return Linux file capabilities assigned to an executable."""
    getcap = shutil.which("getcap")
    if not getcap:
        return set()
    try:
        result = subprocess.run(
            [getcap, program], capture_output=True, text=True, errors="replace", timeout=5
        )
    except (OSError, subprocess.TimeoutExpired):
        return set()
    return parse_capability_names(result.stdout) if result.returncode == 0 else set()


def capture_privilege_status(
    tcpdump: str,
    promiscuous: bool,
    *,
    effective_uid: int | None = None,
    ambient_capabilities: set[str] | None = None,
    file_capabilities: set[str] | None = None,
) -> tuple[bool, str]:
    """Check for root or the Linux capabilities needed by tcpdump."""
    if not hasattr(os, "geteuid"):
        return True, "platform does not use Unix effective user IDs"
    uid = os.geteuid() if effective_uid is None else effective_uid
    if uid == 0:
        return True, "running as root"
    required = {"cap_net_raw"}
    if promiscuous:
        required.add("cap_net_admin")
    ambient_caps = (
        process_ambient_capabilities()
        if ambient_capabilities is None
        else ambient_capabilities
    )
    file_caps = (
        executable_capabilities(tcpdump)
        if file_capabilities is None
        else file_capabilities
    )
    if required <= file_caps or required <= ambient_caps:
        return True, "capture capabilities available"
    closest = max((file_caps, ambient_caps), key=lambda item: len(required & item))
    missing = ", ".join(sorted(required - closest))
    return False, f"missing {missing}"


def privilege_error(_tcpdump: str, _detail: str) -> AppError:
    return AppError(
        "Packet capture requires administrator privileges. Run:\n"
        "  sudo python3 tcpdump_tui.py"
    )


@dataclasses.dataclass(slots=True)
class Config:
    capture_dir: Path = Path.home() / "pcaps"
    default_interface: str = ""
    last_filter: str = ""
    snaplen: int = 262144
    buffer_kib: int = 4096
    promiscuous: bool = True
    immediate_mode: bool = True
    max_rows: int = 5000
    refresh_ms: int = 80

    def validate(self) -> None:
        if not 64 <= self.snaplen <= 262144:
            raise AppError("snaplen must be between 64 and 262144 bytes")
        if not 128 <= self.buffer_kib <= 1048576:
            raise AppError("buffer_kib must be between 128 and 1048576")
        if not 100 <= self.max_rows <= 100000:
            raise AppError("max_rows must be between 100 and 100000")
        if not 25 <= self.refresh_ms <= 1000:
            raise AppError("refresh_ms must be between 25 and 1000")


def load_config(path: Path) -> Config:
    if not path.exists():
        config = Config()
        config.validate()
        return config
    if tomllib is None:
        raise AppError("Python 3.11 or newer is required to read TOML configuration")
    try:
        with path.open("rb") as handle:
            raw = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise AppError(f"Cannot read configuration {path}: {exc}") from exc
    section = raw.get("tcpdump_tui", raw)
    if not isinstance(section, dict):
        raise AppError("Configuration must contain a [tcpdump_tui] table")
    defaults = Config()
    try:
        config = Config(
            capture_dir=Path(section.get("capture_dir", defaults.capture_dir)).expanduser(),
            default_interface=str(section.get("default_interface", "")),
            last_filter=str(section.get("last_filter", "")),
            snaplen=int(section.get("snaplen", defaults.snaplen)),
            buffer_kib=int(section.get("buffer_kib", defaults.buffer_kib)),
            promiscuous=bool(section.get("promiscuous", defaults.promiscuous)),
            immediate_mode=bool(section.get("immediate_mode", defaults.immediate_mode)),
            max_rows=int(section.get("max_rows", defaults.max_rows)),
            refresh_ms=int(section.get("refresh_ms", defaults.refresh_ms)),
        )
    except (TypeError, ValueError) as exc:
        raise AppError(f"Invalid configuration value: {exc}") from exc
    config.validate()
    return config


def _toml_string(value: str) -> str:
    # JSON string escaping is also valid for TOML basic strings.
    return json.dumps(value, ensure_ascii=False)


def save_config(path: Path, config: Config) -> None:
    config.validate()
    content = "\n".join(
        [
            "# tcpdump-tui settings. Changes made in the TUI are saved here.",
            "[tcpdump_tui]",
            f"capture_dir = {_toml_string(str(config.capture_dir))}",
            f"default_interface = {_toml_string(config.default_interface)}",
            f"last_filter = {_toml_string(config.last_filter)}",
            f"snaplen = {config.snaplen}",
            f"buffer_kib = {config.buffer_kib}",
            f"promiscuous = {str(config.promiscuous).lower()}",
            f"immediate_mode = {str(config.immediate_mode).lower()}",
            f"max_rows = {config.max_rows}",
            f"refresh_ms = {config.refresh_ms}",
            "",
        ]
    )
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=".config-", dir=path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, path)
        except Exception:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise
    except OSError as exc:
        raise AppError(f"Cannot save configuration {path}: {exc}") from exc


@dataclasses.dataclass(slots=True)
class InterfaceInfo:
    index: int
    name: str
    description: str = ""
    state: str = "unknown"
    addresses: tuple[str, ...] = ()
    flags: tuple[str, ...] = ()

    @property
    def usable(self) -> bool:
        return self.state == "up"


TCPDUMP_INTERFACE_RE = re.compile(
    r"^\s*(?P<index>\d+)\.(?P<name>\S+)"
    r"(?:\s+\((?P<description>.*?)\))?"
    r"(?:\s+\[(?P<flags>.*?)\])?\s*$"
)


def parse_tcpdump_interfaces(output: str) -> list[InterfaceInfo]:
    interfaces: list[InterfaceInfo] = []
    for line in output.splitlines():
        match = TCPDUMP_INTERFACE_RE.match(line)
        if not match:
            continue
        flags = tuple(
            part.strip() for part in (match.group("flags") or "").split(",") if part.strip()
        )
        lowered = {flag.lower() for flag in flags}
        state = "up" if "up" in lowered or "running" in lowered else "unknown"
        if "down" in lowered:
            state = "down"
        interfaces.append(
            InterfaceInfo(
                index=int(match.group("index")),
                name=match.group("name"),
                description=match.group("description") or "",
                state=state,
                flags=flags,
            )
        )
    return interfaces


def _system_interface_state(name: str) -> str:
    if name == "any":
        return "up"
    operstate = Path("/sys/class/net") / name / "operstate"
    try:
        value = operstate.read_text(encoding="ascii").strip().lower()
    except OSError:
        return "unknown"
    if value in {"up", "unknown", "dormant"}:
        return "up"
    if value in {"down", "lowerlayerdown", "notpresent"}:
        return "down"
    return "unknown"


def _interface_addresses() -> dict[str, list[str]]:
    addresses: dict[str, list[str]] = collections.defaultdict(list)
    # SIOCGIFADDR is portable across common Unix systems for primary IPv4.
    if hasattr(socket, "AF_INET"):
        try:
            import fcntl

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                for _, name in socket.if_nameindex():
                    request = struct.pack("256s", name.encode("utf-8")[:15])
                    try:
                        result = fcntl.ioctl(sock.fileno(), 0x8915, request)
                        addresses[name].append(socket.inet_ntoa(result[20:24]))
                    except OSError:
                        pass
            finally:
                sock.close()
        except (ImportError, OSError):
            pass
    try:
        for line in Path("/proc/net/if_inet6").read_text(encoding="ascii").splitlines():
            fields = line.split()
            if len(fields) == 6:
                packed, name = fields[0], fields[5]
                address = str(ipaddress.IPv6Address(int(packed, 16)))
                addresses[name].append(address)
    except OSError:
        pass
    return addresses


def discover_interfaces(tcpdump: str) -> tuple[list[InterfaceInfo], str]:
    try:
        result = subprocess.run(
            [tcpdump, "-D"], capture_output=True, text=True, errors="replace", timeout=8
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        result = None
        warning = f"tcpdump interface discovery failed: {exc}"
    else:
        warning = "" if result.returncode == 0 else (result.stderr.strip() or result.stdout.strip())
    interfaces = parse_tcpdump_interfaces(result.stdout) if result else []
    known = {item.name for item in interfaces}
    try:
        native = socket.if_nameindex()
    except OSError:
        native = []
    native_by_name = {name: index for index, name in native}
    try:
        sysfs_names = sorted(path.name for path in Path("/sys/class/net").iterdir())
    except OSError:
        sysfs_names = []
    for name in sysfs_names:
        if name in native_by_name:
            continue
        try:
            index = int((Path("/sys/class/net") / name / "ifindex").read_text(encoding="ascii"))
        except (OSError, ValueError):
            index = len(native_by_name) + 1
        native.append((index, name))
        native_by_name[name] = index
    for index, name in native:
        if name not in known:
            interfaces.append(InterfaceInfo(index=index, name=name))
    addresses = _interface_addresses()
    for item in interfaces:
        system_state = _system_interface_state(item.name)
        if system_state != "unknown":
            item.state = system_state
        elif item.name not in native_by_name and item.state == "unknown":
            # libpcap pseudo-devices returned by -D are available even though
            # they have no /sys entry.
            item.state = "up"
        item.addresses = tuple(addresses.get(item.name, ()))
    interfaces.sort(key=lambda item: (item.name != "any", item.state != "up", item.index, item.name))
    return interfaces, warning


@dataclasses.dataclass(slots=True)
class FilterClause:
    label: str
    expression: str


class FilterPlan:
    def __init__(self, expression: str = ""):
        self.clauses: list[FilterClause] = []
        self.operator = "and"
        if expression.strip():
            self.clauses.append(FilterClause("Previous/custom filter", expression.strip()))

    @property
    def expression(self) -> str:
        if not self.clauses:
            return ""
        return f" {self.operator} ".join(f"({clause.expression})" for clause in self.clauses)

    def add(self, label: str, expression: str) -> None:
        self.clauses.append(FilterClause(label, expression))


def validate_host(value: str) -> str:
    value = value.strip()
    if not value or len(value) > 253 or not re.fullmatch(r"[A-Za-z0-9_.:%-]+", value):
        raise AppError("Enter an IP address or hostname without spaces")
    return value


def validate_network(value: str) -> str:
    try:
        return str(ipaddress.ip_network(value.strip(), strict=False))
    except ValueError as exc:
        raise AppError("Enter a network in CIDR form, such as 192.168.1.0/24") from exc


def validate_port(value: str) -> int:
    try:
        port = int(value)
    except ValueError as exc:
        raise AppError("Port must be a number from 1 to 65535") from exc
    if not 1 <= port <= 65535:
        raise AppError("Port must be a number from 1 to 65535")
    return port


def validate_mac(value: str) -> str:
    value = value.strip()
    if not re.fullmatch(r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}", value):
        raise AppError("Enter a MAC address such as 00:11:22:aa:bb:cc")
    return value.replace("-", ":").lower()


def validate_bpf(tcpdump: str, expression: str) -> tuple[bool, str]:
    if not expression.strip():
        return True, "All traffic"
    try:
        result = subprocess.run(
            [tcpdump, "-d", "-y", "EN10MB", expression],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=8,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)
    if result.returncode == 0:
        return True, "Filter compiled successfully"
    detail = result.stderr.strip() or result.stdout.strip() or "tcpdump rejected the filter"
    return False, detail.splitlines()[-1]


@dataclasses.dataclass(slots=True)
class PacketRow:
    timestamp: float
    source: str
    source_port: str
    destination: str
    destination_port: str
    protocol: str
    length: int
    info: str
    raw: str


def _split_endpoint(value: str, has_port: bool) -> tuple[str, str]:
    value = value.rstrip(":")
    if not has_port:
        return value, ""
    host, separator, port = value.rpartition(".")
    if separator and port.isdigit():
        return host, port
    return value, ""


def parse_packet_line(line: str) -> PacketRow | None:
    raw = line.rstrip("\r\n")
    match = re.match(r"^(\d+(?:\.\d+)?)\s+(.*)$", raw)
    if not match:
        return None
    timestamp = float(match.group(1))
    body = match.group(2)
    network_match = re.match(
        r"^(?:(?P<device>\S+)\s+(?P<direction>In|Out)\s+)?"
        r"(?P<network>IP6?|ARP|RARP)\s*,?\s*(?P<rest>.*)$",
        body,
    )
    network = network_match.group("network") if network_match else "OTHER"
    rest = network_match.group("rest") if network_match else body
    interface_note = ""
    if network_match and network_match.group("device"):
        interface_note = f"[{network_match.group('device')} {network_match.group('direction')}] "

    if network in {"ARP", "RARP"}:
        who = re.search(r"who-has\s+(\S+)", rest)
        tell = re.search(r"tell\s+(\S+)", rest)
        length_match = re.search(r"length\s+(\d+)", rest)
        return PacketRow(
            timestamp, tell.group(1).rstrip(",") if tell else "", "",
            who.group(1).rstrip(",") if who else "", "", network,
            int(length_match.group(1)) if length_match else 0, interface_note + rest, raw,
        )

    endpoints = re.match(r"^(\S+)\s+>\s+(\S+):\s*(.*)$", rest)
    if not endpoints:
        return PacketRow(timestamp, "", "", "", "", network, 0, rest, raw)
    source_raw, destination_raw, info = endpoints.groups()
    upper = info.upper()
    if info.startswith("Flags [") or upper.startswith("TCP"):
        protocol = "TCP"
    elif upper.startswith("UDP"):
        protocol = "UDP"
    elif upper.startswith("ICMP6"):
        protocol = "ICMP6"
    elif upper.startswith("ICMP"):
        protocol = "ICMP"
    elif upper.startswith("SCTP"):
        protocol = "SCTP"
    elif upper.startswith("IGMP"):
        protocol = "IGMP"
    elif upper.startswith("ESP"):
        protocol = "ESP"
    else:
        protocol = network
    has_port = protocol in {"TCP", "UDP", "SCTP"}
    source, source_port = _split_endpoint(source_raw, has_port)
    destination, destination_port = _split_endpoint(destination_raw, has_port)
    length_match = re.search(r"(?:length|len)\s+(\d+)", info)
    length = int(length_match.group(1)) if length_match else 0
    return PacketRow(
        timestamp, source, source_port, destination, destination_port,
        protocol, length, interface_note + info, raw,
    )


class CaptureSession:
    """Own one tcpdump process and its continuously written spool capture."""

    def __init__(self, tcpdump: str, interface: str, expression: str, config: Config):
        self.tcpdump = tcpdump
        self.interface = interface
        self.expression = expression
        self.config = config
        self._temporary = tempfile.TemporaryDirectory(prefix="tcpdump-tui-")
        self.spool = Path(self._temporary.name) / "live.pcap"
        self.process: subprocess.Popen[str] | None = None
        self.lines: queue.Queue[str] = queue.Queue(maxsize=10000)
        self.errors: queue.Queue[str] = queue.Queue(maxsize=500)
        self.reader_drops = 0
        self._threads: list[threading.Thread] = []
        self.started = time.monotonic()

    def command(self) -> list[str]:
        command = [
            self.tcpdump,
            "-i", self.interface,
            "-nn",
            "-tt",
            "-q",
            "-U",
            "--print",
            "-s", str(self.config.snaplen),
            "-B", str(self.config.buffer_kib),
            "-w", str(self.spool),
        ]
        if not self.config.promiscuous:
            command.append("-p")
        if self.config.immediate_mode:
            command.append("--immediate-mode")
        if self.expression:
            command.append(self.expression)
        return command

    def start(self) -> None:
        try:
            self.process = subprocess.Popen(
                self.command(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                errors="replace",
                bufsize=1,
                start_new_session=(os.name == "posix"),
            )
        except OSError as exc:
            self._temporary.cleanup()
            raise AppError(f"Could not start tcpdump: {exc}") from exc
        assert self.process.stdout is not None and self.process.stderr is not None
        self._threads = [
            threading.Thread(target=self._read_stdout, daemon=True),
            threading.Thread(target=self._read_stderr, daemon=True),
        ]
        for thread in self._threads:
            thread.start()

    def _read_stdout(self) -> None:
        assert self.process and self.process.stdout
        for line in self.process.stdout:
            try:
                self.lines.put_nowait(line)
            except queue.Full:
                self.reader_drops += 1

    def _read_stderr(self) -> None:
        assert self.process and self.process.stderr
        for line in self.process.stderr:
            try:
                self.errors.put_nowait(line.rstrip())
            except queue.Full:
                pass

    @property
    def running(self) -> bool:
        return self.process is not None and self.process.poll() is None

    def flush(self) -> None:
        if not self.running or self.process is None or os.name != "posix":
            return
        try:
            os.kill(self.process.pid, signal.SIGUSR2)
            time.sleep(0.04)
        except (OSError, AttributeError):
            pass

    def save_snapshot(self, directory: Path) -> Path:
        self.flush()
        try:
            directory.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise AppError(f"Cannot create capture directory {directory}: {exc}") from exc
        if not self.spool.exists() or self.spool.stat().st_size < 24:
            raise AppError("No packets have been written yet")
        stamp = dt.datetime.now().astimezone().strftime("%Y%m%d-%H%M%S")
        safe_interface = re.sub(r"[^A-Za-z0-9_.-]+", "_", self.interface)
        destination = directory / f"capture-{safe_interface}-{stamp}.pcap"
        counter = 2
        while destination.exists():
            destination = directory / f"capture-{safe_interface}-{stamp}-{counter}.pcap"
            counter += 1
        size = self.spool.stat().st_size
        try:
            with self.spool.open("rb") as source, destination.open("xb") as target:
                remaining = size
                while remaining:
                    block = source.read(min(1024 * 1024, remaining))
                    if not block:
                        break
                    target.write(block)
                    remaining -= len(block)
                target.flush()
                os.fsync(target.fileno())
            trim_incomplete_pcap_record(destination)
        except (OSError, AppError) as exc:
            try:
                destination.unlink()
            except OSError:
                pass
            raise AppError(f"Could not save capture: {exc}") from exc
        return destination

    def stop(self) -> None:
        process = self.process
        if process is None or process.poll() is not None:
            return
        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGINT)
            else:  # pragma: no cover - curses/tcpdump is normally Unix
                process.send_signal(signal.SIGINT)
            process.wait(timeout=3)
        except (OSError, subprocess.TimeoutExpired):
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)

    def close(self) -> None:
        self.stop()
        for thread in self._threads:
            thread.join(timeout=0.2)
        self._temporary.cleanup()


def trim_incomplete_pcap_record(path: Path) -> None:
    """Trim a concurrently copied classic-PCAP file to its last whole record."""
    magic_to_endian = {
        b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">",
        b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">",
    }
    with path.open("r+b") as handle:
        header = handle.read(24)
        endian = magic_to_endian.get(header[:4])
        if len(header) != 24 or endian is None:
            raise AppError("tcpdump produced an unrecognized capture format")
        last_complete = 24
        while True:
            record = handle.read(16)
            if not record:
                break
            if len(record) != 16:
                handle.truncate(last_complete)
                break
            captured_length = struct.unpack(f"{endian}I", record[8:12])[0]
            if captured_length > 256 * 1024 * 1024:
                handle.truncate(last_complete)
                break
            payload = handle.read(captured_length)
            if len(payload) != captured_length:
                handle.truncate(last_complete)
                break
            last_complete = handle.tell()


class Colors:
    HEADER = 1
    BORDER = 2
    GOOD = 3
    BAD = 4
    WARN = 5
    SOURCE = 6
    DESTINATION = 7
    TCP = 8
    UDP = 9
    ICMP = 10
    MUTED = 11
    SELECTED = 12
    PORT = 13


class TcpdumpTUI:
    def __init__(
        self, screen: "curses.window", config: Config, config_path: Path,
        tcpdump: str, initial_interface: str = "", initial_filter: str | None = None,
    ):
        self.screen = screen
        self.config = config
        self.config_path = config_path
        self.tcpdump = tcpdump
        self.interfaces: list[InterfaceInfo] = []
        self.discovery_warning = ""
        self.interface = initial_interface or config.default_interface
        self.filter_expression = config.last_filter if initial_filter is None else initial_filter
        self.notice = ""
        self.notice_until = 0.0
        self._init_screen()

    def _init_screen(self) -> None:
        curses.curs_set(0)
        self.screen.keypad(True)
        self.screen.timeout(-1)
        if curses.has_colors():
            curses.start_color()
            try:
                curses.use_default_colors()
                background = -1
            except curses.error:
                background = curses.COLOR_BLACK
            pairs = {
                Colors.HEADER: (curses.COLOR_BLACK, curses.COLOR_CYAN),
                Colors.BORDER: (curses.COLOR_CYAN, background),
                Colors.GOOD: (curses.COLOR_GREEN, background),
                Colors.BAD: (curses.COLOR_RED, background),
                Colors.WARN: (curses.COLOR_YELLOW, background),
                Colors.SOURCE: (curses.COLOR_CYAN, background),
                Colors.DESTINATION: (curses.COLOR_MAGENTA, background),
                Colors.TCP: (curses.COLOR_GREEN, background),
                Colors.UDP: (curses.COLOR_BLUE, background),
                Colors.ICMP: (curses.COLOR_YELLOW, background),
                Colors.MUTED: (curses.COLOR_WHITE, background),
                Colors.SELECTED: (curses.COLOR_BLACK, curses.COLOR_WHITE),
                Colors.PORT: (curses.COLOR_YELLOW, background),
            }
            for number, (foreground, bg) in pairs.items():
                try:
                    curses.init_pair(number, foreground, bg)
                except curses.error:
                    pass

    def color(self, number: int) -> int:
        return curses.color_pair(number) if curses.has_colors() else 0

    def add(self, row: int, column: int, text: object, attr: int = 0, limit: int | None = None) -> None:
        height, width = self.screen.getmaxyx()
        if row < 0 or row >= height or column < 0 or column >= width:
            return
        available = max(0, width - column - 1)
        if limit is not None:
            available = min(available, max(0, limit))
        value = str(text).replace("\t", "    ")
        if len(value) > available:
            value = value[: max(0, available - 1)] + ("…" if available else "")
        try:
            self.screen.addstr(row, column, value, attr)
        except curses.error:
            pass

    def title(self, section: str) -> None:
        _, width = self.screen.getmaxyx()
        text = f" {APP_NAME.upper()} {VERSION}  │  {section} "
        self.add(0, 0, text.ljust(max(1, width - 1)), self.color(Colors.HEADER) | curses.A_BOLD)

    def footer(self, text: str) -> None:
        height, width = self.screen.getmaxyx()
        self.add(height - 1, 0, text.ljust(max(1, width - 1)), curses.A_REVERSE)

    def panel(self, top: int, left: int, bottom: int, right: int, title: str) -> None:
        if bottom <= top or right <= left:
            return
        border = self.color(Colors.BORDER)
        self.add(top, left, "┌" + "─" * max(0, right - left - 1) + "┐", border)
        for row in range(top + 1, bottom):
            self.add(row, left, "│", border)
            self.add(row, right, "│", border)
        self.add(bottom, left, "└" + "─" * max(0, right - left - 1) + "┘", border)
        self.add(top, left + 2, f" {title} ", border | curses.A_BOLD)

    def ensure_size(self) -> bool:
        height, width = self.screen.getmaxyx()
        if height >= MIN_HEIGHT and width >= MIN_WIDTH:
            return True
        self.screen.erase()
        self.title("Terminal too small")
        self.add(4, 2, f"Resize to at least {MIN_WIDTH} columns × {MIN_HEIGHT} rows.", self.color(Colors.WARN))
        self.add(6, 2, f"Current size: {width} × {height}")
        self.footer("q quit  │  resize the terminal to continue")
        self.screen.refresh()
        return False

    def show_notice(self, message: str, seconds: float = 4.0) -> None:
        self.notice = message
        self.notice_until = time.monotonic() + seconds

    def persist(self) -> None:
        self.config.default_interface = self.interface
        self.config.last_filter = self.filter_expression
        try:
            save_config(self.config_path, self.config)
        except AppError as exc:
            self.show_notice(str(exc), 7)

    def refresh_interfaces(self) -> None:
        self.interfaces, self.discovery_warning = discover_interfaces(self.tcpdump)
        names = {item.name for item in self.interfaces}
        if self.interface and self.interface not in names:
            self.interface = ""

    def menu(
        self, title: str, choices: Sequence[str], subtitle: str = "",
        initial: int = 0, footer: str = "↑/↓ move  │  Enter select  │  q/Esc back",
    ) -> int | None:
        if not choices:
            self.message(title, "There are no choices available.")
            return None
        selected = max(0, min(initial, len(choices) - 1))
        while True:
            self.screen.erase()
            if not self.ensure_size():
                key = self.screen.getch()
                if key in (ord("q"), 27):
                    return None
                continue
            self.title(title)
            if subtitle:
                self.add(2, 2, subtitle, self.color(Colors.MUTED) | curses.A_DIM)
            height, width = self.screen.getmaxyx()
            top = 4
            visible = max(1, height - top - 2)
            start = min(max(0, selected - visible + 1), max(0, len(choices) - visible))
            for row, index in enumerate(range(start, min(len(choices), start + visible)), top):
                attr = self.color(Colors.SELECTED) if index == selected else 0
                self.add(row, 2, f" {choices[index]} ", attr, width - 5)
            self.footer(footer)
            self.screen.refresh()
            key = self.screen.getch()
            if key in (ord("q"), 27):
                return None
            if key in (curses.KEY_UP, ord("k")):
                selected = (selected - 1) % len(choices)
            elif key in (curses.KEY_DOWN, ord("j")):
                selected = (selected + 1) % len(choices)
            elif key == curses.KEY_PPAGE:
                selected = max(0, selected - visible)
            elif key == curses.KEY_NPAGE:
                selected = min(len(choices) - 1, selected + visible)
            elif key in (curses.KEY_ENTER, 10, 13):
                return selected

    def input_text(self, title: str, prompt: str, initial: str = "") -> str | None:
        self.screen.erase()
        self.title(title)
        self.add(3, 2, prompt)
        if initial:
            self.add(5, 2, f"Current: {initial}", curses.A_DIM)
        self.add(7, 2, "> ", self.color(Colors.BORDER) | curses.A_BOLD)
        self.screen.move(7, 4)
        self.footer("Enter accept  │  Ctrl-C cancel")
        curses.curs_set(1)
        curses.echo()
        try:
            raw = self.screen.getstr(7, 4, 4096)
            value = raw.decode("utf-8", "replace").strip()
            return value if value else initial
        except (KeyboardInterrupt, curses.error):
            return None
        finally:
            curses.noecho()
            curses.curs_set(0)

    def message(self, title: str, message: str) -> None:
        self.screen.erase()
        self.title(title)
        width = max(20, self.screen.getmaxyx()[1] - 6)
        row = 3
        for paragraph in message.splitlines() or [""]:
            for line in textwrap.wrap(paragraph, width=width) or [""]:
                self.add(row, 2, line)
                row += 1
        self.footer("Press any key to continue")
        self.screen.refresh()
        self.screen.getch()

    def select_interface(self) -> None:
        self.refresh_interfaces()
        if not self.interfaces:
            self.message("Interfaces", self.discovery_warning or "No capture interfaces were found.")
            return
        selected = next((i for i, item in enumerate(self.interfaces) if item.name == self.interface), 0)
        while True:
            self.screen.erase()
            if not self.ensure_size():
                key = self.screen.getch()
                if key in (ord("q"), 27):
                    return
                continue
            self.title("1 · Select capture interface")
            subtitle = self.discovery_warning or "Green=available  Red=down  Yellow=unknown"
            self.add(2, 2, subtitle, curses.A_DIM)
            height, width = self.screen.getmaxyx()
            top = 4
            visible = max(1, height - top - 2)
            start = min(max(0, selected - visible + 1), max(0, len(self.interfaces) - visible))
            for row, index in enumerate(range(start, min(len(self.interfaces), start + visible)), top):
                item = self.interfaces[index]
                marker = "●" if item.state == "up" else "○" if item.state == "down" else "?"
                address = ", ".join(item.addresses[:2]) or "no address"
                description = f" — {item.description}" if item.description else ""
                label = f" {marker} {item.name:<18} {item.state.upper():<7} {address}{description} "
                if index == selected:
                    attr = self.color(Colors.SELECTED)
                elif item.state == "up":
                    attr = self.color(Colors.GOOD)
                elif item.state == "down":
                    attr = self.color(Colors.BAD)
                else:
                    attr = self.color(Colors.WARN)
                self.add(row, 2, label, attr, width - 5)
            self.footer("↑/↓ move  │  Enter choose  │  r refresh  │  q/Esc back")
            self.screen.refresh()
            key = self.screen.getch()
            if key in (ord("q"), 27):
                return
            if key in (curses.KEY_UP, ord("k")):
                selected = (selected - 1) % len(self.interfaces)
            elif key in (curses.KEY_DOWN, ord("j")):
                selected = (selected + 1) % len(self.interfaces)
            elif key == curses.KEY_PPAGE:
                selected = max(0, selected - visible)
            elif key == curses.KEY_NPAGE:
                selected = min(len(self.interfaces) - 1, selected + visible)
            elif key == ord("r"):
                previous = self.interfaces[selected].name
                self.refresh_interfaces()
                if not self.interfaces:
                    self.message("Interfaces", self.discovery_warning or "No capture interfaces were found.")
                    return
                selected = next(
                    (index for index, item in enumerate(self.interfaces) if item.name == previous), 0
                )
            elif key in (curses.KEY_ENTER, 10, 13):
                self.interface = self.interfaces[selected].name
                self.persist()
                return

    def choose_direction(self, title: str) -> str | None:
        choice = self.menu(title, ["Either source or destination", "Source only", "Destination only"])
        return None if choice is None else ("", "src ", "dst ")[choice]

    def choose_transport(self) -> str | None:
        choice = self.menu("Transport protocol", ["TCP or UDP", "TCP only", "UDP only", "SCTP only"])
        return None if choice is None else ("", "tcp ", "udp ", "sctp ")[choice]

    def add_host_clause(self, plan: FilterPlan, exclude: bool = False) -> None:
        direction = self.choose_direction("Host direction")
        if direction is None:
            return
        value = self.input_text("Host filter", "IP address or hostname:")
        if value is None:
            return
        try:
            host = validate_host(value)
        except AppError as exc:
            self.message("Invalid host", str(exc))
            return
        expression = f"{direction}host {host}"
        if exclude:
            expression = f"not ({expression})"
        plan.add(("Exclude " if exclude else "Host ") + host, expression)

    def add_network_clause(self, plan: FilterPlan, exclude: bool = False) -> None:
        direction = self.choose_direction("Network direction")
        if direction is None:
            return
        value = self.input_text("Network filter", "Network in CIDR form (example: 10.20.0.0/16):")
        if value is None:
            return
        try:
            network = validate_network(value)
        except AppError as exc:
            self.message("Invalid network", str(exc))
            return
        expression = f"{direction}net {network}"
        if exclude:
            expression = f"not ({expression})"
        plan.add(("Exclude " if exclude else "Network ") + network, expression)

    def add_mac_clause(self, plan: FilterPlan) -> None:
        direction = self.choose_direction("Ethernet address direction")
        if direction is None:
            return
        value = self.input_text("Ethernet filter", "MAC address (example: 00:11:22:aa:bb:cc):")
        if value is None:
            return
        try:
            address = validate_mac(value)
        except AppError as exc:
            self.message("Invalid MAC address", str(exc))
            return
        plan.add(f"Ethernet host {address}", f"ether {direction}host {address}")

    def add_port_clause(self, plan: FilterPlan, port_range: bool = False, exclude: bool = False) -> None:
        transport = self.choose_transport()
        if transport is None:
            return
        direction = self.choose_direction("Port direction")
        if direction is None:
            return
        prompt = "Port range (example: 8000-8100):" if port_range else "Port number (1-65535):"
        value = self.input_text("Port filter", prompt)
        if value is None:
            return
        try:
            if port_range:
                parts = value.split("-", 1)
                if len(parts) != 2:
                    raise AppError("Use start-end form, such as 8000-8100")
                start, end = validate_port(parts[0]), validate_port(parts[1])
                if start > end:
                    raise AppError("The first port must not be greater than the second")
                primitive = f"portrange {start}-{end}"
                label_value = f"{start}-{end}"
            else:
                port = validate_port(value)
                primitive = f"port {port}"
                label_value = str(port)
        except AppError as exc:
            self.message("Invalid port", str(exc))
            return
        expression = f"{transport}{direction}{primitive}"
        if exclude:
            expression = f"not ({expression})"
        plan.add(("Exclude " if exclude else "Port ") + label_value, expression)

    def add_protocol_clause(self, plan: FilterPlan) -> None:
        options = [
            ("TCP", "tcp"), ("UDP", "udp"), ("ICMP (IPv4)", "icmp"),
            ("ICMPv6", "icmp6"), ("ARP", "arp"), ("IPv4", "ip"),
            ("IPv6", "ip6"), ("SCTP", "sctp"), ("ESP", "esp"),
        ]
        choice = self.menu("Protocol", [label for label, _ in options])
        if choice is not None:
            label, expression = options[choice]
            plan.add(label, expression)

    def add_preset(self, plan: FilterPlan) -> None:
        presets = [
            ("Web · HTTP and HTTPS", "tcp port 80 or tcp port 443"),
            ("DNS · TCP and UDP 53", "port 53"),
            ("SSH · TCP 22", "tcp port 22"),
            ("DHCPv4 · UDP 67 and 68", "udp port 67 or udp port 68"),
            ("NTP · UDP 123", "udp port 123"),
            ("SMB · TCP 445", "tcp port 445"),
            ("Email · SMTP/IMAP/POP common ports", "tcp port 25 or tcp port 110 or tcp port 143 or tcp port 465 or tcp port 587 or tcp port 993 or tcp port 995"),
            ("Ping · ICMP and ICMPv6", "icmp or icmp6"),
            ("ARP only", "arp"),
            ("New TCP connections · SYN without ACK", "tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn"),
            ("TCP resets · RST flag", "tcp[tcpflags] & tcp-rst != 0"),
        ]
        choice = self.menu("Common capture presets", [label for label, _ in presets])
        if choice is not None:
            label, expression = presets[choice]
            plan.add(label, expression)

    def add_size_clause(self, plan: FilterPlan) -> None:
        choice = self.menu("Packet size", ["At least this many bytes", "At most this many bytes"])
        if choice is None:
            return
        value = self.input_text("Packet size", "Byte count:")
        if value is None:
            return
        try:
            length = int(value)
            if not 1 <= length <= 16777216:
                raise ValueError
        except ValueError:
            self.message("Invalid size", "Enter a byte count between 1 and 16777216.")
            return
        keyword = "greater" if choice == 0 else "less"
        plan.add(f"{keyword.title()} {length} bytes", f"{keyword} {length}")

    def add_special_clause(self, plan: FilterPlan) -> None:
        options = [
            ("Ethernet broadcast", "ether broadcast"),
            ("Ethernet multicast", "ether multicast"),
            ("IPv4 multicast", "ip multicast"),
            ("IPv6 multicast", "ip6 multicast"),
        ]
        choice = self.menu("Broadcast / multicast", [label for label, _ in options])
        if choice is not None:
            label, expression = options[choice]
            plan.add(label, expression)

    def add_custom_clause(self, plan: FilterPlan) -> None:
        value = self.input_text(
            "Advanced BPF clause", "libpcap filter expression (example: tcp[tcpflags] & tcp-syn != 0):"
        )
        if value is None or not value.strip():
            return
        valid, detail = validate_bpf(self.tcpdump, value.strip())
        if not valid:
            self.message("Filter rejected", detail)
            return
        plan.add("Custom clause", value.strip())

    def filter_builder(self) -> None:
        plan = FilterPlan(self.filter_expression)
        while True:
            expression = plan.expression
            choices = [
                "✓ Apply this filter",
                "Common preset (web, DNS, SSH, DHCP, NTP…)",
                "Protocol",
                "Host / IP address",
                "Network / subnet",
                "Ethernet MAC address",
                "Port",
                "Port range",
                "Exclude a host",
                "Exclude a network",
                "Exclude a port",
                "Packet size",
                "Broadcast / multicast",
                "Advanced custom BPF clause",
                f"Combine clauses with: {plan.operator.upper()} (toggle)",
                "Remove a clause",
                "Clear all · capture every packet",
            ]
            subtitle = f"Preview: {expression or 'all traffic'}"
            choice = self.menu("2 · Guided capture filter", choices, subtitle)
            if choice is None:
                return
            if choice == 0:
                valid, detail = validate_bpf(self.tcpdump, expression)
                if not valid:
                    self.message("Filter rejected", detail)
                    continue
                self.filter_expression = expression
                self.persist()
                self.show_notice(detail)
                return
            if choice == 1:
                self.add_preset(plan)
            elif choice == 2:
                self.add_protocol_clause(plan)
            elif choice == 3:
                self.add_host_clause(plan)
            elif choice == 4:
                self.add_network_clause(plan)
            elif choice == 5:
                self.add_mac_clause(plan)
            elif choice == 6:
                self.add_port_clause(plan)
            elif choice == 7:
                self.add_port_clause(plan, port_range=True)
            elif choice == 8:
                self.add_host_clause(plan, exclude=True)
            elif choice == 9:
                self.add_network_clause(plan, exclude=True)
            elif choice == 10:
                self.add_port_clause(plan, exclude=True)
            elif choice == 11:
                self.add_size_clause(plan)
            elif choice == 12:
                self.add_special_clause(plan)
            elif choice == 13:
                self.add_custom_clause(plan)
            elif choice == 14:
                plan.operator = "or" if plan.operator == "and" else "and"
            elif choice == 15:
                if not plan.clauses:
                    self.message("Remove clause", "The filter has no clauses.")
                else:
                    remove = self.menu("Remove clause", [item.label for item in plan.clauses])
                    if remove is not None:
                        plan.clauses.pop(remove)
            elif choice == 16:
                plan.clauses.clear()

    def settings(self) -> None:
        draft = dataclasses.replace(self.config)
        while True:
            choices = [
                f"Capture directory        {draft.capture_dir}",
                f"Snapshot length          {draft.snaplen} bytes",
                f"Kernel buffer            {draft.buffer_kib} KiB",
                f"Promiscuous mode         {'on' if draft.promiscuous else 'off'}",
                f"Immediate mode           {'on' if draft.immediate_mode else 'off'}",
                f"Packet history rows      {draft.max_rows}",
                f"Screen refresh           {draft.refresh_ms} ms",
                "Save and return",
            ]
            choice = self.menu("Settings", choices, f"Config: {self.config_path}")
            if choice is None:
                return
            try:
                if choice == 0:
                    value = self.input_text("Capture directory", "Directory for saved snapshots:", str(draft.capture_dir))
                    if value is not None:
                        draft.capture_dir = Path(value).expanduser()
                elif choice == 1:
                    value = self.input_text("Snapshot length", "Bytes per packet (64-262144):", str(draft.snaplen))
                    if value is not None:
                        draft.snaplen = int(value)
                elif choice == 2:
                    value = self.input_text("Kernel buffer", "Capture buffer in KiB (128-1048576):", str(draft.buffer_kib))
                    if value is not None:
                        draft.buffer_kib = int(value)
                elif choice == 3:
                    draft.promiscuous = not draft.promiscuous
                elif choice == 4:
                    draft.immediate_mode = not draft.immediate_mode
                elif choice == 5:
                    value = self.input_text("Packet history", "Rows kept in memory (100-100000):", str(draft.max_rows))
                    if value is not None:
                        draft.max_rows = int(value)
                elif choice == 6:
                    value = self.input_text("Refresh interval", "Milliseconds (25-1000):", str(draft.refresh_ms))
                    if value is not None:
                        draft.refresh_ms = int(value)
                elif choice == 7:
                    draft.validate()
                    self.config = draft
                    self.persist()
                    return
                draft.validate()
            except (ValueError, AppError) as exc:
                self.message("Invalid setting", str(exc))

    def help(self) -> None:
        self.message(
            "Help",
            "Choose an available interface, build a capture filter, then start the live view. "
            "The filter controls which packets are captured, so excluded packets cannot be recovered later.\n\n"
            "During capture: s saves a timestamped PCAP snapshot without stopping; Space pauses or resumes "
            "automatic scrolling; ↑/↓ and PgUp/PgDn browse history while paused; x stops capture; q returns "
            "to the dashboard and stops capture. The live table is a concise tcpdump summary. Saved PCAPs "
            "retain the raw packet bytes allowed by the configured snapshot length.\n\n"
            "Packet capture normally needs root or OS-granted capture capabilities. If tcpdump reports a "
            "permission error, configure capture permissions using your operating system's recommended method."
        )

    def draw_dashboard(self) -> None:
        self.screen.erase()
        self.title("Capture setup")
        height, width = self.screen.getmaxyx()
        middle = max(40, int(width * 0.57))
        self.panel(2, 1, height - 3, middle, "FLOW")
        self.panel(2, middle + 1, height - 3, width - 2, "CURRENT SETUP")
        selected = next((item for item in self.interfaces if item.name == self.interface), None)
        steps = [
            ("1", "Interface", self.interface or "choose an interface", bool(self.interface)),
            ("2", "Capture filter", self.filter_expression or "all traffic", True),
            ("3", "Live capture", "ready" if self.interface else "waiting for interface", bool(self.interface)),
        ]
        row = 5
        for number, label, value, ready in steps:
            attr = self.color(Colors.GOOD if ready else Colors.WARN)
            self.add(row, 4, "●" if ready else "○", attr | curses.A_BOLD)
            self.add(row, 7, f"{number}. {label}", curses.A_BOLD)
            self.add(row + 1, 10, value, curses.A_DIM, middle - 13)
            row += 4
        right = middle + 4
        self.add(5, right, "INTERFACE", curses.A_DIM)
        state = selected.state.upper() if selected else "NOT SELECTED"
        state_attr = self.color(Colors.GOOD if selected and selected.usable else Colors.BAD)
        self.add(6, right, f"{self.interface or '—'}  {state}", state_attr | curses.A_BOLD)
        self.add(9, right, "FILTER", curses.A_DIM)
        filter_lines = textwrap.wrap(self.filter_expression or "all traffic", max(20, width - right - 4))[:4]
        for offset, line in enumerate(filter_lines):
            self.add(10 + offset, right, line, self.color(Colors.WARN) if self.filter_expression else 0)
        self.add(15, right, "SAVES TO", curses.A_DIM)
        self.add(16, right, self.config.capture_dir, self.color(Colors.SOURCE), width - right - 3)
        if self.discovery_warning:
            self.add(height - 5, 4, self.discovery_warning, self.color(Colors.WARN), middle - 7)
        if self.notice and time.monotonic() < self.notice_until:
            self.add(height - 2, 2, self.notice, self.color(Colors.GOOD), width - 4)
        self.footer("i interface  │  f filter  │  Enter/c start  │  s settings  │  h help  │  q quit")

    def _draw_packet_row(self, screen_row: int, packet: PacketRow, width: int) -> None:
        if width >= 126:
            columns = [(12, 0), (28, Colors.SOURCE), (6, Colors.PORT), (28, Colors.DESTINATION),
                       (6, Colors.PORT), (8, 0), (7, 0)]
        elif width >= 98:
            columns = [(12, 0), (21, Colors.SOURCE), (6, Colors.PORT), (21, Colors.DESTINATION),
                       (6, Colors.PORT), (7, 0), (6, 0)]
        else:
            columns = [(9, 0), (17, Colors.SOURCE), (5, Colors.PORT), (17, Colors.DESTINATION),
                       (5, Colors.PORT), (6, 0), (5, 0)]
        values = [
            dt.datetime.fromtimestamp(packet.timestamp).strftime("%H:%M:%S.%f")[:-3],
            packet.source or "—", packet.source_port or "—", packet.destination or "—",
            packet.destination_port or "—", packet.protocol, str(packet.length or "—"),
        ]
        protocol_color = {
            "TCP": Colors.TCP, "UDP": Colors.UDP, "ICMP": Colors.ICMP,
            "ICMP6": Colors.ICMP, "ARP": Colors.WARN,
        }.get(packet.protocol, Colors.MUTED)
        x = 1
        for index, ((column_width, pair), value) in enumerate(zip(columns, values)):
            if index == 5:
                pair = protocol_color
            self.add(screen_row, x, value, self.color(pair), column_width - 1)
            x += column_width
        self.add(screen_row, x, packet.info, curses.A_DIM, width - x - 1)

    def _draw_live(
        self, session: CaptureSession, rows: collections.deque[PacketRow], packet_count: int,
        byte_count: int, protocols: collections.Counter[str], paused: bool, scroll: int,
        status: str, recent: collections.deque[tuple[float, int]], stderr_tail: str,
    ) -> None:
        self.screen.erase()
        self.title("LIVE CAPTURE")
        height, width = self.screen.getmaxyx()
        elapsed = max(0.001, time.monotonic() - session.started)
        now = time.monotonic()
        while recent and recent[0][0] < now - 1.0:
            recent.popleft()
        pps = len(recent)
        bps = sum(item[1] for item in recent) * 8
        state = "RUNNING" if session.running else "STOPPED"
        state_attr = self.color(Colors.GOOD if session.running else Colors.BAD)
        self.add(2, 1, f"● {state}", state_attr | curses.A_BOLD)
        self.add(2, 14, f"iface {session.interface}", self.color(Colors.SOURCE))
        self.add(2, 34, f"packets {packet_count:,}")
        self.add(2, 53, f"rate {pps:,} pps / {bps / 1_000_000:.2f} Mb/s")
        self.add(2, 86, f"elapsed {elapsed:,.1f}s")
        top_protocols = "  ".join(f"{name}:{count:,}" for name, count in protocols.most_common(4))
        self.add(3, 1, f"filter: {session.expression or 'all traffic'}", curses.A_DIM, max(10, width - 35))
        self.add(3, max(1, width - len(top_protocols) - 2), top_protocols, curses.A_DIM)
        header = "TIME         SOURCE                      SPT   DESTINATION                 DPT   PROTO   LEN    DETAILS"
        if width < 126:
            header = "TIME         SOURCE               SPT   DESTINATION          DPT   PROTO  LEN   DETAILS"
        if width < 98:
            header = "TIME      SOURCE           SPT  DESTINATION      DPT  PROTO LEN  DETAILS"
        self.add(5, 1, header, curses.A_BOLD | self.color(Colors.BORDER), width - 2)
        visible = max(1, height - 8)
        history = list(rows)
        end = max(0, len(history) - scroll)
        start = max(0, end - visible)
        for screen_row, packet in enumerate(history[start:end], 6):
            self._draw_packet_row(screen_row, packet, width)
        if not history:
            self.add(8, 3, "Waiting for matching packets…", curses.A_DIM)
        if status:
            self.add(height - 2, 1, status, self.color(Colors.GOOD), width - 2)
        elif stderr_tail and not session.running:
            self.add(height - 2, 1, stderr_tail, self.color(Colors.BAD), width - 2)
        elif paused:
            self.add(height - 2, 1, f"PAUSED VIEW · {scroll} newer rows below", self.color(Colors.WARN), width - 2)
        elif session.reader_drops:
            self.add(height - 2, 1, f"UI skipped {session.reader_drops:,} summaries; raw PCAP capture continues", self.color(Colors.WARN), width - 2)
        self.footer("s save PCAP  │  Space pause/scroll  │  ↑/↓ PgUp/PgDn history  │  x stop  │  q back")
        self.screen.refresh()

    def live_capture(self) -> None:
        if not self.interface:
            self.message("Capture", "Choose an interface first.")
            return
        privileged, privilege_detail = capture_privilege_status(
            self.tcpdump, self.config.promiscuous
        )
        if not privileged:
            self.message(
                "Capture privileges required",
                str(privilege_error(self.tcpdump, privilege_detail)),
            )
            return
        valid, detail = validate_bpf(self.tcpdump, self.filter_expression)
        if not valid:
            self.message("Invalid capture filter", detail)
            return
        session = CaptureSession(self.tcpdump, self.interface, self.filter_expression, self.config)
        try:
            session.start()
        except AppError as exc:
            self.message("Capture failed", str(exc))
            return
        rows: collections.deque[PacketRow] = collections.deque(maxlen=self.config.max_rows)
        recent: collections.deque[tuple[float, int]] = collections.deque()
        protocols: collections.Counter[str] = collections.Counter()
        packet_count = 0
        byte_count = 0
        paused = False
        scroll = 0
        status = ""
        status_until = 0.0
        stderr_lines: collections.deque[str] = collections.deque(maxlen=8)
        self.screen.timeout(self.config.refresh_ms)
        try:
            while True:
                # Bound work per redraw so a very busy interface cannot starve
                # keyboard handling. The reader queue is also bounded; tcpdump's
                # raw PCAP writer remains independent of display drops.
                for _ in range(5000):
                    try:
                        line = session.lines.get_nowait()
                    except queue.Empty:
                        break
                    packet = parse_packet_line(line)
                    if packet:
                        rows.append(packet)
                        packet_count += 1
                        byte_count += packet.length
                        protocols[packet.protocol] += 1
                        recent.append((time.monotonic(), packet.length))
                        if not paused:
                            scroll = 0
                while True:
                    try:
                        error_line = session.errors.get_nowait()
                    except queue.Empty:
                        break
                    if error_line:
                        stderr_lines.append(error_line)
                if time.monotonic() > status_until:
                    status = ""
                self._draw_live(
                    session, rows, packet_count, byte_count, protocols, paused, scroll,
                    status, recent, stderr_lines[-1] if stderr_lines else "",
                )
                key = self.screen.getch()
                if key == curses.KEY_RESIZE:
                    continue
                if key in (ord("q"), 27):
                    break
                if key == ord("x"):
                    session.stop()
                    status = "Capture stopped. Press s to save the final PCAP or q to return."
                    status_until = float("inf")
                elif key == ord("s"):
                    try:
                        saved = session.save_snapshot(self.config.capture_dir)
                        status = f"Saved {saved} ({saved.stat().st_size:,} bytes); capture is {'still running' if session.running else 'stopped'}"
                        status_until = time.monotonic() + 6
                    except AppError as exc:
                        status = str(exc)
                        status_until = time.monotonic() + 6
                elif key == ord(" "):
                    paused = not paused
                    if not paused:
                        scroll = 0
                elif key in (curses.KEY_UP, ord("k")):
                    paused = True
                    scroll = min(max(0, len(rows) - 1), scroll + 1)
                elif key in (curses.KEY_DOWN, ord("j")):
                    scroll = max(0, scroll - 1)
                    if scroll == 0:
                        paused = False
                elif key == curses.KEY_PPAGE:
                    paused = True
                    scroll = min(max(0, len(rows) - 1), scroll + max(1, self.screen.getmaxyx()[0] - 8))
                elif key == curses.KEY_NPAGE:
                    scroll = max(0, scroll - max(1, self.screen.getmaxyx()[0] - 8))
                    if scroll == 0:
                        paused = False
        finally:
            session.close()
            self.screen.timeout(-1)

    def run(self) -> int:
        self.refresh_interfaces()
        while True:
            if not self.ensure_size():
                key = self.screen.getch()
                if key in (ord("q"), 27):
                    return 0
                continue
            self.draw_dashboard()
            self.screen.refresh()
            key = self.screen.getch()
            if key in (ord("q"), 27):
                return 0
            if key == ord("i"):
                self.select_interface()
            elif key == ord("f"):
                self.filter_builder()
            elif key in (ord("c"), curses.KEY_ENTER, 10, 13):
                self.live_capture()
            elif key == ord("s"):
                self.settings()
            elif key == ord("h"):
                self.help()
            elif key == ord("r"):
                self.refresh_interfaces()
                self.show_notice("Interface list refreshed")


def format_interface_list(interfaces: Iterable[InterfaceInfo]) -> str:
    lines = ["STATE    INTERFACE           ADDRESSES / DESCRIPTION"]
    for item in interfaces:
        details = ", ".join(item.addresses) or item.description or "—"
        lines.append(f"{item.state.upper():<8} {item.name:<19} {details}")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG, help=f"TOML config path (default: {DEFAULT_CONFIG})")
    parser.add_argument("--interface", help="preselect a capture interface")
    parser.add_argument("--filter", dest="capture_filter", help="preload a libpcap capture filter")
    parser.add_argument("--list-interfaces", action="store_true", help="print capture interfaces and exit")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    tcpdump = shutil.which("tcpdump")
    if not tcpdump:
        print("Error: tcpdump is not installed or is not in PATH", file=sys.stderr)
        return 1
    try:
        config_path = args.config.expanduser()
        config = load_config(config_path)
        if not config_path.exists():
            save_config(config_path, config)
        if args.list_interfaces:
            interfaces, warning = discover_interfaces(tcpdump)
            print(format_interface_list(interfaces))
            if warning:
                print(f"Warning: {warning}", file=sys.stderr)
            return 0 if interfaces else 1
        privileged, privilege_detail = capture_privilege_status(
            tcpdump, config.promiscuous
        )
        if not privileged:
            raise privilege_error(tcpdump, privilege_detail)
        if not sys.stdin.isatty() or not sys.stdout.isatty():
            raise AppError("The TUI needs an interactive terminal; use --list-interfaces for text output")
        if curses is None:
            raise AppError("Python curses support is required")
        return curses.wrapper(
            lambda screen: TcpdumpTUI(
                screen, config, config_path, tcpdump,
                args.interface or "", args.capture_filter,
            ).run()
        )
    except AppError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
