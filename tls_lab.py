#!/usr/bin/env python3
"""Terminal TLS capture, session-secret correlation, and readable payloads.

Requires tcpdump and tshark on Linux. Run as a normal user; sudo is used only
for tcpdump. TLS key logs are read from a path explicitly selected by the user.

Examples:
  python3 lan_tls_lab.py
  python3 lan_tls_lab.py --pcap capture.pcap --keylog session.keys
  python3 lan_tls_lab.py --pcap-dir ./captures --keylog session.keys
  python3 lan_tls_lab.py --pcap legacy.pcap --rsa-key server.key
  python3 lan_tls_lab.py --interface eth0 --host 192.0.2.10 --port 443 \
    --seconds 60 --keylog session.keys
"""

import argparse
import curses
from contextlib import redirect_stdout
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import subprocess
import sys
import textwrap
from datetime import datetime


VERSION = "2.0"
CAPTURE_SUFFIXES = (".pcap", ".pcapng", ".cap", ".pcap.gz", ".pcapng.gz", ".cap.gz")
FIELDS = ["frame.number", "tcp.stream", "ip.src", "ipv6.src", "tcp.srcport",
          "ip.dst", "ipv6.dst", "tcp.dstport", "tls.handshake.random",
          "tls.handshake.extensions_server_name", "tls.handshake.version",
          "tls.handshake.extensions.supported_version", "tls.handshake.ciphersuite"]
NAMES = {
    0x1301: "TLS_AES_128_GCM_SHA256", 0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256", 0x1304: "TLS_AES_128_CCM_SHA256",
    0x1305: "TLS_AES_128_CCM_8_SHA256",
    0xC02F: "ECDHE_RSA_AES_128_GCM", 0xC030: "ECDHE_RSA_AES_256_GCM",
    0xC02B: "ECDHE_ECDSA_AES_128_GCM", 0xC02C: "ECDHE_ECDSA_AES_256_GCM",
    0xCCA8: "ECDHE_RSA_CHACHA20", 0xCCA9: "ECDHE_ECDSA_CHACHA20",
    0x009C: "RSA_AES_128_GCM", 0x009D: "RSA_AES_256_GCM",
    0x002F: "RSA_AES_128_CBC", 0x0035: "RSA_AES_256_CBC",
}
RSA_KX = {0x0004, 0x0005, 0x000A, 0x002F, 0x0035, 0x003C, 0x003D,
          0x009C, 0x009D, 0x0096, 0x0097}
ECDHE_KX = {0xC009, 0xC00A, 0xC013, 0xC014, 0xC023, 0xC024, 0xC027,
            0xC028, 0xC02B, 0xC02C, 0xC02F, 0xC030, 0xC02D, 0xC02E,
            0xC031, 0xC032, 0xCCA8, 0xCCA9}
DHE_KX = {0x0016, 0x0013, 0x0033, 0x0039, 0x0067, 0x006B, 0x009E, 0x009F,
          0xCCAA}
VERSIONS = {0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2",
            0x0304: "TLS 1.3"}
KEY_LINE = re.compile(r"^([A-Z][A-Z0-9_]*)\s+([0-9a-fA-F]{64})\s+([0-9a-fA-F]+)$")
HEX_DUMP_LINE = re.compile(r"^[0-9a-fA-F]{4,8}  (.*)$")


def say(message=""):
    print(message, flush=True)


def ask(prompt, default=None):
    suffix = f" [{default}]" if default is not None else ""
    answer = input(f"{prompt}{suffix}: ").strip()
    return answer if answer else default


def run(args, *, check=True):
    result = subprocess.run(args, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    if check and result.returncode:
        raise RuntimeError(f"{' '.join(args[:2])}: {result.stderr.strip() or 'failed'}")
    return result.stdout


def need_tools(capture=False):
    missing = [x for x in (("tshark", "tcpdump") if capture else ("tshark",))
               if not shutil.which(x)]
    if missing:
        raise RuntimeError("Missing " + ", ".join(missing) +
                           ". Install them with your system package manager.")


def interfaces():
    raw = run(["tcpdump", "-D"])
    found = []
    for line in raw.splitlines():
        match = re.match(r"^\d+\.([^\s]+)(?:\s+(.*))?$", line)
        if match:
            found.append((match[1], match[2] or ""))
    return found


def ip_overview():
    if shutil.which("ip"):
        say("\nLocal addresses:")
        say(run(["ip", "-br", "addr"], check=False).strip())


def choose_interface():
    items = interfaces()
    if not items:
        raise RuntimeError("tcpdump found no capture interfaces")
    say("\nCapture interfaces:")
    for number, (name, description) in enumerate(items, 1):
        say(f"  {number:2}. {name:18} {description}")
    ip_overview()
    while True:
        choice = ask("Interface number", "1")
        if choice.isdecimal() and 1 <= int(choice) <= len(items):
            return items[int(choice) - 1][0]
        say("Choose one of the listed numbers.")


def parse_port(value):
    if value in (None, ""):
        return None
    if not value.isdecimal() or not 1 <= int(value) <= 65535:
        raise ValueError("port must be between 1 and 65535")
    return int(value)


def parse_host(value):
    if value in (None, ""):
        return None
    return str(ipaddress.ip_address(value))


def capture_files(directory):
    """List direct child captures, newest first, without scanning elsewhere."""
    directory = directory.expanduser().resolve()
    if not directory.is_dir():
        raise NotADirectoryError(directory)
    try:
        files = [path for path in directory.iterdir()
                 if path.is_file() and path.name.lower().endswith(CAPTURE_SUFFIXES)]
        return sorted(files, key=lambda path: (path.stat().st_mtime, path.name), reverse=True)
    except OSError as error:
        raise RuntimeError(f"Cannot list captures in {directory}: {error}") from error


def human_size(size):
    amount = float(size)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if amount < 1024 or unit == "GiB":
            return f"{amount:.0f} {unit}" if unit == "B" else f"{amount:.1f} {unit}"
        amount /= 1024
    return f"{amount:.1f} GiB"


def choose_capture(start):
    """Accept a file or browse a directory by page and global index."""
    location = start.expanduser()
    while True:
        if location.is_file():
            return location.resolve()
        if not location.is_dir():
            say(f"Capture file or directory not found: {location}")
            entered = ask("Enter a capture file/directory path (q to cancel)")
            if not entered or entered.lower() == "q":
                return None
            location = Path(entered).expanduser()
            continue
        files = capture_files(location)
        if not files:
            say(f"No capture files directly in {location}")
            entered = ask("Another capture file/directory path (q to cancel)")
            if not entered or entered.lower() == "q":
                return None
            location = Path(entered).expanduser()
            continue
        page = 0
        while True:
            page_size = 15
            pages = (len(files) + page_size - 1) // page_size
            say(f"\nCaptures in {location.resolve()} — {len(files)} file(s), newest first (page {page + 1}/{pages}):")
            for index in range(page * page_size, min((page + 1) * page_size, len(files))):
                path = files[index]
                info = path.stat()
                when = datetime.fromtimestamp(info.st_mtime).strftime("%Y-%m-%d %H:%M")
                empty = "  (header only; no packets)" if path.suffix.lower() == ".pcap" and info.st_size == 24 else ""
                say(f"  {index + 1:3}. {when}  {human_size(info.st_size):>9}  {path.name}{empty}")
            answer = ask("Number, n/p page, d change path, q cancel")
            if answer and answer.isdecimal() and 1 <= int(answer) <= len(files):
                return files[int(answer) - 1].resolve()
            if answer == "n" and page + 1 < pages:
                page += 1
            elif answer == "p" and page > 0:
                page -= 1
            elif answer == "d":
                entered = ask("Capture file/directory path")
                if entered:
                    location = Path(entered).expanduser()
                    break
            elif answer == "q":
                return None
            else:
                say("Choose a listed number or menu option.")


def default_capture_dir():
    return Path.cwd()


def choose_existing_keys():
    say("\nDecryption source:")
    say("  1. Endpoint keylog")
    say("  2. Keylog plus legacy server RSA key (mixed captures)")
    say("  3. Legacy server RSA key only")
    say("  4. Classify handshakes only")
    mode = ask("Choose", "4")
    key = rsa = None
    if mode in ("1", "2"):
        key = ask("TLS keylog path")
        if not key:
            raise ValueError("keylog path is required for this choice")
    if mode in ("2", "3"):
        say("RSA needs the server's private key and a full legacy RSA handshake;")
        say("it does not decrypt TLS 1.3 sessions.")
        rsa = ask("Server RSA private key PEM path")
        if not rsa:
            raise ValueError("RSA key path is required for this choice")
    if mode not in ("1", "2", "3", "4"):
        raise ValueError("choose key source 1, 2, 3, or 4")
    return (Path(key).expanduser().resolve() if key else None,
            Path(rsa).expanduser().resolve() if rsa else None)


def prepare_keylog():
    suggested = Path.cwd() / "session.keys"
    key = Path(ask("New keylog path", str(suggested))).expanduser()
    key.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    say(f"\nExport the secrets to: {key}")
    say("  Browser/client: set SSLKEYLOGFILE to this path BEFORE starting it.")
    browser = next((x for x in ("firefox", "chromium", "google-chrome")
                    if shutil.which(x)), "firefox")
    say(f"  Example (close existing browser first): env SSLKEYLOGFILE={shlex.quote(str(key))} {browser}")
    say("  Python ssl: set context.keylog_filename before connecting.")
    say("  Start the client, then trigger a NEW connection while capturing.")
    return key


def choose_capture_keys():
    say("\nDecryption source for this capture:")
    say("  1. Existing endpoint keylog")
    say("  2. Prepare a new endpoint keylog path")
    say("  3. Legacy server RSA key only")
    say("  4. Classify handshakes only")
    say("  5. Existing keylog plus legacy server RSA key")
    say("  6. New keylog plus legacy server RSA key")
    mode = ask("Choose", "4")
    key = rsa = None
    if mode in ("1", "5"):
        answer = ask("Existing keylog path")
        if not answer:
            raise ValueError("keylog path is required for this choice")
        key = Path(answer).expanduser()
    elif mode in ("2", "6"):
        key = prepare_keylog()
    if mode in ("3", "5", "6"):
        say("RSA only helps with full legacy RSA key-transport handshakes;")
        say("it cannot decrypt TLS 1.3 traffic.")
        answer = ask("Server RSA private key PEM path")
        if not answer:
            raise ValueError("RSA key path is required for this choice")
        rsa = Path(answer).expanduser()
    if mode not in ("1", "2", "3", "4", "5", "6"):
        raise ValueError("choose a listed key source")
    return key, rsa


def capture(interface, host, port, seconds, path):
    need_tools(capture=True)
    if not 1 <= seconds <= 3600:
        raise ValueError("duration must be 1–3600 seconds")
    path = path.expanduser().resolve()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.exists():
        raise FileExistsError(f"refusing to overwrite {path}")
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(fd)
    bpf = []
    if host:
        bpf += ["host", host]
    if port:
        bpf += ["and"] if bpf else []
        bpf += ["tcp", "port", str(port)]
    elif not bpf:
        bpf = ["tcp"]
    else:
        bpf += ["and", "tcp"]
    prefix = [] if os.geteuid() == 0 else ["sudo"]
    cmd = prefix + ["tcpdump", "-Z", "root", "-i", interface,
                    "-s", "0", "-U", "-w", str(path)] + bpf
    say(f"\nCapture: {interface}, {seconds}s; filter: {' '.join(bpf)}")
    say(f"File: {path}")
    say("Start a NEW connection now. Ctrl+C ends the capture early.")
    try:
        process = subprocess.Popen(cmd)
        try:
            process.wait(timeout=seconds)
        except subprocess.TimeoutExpired:
            process.send_signal(signal.SIGINT)
            process.wait(timeout=10)
    except KeyboardInterrupt:
        if 'process' in locals() and process.poll() is None:
            process.send_signal(signal.SIGINT)
            process.wait(timeout=10)
    # sudo can return 130 when forwarding SIGINT to tcpdump on early stop.
    if 'process' in locals() and process.returncode not in (0, 130, -signal.SIGINT):
        raise RuntimeError(f"tcpdump exited with status {process.returncode}; inspect its message above")
    if path.stat().st_size < 24:
        raise RuntimeError("No useful capture was written; inspect tcpdump errors above")
    say(f"Captured {path.stat().st_size:,} bytes.")
    return path


def rows(pcap, kind):
    out = run(["tshark", "-n", "-r", str(pcap), "-Y",
               f"tls.handshake.type == {kind}", "-T", "fields",
               "-E", "separator=\t", "-E", "occurrence=f"] +
              [piece for field in FIELDS for piece in ("-e", field)])
    for line in out.splitlines():
        parts = line.split("\t")
        parts.extend([""] * (len(FIELDS) - len(parts)))
        yield dict(zip(FIELDS, parts))


def number(s):
    try:
        return int(s, 0) if s.startswith("0x") else int(s)
    except (ValueError, AttributeError):
        return None


def random_value(s):
    candidate = s.replace(":", "").lower()
    return candidate if re.fullmatch(r"[0-9a-f]{64}", candidate) else None


def version(row, suite):
    selected = number(row.get("tls.handshake.extensions.supported_version", ""))
    legacy = number(row.get("tls.handshake.version", ""))
    if selected == 0x0304 or suite in range(0x1301, 0x1306):
        return "TLS 1.3"
    return VERSIONS.get(selected or legacy, "unknown")


def exchange(ver, suite):
    if ver == "TLS 1.3":
        return "session secrets required"
    if suite in RSA_KX:
        return "RSA key transport (eligible if full, non-resumed handshake)"
    if suite in ECDHE_KX or suite in DHE_KX:
        return "ephemeral DH (session secrets required)"
    return "unknown suite; use endpoint key log"


def collect_sessions(pcap):
    sessions = {}
    for row in rows(pcap, 1):
        stream = row["tcp.stream"]
        if stream and stream not in sessions:
            sessions[stream] = {"client": row, "server": None}
    for row in rows(pcap, 2):
        stream = row["tcp.stream"]
        if stream:
            sessions.setdefault(stream, {"client": None, "server": None})
            if sessions[stream]["server"] is None:
                sessions[stream]["server"] = row
    return sessions


def read_keylog(path):
    entries = {}
    with path.open("r", encoding="ascii", errors="replace") as handle:
        for line in handle:
            match = KEY_LINE.match(line.strip())
            if match:
                label, random, _secret = match.groups()
                entries.setdefault(random.lower(), set()).add(label)
    return entries


def decoded_rows(pcap, stream, keylog=None, rsa_key=None):
    # tls.app_data is ciphertext. app_data_proto is emitted for decrypted data;
    # compare against a baseline to avoid mistaking a visible field for success.
    # Its protocol *label* may be a wrong heuristic for an unknown payload.
    cmd = ["tshark", "-n", "-r", str(pcap)]
    if keylog:
        cmd += ["-o", f"tls.keylog_file:{keylog}"]
    if rsa_key:
        if any(char in str(rsa_key) for char in ('"', '\n', '\r', '\\')):
            raise ValueError("RSA key path cannot contain quotes, backslashes or newlines")
        cmd += ["-o", f'uat:rsa_keys:"{rsa_key}",""']
    cmd += ["-Y", f"tcp.stream == {int(stream)} && tls.app_data_proto",
            "-T", "fields", "-e", "frame.number", "-e", "tls.app_data_proto"]
    return {line for line in run(cmd).splitlines() if line.strip()}


def tls_options(keylog=None, rsa_key=None):
    if keylog:
        return ["-o", f"tls.keylog_file:{keylog}"]
    if rsa_key:
        if any(char in str(rsa_key) for char in ('"', '\n', '\r', '\\')):
            raise ValueError("RSA key path cannot contain quotes, backslashes or newlines")
        return ["-o", f'uat:rsa_keys:"{rsa_key}",""']
    return []


def decrypted_sources(lines):
    """Yield (frame, direction, bytes) from tshark -V -x data sources."""
    frame, direction, expected, data = None, "", None, bytearray()
    for line in lines:
        if expected is not None:
            match = HEX_DUMP_LINE.match(line)
            if match:
                hex_column = match[1].split("   ", 1)[0].strip()
                try:
                    data.extend(bytes.fromhex(hex_column))
                except ValueError:
                    pass
                if len(data) == expected:
                    yield frame, direction, bytes(data)
                    expected, data = None, bytearray()
                continue
            expected, data = None, bytearray()
        match = re.match(r"^Frame (\d+):", line)
        if match:
            frame, direction = int(match[1]), ""
            continue
        match = re.match(r"^Internet Protocol Version [46], Src: ([^,]+), Dst: ([^\s]+)", line)
        if match:
            direction = f"{match[1]} → {match[2]}"
            continue
        match = re.match(r"^Decrypted TLS \((\d+) bytes\):", line)
        if match:
            expected, data = int(match[1]), bytearray()


def pb_varint(data, offset):
    result = 0
    for shift in range(0, 70, 7):
        if offset >= len(data):
            raise ValueError("truncated protobuf varint")
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7f) << shift
        if not byte & 0x80:
            return result, offset
    raise ValueError("protobuf varint too long")


def cast_message(data):
    """Decode the small set of CastMessage fields needed for a readable summary."""
    fields = {}
    offset = 0
    try:
        while offset < len(data):
            tag, offset = pb_varint(data, offset)
            field, wire = tag >> 3, tag & 7
            if field == 0:
                return None
            if wire == 0:
                value, offset = pb_varint(data, offset)
            elif wire == 2:
                length, offset = pb_varint(data, offset)
                if length > len(data) - offset:
                    return None
                value = data[offset:offset + length]
                offset += length
            elif wire in (1, 5):
                length = 8 if wire == 1 else 4
                if length > len(data) - offset:
                    return None
                offset += length
                continue
            else:
                return None
            fields[field] = value
        namespace = fields.get(4, b"").decode("utf-8")
        if not namespace.startswith("urn:x-cast:"):
            return None
        return {
            "source": fields.get(2, b"").decode("utf-8"),
            "destination": fields.get(3, b"").decode("utf-8"),
            "namespace": namespace,
            "payload": fields.get(6, b"").decode("utf-8") if 6 in fields else None,
            "binary_length": len(fields[7]) if 7 in fields else None,
        }
    except (UnicodeDecodeError, ValueError, TypeError):
        return None


def readable_parts(data):
    """Return Cast messages or a mostly printable plaintext preview."""
    messages, offset = [], 0
    while offset + 4 <= len(data):
        length = int.from_bytes(data[offset:offset + 4], "big")
        if not 1 <= length <= len(data) - offset - 4:
            break
        message = cast_message(data[offset + 4:offset + 4 + length])
        if message is None:
            break
        messages.append(message)
        offset += 4 + length
    if messages and offset == len(data):
        return messages
    if len(data) >= 8 and sum(b in (9, 10, 13) or 32 <= b <= 126 for b in data) / len(data) >= 0.85:
        return [data.decode("utf-8", errors="replace")]
    return []


def limit_text(value, max_chars):
    return value if max_chars == 0 or len(value) <= max_chars else value[:max_chars] + "…"


def show_readable(pcap, sources, max_chars=1200):
    if max_chars < 0:
        raise ValueError("max-chars must be 0 or greater")
    say("\nReadable decrypted TLS messages:")
    total_frames, total_messages = set(), 0
    for stream, keylog, rsa_key in sources:
        cmd = (["tshark", "-n", "-r", str(pcap)] + tls_options(keylog, rsa_key) +
               ["-Y", f"tcp.stream == {int(stream)} && tls", "-V", "-x"])
        process = subprocess.Popen(cmd, text=True, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, errors="replace")
        assert process.stdout is not None
        for frame, direction, data in decrypted_sources(process.stdout):
            parts = readable_parts(data)
            if not parts:
                continue
            total_frames.add(frame)
            for item in parts:
                total_messages += 1
                say(f"  Frame {frame} | stream {stream} | {direction}")
                if isinstance(item, dict):
                    say(f"    Cast {item['source']} → {item['destination']} | {item['namespace']}")
                    if item["payload"] is not None:
                        try:
                            payload = json.dumps(json.loads(item["payload"]), ensure_ascii=False)
                        except ValueError:
                            payload = item["payload"]
                        say("    " + limit_text(payload, max_chars))
                    elif item["binary_length"] is not None:
                        say(f"    Binary Cast payload: {item['binary_length']} bytes")
                else:
                    say("    " + limit_text(repr(item), max_chars))
        error = process.stderr.read() if process.stderr else ""
        if process.wait():
            raise RuntimeError(f"tshark readable view failed: {error.strip()}")
    say(f"Readable summary: {len(total_frames)} frame(s), {total_messages} message(s).")
    if not total_messages:
        say("No readable Cast or mostly printable payloads found; binary data may still have decrypted.")


def has_client_key_exchange(pcap, stream):
    output = run(["tshark", "-n", "-r", str(pcap), "-Y",
                  f"tcp.stream == {int(stream)} && tls.handshake.type == 16",
                  "-T", "fields", "-e", "frame.number"])
    return bool(output.strip())


def endpoint(row, prefix):
    return (row.get(f"ip.{prefix}") or row.get(f"ipv6.{prefix}") or "?") + \
           ":" + (row.get(f"tcp.{prefix}port") or "?")


def analyze(pcap, keylog, rsa_key=None):
    need_tools()
    pcap = pcap.expanduser().resolve()
    if not pcap.is_file():
        raise FileNotFoundError(pcap)
    entries = read_keylog(keylog) if keylog else {}
    if rsa_key and not rsa_key.is_file():
        raise FileNotFoundError(rsa_key)
    sessions = collect_sessions(pcap)
    say(f"\nCapture: {pcap}")
    say(f"TLS streams with a visible Hello: {len(sessions)}")
    if not sessions:
        say("No visible TLS Hello. Capture a new connection from its start, check the interface/filter,")
        say("or consider that this traffic might be QUIC, DTLS, or an unrecognized TLS port.")
        return []
    sources = []
    for stream, pair in sorted(sessions.items(), key=lambda item: int(item[0])):
        client, server = pair["client"], pair["server"]
        seed = client or server
        suite = number(server["tls.handshake.ciphersuite"]) if server else None
        ver = version(server, suite) if server else "unknown (no ServerHello)"
        random = random_value(client["tls.handshake.random"]) if client else None
        labels = entries.get(random, set()) if random else set()
        sni = client["tls.handshake.extensions_server_name"] if client else ""
        say(f"\nStream {stream}: {endpoint(seed, 'src')} → {endpoint(seed, 'dst')}")
        say(f"  SNI: {sni or 'absent/hidden'} | Version: {ver}")
        say(f"  Cipher: {NAMES.get(suite, 'unmapped')} ({f'0x{suite:04x}' if suite is not None else 'unknown'})")
        say(f"  Key path: {exchange(ver, suite)}")
        if not client or not server:
            say("  Handshake: incomplete in this capture; classification may be limited.")
        usable_keylog = bool(labels and (
            any("TRAFFIC_SECRET" in label for label in labels)
            if ver == "TLS 1.3" else "CLIENT_RANDOM" in labels))
        if keylog:
            if not random:
                say("  Keylog: no visible ClientHello random; cannot correlate this stream.")
            elif not labels:
                say("  Keylog: NO MATCH for ClientHello random.")
            else:
                say("  Keylog match: " + ", ".join(sorted(labels)))
                if not usable_keylog:
                    say("  Matching entry lacks the required application/master secret.")
        eligible_rsa = bool(rsa_key and suite in RSA_KX and ver != "TLS 1.3" and
                            client and server and has_client_key_exchange(pcap, stream))
        if rsa_key and not eligible_rsa:
            say("  RSA key: ineligible or incomplete handshake; not attempted.")
        if not usable_keylog and not eligible_rsa:
            if not keylog and not rsa_key:
                say("  No key source supplied; decryption not attempted.")
            elif keylog and not labels:
                say("  Export secrets from the endpoint during this exact connection.")
            continue
        sources.append((stream, keylog if usable_keylog else None,
                        rsa_key if eligible_rsa and not usable_keylog else None))
        baseline = decoded_rows(pcap, stream)
        source = "endpoint keylog" if usable_keylog else "server RSA key"
        candidate = decoded_rows(pcap, stream, keylog if usable_keylog else None,
                                 rsa_key if eligible_rsa and not usable_keylog else None)
        novel = candidate - baseline
        inspect_filter = f"tcp.stream == {stream}"
        if novel:
            frames = sorted({row.split("\t", 1)[0] for row in novel}, key=int)
            labels_seen = sorted({row.split("\t", 1)[1] for row in novel if "\t" in row})
            say(f"  Decryption proof using {source} (baseline comparison), frame(s): "
                + ", ".join(frames[:8]))
            if labels_seen:
                say("  Wireshark dissector guess (unconfirmed): " + ", ".join(labels_seen[:3]))
            inspect_filter = " || ".join(f"frame.number == {n}" for n in frames[:8])
        else:
            say(f"  {source} attempted, but no new decoded application frames were confirmed.")
            say("  Possible causes: no app data, missing packets/secret, wrong RSA key,")
            say("  or an unsupported application dissector. Inspect in Wireshark.")
        if usable_keylog:
            say(f"  Inspect proof bytes: tshark -r {shlex.quote(str(pcap))} -o {shlex.quote(f'tls.keylog_file:{keylog}')} -Y {shlex.quote(inspect_filter)} -V -x")
        else:
            say(f"  Inspect proof bytes: tshark -r {shlex.quote(str(pcap))} -o {shlex.quote(f'uat:rsa_keys:{chr(34)}{rsa_key}{chr(34)},{chr(34)}{chr(34)}')} -Y {shlex.quote(inspect_filter)} -V -x")
    return sources


def offer_readable(pcap, sources, args):
    if not sources:
        return
    requested = args.show_decoded
    if not requested and sys.stdin.isatty():
        requested = ask("Show all readable decrypted frames now? (y/N)", "n").lower() in ("y", "yes")
    if requested:
        max_chars = args.max_chars
        if sys.stdin.isatty() and not args.show_decoded:
            max_chars = int(ask("Characters per message (0 = full)", str(max_chars)))
        show_readable(pcap.expanduser().resolve(), sources, max_chars)


class LabTUI:
    """Keyboard driven front end; analysis and command line modes share the same engine."""

    def __init__(self, screen):
        self.screen = screen
        self.directory = Path.cwd()
        self.screen.keypad(True)
        try:
            curses.curs_set(0)
        except curses.error:
            pass

    def draw(self, title, lines=(), footer="Enter=select  Esc/q=back"):
        self.screen.erase()
        height, width = self.screen.getmaxyx()
        if height < 8 or width < 30:
            self.screen.addnstr(0, 0, "Resize terminal (at least 30x8)", max(1, width - 1))
            self.screen.refresh()
            return height, width
        self.screen.addnstr(0, 1, f"LAN TLS Lab {VERSION}  |  {title}", width - 2, curses.A_BOLD)
        self.screen.hline(1, 0, ord('-'), width - 1)
        for row, line in enumerate(lines, 2):
            if row >= height - 2:
                break
            self.screen.addnstr(row, 1, str(line), width - 2)
        self.screen.hline(height - 2, 0, ord('-'), width - 1)
        self.screen.addnstr(height - 1, 1, footer, width - 2)
        self.screen.refresh()
        return height, width

    def menu(self, title, choices, subtitle="", footer="↑/↓ or j/k  Enter=select  Esc/q=back"):
        selected, offset = 0, 0
        while True:
            height, width = self.screen.getmaxyx()
            count = max(1, height - 6)
            offset = max(0, min(offset, max(0, len(choices) - count)))
            if selected < offset:
                offset = selected
            if selected >= offset + count:
                offset = selected - count + 1
            self.draw(title, [subtitle, ""] if subtitle else (), footer)
            base = 4 if subtitle else 2
            for index in range(offset, min(offset + count, len(choices))):
                if base + index - offset >= height - 2:
                    break
                style = curses.A_REVERSE if index == selected else curses.A_NORMAL
                self.screen.addnstr(base + index - offset, 2,
                                    f"{index + 1:>3}. {choices[index]}",
                                    max(1, width - 4), style)
            self.screen.refresh()
            key = self.screen.getch()
            if key in (27, ord('q')):
                return None
            if key in (curses.KEY_UP, ord('k')):
                selected = max(0, selected - 1)
            elif key in (curses.KEY_DOWN, ord('j')):
                selected = min(len(choices) - 1, selected + 1)
            elif key == curses.KEY_PPAGE:
                selected = max(0, selected - count)
            elif key == curses.KEY_NPAGE:
                selected = min(len(choices) - 1, selected + count)
            elif key in (10, 13, curses.KEY_ENTER) and choices:
                return selected
            elif ord('1') <= key <= ord('9') and key - ord('1') < len(choices):
                return key - ord('1')

    def input_text(self, title, prompt, initial=""):
        value = str(initial)
        try:
            curses.curs_set(1)
        except curses.error:
            pass
        try:
            while True:
                height, width = self.draw(title, [prompt, "", "Enter=accept  Esc=cancel"],
                                          "Backspace=edit")
                row = min(5, height - 3)
                self.screen.addnstr(row, 2, value[-max(1, width - 5):], max(1, width - 4))
                self.screen.move(row, min(width - 2, 2 + len(value[-max(1, width - 5):])))
                self.screen.refresh()
                key = self.screen.getch()
                if key == 27:
                    return None
                if key in (10, 13, curses.KEY_ENTER):
                    return value.strip()
                if key in (curses.KEY_BACKSPACE, 127, 8):
                    value = value[:-1]
                elif 32 <= key <= 126:
                    value += chr(key)
        finally:
            try:
                curses.curs_set(0)
            except curses.error:
                pass

    def viewer(self, title, content):
        offset = 0
        while True:
            height, width = self.screen.getmaxyx()
            lines = []
            for line in str(content).splitlines():
                lines.extend(textwrap.wrap(line, width=max(15, width - 3),
                                           replace_whitespace=False,
                                           drop_whitespace=False) or [""])
            page = max(1, height - 4)
            offset = min(offset, max(0, len(lines) - page))
            self.draw(title, lines[offset:offset + page],
                      f"{offset + 1}-{min(len(lines), offset + page)}/{len(lines)}  ↑/↓ PgUp/PgDn Home/End  q=back")
            key = self.screen.getch()
            if key in (27, ord('q'), 10, 13):
                return
            if key in (curses.KEY_DOWN, ord('j')):
                offset = min(max(0, len(lines) - page), offset + 1)
            elif key in (curses.KEY_UP, ord('k')):
                offset = max(0, offset - 1)
            elif key == curses.KEY_NPAGE or key == ord(' '):
                offset = min(max(0, len(lines) - page), offset + page)
            elif key == curses.KEY_PPAGE:
                offset = max(0, offset - page)
            elif key in (curses.KEY_HOME, ord('g')):
                offset = 0
            elif key in (curses.KEY_END, ord('G')):
                offset = max(0, len(lines) - page)

    def capture_path(self):
        while True:
            try:
                files = capture_files(self.directory)
            except (OSError, RuntimeError) as error:
                self.viewer("Capture directory", str(error))
                files = []
            labels = []
            for file in files:
                info = file.stat()
                when = datetime.fromtimestamp(info.st_mtime).strftime("%Y-%m-%d %H:%M")
                empty = "  (header only)" if file.suffix.lower() == ".pcap" and info.st_size == 24 else ""
                labels.append(f"{when}  {human_size(info.st_size):>9}  {file.name}{empty}")
            choice = self.menu("Select capture", labels + ["Change directory or enter a file path"],
                               f"Directory: {self.directory}  |  {len(files)} capture(s), newest first")
            if choice is None:
                return None
            if choice < len(files):
                return files[choice]
            entered = self.input_text("Capture location", "Directory or exact capture file", str(self.directory))
            if entered is None:
                continue
            path = Path(entered).expanduser().resolve()
            if path.is_file():
                self.directory = path.parent
                return path
            if path.is_dir():
                self.directory = path
            else:
                self.viewer("Capture location", f"File or directory not found: {path}")

    def key_sources(self, new_capture=False):
        choices = ["Classify only (no decryption)", "Existing endpoint TLS keylog"]
        if new_capture:
            choices.append("Prepare a new endpoint keylog path")
        choices += ["Legacy server RSA private key", "Keylog and legacy RSA key"]
        choice = self.menu("Decryption source", choices,
                           "TLS 1.3 needs endpoint session secrets; RSA applies to legacy RSA key transport.")
        if choice is None:
            return None
        selected = choices[choice]
        keylog = rsa = None
        if "keylog" in selected.lower():
            initial = str(self.directory / "session.keys") if selected.startswith("Prepare") else ""
            entered = self.input_text("TLS keylog", "Path exported by an endpoint you control", initial)
            if not entered:
                return None
            keylog = Path(entered).expanduser().resolve()
            if selected.startswith("Prepare"):
                keylog.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                self.viewer("Prepare endpoint", f"Configure your client before connecting:\n\n"
                            f"export SSLKEYLOGFILE={shlex.quote(str(keylog))}\n\n"
                            "For Python ssl, set context.keylog_filename to this path.\n"
                            "Start a new connection during capture. The application must support key logging.")
            elif not keylog.is_file():
                self.viewer("TLS keylog", f"No keylog at {keylog}")
                return None
        if "RSA" in selected:
            entered = self.input_text("Legacy RSA key", "Server private key PEM path (does not decrypt TLS 1.3)")
            if not entered:
                return None
            rsa = Path(entered).expanduser().resolve()
            if not rsa.is_file():
                self.viewer("Legacy RSA key", f"No key at {rsa}")
                return None
        return keylog, rsa

    def report(self, pcap, keylog, rsa):
        output = io.StringIO()
        with redirect_stdout(output):
            sources = analyze(pcap, keylog, rsa)
        self.viewer("TLS analysis", output.getvalue())
        if sources:
            while True:
                choice = self.menu("Decrypted data", ["Show readable messages", "Review analysis", "Return to main menu"],
                                   f"Capture: {pcap.name}")
                if choice in (None, 2):
                    return
                if choice == 1:
                    self.viewer("TLS analysis", output.getvalue())
                    continue
                entered = self.input_text("Readable messages", "Characters per message (0 = full)", "1200")
                if entered is None:
                    continue
                try:
                    limit = int(entered)
                    if limit < 0:
                        raise ValueError("limit must be 0 or greater")
                    readable = io.StringIO()
                    with redirect_stdout(readable):
                        show_readable(pcap, sources, limit)
                    self.viewer("Readable decrypted messages", readable.getvalue())
                except ValueError as error:
                    self.viewer("Invalid limit", str(error))

    def analyze_flow(self):
        pcap = self.capture_path()
        if pcap is None:
            return
        source = self.key_sources()
        if source is not None:
            self.report(pcap, *source)

    def capture_flow(self):
        need_tools(capture=True)
        found = interfaces()
        if not found:
            raise RuntimeError("tcpdump found no interfaces")
        addresses = run(["ip", "-br", "addr"], check=False) if shutil.which("ip") else ""
        if addresses:
            self.viewer("Local addresses", addresses)
        selected = self.menu("Capture interface", [f"{name}  {description}" for name, description in found])
        if selected is None:
            return
        interface = found[selected][0]
        host = self.input_text("Capture filter", "Target IPv4/IPv6 (blank = all TCP)")
        if host is None:
            return
        host = parse_host(host)
        port = self.input_text("Capture filter", "Target TCP port (blank = all TCP for target)")
        if port is None:
            return
        port = parse_port(port)
        duration = self.input_text("Capture duration", "Seconds (1–3600)", "45")
        if duration is None:
            return
        seconds = int(duration)
        if not 1 <= seconds <= 3600:
            raise ValueError("duration must be 1–3600 seconds")
        default = self.directory / f"capture-{datetime.now().strftime('%Y%m%d-%H%M%S')}.pcap"
        entered = self.input_text("Capture output", "Save capture as", str(default))
        if not entered:
            return
        path = Path(entered).expanduser().resolve()
        source = self.key_sources(new_capture=True)
        if source is None:
            return
        keylog, rsa = source
        details = (f"Interface: {interface}\nFilter: {host or 'all hosts'}; "
                   f"TCP port: {port or 'all'}\nDuration: {seconds}s\nFile: {path}\n"
                   f"Keylog: {keylog or 'none'}\nRSA key: {rsa or 'none'}")
        self.viewer("Capture settings", details)
        if self.menu("Start capture?", ["Start capture", "Cancel"],
                     "Review settings shown on the previous screen") != 0:
            return
        # sudo and tcpdump need the real terminal for credentials and Ctrl+C.
        curses.def_prog_mode()
        curses.endwin()
        try:
            pcap = capture(interface, host, port, seconds, path)
        finally:
            curses.reset_prog_mode()
            self.screen.refresh()
        self.directory = pcap.parent
        if keylog and not keylog.is_file():
            self.viewer("Missing keylog", f"Endpoint did not write {keylog}; classifying without it.")
            keylog = None
        self.report(pcap, keylog, rsa)

    def run(self):
        while True:
            selected = self.menu("Main menu", ["Capture a new TCP TLS connection",
                                                "Analyze an existing capture",
                                                "Set capture directory", "Help", "Quit"],
                                 f"Capture directory: {self.directory}")
            if selected in (None, 4):
                return
            try:
                if selected == 0:
                    self.capture_flow()
                elif selected == 1:
                    self.analyze_flow()
                elif selected == 2:
                    entered = self.input_text("Capture directory", "Directory containing captures", str(self.directory))
                    if entered is not None:
                        path = Path(entered).expanduser().resolve()
                        if not path.is_dir():
                            raise NotADirectoryError(path)
                        self.directory = path
                elif selected == 3:
                    self.viewer("Help", "Select with arrows or j/k and Enter. Escape or q goes back.\n\n"
                                "Choose a capture directory or exact file, then a key source. "
                                "An endpoint keylog contains secrets for the actual session; "
                                "the server RSA private key works only for eligible legacy handshakes.\n\n"
                                "Reports show TLS classification and decryption proof. "
                                "Readable messages show Cast when detected and printable plaintext otherwise. "
                                "Use the displayed tshark command for raw bytes.\n\n"
                                "Use --no-tui for the numbered prompts; --help lists command line flags.")
            except (ValueError, OSError, RuntimeError) as error:
                self.viewer("Error", str(error))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    capture_input = parser.add_mutually_exclusive_group()
    capture_input.add_argument("--pcap", type=Path,
                               help="existing capture file, or directory to browse interactively")
    capture_input.add_argument("--pcap-dir", type=Path,
                               help="browse captures in this directory interactively")
    parser.add_argument("--keylog", type=Path, help="explicit endpoint-exported TLS key log")
    parser.add_argument("--rsa-key", type=Path, help="optional legacy TLS server RSA private key")
    parser.add_argument("--interface", help="capture interface (otherwise choose in UI)")
    parser.add_argument("--host", help="target IPv4/IPv6 address; optional BPF scope")
    parser.add_argument("--port", type=parse_port, help="target TCP port; optional BPF scope")
    parser.add_argument("--seconds", type=int, default=45, help="capture duration (default: 45)")
    parser.add_argument("--output", type=Path, help="new capture path")
    parser.add_argument("--show-decoded", action="store_true",
                        help="list all readable decrypted messages after analysis")
    parser.add_argument("--max-chars", type=int, default=1200,
                        help="maximum characters shown per message (0 = unlimited)")
    parser.add_argument("--no-tui", action="store_true", help="use numbered text prompts instead of curses")
    args = parser.parse_args()
    if len(sys.argv) == 1 and sys.stdin.isatty() and sys.stdout.isatty():
        curses.wrapper(lambda screen: LabTUI(screen).run())
        return
    say(f"LAN TLS Lab {VERSION} — capture, classify, correlate, verify")
    if args.pcap or args.pcap_dir:
        target = (args.pcap or args.pcap_dir).expanduser()
        if target.is_dir():
            if not sys.stdin.isatty():
                parser.error("directory selection needs a terminal; use --pcap FILE instead")
            target = choose_capture(target)
            if target is None:
                return
        elif args.pcap_dir:
            raise NotADirectoryError(args.pcap_dir)
        keylog = args.keylog.expanduser().resolve() if args.keylog else None
        rsa_key = args.rsa_key.expanduser().resolve() if args.rsa_key else None
        if sys.stdin.isatty() and not keylog and not rsa_key:
            keylog, rsa_key = choose_existing_keys()
        sources = analyze(target, keylog, rsa_key)
        offer_readable(target, sources, args)
        return
    interactive = sys.stdin.isatty()
    if interactive:
        say("\n1. Capture a new TCP TLS connection")
        say("2. Analyze an existing capture")
        mode = ask("Choose", "1")
        if mode == "2":
            start = Path(ask("Capture directory or exact file", str(default_capture_dir()))).expanduser()
            pcap = choose_capture(start)
            if pcap is None:
                return
            keylog, rsa_key = choose_existing_keys()
            sources = analyze(pcap, keylog, rsa_key)
            offer_readable(pcap, sources, args)
            return
        if mode != "1":
            raise ValueError("choose 1 or 2")
    elif not args.interface:
        parser.error("noninteractive capture requires --interface")
    need_tools(capture=True)
    interface = args.interface or choose_interface()
    host = parse_host(args.host if args.host is not None else
                      (ask("Target IP (Enter = all TCP on interface)") if interactive else None))
    port = args.port if args.port is not None else parse_port(
        ask("Target TCP port (Enter = all TCP for target)") if interactive else None)
    seconds = int(ask("Capture seconds", str(args.seconds))) if interactive else args.seconds
    path = args.output or (Path.cwd() /
                           f"capture-{datetime.now().strftime('%Y%m%d-%H%M%S')}.pcap")
    if interactive and not args.output:
        path = Path(ask("Save capture as", str(path))).expanduser()
    key = args.keylog
    rsa = args.rsa_key
    if interactive and not key and not rsa:
        key, rsa = choose_capture_keys()
    if key:
        key = key.expanduser().resolve()
        if not key.exists():
            say(f"Keylog {key} does not exist yet. Start the instrumented endpoint")
            say("before making a NEW connection; the file must exist after capture.")
    if interactive:
        ask("Press Enter to start capturing, then trigger a new connection", "")
    pcap = capture(interface, host, port, seconds, path)
    if key and not key.is_file():
        say("Keylog was not created; classifying without secrets.")
        key = None
    sources = analyze(pcap, key, rsa.expanduser().resolve() if rsa else None)
    offer_readable(pcap, sources, args)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, RuntimeError) as error:
        print(f"Error: {error}", file=sys.stderr)
        sys.exit(1)
