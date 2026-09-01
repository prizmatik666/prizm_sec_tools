#!/usr/bin/env python3
"""LogLens: portable Linux process, audit, and login investigation console.

Requirements: Python 3.8+ with curses support. Optional data providers include
journalctl, auditd/ausearch/auditctl, and process accounting (lastcomm/sa).
Run as root for the most complete results; LogLens never prompts for sudo.
"""

from __future__ import annotations

import curses
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import textwrap
import time
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional, Sequence, Union

APP = "LogLens v3 - Linux Log Investigation Console"
REFRESH_SECONDS = 3
Command = Union[str, Sequence[str]]
ACTIVE_PROCESS: Optional[subprocess.Popen] = None
SHELL = shutil.which("bash") or shutil.which("sh") or "/bin/sh"


def command_path(name: str) -> Optional[str]:
    return shutil.which(name)


def stop_process(proc: subprocess.Popen) -> None:
    """Stop a command and its children without touching unrelated processes."""
    if proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM)
        proc.wait(timeout=1.5)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def run(cmd: Command, timeout: int = 20, *, shell: bool = False) -> str:
    """Run a bounded command and return display-ready combined output."""
    global ACTIVE_PROCESS
    argv: Command = [SHELL, "-c", cmd] if shell and isinstance(cmd, str) else cmd
    try:
        ACTIVE_PROCESS = subprocess.Popen(
            argv,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        output, _ = ACTIVE_PROCESS.communicate(timeout=timeout)
        status = ACTIVE_PROCESS.returncode
        output = output.rstrip()
        if status and not output:
            return f"[command failed: exit {status}]"
        if status:
            return f"{output}\n[exit {status}]"
        return output or "(no entries returned)"
    except subprocess.TimeoutExpired:
        if ACTIVE_PROCESS:
            stop_process(ACTIVE_PROCESS)
        return f"[timed out after {timeout}s]"
    except KeyboardInterrupt:
        if ACTIVE_PROCESS:
            stop_process(ACTIVE_PROCESS)
        raise
    except FileNotFoundError as exc:
        return f"[not installed: {exc.filename}]"
    except PermissionError as exc:
        return f"[permission denied: {exc.filename or 'command'}]"
    except OSError as exc:
        return f"[could not run command: {exc}]"
    finally:
        ACTIVE_PROCESS = None


def privileged(args: Sequence[str], timeout: int = 20) -> str:
    """Run with existing privileges; never stall the UI on a sudo prompt."""
    if os.geteuid() == 0:
        return run(args, timeout)
    if command_path("sudo"):
        result = run(["sudo", "-n", *args], timeout)
        if "password is required" not in result.lower() and "a password is required" not in result.lower():
            return result
    return "[permission required: rerun LogLens as root for this data]"


def section(title: str, body: str) -> str:
    return f"{title}\n{'-' * 72}\n{body}"


def unavailable(tool: str, purpose: str = "this view") -> str:
    return f"[unavailable: {tool} is not installed; {purpose} cannot be collected]"


def journal(args: Sequence[str], lines: int = 120) -> str:
    if not command_path("journalctl"):
        return unavailable("journalctl", "journal data")
    return run(["journalctl", *args, "--no-pager", "-n", str(lines)])


def readable_log(candidates: Sequence[str], pattern: Optional[str] = None, lines: int = 120) -> str:
    for name in candidates:
        path = Path(name)
        if not path.exists():
            continue
        if not os.access(path, os.R_OK):
            return f"[permission denied reading {path}]"
        try:
            data = path.read_text(errors="replace").splitlines()
        except OSError as exc:
            return f"[could not read {path}: {exc}]"
        if pattern:
            rx = re.compile(pattern, re.IGNORECASE)
            data = [line for line in data if rx.search(line)]
        return "\n".join(data[-lines:]) or f"(no matching entries in {path})"
    return f"[no supported log file found: {', '.join(candidates)}]"


def service_state(names: Sequence[str]) -> str:
    if command_path("systemctl") and Path("/run/systemd/system").exists():
        for name in names:
            state = run(["systemctl", "is-active", name], 5)
            if state not in ("inactive\n[exit 3]", "unknown\n[exit 4]"):
                return f"{name}: {state}"
        return f"{names[0]}: inactive or not installed"
    if command_path("rc-service"):
        for name in names:
            result = run(["rc-service", name, "status"], 5)
            if "does not exist" not in result.lower():
                return f"{name}: {result}"
    if command_path("sv"):
        for name in names:
            result = run(["sv", "status", name], 5)
            if "fail:" not in result.lower():
                return f"{name}: {result}"
    return "[service manager/status unavailable]"


def decode_hex(value: str) -> str:
    try:
        return bytes.fromhex(value).decode("utf-8", errors="replace")
    except ValueError:
        return value


def collect_audit_recent():
    if not command_path("ausearch"):
        return [], unavailable("ausearch", "audit events")
    raw = privileged(["ausearch", "-ts", "recent", "-i"], 25)
    if raw.startswith("[permission required"):
        return [], raw
    return parse_audit(raw), ""


def parse_audit(raw: str):
    events = {}
    current = None
    for line in raw.splitlines():
        match = re.search(r"msg=audit\(([^)]+):(\d+)\)", line)
        if match:
            event_id = match.group(2)
            current = events.setdefault(event_id, {"id": event_id, "raw": []})
            current["raw"].append(line)
            if "type=SYSCALL" in line:
                for key in ("comm", "exe", "key"):
                    found = re.search(rf'{key}=("?)([^"\s]+)\1', line)
                    if found:
                        current[key] = found.group(2)
                for key in ("pid", "uid", "auid", "ses"):
                    found = re.search(rf"{key}=([^\s]+)", line)
                    if found:
                        current[key] = found.group(1)
            elif "type=PATH" in line:
                # ausearch emits quoted paths normally, but ``-i`` commonly
                # renders them without quotes.  Accept either representation.
                name = re.search(r'name=(?:"([^"]+)"|(\S+))', line)
                inode = re.search(r"inode=(\d+)", line)
                action = re.search(r"nametype=([A-Z_]+)", line)
                path_type = action.group(1) if action else None
                path_value = (name.group(1) or name.group(2)) if name else None
                # A single filesystem event often contains its target PATH
                # followed by a PARENT PATH.  PARENT is context, not the file
                # operation, and must not overwrite CREATE/DELETE.
                if path_value and path_type != "PARENT":
                    current.setdefault("paths", []).append(path_value)
                if inode and path_type != "PARENT":
                    current["inode"] = inode.group(1)
                if path_type and path_type != "PARENT":
                    current["action"] = path_type
            elif "type=CWD" in line:
                found = re.search(r'cwd="([^"]+)"', line)
                if found:
                    current["cwd"] = found.group(1)
            elif "type=PROCTITLE" in line:
                found = re.search(r"proctitle=([0-9A-Fa-f]+)", line)
                if found:
                    current["cmd"] = decode_hex(found.group(1)).replace("\x00", " ")
            elif "type=USER_CMD" in line:
                found = re.search(r"cmd=([0-9A-Fa-f]+)", line)
                if found:
                    current["cmd"] = decode_hex(found.group(1))
        elif current:
            current["raw"].append(line)
    return list(events.values())


def event_line(event) -> str:
    action = event.get("action", "EVENT")
    cmd = event.get("cmd") or event.get("comm") or "?"
    user = event.get("auid") or event.get("uid") or "?"
    path = ", ".join(event.get("paths", []))
    inode = f" inode={event['inode']}" if event.get("inode") else ""
    key = f" key={event['key']}" if event.get("key") else ""
    return f"audit:{event.get('id')}  {action:<8} user={user:<8} cmd={cmd:<28} {path}{inode}{key}"


def audit_rules() -> str:
    if not command_path("auditctl"):
        return unavailable("auditctl", "active audit rules")
    return privileged(["auditctl", "-l"])


def dashboard() -> str:
    identity = run(["hostnamectl"], 8) if command_path("hostnamectl") else run(["uname", "-a"])
    account_dirs = [p for p in (Path("/var/log/account"), Path("/var/account")) if p.exists()]
    acct_files = "\n".join(f"{p}: {sum(1 for _ in p.iterdir())} entries" for p in account_dirs)
    if not acct_files:
        acct_files = "[no process-accounting directory found]"
    usage = journal(["--disk-usage"], 20) if command_path("journalctl") else unavailable("journalctl")
    return "\n\n".join([
        section("SYSTEM SUMMARY", identity),
        section("LOGGER STATUS", "\n".join([
            f"audit: {service_state(('auditd',))}",
            f"accounting: {service_state(('acct', 'psacct'))}",
            f"audit tools: {'available' if command_path('ausearch') else 'missing'}",
            f"process accounting tools: {'available' if command_path('lastcomm') else 'missing'}",
            f"privilege: {'root' if os.geteuid() == 0 else 'user (root-only data may be limited)'}",
        ])),
        section("ACCOUNTING FILES", acct_files),
        section("ACTIVE AUDIT WATCHES", audit_rules()),
        section("JOURNAL USAGE", usage),
        section("RECENT SUDO", sudo_activity(8)),
    ])


def unified_timeline() -> str:
    events, notice = collect_audit_recent()
    audit_lines = [event_line(e) for e in events[-30:]] or [notice or "(no recent audit events)"]
    acct = privileged(["lastcomm"], 15) if command_path("lastcomm") else unavailable("lastcomm")
    return "\n\n".join([
        section("AUDITD RECENT EVENTS", "\n".join(audit_lines)),
        section("SUDO ACTIVITY", sudo_activity(20)),
        section("PROCESS ACCOUNTING", "\n".join(acct.splitlines()[:30])),
    ])


def audit_by_action(action: str) -> str:
    events, notice = collect_audit_recent()
    matched = [event for event in events if event.get("action") == action]
    lines = [f"AUDITD FILE {action} EVENTS", "=" * 72]
    if not matched:
        lines.append(notice or "(no recent matches)")
    for event in matched[-80:]:
        lines.append(event_line(event))
        if event.get("cwd"):
            lines.append(f"    cwd={event['cwd']}")
    return "\n".join(lines)


def sudo_activity(lines: int = 120) -> str:
    if command_path("journalctl"):
        result = journal(["_COMM=sudo"], lines)
        if "-- No entries --" not in result:
            return result
    return readable_log(("/var/log/auth.log", "/var/log/secure"), r"sudo", lines)


def ssh_activity() -> str:
    if command_path("journalctl"):
        ssh = journal(["-u", "ssh", "-u", "sshd"], 80)
    else:
        ssh = readable_log(("/var/log/auth.log", "/var/log/secure"), r"sshd?", 80)
    successful = run(["last", "-a"], 15) if command_path("last") else unavailable("last")
    failed = failed_login_activity()
    return "\n\n".join([
        section("SSH LOG", ssh), section("SUCCESSFUL LOGINS", successful), section("FAILED LOGINS", failed)
    ])


def failed_login_activity(lines: int = 80) -> str:
    """Use legacy btmp when present, otherwise inspect authentication logs."""
    if command_path("lastb"):
        return privileged(["lastb", "-a"], 15)

    failure_pattern = re.compile(
        r"failed password|invalid user|authentication failure|failed login|"
        r"maximum authentication attempts|pam_\S+\([^)]*:auth\):\s+authentication failure",
        re.IGNORECASE,
    )
    if command_path("journalctl"):
        raw = journal(["-u", "ssh", "-u", "sshd"], 500)
        if not raw.startswith("[unavailable:"):
            matches = [entry for entry in raw.splitlines() if failure_pattern.search(entry)]
            return "\n".join(matches[-lines:]) if matches else "(no failed SSH logins found in the journal)"

    return readable_log(
        ("/var/log/auth.log", "/var/log/secure"),
        failure_pattern.pattern,
        lines,
    )


def watched_path_activity() -> str:
    chunks = [section("ACTIVE WATCH RULES", audit_rules())]
    for key in ("tmpwatch", "passwd_watch"):
        chunks.append(section(f"{key} EVENTS", audit_key(key, 80)))
    return "\n\n".join(chunks)


def audit_key(key: str, lines: int = 180) -> str:
    if not command_path("ausearch"):
        return unavailable("ausearch")
    result = privileged(["ausearch", "-k", key, "-i"], 25)
    return "\n".join(result.splitlines()[-lines:])


def audit_watches() -> str:
    home = str(Path.home())
    suggested = "\n".join([
        "sudo auditctl -w /tmp -p wa -k tmpwatch",
        "sudo auditctl -w /etc/passwd -p wa -k passwd_watch",
        f"sudo auditctl -w {shlex.quote(home)} -p wa -k home_watch",
    ])
    return f"{section('ACTIVE AUDIT RULES / WATCHES', audit_rules())}\n\n{section('SUGGESTED TEMPORARY WATCHES', suggested)}"


def process_stats() -> str:
    sa = privileged(["sa"], 20) if command_path("sa") else unavailable("sa")
    recent = privileged(["lastcomm"], 20) if command_path("lastcomm") else unavailable("lastcomm")
    return f"{section('ACCOUNTING SUMMARY', sa)}\n\n{section('RECENT COMMANDS', recent)}"


def system_health() -> str:
    if command_path("systemctl") and Path("/run/systemd/system").exists():
        failed = run(["systemctl", "--failed", "--no-pager"])
    elif command_path("rc-status"):
        failed = run(["rc-status", "--crashed"])
    else:
        failed = "[failed-service view unavailable for this init system]"
    warnings = journal(["-b", "-p", "warning..alert"], 120) if command_path("journalctl") else readable_log(
        ("/var/log/syslog", "/var/log/messages"), r"warn|error|fail|crit|alert", 120
    )
    return f"{section('FAILED SERVICES', failed)}\n\n{section('WARNINGS / ERRORS', warnings)}"


HELP = f"""{APP}

Views: 1 dashboard | 2 timeline | 3 create | 4 delete | 5 sudo
       6 SSH/login | 7 watched paths | 8 audit rules | 9 accounting
       0 system health | t tmpwatch | p passwd_watch

Controls: / filter | c custom command | r refresh | l live refresh
          h help | q quit | Ctrl+C quit
Scroll:   arrows or j/k | PgUp/PgDn | Home/End

LogLens detects available Linux logging tools and init systems. Missing tools,
permissions, and unsupported data sources are shown in the relevant view.
It never opens an interactive sudo prompt. Run as root when complete audit,
failed-login, or process-accounting access is required.
"""

PRESETS = {
    "1": ("Dashboard", dashboard), "2": ("Unified Timeline", unified_timeline),
    "3": ("File Creations", lambda: audit_by_action("CREATE")),
    "4": ("File Deletions", lambda: audit_by_action("DELETE")),
    "5": ("Sudo Activity", sudo_activity), "6": ("SSH / Login Activity", ssh_activity),
    "7": ("Watched Path Activity", watched_path_activity), "8": ("Audit Watches / Rules", audit_watches),
    "9": ("Process Accounting Stats", process_stats), "0": ("System Health", system_health),
    "t": ("tmpwatch Events", lambda: audit_key("tmpwatch")),
    "p": ("passwd_watch Events", lambda: audit_key("passwd_watch")),
}


def wrap(text: str, width: int):
    output = []
    for line in text.splitlines() or [""]:
        output.extend(textwrap.wrap(line, width=max(20, width), replace_whitespace=False,
                                    drop_whitespace=False) if line else [""])
    return output


def safe_addstr(window, y: int, x: int, value: str, attr=0) -> None:
    try:
        height, width = window.getmaxyx()
        if 0 <= y < height and x < width:
            window.addnstr(y, x, value, max(0, width - x - 1), attr)
    except curses.error:
        pass


def prompt(stdscr, label: str) -> str:
    height, width = stdscr.getmaxyx()
    if height < 2 or width <= len(label) + 2:
        return ""
    curses.echo()
    try:
        curses.curs_set(1)
    except curses.error:
        pass
    stdscr.move(height - 1, 0)
    stdscr.clrtoeol()
    safe_addstr(stdscr, height - 1, 0, label)
    stdscr.refresh()
    try:
        value = stdscr.getstr(height - 1, len(label), max(1, width - len(label) - 1))
        return value.decode(errors="ignore").strip()
    finally:
        curses.noecho()
        try:
            curses.curs_set(0)
        except curses.error:
            pass


def draw(stdscr, title: str, output: str, scroll: int, live: bool):
    stdscr.erase()
    height, width = stdscr.getmaxyx()
    if height < 7 or width < 30:
        safe_addstr(stdscr, 0, 0, "Terminal too small (minimum 30x7). Resize or press q.", curses.A_BOLD)
        stdscr.refresh()
        return 0, 0
    header = f" {APP} " + ("[LIVE]" if live else "")
    safe_addstr(stdscr, 0, 0, header, curses.A_REVERSE)
    safe_addstr(stdscr, 1, 0, f"View: {title}", curses.A_BOLD)
    safe_addstr(stdscr, 2, 0, f"Updated: {datetime.now():%Y-%m-%d %H:%M:%S}", curses.A_DIM)
    try:
        stdscr.hline(3, 0, curses.ACS_HLINE, width - 1)
    except curses.error:
        pass
    lines = wrap(output, width - 2)
    view_height = height - 6
    max_scroll = max(0, len(lines) - view_height)
    scroll = max(0, min(scroll, max_scroll))
    for index, line in enumerate(lines[scroll:scroll + view_height]):
        lowered = line.lower()
        attr = curses.A_BOLD if any(word in lowered for word in ("failed", "error", "denied", "warning")) else 0
        safe_addstr(stdscr, 4 + index, 0, line, attr)
    footer = " 1 dash | 2 timeline | / filter | r refresh | l live | h help | q quit "
    position = f" {scroll + 1}-{min(scroll + view_height, len(lines))}/{len(lines)} "
    safe_addstr(stdscr, height - 1, 0, footer, curses.A_REVERSE)
    if len(position) < width:
        safe_addstr(stdscr, height - 1, width - len(position) - 1, position, curses.A_REVERSE)
    stdscr.refresh()
    return scroll, max_scroll


def main(stdscr) -> None:
    try:
        curses.curs_set(0)
    except curses.error:
        pass
    stdscr.keypad(True)
    stdscr.timeout(1000)
    title, loader, output, original = "Help", lambda: HELP, HELP, HELP
    scroll, live, last_refresh = 0, False, 0.0
    while True:
        now = time.monotonic()
        if live and now - last_refresh >= REFRESH_SECONDS:
            output = original = loader()
            last_refresh = now
        scroll, max_scroll = draw(stdscr, title, output, scroll, live)
        keycode = stdscr.getch()
        if keycode == -1:
            continue
        key = chr(keycode) if 0 <= keycode <= 255 else ""
        if key == "q":
            return
        if key in PRESETS:
            title, loader = PRESETS[key]
            output = original = loader()
            scroll, last_refresh = 0, time.monotonic()
        elif key == "h":
            title, loader, output, original, scroll = "Help", lambda: HELP, HELP, HELP, 0
        elif key == "r":
            output = original = loader()
            scroll, last_refresh = 0, time.monotonic()
        elif key == "l":
            live, last_refresh = not live, 0.0
        elif key == "/":
            term = prompt(stdscr, "filter: ")
            if term:
                matches = [line for line in original.splitlines() if term.casefold() in line.casefold()]
                output = "\n".join(matches) if matches else f"(no matches for {term!r})"
                title, scroll = f"{title.split(' | filter=', 1)[0]} | filter={term}", 0
        elif key == "c":
            command = prompt(stdscr, "custom command: ")
            if command:
                title, loader = "Custom Command", lambda value=command: run(value, 30, shell=True)
                output = original = loader()
                scroll = 0
        elif keycode in (curses.KEY_DOWN, ord("j")):
            scroll = min(max_scroll, scroll + 1)
        elif keycode in (curses.KEY_UP, ord("k")):
            scroll = max(0, scroll - 1)
        elif keycode == curses.KEY_NPAGE:
            scroll = min(max_scroll, scroll + max(1, stdscr.getmaxyx()[0] - 6))
        elif keycode == curses.KEY_PPAGE:
            scroll = max(0, scroll - max(1, stdscr.getmaxyx()[0] - 6))
        elif keycode == curses.KEY_HOME:
            scroll = 0
        elif keycode == curses.KEY_END:
            scroll = max_scroll


def cli() -> int:
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        print("LogLens requires an interactive terminal.", file=sys.stderr)
        return 2
    try:
        curses.wrapper(main)
        return 0
    except KeyboardInterrupt:
        if ACTIVE_PROCESS:
            stop_process(ACTIVE_PROCESS)
        print("\nLogLens interrupted; terminal restored.", file=sys.stderr)
        return 130
    except curses.error as exc:
        print(f"LogLens could not initialize the terminal: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(cli())
