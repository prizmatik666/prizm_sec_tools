#!/usr/bin/env python3
"""
auto_enumerate.py v1.5

- Trust-direction engine distinguishes writer privilege from execution privilege
- Root control of non-root services is no longer treated as a vulnerability
- Same-identity control is distinguished from cross-account influence
- Cron parser distinguishes commands from redirects/log files
- Systemd/cron checks account for the actual execution user
- Systemd unit symlinks are canonicalized before analysis
- Package provenance handles usrmerge and architecture-qualified packages
- Duplicate findings are merged instead of repeated
- Starts at a mode-selection menu
- Optional sudo authentication per scan
- Continues unprivileged if sudo is skipped/fails
- Five scan modes
- Findings are severity-ranked with WHY / EVIDENCE / NEXT STEP
- Package provenance is considered for SUID/SGID and file capabilities
- Writable-path checks distinguish owner/group/world exposure
- Raw evidence is available for modes that collect it
- Reports are saved only when requested
"""

import curses
import grp
import os
import pwd
import re
import shlex
import stat
import subprocess
import textwrap
from collections import Counter
from datetime import datetime
from pathlib import Path

# ============================================================
# GLOBAL STATE
# ============================================================

SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
}

FINDINGS = []
FINDING_INDEX = {}
RAW_SECTIONS = []
SUDO_READY = False
CURRENT_MODE = None

MODE_DEFS = [
    {
        "id": "full",
        "name": "Full Triage",
        "desc": "Broad forensic/security collection. Large output; includes raw system state.",
    },
    {
        "id": "offensive",
        "name": "Offensive POV",
        "desc": "Attack-surface and privilege-escalation focused, read-only.",
    },
    {
        "id": "defensive",
        "name": "Defensive POV",
        "desc": "Persistence, auth anomalies, exposure, hardening and suspicious activity.",
    },
    {
        "id": "quick",
        "name": "Meat & Potatoes",
        "desc": "Fast security essentials: users, sudo, SSH, services, firewall, persistence.",
    },
    {
        "id": "network",
        "name": "Network Only",
        "desc": "Interfaces, routes, listeners, active sessions, firewall and network shares.",
    },
]

# ============================================================
# COMMAND HELPERS
# ============================================================

def run(command, timeout=25, privileged=False):
    """
    Run a shell command.
    privileged=True uses sudo -n if sudo auth is available.
    If sudo is unavailable, returns a clean skip marker.
    """
    try:
        if privileged and os.geteuid() != 0:
            if not SUDO_READY:
                return "[skipped: sudo unavailable]"
            argv = ["sudo", "-n", "bash", "-lc", command]
        else:
            argv = ["bash", "-lc", command]

        p = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
        )
        out = p.stdout.strip()

        if p.returncode != 0 and not out:
            return f"[command exited {p.returncode}]"

        return out

    except subprocess.TimeoutExpired:
        return "[timeout]"

    except FileNotFoundError as e:
        return f"[missing command: {e.filename}]"

    except Exception as e:
        return f"[error: {e}]"


def command_exists(name):
    return subprocess.run(
        ["bash", "-lc", f"command -v {shlex.quote(name)} >/dev/null 2>&1"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ).returncode == 0


def add(severity, title, why, evidence="", next_step="", category="General"):
    """Add or merge a finding so duplicate detections do not spam the UI."""
    evidence = (evidence or "").strip()

    if evidence.startswith("[skipped:"):
        return

    key = (severity, category, title)

    if key in FINDING_INDEX:
        existing = FINDING_INDEX[key]

        if evidence and evidence not in existing["evidence"]:
            existing["evidence"] = (
                existing["evidence"] + "\n\n--- additional evidence ---\n" + evidence
                if existing["evidence"] else evidence
            )

        if next_step and next_step not in existing["next"]:
            existing["next"] = (
                existing["next"] + " " + next_step.strip()
                if existing["next"] else next_step.strip()
            )
        return

    finding = {
        "severity": severity,
        "title": title,
        "why": why.strip(),
        "evidence": evidence,
        "next": next_step.strip(),
        "category": category,
    }

    FINDINGS.append(finding)
    FINDING_INDEX[key] = finding


def add_raw(title, command, privileged=False, timeout=30):
    RAW_SECTIONS.append({
        "title": title,
        "output": run(command, timeout=timeout, privileged=privileged),
    })


def mode(path):
    try:
        return stat.S_IMODE(os.stat(path).st_mode)
    except OSError:
        return None


def owner(path):
    try:
        return pwd.getpwuid(os.stat(path).st_uid).pw_name
    except Exception:
        return "?"


def file_identity(path):
    """Return mode/owner/group metadata without raising."""
    try:
        st = os.stat(path)
        return {
            "mode": stat.S_IMODE(st.st_mode),
            "uid": st.st_uid,
            "gid": st.st_gid,
            "owner": pwd.getpwuid(st.st_uid).pw_name,
            "group": grp.getgrgid(st.st_gid).gr_name,
        }
    except Exception:
        return None


def group_users(gid):
    """
    Return users who can act as members of gid, including users whose
    primary GID is this group and supplementary group members.
    """
    users = set()

    try:
        g = grp.getgrgid(gid)
        users.update(g.gr_mem)
    except KeyError:
        pass

    for p in pwd.getpwall():
        if p.pw_gid == gid:
            users.add(p.pw_name)

    return sorted(users)


def nonroot_group_users(gid):
    users = []

    for name in group_users(gid):
        try:
            if pwd.getpwnam(name).pw_uid != 0:
                users.append(name)
        except KeyError:
            continue

    return sorted(set(users))


def writable_exposure(path):
    """
    Describe whether a path is modifiable by a principal other than root.

    Important distinction:
      root:root 0775 is NOT treated as non-root writable merely because the
      group-write bit is present.  A group-write bit only matters when the
      owning group actually contains non-root users.

    Returns:
      (dangerous: bool, reason: str, metadata: dict|None)
    """
    meta = file_identity(path)

    if not meta:
        return False, "", None

    m = meta["mode"]

    if m & stat.S_IWOTH:
        return True, "world-writable", meta

    if m & stat.S_IWGRP:
        members = nonroot_group_users(meta["gid"])
        if members:
            return True, f"group-writable by non-root member(s): {', '.join(members)}", meta

    # A root-executed file owned by a non-root account is inherently
    # modifiable by that owner even when mode is 0755.
    if meta["uid"] != 0:
        return True, f"owned by non-root user {meta['owner']}", meta

    return False, "", meta


def nonroot_writable(path):
    dangerous, _, _ = writable_exposure(path)
    return dangerous


def package_path_candidates(path):
    """Return likely dpkg path spellings, including usrmerge aliases."""
    candidates = []

    def add_candidate(value):
        if value and value not in candidates:
            candidates.append(value)

    path = str(path)
    add_candidate(path)

    try:
        add_candidate(os.path.realpath(path))
    except Exception:
        pass

    swaps = (
        ("/usr/bin/", "/bin/"),
        ("/bin/", "/usr/bin/"),
        ("/usr/sbin/", "/sbin/"),
        ("/sbin/", "/usr/sbin/"),
        ("/usr/lib/", "/lib/"),
        ("/lib/", "/usr/lib/"),
    )

    for current in list(candidates):
        for prefix, alternate in swaps:
            if current.startswith(prefix):
                add_candidate(alternate + current[len(prefix):])

    return candidates


def parse_dpkg_search_line(line):
    """Parse package[:arch]: /path while preserving an architecture suffix."""
    if ": " not in line:
        return None, None

    package, matched_path = line.rsplit(": ", 1)
    return (package.strip() or None), (matched_path.strip() or None)


def package_owner(path):
    """Return (package, matched_path) using best-effort Debian/Kali provenance."""
    if not command_exists("dpkg-query"):
        return None, None

    for candidate in package_path_candidates(path):
        try:
            p = subprocess.run(
                ["dpkg-query", "-S", candidate],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=5,
            )
        except Exception:
            continue

        if p.returncode != 0 or not p.stdout.strip():
            continue

        for line in p.stdout.splitlines():
            package, matched_path = parse_dpkg_search_line(line)
            if package:
                return package, matched_path

    return None, None


def package_status(package):
    if not package or not command_exists("dpkg-query"):
        return None

    try:
        p = subprocess.run(
            ["dpkg-query", "-W", "-f=${db:Status-Abbrev}", package],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
        )
        return p.stdout.strip() if p.returncode == 0 else None
    except Exception:
        return None


def packaged_and_installed(path):
    pkg, matched_path = package_owner(path)
    status = package_status(pkg)
    return pkg, bool(status and status.startswith("ii")), matched_path


def path_evidence(path, extra=""):
    meta = file_identity(path)
    pkg, installed, matched_path = packaged_and_installed(path)

    lines = []

    if meta:
        lines.append(
            f"mode={oct(meta['mode'])} owner={meta['owner']} "
            f"group={meta['group']} path={path}"
        )

    if pkg:
        package_line = (
            f"package={pkg} status={'installed' if installed else 'unknown/not-installed'}"
        )
        if matched_path and matched_path != str(path):
            package_line += f" dpkg_path={matched_path}"
        lines.append(package_line)
    else:
        lines.append("package=UNOWNED/UNKNOWN")

    if extra:
        lines.append(extra)

    return "\n".join(lines)


def current_username():
    try:
        return pwd.getpwuid(os.getuid()).pw_name
    except Exception:
        return str(os.getuid())


# ============================================================
# SECURITY CHECKS
# ============================================================

def check_accounts():
    for p in pwd.getpwall():
        if p.pw_uid == 0 and p.pw_name != "root":
            add(
                "CRITICAL",
                f"Additional UID 0 account: {p.pw_name}",
                "UID 0 is root-equivalent. An unexpected second UID 0 account "
                "has unrestricted administrative control.",
                f"user={p.pw_name}\nuid=0\nhome={p.pw_dir}\nshell={p.pw_shell}",
                "Review login history, shell history, authorized_keys and account creation evidence.",
                "Accounts",
            )

    shadow = run(
        r"""awk -F: '($2==""){print $1}' /etc/shadow 2>/dev/null""",
        privileged=True,
    )
    if shadow and not shadow.startswith("["):
        add(
            "CRITICAL",
            "Account(s) with empty password hashes",
            "Depending on PAM/service configuration, an empty password hash may permit authentication without a password.",
            shadow,
            "Identify the accounts and determine whether local or remote login is possible.",
            "Accounts",
        )

    for group_name in ("sudo", "wheel", "docker", "lxd"):
        try:
            members = grp.getgrnam(group_name).gr_mem
        except KeyError:
            continue

        if not members:
            continue

        if group_name in ("docker", "lxd"):
            sev = "HIGH"
            why = (
                f"Membership in '{group_name}' can often provide practical "
                "root-equivalent control through the associated daemon."
            )
        else:
            sev = "INFO"
            why = "Administrative group membership expands privileges and should be intentional."

        add(
            sev,
            f"Privileged group: {group_name}",
            why,
            ", ".join(members),
            "Verify each member is expected and review recent activity.",
            "Accounts",
        )


def check_sudo():
    output = run("sudo -n -l 2>/dev/null")

    if not output or "not allowed to run sudo" in output.lower():
        return

    lines = [x for x in output.splitlines() if "NOPASSWD" in x]

    if lines:
        evidence = "\n".join(lines)
        unrestricted = bool(re.search(r"NOPASSWD:\s*ALL", evidence))

        add(
            "CRITICAL" if unrestricted else "HIGH",
            "Passwordless sudo rule",
            "Passwordless sudo can turn compromise of the account into immediate privileged command execution.",
            evidence,
            "Determine whether the permitted commands can spawn shells, interpreters, editors, package managers or arbitrary files.",
            "Privilege",
        )


def check_path():
    """
    Review the interactive user's PATH without treating a private, user-owned
    ~/bin-style directory as a privilege-escalation vulnerability by itself.
    """
    current_path = os.environ.get("PATH", "")
    me = current_username()

    for directory in current_path.split(":"):
        if directory == "":
            add(
                "MEDIUM",
                "Empty PATH component",
                "An empty PATH element can resolve commands from the current "
                "working directory. The risk becomes serious when a privileged "
                "script inherits that PATH.",
                current_path,
                "Remove empty PATH components and verify privileged jobs use a controlled PATH.",
                "Privilege",
            )
            continue

        meta = file_identity(directory)
        if not meta:
            continue

        # World writable is always noteworthy.
        if meta["mode"] & stat.S_IWOTH:
            add(
                "HIGH",
                f"World-writable PATH directory: {directory}",
                "Any local user could plant or replace a command in this PATH directory.",
                path_evidence(directory),
                "Identify who uses this PATH and whether any privileged process inherits it.",
                "Privilege",
            )
            continue

        # Group writable matters only when another non-root account actually
        # belongs to that group.
        if meta["mode"] & stat.S_IWGRP:
            members = [u for u in nonroot_group_users(meta["gid"]) if u != me]
            if members:
                add(
                    "MEDIUM",
                    f"Shared group-writable PATH directory: {directory}",
                    "Another non-root account can modify a directory used for command resolution.",
                    path_evidence(directory, f"other_writers={','.join(members)}"),
                    "Determine whether privileged scripts inherit this PATH or execute bare command names.",
                    "Privilege",
                )

        # A private user-owned ~/.local/bin or ~/.deno/bin is normal and is
        # intentionally not emitted as a finding merely because its owner can
        # write it.


def check_privileged_path():
    """
    Inspect root/sudo PATH separately.  A writable directory is only elevated
    here when a privileged command-resolution context can actually reach it.
    """
    privileged_path = ""

    if SUDO_READY or os.geteuid() == 0:
        privileged_path = run(
            r"""printf '%s' "$PATH" """,
            privileged=True,
        )

    if not privileged_path or privileged_path.startswith("["):
        return

    me = current_username()

    for directory in privileged_path.split(":"):
        if not directory:
            add(
                "HIGH",
                "Empty component in privileged PATH",
                "Root command resolution may search the current directory.",
                privileged_path,
                "Use a fixed absolute PATH for privileged jobs.",
                "Privilege",
            )
            continue

        meta = file_identity(directory)
        if not meta:
            continue

        dangerous, reason, _ = writable_exposure(directory)

        if dangerous:
            add(
                "HIGH",
                f"Privileged PATH includes modifiable directory: {directory}",
                "A privileged process may resolve commands from a location modifiable by a non-root principal.",
                path_evidence(directory, f"exposure={reason}\nprivileged_PATH={privileged_path}"),
                "Trace root scripts/services using bare command names and remove the writable directory from privileged PATH.",
                "Privilege",
            )


def check_suid():
    result = run(
        r"""
        find / -xdev -type f \( -perm -4000 -o -perm -2000 \) \
        -printf '%m %u %g %p\n' 2>/dev/null
        """,
        timeout=50,
        privileged=True,
    )

    if not result or result.startswith("["):
        return

    packaged_context = []

    for line in result.splitlines():
        parts = line.split(maxsplit=3)
        if len(parts) != 4:
            continue

        path = parts[3]
        pkg, installed, matched_path = packaged_and_installed(path)
        dangerous, exposure, _ = writable_exposure(path)

        if dangerous:
            add(
                "CRITICAL",
                f"Privileged executable is modifiable: {path}",
                "A SUID/SGID executable runs with elevated identity and can be "
                "modified by a non-root principal. That creates a direct privilege-escalation condition.",
                path_evidence(path, f"exposure={exposure}\\nraw={line}"),
                "Preserve timestamps/hash, identify every writer, and verify the file against its package before changing it.",
                "Privilege",
            )
            continue

        if pkg and installed:
            packaged_context.append(path_evidence(path, f"raw={line}"))
            continue

        add(
            "HIGH",
            f"Unpackaged/unknown privileged executable: {path}",
            "A SUID/SGID binary with no confirmed package provenance deserves "
            "manual review because it executes with elevated identity.",
            path_evidence(path, f"raw={line}"),
            f"Inspect stat/file/hash/strings for {path} and determine who installed it.",
            "Privilege",
        )

    if packaged_context:
        add(
            "INFO",
            f"Package-managed SUID/SGID executables ({len(packaged_context)})",
            "These executables have SUID/SGID privileges but are owned by installed "
            "Debian/Kali packages and were not found modifiable by a non-root principal. "
            "Package ownership lowers suspicion but does not prove file integrity.",
            "\\n\\n".join(packaged_context),
            "Review individual entries only if unexpected; verify package/file integrity when warranted.",
            "Privilege",
        )


def check_capabilities():
    result = run("getcap -r / 2>/dev/null", timeout=50, privileged=True)

    if not result or result.startswith("["):
        return

    capability_risk = {
        "cap_setuid": ("HIGH", "Can change process UID, potentially becoming root."),
        "cap_setgid": ("HIGH", "Can change process group identity."),
        "cap_sys_admin": ("HIGH", "Very broad kernel-level administrative capability."),
        "cap_dac_override": ("HIGH", "Can bypass normal filesystem permission checks."),
        "cap_sys_ptrace": ("HIGH", "Can inspect or manipulate other processes."),
        "cap_net_admin": ("MEDIUM", "Can alter network configuration/interfaces."),
        "cap_net_raw": ("LOW", "Can create raw/packet sockets for capture or crafted traffic."),
        "cap_net_bind_service": ("LOW", "Can bind privileged TCP/UDP ports."),
        "cap_sys_nice": ("LOW", "Can adjust scheduling priority beyond normal user limits."),
    }

    package_managed_context = []

    for line in result.splitlines():
        if " " not in line:
            continue

        path, cap_text = line.split(None, 1)
        hits = [(cap, *capability_risk[cap]) for cap in capability_risk if cap in line]
        if not hits:
            continue

        pkg, installed, matched_path = packaged_and_installed(path)
        dangerous, exposure, _ = writable_exposure(path)

        highest = min(
            (SEVERITY_ORDER[sev] for _, sev, _ in hits),
            default=SEVERITY_ORDER["INFO"],
        )
        raw_sev = next(k for k, v in SEVERITY_ORDER.items() if v == highest)
        explanations = " ".join(expl for _, _, expl in hits)

        if dangerous:
            add(
                "CRITICAL",
                f"Capability-bearing executable is modifiable: {path}",
                "Linux capabilities grant elevated kernel privileges without full SUID root. "
                "Because this executable is modifiable by a non-root principal, those privileges "
                "may be transferable to modified code.",
                path_evidence(path, f"capabilities={cap_text}\\nexposure={exposure}"),
                "Preserve and verify the file, identify all writers, and compare against package integrity.",
                "Privilege",
            )
            continue

        strong = any(
            cap in {"cap_setuid", "cap_setgid", "cap_sys_admin", "cap_dac_override", "cap_sys_ptrace"}
            for cap, _, _ in hits
        )

        if pkg and installed and not strong:
            package_managed_context.append(path_evidence(path, f"capabilities={cap_text}"))
            continue

        why = explanations
        if pkg and installed:
            why += f" The file is package-managed by '{pkg}', but the capability is powerful enough to remain a review item."
        else:
            why += " No owning Debian/Kali package was confirmed, increasing review priority."

        add(
            raw_sev,
            f"Privileged file capability: {path}",
            why,
            path_evidence(path, f"capabilities={cap_text}"),
            "Confirm the capability is required, verify package/file integrity, and remove unnecessary capabilities.",
            "Privilege",
        )

    if package_managed_context:
        add(
            "INFO",
            f"Package-managed capability-bearing executables ({len(package_managed_context)})",
            "These files carry elevated Linux capabilities and are owned by installed packages. "
            "This is attack-surface context, not proof that the capability is expected or that the file is unmodified.",
            "\\n\\n".join(package_managed_context),
            "Review unexpected entries and verify package/file integrity when warranted.",
            "Privilege",
        )


def check_sensitive_files():
    targets = (
        "/etc/passwd",
        "/etc/shadow",
        "/etc/group",
        "/etc/sudoers",
        "/etc/ssh/sshd_config",
    )

    for path in targets:
        if not os.path.exists(path):
            continue

        m = mode(path)
        if m is not None and m & 0o022:
            add(
                "CRITICAL",
                f"Sensitive file writable by non-root: {path}",
                "Modification could alter accounts, authentication, sudo policy or remote-access controls.",
                f"mode={oct(m)} owner={owner(path)} path={path}",
                "Review timestamps and ownership before changing permissions so possible tampering evidence is preserved.",
                "Permissions",
            )

    output = run(
        r"""
        find /etc /usr/local /opt -xdev -type f -perm -0002 \
        -printf '%m %u %g %p\n' 2>/dev/null | head -100
        """,
        timeout=35,
        privileged=True,
    )

    if output and not output.startswith("["):
        add(
            "HIGH",
            "World-writable files in sensitive directories",
            "Privileged software may consume these files, creating persistence or privilege-escalation opportunities.",
            output[:5000],
            "Determine which services, cron jobs or root scripts reference each writable file.",
            "Permissions",
        )


def check_ssh():
    if not command_exists("sshd"):
        return

    config = run("sshd -T 2>/dev/null", privileged=True)
    if not config or config.startswith("["):
        return

    values = {}
    for line in config.splitlines():
        if " " in line:
            key, value = line.split(None, 1)
            values[key] = value

    context_keys = (
        "passwordauthentication",
        "permitrootlogin",
        "pubkeyauthentication",
        "permitemptypasswords",
        "maxauthtries",
        "allowusers",
        "allowgroups",
        "listenaddress",
    )
    context = "\\n".join(f"{key} {values[key]}" for key in context_keys if key in values)

    if values.get("permitemptypasswords") == "yes":
        add(
            "CRITICAL",
            "SSH permits empty passwords",
            "An account without a password may be able to authenticate remotely.",
            context,
            "Disable empty-password authentication and inspect affected accounts.",
            "Remote Access",
        )

    if values.get("permitrootlogin") == "yes":
        add(
            "HIGH",
            "Direct root SSH login enabled",
            "Remote root login removes privilege separation and increases the impact of stolen root credentials.",
            context,
            "Prefer individual user accounts plus controlled sudo escalation.",
            "Remote Access",
        )

    if values.get("passwordauthentication") == "yes":
        severity = "MEDIUM" if values.get("permitrootlogin") == "yes" else "LOW"
        add(
            severity,
            "SSH password authentication enabled",
            "Password authentication is not inherently a vulnerability, but it increases exposure "
            "to password guessing, credential reuse and credential theft. Severity depends on account policy and network reachability.",
            context,
            "Confirm strong credentials, sensible MaxAuthTries, intended listen addresses, and whether key-only authentication fits this host.",
            "Remote Access",
        )


def check_network():
    listeners = run("ss -H -lntup 2>/dev/null")

    notable_ports = {
        21: ("FTP", "MEDIUM"),
        23: ("Telnet", "HIGH"),
        111: ("RPC", "MEDIUM"),
        2049: ("NFS", "MEDIUM"),
        3306: ("MySQL", "MEDIUM"),
        5432: ("PostgreSQL", "MEDIUM"),
        6379: ("Redis", "MEDIUM"),
        9200: ("Elasticsearch", "MEDIUM"),
        11211: ("Memcached", "MEDIUM"),
    }

    for line in listeners.splitlines():
        match = re.search(r'(?:0\.0\.0\.0|\*|\[::\]|::):(\d+)', line)
        if not match:
            continue

        port = int(match.group(1))
        if port in notable_ports:
            name, sev = notable_ports[port]
            add(
                sev,
                f"{name} exposed on all interfaces",
                "The service may be reachable from every connected network unless another firewall/access-control layer restricts it.",
                line,
                "Identify the owning process, authentication requirements, firewall policy and whether broad exposure is intentional.",
                "Network",
            )


def check_firewall():
    ufw = run("ufw status 2>/dev/null", privileged=True)
    nft = run("nft list ruleset 2>/dev/null", privileged=True)
    iptables = run("iptables -S 2>/dev/null", privileged=True)

    vals = [ufw, nft, iptables]
    readable = [x for x in vals if x and not x.startswith("[")]

    if not readable and not SUDO_READY and os.geteuid() != 0:
        add(
            "INFO",
            "Firewall state could not be fully inspected",
            "Firewall inspection commonly requires elevated privileges.",
            "sudo was not available for this scan",
            "Re-run the mode with sudo authentication to inspect host firewall policy.",
            "Network",
        )
        return

    if "inactive" in ufw.lower() and not nft and not iptables:
        add(
            "MEDIUM",
            "No active host firewall detected",
            "Without host-level filtering, listening services may be reachable from any attached network.",
            ufw or "No UFW/nftables/iptables rules returned.",
            "Determine whether filtering occurs upstream or whether host firewall rules should be configured.",
            "Network",
        )


def parse_service_user(text):
    """Systemd services run as root unless User= says otherwise."""
    run_user = "root"

    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("User="):
            candidate = stripped.split("=", 1)[1].strip()
            if candidate:
                run_user = candidate

    return run_user


def resolve_command(command, path_value=None):
    if not command:
        return None

    if os.path.isabs(command):
        return command if os.path.exists(command) else command

    search_path = path_value or os.environ.get("PATH", "")

    for directory in search_path.split(":"):
        if not directory:
            continue
        candidate = os.path.join(directory, command)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate

    return None


def interpreter_script_candidate(tokens):
    if len(tokens) < 2:
        return None

    interpreter = os.path.basename(tokens[0])

    if interpreter in {
        "python", "python2", "python3", "perl", "ruby",
        "bash", "sh", "dash", "zsh", "node", "php",
    }:
        for token in tokens[1:]:
            if token.startswith("-"):
                continue
            if os.path.isabs(token) and os.path.isfile(token):
                return token
            break

    return None


def parse_execstart(text):
    results = []

    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("ExecStart="):
            continue

        value = line.split("=", 1)[1].lstrip("-@:+!")

        try:
            tokens = shlex.split(value)
        except ValueError:
            tokens = value.split()

        if not tokens:
            continue

        if tokens[0].startswith("/"):
            results.append(tokens[0])

        script = interpreter_script_candidate(tokens)
        if script:
            results.append(script)

    return list(dict.fromkeys(results))


def principal_info(name):
    """Resolve a local account and its effective local group memberships."""
    try:
        p = pwd.getpwnam(name)
    except KeyError:
        return None

    groups = {p.pw_gid}

    for g in grp.getgrall():
        if name in g.gr_mem:
            groups.add(g.gr_gid)

    return {
        "name": p.pw_name,
        "uid": p.pw_uid,
        "gid": p.pw_gid,
        "groups": groups,
    }


def all_local_principals():
    principals = []

    for p in pwd.getpwall():
        info = principal_info(p.pw_name)
        if info:
            principals.append(info)

    return principals


def discover_file_writers(path):
    """
    Determine local identities that can modify a file using ordinary Unix DAC.

    Root is recorded because it always dominates normal DAC, but the trust
    classifier later treats root -> non-root control as expected administration,
    not as a vulnerability.

    ACLs, immutable flags, read-only mounts and MAC policy are deliberately not
    inferred here; those can be added as separate evidence layers later.
    """
    meta = file_identity(path)

    if not meta:
        return [], None

    writers = {
        0: {
            "name": "root",
            "uid": 0,
            "reason": "UID 0 can override ordinary DAC permissions",
        }
    }

    m = meta["mode"]

    if m & stat.S_IWUSR:
        writers[meta["uid"]] = {
            "name": meta["owner"],
            "uid": meta["uid"],
            "reason": "owner write permission",
        }

    if m & stat.S_IWGRP:
        for principal in all_local_principals():
            if meta["gid"] in principal["groups"]:
                writers[principal["uid"]] = {
                    "name": principal["name"],
                    "uid": principal["uid"],
                    "reason": f"group write permission via {meta['group']}",
                }

    if m & stat.S_IWOTH:
        for principal in all_local_principals():
            writers.setdefault(
                principal["uid"],
                {
                    "name": principal["name"],
                    "uid": principal["uid"],
                    "reason": "world write permission",
                },
            )

    return sorted(writers.values(), key=lambda item: (item["uid"], item["name"])), meta


def trust_relationship(writer_uid, execution_uid):
    """
    Directional trust relationship.

    Root -> non-root is expected administrative control and is not an attacker
    path. The interesting direction is a lower-trust or unrelated principal
    controlling code executed by another identity.
    """
    if writer_uid == execution_uid:
        return "same-identity"

    if writer_uid == 0:
        return "same-identity" if execution_uid == 0 else "higher-trust-writer"

    if execution_uid == 0:
        return "lower-trust-writer"

    return "cross-account-writer"


def trust_boundary_assessment(path, run_user):
    """
    Analyze who can modify `path` relative to the identity executing it.

    Returns a structured dictionary even when there is no finding so callers
    can explain why an apparent write relationship is or is not dangerous.
    """
    execution = principal_info(run_user)

    if not execution:
        return {
            "valid": False,
            "finding": False,
            "severity": None,
            "reason": f"execution identity could not be resolved: {run_user}",
            "evidence": f"execution_user={run_user}\\nidentity_resolution=FAILED",
        }

    writers, meta = discover_file_writers(path)

    if meta is None:
        return {
            "valid": False,
            "finding": False,
            "severity": None,
            "reason": f"target metadata could not be read: {path}",
            "evidence": f"execution_user={run_user}\\ntarget={path}\\nmetadata=FAILED",
        }

    threatening = []
    same_identity = []
    higher_trust = []

    for writer in writers:
        relationship = trust_relationship(writer["uid"], execution["uid"])
        item = dict(writer)
        item["relationship"] = relationship

        if relationship in ("lower-trust-writer", "cross-account-writer"):
            threatening.append(item)
        elif relationship == "same-identity":
            same_identity.append(item)
        else:
            higher_trust.append(item)

    boundary = bool(threatening)

    same_identity_persistence = (
        not boundary
        and execution["uid"] != 0
        and any(item["uid"] == execution["uid"] for item in same_identity)
    )

    if boundary and execution["uid"] == 0:
        severity = "CRITICAL"
        reason = (
            "non-root principal(s) can modify code executed as root: "
            + ", ".join(item["name"] for item in threatening)
        )
    elif boundary:
        severity = "MEDIUM"
        reason = (
            f"unrelated account(s) can modify code executed as {run_user}: "
            + ", ".join(item["name"] for item in threatening)
        )
    else:
        severity = None
        reason = "no lower-trust or unrelated writer crosses the execution boundary"

    def describe(items):
        if not items:
            return "NONE"
        return ", ".join(
            f"{item['name']} [{item['reason']}]"
            for item in items
        )

    evidence = "\\n".join([
        "TRUST RELATIONSHIP",
        f"execution_user={execution['name']} uid={execution['uid']}",
        f"target_owner={meta['owner']} uid={meta['uid']}",
        f"target_group={meta['group']} gid={meta['gid']}",
        f"target_mode={oct(meta['mode'])}",
        f"all_writers={describe(writers)}",
        f"same_identity_writers={describe(same_identity)}",
        f"higher_trust_writers={describe(higher_trust)}",
        f"threatening_writers={describe(threatening)}",
        f"privilege_boundary={'YES' if boundary else 'NO'}",
        f"same_identity_persistence={'YES' if same_identity_persistence else 'NO'}",
    ])

    return {
        "valid": True,
        "finding": boundary,
        "severity": severity,
        "reason": reason,
        "evidence": evidence,
        "same_identity_persistence": same_identity_persistence,
        "threatening_writers": threatening,
    }


def execution_boundary(path, run_user):
    """Return None or (severity, reason, trust_evidence)."""
    assessment = trust_boundary_assessment(path, run_user)

    if not assessment["valid"] or not assessment["finding"]:
        return None

    return (
        assessment["severity"],
        assessment["reason"],
        assessment["evidence"],
    )


def check_systemd():
    roots = ("/etc/systemd/system", "/usr/local/lib/systemd/system")
    seen_units = set()

    for base in roots:
        root = Path(base)
        if not root.exists():
            continue

        for discovered_unit in root.rglob("*.service"):
            try:
                if not discovered_unit.is_file():
                    continue

                unit = Path(os.path.realpath(discovered_unit))
                canonical = str(unit)

                if canonical in seen_units:
                    continue

                seen_units.add(canonical)
                service_text = unit.read_text(errors="ignore")
            except OSError:
                continue

            run_user = parse_service_user(service_text)

            # Unit definitions themselves are interpreted by systemd/root,
            # regardless of the User= used for the service payload.
            unit_boundary = execution_boundary(unit, "root")

            if unit_boundary:
                severity, reason, trust_evidence = unit_boundary

                add(
                    "HIGH" if severity == "CRITICAL" else severity,
                    f"Systemd unit modifiable across privilege boundary: {unit}",
                    "Systemd unit definitions determine what services execute. "
                    "Modification by a lower-trust principal can alter service behavior.",
                    path_evidence(
                        unit,
                        f"service_user={run_user}\\nexposure={reason}\\n{trust_evidence}",
                    ),
                    f"Review `systemctl cat {unit.name}` and identify every principal able to modify the unit.",
                    "Persistence",
                )

            for executable in parse_execstart(service_text):
                if not os.path.exists(executable):
                    continue

                boundary = execution_boundary(executable, run_user)

                if not boundary:
                    continue

                severity, reason, trust_evidence = boundary

                add(
                    severity,
                    f"Service execution target modifiable across boundary: {executable}",
                    "A service executes code controlled by a lower-trust or "
                    "unrelated principal relative to the service identity.",
                    (
                        f"unit={unit}\\n"
                        f"service_user={run_user}\\n"
                        f"{path_evidence(executable, f'exposure={reason}')}\\n"
                        f"{trust_evidence}"
                    ),
                    "Inspect service status, timestamps, hashes, ownership and "
                    "the principals able to modify this target.",
                    "Persistence",
                )


def parse_cron_entry(entry):
    """Parse /etc/crontab and /etc/cron.d entries into (run_user, command)."""
    stripped = entry.strip()

    if not stripped or stripped.startswith("#"):
        return None, None

    if re.match(r"^[A-Za-z_][A-Za-z0-9_]*\s*=", stripped):
        return None, None

    parts = stripped.split()
    if not parts:
        return None, None

    if parts[0].startswith("@"):
        if len(parts) < 3:
            return None, None
        return parts[1], " ".join(parts[2:])

    if len(parts) < 7:
        return None, None

    return parts[5], " ".join(parts[6:])


def cron_command_tokens(command):
    """
    Return command names from common shell chains while excluding redirect
    destinations such as log files.
    """
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars="|&;<>")
        lexer.whitespace_split = True
        lexer.commenters = ""
        tokens = list(lexer)
    except Exception:
        try:
            tokens = shlex.split(command)
        except Exception:
            tokens = command.split()

    commands = []
    expect_command = True
    skip_redirect_target = False
    i = 0

    separators = {"|", "||", "&&", ";", "&"}
    redirects = {">", ">>", "<", "<<", "<<<", "<>", ">|"}

    while i < len(tokens):
        token = tokens[i]

        if token.isdigit() and i + 1 < len(tokens) and tokens[i + 1] in redirects:
            i += 1
            token = tokens[i]

        if token in redirects or re.fullmatch(r"\d*(?:>|>>|<|<<|<<<|<>|>\|)", token):
            skip_redirect_target = True
            i += 1
            continue

        if skip_redirect_target:
            skip_redirect_target = False
            i += 1
            continue

        if token in separators:
            expect_command = True
            i += 1
            continue

        if expect_command:
            if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", token):
                i += 1
                continue

            commands.append(token)
            expect_command = False

        i += 1

    return commands


def cron_path_from_file(lines):
    path_value = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

    for line in lines:
        match = re.match(r"^\s*PATH\s*=\s*(.*)$", line)
        if match:
            value = match.group(1).strip().strip("'\\\"")
            if value:
                path_value = value.replace("$PATH", path_value)

    return path_value


def check_cron():
    files = []

    crontab = Path("/etc/crontab")
    if crontab.is_file():
        files.append(crontab)

    crond = Path("/etc/cron.d")
    if crond.is_dir():
        files.extend(x for x in crond.iterdir() if x.is_file())

    for cronfile in files:
        # Cron configuration is interpreted by root/system cron infrastructure.
        cron_boundary = execution_boundary(cronfile, "root")

        if cron_boundary:
            severity, reason, trust_evidence = cron_boundary

            add(
                "HIGH" if severity == "CRITICAL" else severity,
                f"Cron configuration modifiable across privilege boundary: {cronfile}",
                "System cron configuration controls scheduled command execution. "
                "Modification by a lower-trust principal can alter scheduled behavior.",
                path_evidence(
                    cronfile,
                    f"exposure={reason}\\n{trust_evidence}",
                ),
                "Review ownership, group membership and modification history for the cron file.",
                "Persistence",
            )

        try:
            lines = cronfile.read_text(errors="ignore").splitlines()
        except OSError:
            continue

        cron_path = cron_path_from_file(lines)

        for raw_entry in lines:
            run_user, command = parse_cron_entry(raw_entry)

            if not run_user or not command:
                continue

            for command_name in cron_command_tokens(command):
                executable = resolve_command(command_name, cron_path)

                if not executable or not os.path.isfile(executable):
                    continue

                boundary = execution_boundary(executable, run_user)

                if not boundary:
                    continue

                severity, reason, trust_evidence = boundary

                add(
                    severity,
                    f"Cron execution target modifiable across boundary: {executable}",
                    "A scheduled command executes code controlled by a lower-trust "
                    "or unrelated principal. Redirect destinations and log files "
                    "are excluded from this analysis.",
                    (
                        f"cron={cronfile}\\n"
                        f"run_user={run_user}\\n"
                        f"entry={raw_entry.strip()}\\n"
                        f"{path_evidence(executable, f'exposure={reason}')}\\n"
                        f"{trust_evidence}"
                    ),
                    "Inspect the executable, cron execution identity, ownership "
                    "and every principal able to modify it.",
                    "Persistence",
                )


def check_mounts():
    mounts = run("findmnt -rn -o TARGET,SOURCE,FSTYPE,OPTIONS 2>/dev/null")

    for line in mounts.splitlines():
        fields = line.split()
        if len(fields) < 4:
            continue

        target, _, fstype, options = fields[:4]

        if fstype in ("cifs", "nfs", "nfs4"):
            add(
                "INFO",
                f"Network filesystem mounted: {target}",
                "Network storage expands the host trust boundary. This is often legitimate but security-relevant.",
                line,
                "Review mount options, credential-file permissions and whether privileged jobs consume remote writable content.",
                "Network",
            )

        if target in ("/tmp", "/var/tmp") and "noexec" not in options:
            add(
                "LOW",
                f"Hardening: {target} mounted without noexec",
                "The mount does not use the noexec hardening option. This may make payload staging more convenient, but noexec is not a security boundary and its absence is not a vulnerability by itself.",
                line,
                "Treat this as hardening context, not proof of compromise.",
                "Hardening",
            )


def check_kernel():
    tests = [
        (
            "/proc/sys/kernel/randomize_va_space",
            "2",
            "ASLR not fully enabled",
            "Full address-space randomization makes memory exploitation less predictable.",
        ),
        (
            "/proc/sys/kernel/dmesg_restrict",
            "1",
            "Unprivileged dmesg access allowed",
            "Kernel logs can expose system internals useful to an attacker.",
        ),
    ]

    for path, desired, title, why in tests:
        try:
            value = Path(path).read_text().strip()
        except OSError:
            continue

        if value != desired:
            add(
                "LOW",
                title,
                why,
                f"{path}={value}",
                "Confirm compatibility requirements before changing kernel hardening settings.",
                "Hardening",
            )


def check_temp_execs():
    result = run(
        r"""
        find /tmp /var/tmp /dev/shm -xdev -type f -perm /111 -mtime -7 \
        -printf '%TY-%Tm-%Td %TH:%TM %u %m %p\n' 2>/dev/null |
        sort -r | head -60
        """,
        timeout=25,
        privileged=True,
    )

    if result and not result.startswith("["):
        add(
            "MEDIUM",
            "Recent executable files in temporary directories",
            "Temporary directories are common staging locations for legitimate installers and malicious payloads.",
            result,
            "Inspect file type, owner, hash, timestamps, process references and whether the files belong to legitimate software.",
            "Triage",
        )


def check_auth_anomalies():
    auth = run(
        r"""
        grep -Eai 'failed password|invalid user|authentication failure|accepted password|accepted publickey|sudo:' \
        /var/log/auth.log 2>/dev/null | tail -200
        """,
        privileged=True,
    )

    if not auth or auth.startswith("["):
        return

    failed = sum(
        1 for line in auth.splitlines()
        if re.search(r"failed password|invalid user|authentication failure", line, re.I)
    )

    if failed >= 10:
        add(
            "MEDIUM",
            f"Multiple recent authentication failures ({failed})",
            "Repeated failures may indicate brute-force activity, password guessing or a misconfigured service.",
            "\n".join(auth.splitlines()[-40:]),
            "Group failures by source IP/user/time and compare with successful logins.",
            "Authentication",
        )


def check_recent_files():
    result = run(
        r"""
        find /etc /usr/local /opt /var/www /home \
        -xdev -type f -mtime -7 \
        -printf '%TY-%Tm-%Td %TH:%TM %u %g %m %p\n' 2>/dev/null |
        sort -r | head -250
        """,
        timeout=40,
        privileged=True,
    )

    if result and not result.startswith("["):
        add(
            "INFO",
            "Recently modified files in security-relevant locations",
            "Recent changes are useful forensic context but are not automatically suspicious.",
            result[:6000],
            "Correlate unexpected changes with users, package activity, service changes and incident timing.",
            "Triage",
        )


def trust_engine_self_test():
    """Run non-destructive trust-direction sanity checks."""
    cases = [
        ("root controls non-root execution", 0, 999, "higher-trust-writer"),
        ("same account", 999, 999, "same-identity"),
        ("non-root controls root execution", 1000, 0, "lower-trust-writer"),
        ("unrelated non-root accounts", 1000, 999, "cross-account-writer"),
        ("root controls root execution", 0, 0, "same-identity"),
    ]

    messages = []
    passed = True

    for name, writer_uid, execution_uid, expected in cases:
        got = trust_relationship(writer_uid, execution_uid)
        ok = got == expected
        passed = passed and ok
        messages.append(
            f"{'PASS' if ok else 'FAIL'}: {name}: expected={expected} got={got}"
        )

    return passed, messages


# ============================================================
# RAW TRIAGE / NETWORK COLLECTION
# ============================================================

def collect_full_triage():
    add_raw("System Identity", "date; hostnamectl 2>/dev/null || hostname; uname -a; cat /etc/os-release 2>/dev/null; uptime")
    add_raw("Users and Groups", "cat /etc/passwd; echo; cat /etc/group")
    add_raw("Current / Historical Logins", "who; echo; w; echo; last -n 50; echo; lastb -n 30 2>/dev/null", privileged=True)
    add_raw("Network Interfaces / Routes", "ip -br addr; echo; ip route; echo; ip neigh")
    add_raw("Listening Services", "ss -lntup")
    add_raw("Active Connections", "ss -tunap")
    add_raw("Processes", "ps auxww")
    add_raw("Mounts / Disks", "findmnt; echo; lsblk -f; echo; df -hT")
    add_raw("Running Services", "systemctl --no-pager --type=service --state=running 2>/dev/null")
    add_raw("Enabled Services", "systemctl list-unit-files --state=enabled --no-pager 2>/dev/null")
    add_raw("Timers", "systemctl list-timers --all --no-pager 2>/dev/null")
    add_raw("Cron", "ls -la /etc/cron* /var/spool/cron* 2>/dev/null", privileged=True)
    add_raw("SSH Configuration", "sshd -T 2>/dev/null", privileged=True)
    add_raw("Shell Histories", r"""for f in /home/*/.bash_history /root/.bash_history; do [ -f "$f" ] && echo "--- $f ---" && tail -200 "$f"; done""", privileged=True)
    add_raw("Recent Auth Activity", "tail -300 /var/log/auth.log 2>/dev/null", privileged=True)
    add_raw("Recent Syslog", "tail -300 /var/log/syslog 2>/dev/null", privileged=True)
    add_raw("APT History", "cat /var/log/apt/history.log 2>/dev/null; echo; tail -200 /var/log/dpkg.log 2>/dev/null", privileged=True)
    add_raw("Kernel Warnings / Errors", "dmesg --level=emerg,alert,crit,err,warn 2>/dev/null | tail -250", privileged=True)
    add_raw("Recent Files", r"""find /etc /usr/local /opt /var/www /home -xdev -type f -mtime -7 -printf '%TY-%Tm-%Td %TH:%TM %u %g %m %p\n' 2>/dev/null | sort -r | head -400""", privileged=True)


def collect_network_raw():
    add_raw("Interfaces", "ip -br addr")
    add_raw("Routes", "ip route")
    add_raw("ARP / Neighbors", "ip neigh")
    add_raw("Listening TCP/UDP", "ss -lntup")
    add_raw("Active TCP/UDP Sessions", "ss -tunap")
    add_raw("DNS Configuration", "cat /etc/resolv.conf 2>/dev/null")
    add_raw("Network Mounts", "findmnt -t cifs,nfs,nfs4 2>/dev/null")
    add_raw("UFW", "ufw status verbose 2>/dev/null", privileged=True)
    add_raw("nftables", "nft list ruleset 2>/dev/null", privileged=True)
    add_raw("iptables", "iptables -S 2>/dev/null", privileged=True)


# ============================================================
# MODES
# ============================================================

MODE_CHECKS = {
    "full": [
        check_accounts,
        check_sudo,
        check_path,
        check_privileged_path,
        check_suid,
        check_capabilities,
        check_sensitive_files,
        check_ssh,
        check_network,
        check_firewall,
        check_systemd,
        check_cron,
        check_mounts,
        check_kernel,
        check_temp_execs,
        check_auth_anomalies,
        check_recent_files,
    ],
    "offensive": [
        check_accounts,
        check_sudo,
        check_path,
        check_privileged_path,
        check_suid,
        check_capabilities,
        check_sensitive_files,
        check_ssh,
        check_network,
        check_firewall,
        check_systemd,
        check_cron,
        check_mounts,
    ],
    "defensive": [
        check_accounts,
        check_ssh,
        check_network,
        check_firewall,
        check_systemd,
        check_cron,
        check_mounts,
        check_kernel,
        check_temp_execs,
        check_auth_anomalies,
        check_recent_files,
    ],
    "quick": [
        check_accounts,
        check_sudo,
        check_ssh,
        check_network,
        check_firewall,
        check_systemd,
        check_cron,
    ],
    "network": [
        check_network,
        check_firewall,
        check_mounts,
    ],
}


def perform_scan(mode_id, progress=None):
    global CURRENT_MODE

    CURRENT_MODE = mode_id
    FINDINGS.clear()
    FINDING_INDEX.clear()
    RAW_SECTIONS.clear()

    checks = MODE_CHECKS[mode_id]
    extra = 0

    if mode_id == "full":
        extra = 1
    elif mode_id == "network":
        extra = 1

    total = len(checks) + extra
    index = 0

    for fn in checks:
        index += 1
        name = fn.__name__.replace("check_", "").replace("_", " ").title()

        if progress:
            progress(name, index, total)

        try:
            fn()
        except Exception as e:
            add(
                "INFO",
                f"Check failed: {name}",
                "The scan could not complete this particular check.",
                str(e),
                "Run the area manually if it is important.",
                "Scanner",
            )

    if mode_id == "full":
        index += 1
        if progress:
            progress("Full raw triage collection", index, total)
        collect_full_triage()

    elif mode_id == "network":
        index += 1
        if progress:
            progress("Network evidence collection", index, total)
        collect_network_raw()

    FINDINGS.sort(
        key=lambda f: (
            SEVERITY_ORDER[f["severity"]],
            f["category"],
            f["title"].lower(),
        )
    )


# ============================================================
# REPORT SAVING
# ============================================================

def sanitize_filename(name):
    name = name.strip()

    if not name:
        return f"report_{datetime.now():%Y%m%d_%H%M%S}.txt"

    name = os.path.basename(name)

    if not name.lower().endswith(".txt"):
        name += ".txt"

    name = re.sub(r"[^A-Za-z0-9._ -]", "_", name)

    if name in ("", ".", "..", ".txt"):
        return f"report_{datetime.now():%Y%m%d_%H%M%S}.txt"

    return name


def build_report():
    mode_name = next(
        (m["name"] for m in MODE_DEFS if m["id"] == CURRENT_MODE),
        CURRENT_MODE or "Unknown",
    )

    counts = Counter(f["severity"] for f in FINDINGS)

    lines = [
        "=" * 78,
        "LINUX SECURITY AUDIT v5 (directional trust-aware)",
        "=" * 78,
        f"Host:      {run('hostname')}",
        f"Mode:      {mode_name}",
        f"Generated: {datetime.now().isoformat(timespec='seconds')}",
        f"Privilege: {'root' if os.geteuid() == 0 else ('sudo authenticated' if SUDO_READY else 'unprivileged / partial')}",
        "",
        "SUMMARY",
        "-" * 78,
    ]

    for sev in SEVERITY_ORDER:
        lines.append(f"{sev:8}: {counts.get(sev, 0)}")

    lines.extend(["", "FINDINGS", "=" * 78])

    if not FINDINGS:
        lines.append("No findings generated by the current checks.")

    for i, f in enumerate(FINDINGS, 1):
        lines.extend([
            "",
            f"#{i} [{f['severity']}] {f['title']}",
            f"Category: {f['category']}",
            "",
            "WHY IT MATTERS:",
            f["why"],
        ])

        if f["evidence"]:
            lines.extend(["", "EVIDENCE:", f["evidence"]])

        if f["next"]:
            lines.extend(["", "WHAT TO INSPECT NEXT:", f["next"]])

    if RAW_SECTIONS:
        lines.extend(["", "", "RAW EVIDENCE", "=" * 78])

        for section in RAW_SECTIONS:
            lines.extend([
                "",
                f"--- {section['title']} ---",
                section["output"] or "(no output)",
            ])

    return "\n".join(lines) + "\n"


# ============================================================
# TUI HELPERS
# ============================================================

def safe_addstr(win, y, x, text, attr=0):
    try:
        h, w = win.getmaxyx()
        if 0 <= y < h and 0 <= x < w:
            win.addnstr(y, x, str(text), max(0, w - x - 1), attr)
    except curses.error:
        pass


def wrapped(text, width):
    if not text:
        return []

    out = []
    for raw in text.splitlines():
        if raw == "":
            out.append("")
        else:
            out.extend(
                textwrap.wrap(
                    raw,
                    width=max(10, width),
                    replace_whitespace=False,
                    drop_whitespace=False,
                ) or [""]
            )
    return out


def severity_color(severity):
    return curses.color_pair({
        "CRITICAL": 1,
        "HIGH": 2,
        "MEDIUM": 3,
        "LOW": 4,
        "INFO": 5,
    }.get(severity, 5))


def message_box(stdscr, title, lines):
    stdscr.erase()
    h, w = stdscr.getmaxyx()

    safe_addstr(stdscr, 1, 2, title, curses.A_BOLD)

    y = 3
    for line in lines:
        for part in wrapped(line, w - 6):
            if y >= h - 2:
                break
            safe_addstr(stdscr, y, 2, part)
            y += 1

    safe_addstr(stdscr, h - 1, 1, "Press any key", curses.A_REVERSE)
    stdscr.refresh()
    stdscr.getch()


def text_prompt(stdscr, title, prompt):
    curses.curs_set(1)
    curses.echo()

    try:
        stdscr.erase()
        h, w = stdscr.getmaxyx()

        safe_addstr(stdscr, 1, 2, title, curses.A_BOLD)
        safe_addstr(stdscr, 3, 2, prompt)
        safe_addstr(stdscr, 5, 2, "> ")

        stdscr.refresh()

        raw = stdscr.getstr(5, 4, max(1, w - 8))
        return raw.decode(errors="replace").strip()

    except Exception:
        return ""

    finally:
        curses.noecho()
        curses.curs_set(0)


# ============================================================
# SUDO AUTH
# ============================================================

def request_sudo(stdscr):
    """
    Uses sudo's own password prompt. The Python script never sees/stores password.
    """
    global SUDO_READY

    if os.geteuid() == 0:
        SUDO_READY = True
        message_box(
            stdscr,
            "Privilege",
            ["Already running as root. Full privileged checks are available."],
        )
        return

    if not command_exists("sudo"):
        SUDO_READY = False
        message_box(
            stdscr,
            "Privilege",
            [
                "sudo is not installed.",
                "The scan will continue unprivileged and skip checks that require root access.",
            ],
        )
        return

    # If sudo credential cache already exists, use it without another prompt.
    cached = subprocess.run(
        ["sudo", "-n", "-v"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ).returncode == 0

    if cached:
        SUDO_READY = True
        message_box(
            stdscr,
            "Privilege",
            ["Existing sudo authentication is valid. Full privileged checks are available."],
        )
        return

    stdscr.erase()
    h, _ = stdscr.getmaxyx()

    safe_addstr(stdscr, 2, 2, "Privilege Request", curses.A_BOLD)
    safe_addstr(stdscr, 4, 2, "ENTER  - authenticate with sudo for a full scan")
    safe_addstr(stdscr, 5, 2, "S / ESC - skip sudo and continue with available checks")
    safe_addstr(stdscr, h - 1, 1, "Your password is handled by sudo, not by this script.", curses.A_DIM)
    stdscr.refresh()

    key = stdscr.getch()

    if key not in (10, 13, curses.KEY_ENTER):
        SUDO_READY = False
        return

    # Temporarily leave curses so sudo can securely own the terminal.
    curses.def_prog_mode()
    curses.endwin()

    try:
        rc = subprocess.run(["sudo", "-v"]).returncode
    except Exception:
        rc = 1

    curses.reset_prog_mode()
    stdscr.refresh()

    SUDO_READY = (rc == 0)

    if not SUDO_READY:
        message_box(
            stdscr,
            "Sudo unavailable",
            [
                "Sudo authentication was skipped, cancelled or failed.",
                "The scan will continue without elevated access.",
            ],
        )


# ============================================================
# MODE MENU
# ============================================================

def mode_menu(stdscr):
    selected = 0

    while True:
        stdscr.erase()
        h, w = stdscr.getmaxyx()

        safe_addstr(
            stdscr,
            0,
            0,
            " Linux Security Audit // Select Scan Mode ",
            curses.A_REVERSE | curses.A_BOLD,
        )

        safe_addstr(
            stdscr,
            2,
            2,
            "Choose a perspective. All modes are read-only.",
            curses.A_DIM,
        )

        y = 4

        for i, mode_def in enumerate(MODE_DEFS):
            attr = curses.A_REVERSE | curses.A_BOLD if i == selected else 0
            prefix = "▶" if i == selected else " "

            safe_addstr(
                stdscr,
                y,
                3,
                f"{prefix} {i + 1}. {mode_def['name']}",
                attr,
            )

            desc_lines = wrapped(mode_def["desc"], max(20, w - 10))
            for j, desc in enumerate(desc_lines[:2]):
                safe_addstr(
                    stdscr,
                    y + 1 + j,
                    7,
                    desc,
                    curses.A_DIM | (curses.A_REVERSE if i == selected else 0),
                )

            y += 4

        safe_addstr(
            stdscr,
            h - 1,
            0,
            " ↑↓ select | ENTER scan | 1-5 direct | q quit ",
            curses.A_REVERSE,
        )

        stdscr.refresh()
        key = stdscr.getch()

        if key in (ord("q"), 27):
            return None

        if key == curses.KEY_DOWN:
            selected = min(len(MODE_DEFS) - 1, selected + 1)

        elif key == curses.KEY_UP:
            selected = max(0, selected - 1)

        elif key in (10, 13, curses.KEY_ENTER):
            return MODE_DEFS[selected]["id"]

        elif ord("1") <= key <= ord("5"):
            return MODE_DEFS[key - ord("1")]["id"]


# ============================================================
# PROGRESS
# ============================================================

def scan_screen(stdscr, mode_id):
    mode_name = next(m["name"] for m in MODE_DEFS if m["id"] == mode_id)

    def progress(name, index, total):
        stdscr.erase()
        h, w = stdscr.getmaxyx()

        safe_addstr(stdscr, 2, 2, f"Scanning: {mode_name}", curses.A_BOLD)
        safe_addstr(stdscr, 4, 2, f"Check: {name}")

        bar_width = max(10, min(52, w - 10))
        filled = int(bar_width * index / max(1, total))

        safe_addstr(
            stdscr,
            6,
            2,
            "[" + "#" * filled + "-" * (bar_width - filled) + "]",
            curses.A_BOLD,
        )

        safe_addstr(
            stdscr,
            7,
            2,
            f"{int(index / max(1, total) * 100)}% ({index}/{total})",
        )

        safe_addstr(
            stdscr,
            9,
            2,
            "Privilege: " + (
                "root" if os.geteuid() == 0
                else "sudo available" if SUDO_READY
                else "unprivileged / partial"
            ),
            curses.A_DIM,
        )

        safe_addstr(
            stdscr,
            h - 1,
            1,
            "Read-only scan. No exploitation or configuration changes.",
            curses.A_REVERSE,
        )

        stdscr.refresh()

    perform_scan(mode_id, progress)


# ============================================================
# DETAIL VIEW
# ============================================================

def detail_view(stdscr, finding):
    offset = 0

    while True:
        stdscr.erase()
        h, w = stdscr.getmaxyx()

        sev = finding["severity"]

        safe_addstr(
            stdscr,
            0,
            2,
            f"[{sev}] {finding['title']}",
            curses.A_BOLD | severity_color(sev),
        )
        safe_addstr(stdscr, 1, 2, f"Category: {finding['category']}", curses.A_DIM)

        body = ["", "WHY IT MATTERS"]
        body.extend(wrapped(finding["why"], w - 6))

        if finding["evidence"]:
            body.extend(["", "EVIDENCE"])
            body.extend(wrapped(finding["evidence"], w - 6))

        if finding["next"]:
            body.extend(["", "WHAT TO INSPECT NEXT"])
            body.extend(wrapped(finding["next"], w - 6))

        visible = max(1, h - 5)

        for i, line in enumerate(body[offset:offset + visible]):
            attr = curses.A_BOLD if line in (
                "WHY IT MATTERS",
                "EVIDENCE",
                "WHAT TO INSPECT NEXT",
            ) else 0

            safe_addstr(stdscr, i + 3, 2, line, attr)

        safe_addstr(
            stdscr,
            h - 1,
            1,
            " ↑↓ scroll | PgUp/PgDn | b/ESC back ",
            curses.A_REVERSE,
        )

        stdscr.refresh()
        key = stdscr.getch()

        if key in (27, ord("b"), ord("q")):
            return
        elif key == curses.KEY_DOWN:
            offset = min(max(0, len(body) - visible), offset + 1)
        elif key == curses.KEY_UP:
            offset = max(0, offset - 1)
        elif key == curses.KEY_NPAGE:
            offset = min(max(0, len(body) - visible), offset + visible)
        elif key == curses.KEY_PPAGE:
            offset = max(0, offset - visible)


# ============================================================
# RAW EVIDENCE VIEW
# ============================================================

def raw_view(stdscr):
    if not RAW_SECTIONS:
        message_box(
            stdscr,
            "Raw Evidence",
            ["This mode did not collect a separate raw evidence bundle."],
        )
        return

    selected = 0

    while True:
        stdscr.erase()
        h, _ = stdscr.getmaxyx()

        safe_addstr(stdscr, 0, 0, " Raw Evidence Sections ", curses.A_REVERSE | curses.A_BOLD)

        available = max(1, h - 3)
        offset = max(0, selected - available + 1)

        for row, idx in enumerate(
            range(offset, min(len(RAW_SECTIONS), offset + available)),
            start=1,
        ):
            prefix = "▶" if idx == selected else " "
            attr = curses.A_REVERSE if idx == selected else 0
            safe_addstr(stdscr, row, 2, f"{prefix} {RAW_SECTIONS[idx]['title']}", attr)

        safe_addstr(
            stdscr,
            h - 1,
            0,
            " ↑↓ select | ENTER view | b/ESC back ",
            curses.A_REVERSE,
        )

        stdscr.refresh()
        key = stdscr.getch()

        if key in (27, ord("b"), ord("q")):
            return
        elif key == curses.KEY_DOWN:
            selected = min(len(RAW_SECTIONS) - 1, selected + 1)
        elif key == curses.KEY_UP:
            selected = max(0, selected - 1)
        elif key in (10, 13, curses.KEY_ENTER):
            raw_detail_view(stdscr, RAW_SECTIONS[selected])


def raw_detail_view(stdscr, section):
    offset = 0

    while True:
        stdscr.erase()
        h, w = stdscr.getmaxyx()

        safe_addstr(stdscr, 0, 1, section["title"], curses.A_BOLD)

        body = wrapped(section["output"] or "(no output)", w - 4)
        visible = max(1, h - 3)

        for i, line in enumerate(body[offset:offset + visible]):
            safe_addstr(stdscr, i + 1, 2, line)

        safe_addstr(
            stdscr,
            h - 1,
            0,
            " ↑↓ scroll | PgUp/PgDn | b/ESC back ",
            curses.A_REVERSE,
        )

        stdscr.refresh()
        key = stdscr.getch()

        if key in (27, ord("b"), ord("q")):
            return
        elif key == curses.KEY_DOWN:
            offset = min(max(0, len(body) - visible), offset + 1)
        elif key == curses.KEY_UP:
            offset = max(0, offset - 1)
        elif key == curses.KEY_NPAGE:
            offset = min(max(0, len(body) - visible), offset + visible)
        elif key == curses.KEY_PPAGE:
            offset = max(0, offset - visible)


# ============================================================
# SAVE UI
# ============================================================

def save_report_ui(stdscr):
    name = text_prompt(
        stdscr,
        "Save Report",
        "Filename (.txt optional). Leave blank for report_TIMESTAMP.txt:",
    )

    filename = sanitize_filename(name)
    path = Path.cwd() / filename

    # Do not silently overwrite an existing report.
    if path.exists():
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = path.with_name(f"{path.stem}_{stamp}{path.suffix}")

    try:
        path.write_text(build_report(), encoding="utf-8")

        message_box(
            stdscr,
            "Report Saved",
            [f"Saved to:", str(path)],
        )

    except Exception as e:
        message_box(
            stdscr,
            "Save Failed",
            [str(e)],
        )


# ============================================================
# RESULTS SCREEN
# ============================================================

def results_screen(stdscr):
    selected = 0
    offset = 0
    filter_severity = None

    while True:
        stdscr.erase()
        h, _ = stdscr.getmaxyx()

        mode_name = next(
            (m["name"] for m in MODE_DEFS if m["id"] == CURRENT_MODE),
            CURRENT_MODE or "Unknown",
        )

        visible = [
            f for f in FINDINGS
            if filter_severity is None or f["severity"] == filter_severity
        ]

        counts = Counter(f["severity"] for f in FINDINGS)

        safe_addstr(
            stdscr,
            0,
            0,
            f" Linux Security Audit | {mode_name} | Host: {run('hostname')} ",
            curses.A_REVERSE | curses.A_BOLD,
        )

        safe_addstr(
            stdscr,
            1,
            1,
            f" CRIT:{counts['CRITICAL']} HIGH:{counts['HIGH']} "
            f"MED:{counts['MEDIUM']} LOW:{counts['LOW']} INFO:{counts['INFO']} ",
            curses.A_BOLD,
        )

        safe_addstr(
            stdscr,
            2,
            1,
            f"Filter: {filter_severity or 'ALL'} | Findings: {len(visible)} | "
            f"Privilege: {'root' if os.geteuid() == 0 else ('sudo' if SUDO_READY else 'partial')}",
            curses.A_DIM,
        )

        top = 4
        available = max(1, h - 7)

        if visible:
            selected = min(selected, len(visible) - 1)

            if selected < offset:
                offset = selected
            elif selected >= offset + available:
                offset = selected - available + 1

            for row, idx in enumerate(
                range(offset, min(len(visible), offset + available)),
                start=top,
            ):
                f = visible[idx]
                prefix = "▶" if idx == selected else " "
                text = f"{prefix} [{f['severity']:<8}] {f['category']:<15} {f['title']}"

                attr = severity_color(f["severity"])
                if idx == selected:
                    attr |= curses.A_REVERSE | curses.A_BOLD

                safe_addstr(stdscr, row, 1, text, attr)
        else:
            safe_addstr(stdscr, top, 2, "No findings match this filter.", curses.A_DIM)

        safe_addstr(
            stdscr,
            h - 2,
            0,
            " ENTER details | e raw evidence | s save report | m mode menu | r rescan ",
            curses.A_REVERSE,
        )

        safe_addstr(
            stdscr,
            h - 1,
            0,
            " ↑↓ select | 1 CRIT | 2 HIGH | 3 MED | 4 LOW | 5 INFO | 0 ALL | q quit ",
            curses.A_REVERSE,
        )

        stdscr.refresh()
        key = stdscr.getch()

        if key in (ord("q"), 27):
            return "quit"

        elif key == ord("m"):
            return "menu"

        elif key == ord("r"):
            return "rescan"

        elif key == ord("s"):
            save_report_ui(stdscr)

        elif key == ord("e"):
            raw_view(stdscr)

        elif key == curses.KEY_DOWN and visible:
            selected = min(len(visible) - 1, selected + 1)

        elif key == curses.KEY_UP and visible:
            selected = max(0, selected - 1)

        elif key in (10, 13, curses.KEY_ENTER) and visible:
            detail_view(stdscr, visible[selected])

        elif key == ord("0"):
            filter_severity = None
            selected = offset = 0

        elif key == ord("1"):
            filter_severity = "CRITICAL"
            selected = offset = 0

        elif key == ord("2"):
            filter_severity = "HIGH"
            selected = offset = 0

        elif key == ord("3"):
            filter_severity = "MEDIUM"
            selected = offset = 0

        elif key == ord("4"):
            filter_severity = "LOW"
            selected = offset = 0

        elif key == ord("5"):
            filter_severity = "INFO"
            selected = offset = 0


# ============================================================
# APPLICATION LOOP
# ============================================================

def app(stdscr):
    curses.curs_set(0)
    stdscr.keypad(True)

    if curses.has_colors():
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_RED, -1)
        curses.init_pair(2, curses.COLOR_RED, -1)
        curses.init_pair(3, curses.COLOR_YELLOW, -1)
        curses.init_pair(4, curses.COLOR_CYAN, -1)
        curses.init_pair(5, curses.COLOR_WHITE, -1)

    while True:
        mode_id = mode_menu(stdscr)

        if mode_id is None:
            return

        while True:
            request_sudo(stdscr)
            scan_screen(stdscr, mode_id)

            action = results_screen(stdscr)

            if action == "quit":
                return

            if action == "menu":
                break

            if action == "rescan":
                # Rescan same mode and ask about sudo again as requested.
                continue


if __name__ == "__main__":
    try:
        curses.wrapper(app)
    except KeyboardInterrupt:
        pass
