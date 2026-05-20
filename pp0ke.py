#!/usr/bin/env python3

import sys
import socket
import signal
import pyfiglet
import threading
import queue
import time
import random
import statistics
import math

###################################################
# A Prizmatik Underground  x ,   ` /   @.,  \.  x #
# Production. -Prizm->   x     x  |  / ,. \ . \   #
# P0RT-P0K3R w/ Entropical ,      l  |  \ _; | |  #
# Flow mode_________ V.1.0   x   x \  \,_,_./  , `#
# ORIGINAL REPO FOUND AT :,    x    '\_._._._./ x #
# https://github.com/prizmatik666/prizm_sec_tools #
# ================================================#
# CONFIG                                          #
# ================================================#

DEFAULT_TIMEOUT = 0.30
VERIFY_TIMEOUT = 0.15
THREAD_COUNT = 200

COMMON_PORTS = [
    20, 21, 22, 23, 25, 53,
    67, 68, 69, 80, 110, 111,
    123, 135, 137, 138, 139,
    143, 161, 389, 443, 445,
    465, 514, 587, 631, 993,
    995, 1080, 1433, 1521,
    1723, 1883, 2049, 2375,
    2376, 3306, 3389, 5432,
    5601, 5900, 5985, 5986,
    6379, 8000, 8008, 8080,
    8081, 8088, 8443, 8888,
    9000, 9200, 9418, 27017
]

EPHEMERAL_LOW = 32768
EPHEMERAL_HIGH = 60999

# =========================
# GLOBALS
# =========================

open_ports = []
lock = threading.Lock()
port_queue = queue.Queue()

# =========================
# BANNER
# =========================

title_text = "P0RT-P0K3R"
ascii_banner = pyfiglet.figlet_format(title_text)
print(ascii_banner)

# =========================
# HELP
# =========================

def show_help():
    print("""
Usage:
    python3 p0rt_p0k3r.py
    python3 p0rt_p0k3r.py <ip>
    python3 p0rt_p0k3r.py <ip> -q
    python3 p0rt_p0k3r.py <ip> --common
    python3 p0rt_p0k3r.py <ip> --banner
    python3 p0rt_p0k3r.py <ip> --ports 22,80,443
    python3 p0rt_p0k3r.py <ip> --ports 1-1000
    python3 p0rt_p0k3r.py <ip> --flow

Flags:
    -q          Quick full scan, no UI, full range
    --common    Scan common ports only
    --banner    Full scan with banner grabbing
    --ports     Scan custom single ports / ranges
    --flow      Entropical Flow Scan
""")

# =========================
# PORT PARSER
# =========================

def parse_ports(port_text):
    ports = set()
    chunks = port_text.replace(" ", "").split(",")

    for chunk in chunks:
        if not chunk:
            continue

        if "-" in chunk:
            start, end = chunk.split("-", 1)
            start = int(start)
            end = int(end)

            if start > end:
                start, end = end, start

            for port in range(start, end + 1):
                if 1 <= port <= 65535:
                    ports.add(port)

        else:
            port = int(chunk)

            if 1 <= port <= 65535:
                ports.add(port)

    return sorted(ports)


def prompt_custom_ports():
    while True:
        port_text = input(
            "Enter port, range, or comma-separated mix "
            "(ex: 22 or 1-1000 or 22,80,443,8000-9000): "
        ).strip()

        try:
            ports = parse_ports(port_text)

            if ports:
                return ports

            print("No valid ports entered.")

        except:
            print("Invalid port format.")

# =========================
# PROMPTS
# =========================

def prompt_timeout():
    try:
        return float(
            input("Timeout per port (float, default 0.30): ").strip()
            or "0.30"
        )
    except:
        return 0.30


def prompt_float(label, default):
    try:
        return float(input(f"{label} (default {default}): ").strip() or str(default))
    except:
        return default


def prompt_int(label, default):
    try:
        return int(input(f"{label} (default {default}): ").strip() or str(default))
    except:
        return default


def prompt_flow_settings():
    print("\nEntropical Flow Settings")
    print("-------------------------------------")

    settings = {
        "timeout": prompt_float("Timeout per port", 0.30),
        "min_jitter": prompt_float("Minimum jitter seconds", 0.20),
        "max_jitter": prompt_float("Maximum jitter seconds", 2.50),
        "min_batch": prompt_int("Minimum ports before reshuffle/cooldown", 15),
        "max_batch": prompt_int("Maximum ports before reshuffle/cooldown", 60),
        "min_cooldown": prompt_float("Minimum cooldown seconds", 5.0),
        "max_cooldown": prompt_float("Maximum cooldown seconds", 20.0),
    }

    if settings["min_jitter"] > settings["max_jitter"]:
        settings["min_jitter"], settings["max_jitter"] = (
            settings["max_jitter"],
            settings["min_jitter"],
        )

    if settings["min_batch"] > settings["max_batch"]:
        settings["min_batch"], settings["max_batch"] = (
            settings["max_batch"],
            settings["min_batch"],
        )

    if settings["min_cooldown"] > settings["max_cooldown"]:
        settings["min_cooldown"], settings["max_cooldown"] = (
            settings["max_cooldown"],
            settings["min_cooldown"],
        )

    settings["min_batch"] = max(1, settings["min_batch"])
    settings["max_batch"] = max(1, settings["max_batch"])

    return settings

# =========================
# PORT CHECK
# =========================

def probe_port(ip, port, timeout):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0

    except:
        return False


def verify_port(ip, port):
    hits = 0

    for _ in range(3):
        if probe_port(ip, port, VERIFY_TIMEOUT):
            hits += 1

        time.sleep(0.03)

    return hits >= 2

# =========================
# BANNER GRAB
# =========================

def grab_banner(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect((ip, port))

        try:
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        except:
            pass

        banner = sock.recv(1024).decode(errors="ignore").strip()
        sock.close()

        if banner:
            return banner.split("\n")[0][:80]

    except:
        pass

    return None

# =========================
# OUTPUT HELPERS
# =========================

def print_found_port(ip, port, do_banner=False):
    ephemeral = EPHEMERAL_LOW <= port <= EPHEMERAL_HIGH

    print("-------------------------------------")
    print(f"PORT FOUND ON {ip}")
    print("-------------------------------------")

    if ephemeral:
        print(f"[OPEN?] {port}/tcp (ephemeral-range)")
    else:
        print(f"[OPEN]  {port}/tcp")

    if do_banner:
        banner = grab_banner(ip, port)

        if banner:
            print(f"[BANNER] {banner}")


def print_final_results(ip):
    print("\n=====================================")
    print(f"FINAL RESULTS FOR {ip}")
    print("=====================================")

    if open_ports:
        for port in sorted(open_ports):
            if EPHEMERAL_LOW <= port <= EPHEMERAL_HIGH:
                print(f"[OPEN?] {port}/tcp (ephemeral-range)")
            else:
                print(f"[OPEN]  {port}/tcp")
    else:
        print("N0-P0RTS-P0K3D")


def build_basic_stats(total_ports, elapsed):
    try:
        pps = round(total_ports / elapsed, 2)
    except ZeroDivisionError:
        pps = total_ports

    return (
        "\n=====================================\n"
        "SCAN STATS\n"
        "=====================================\n"
        f"Scan Time:        {elapsed} sec\n"
        f"Ports Scanned:    {total_ports}\n"
        f"Ports/Second:     {pps}\n"
        f"Open Ports Found: {len(open_ports)}\n"
    )

# =========================
# NORMAL THREADED ENGINE
# =========================

def worker(ip, timeout, do_banner=False):
    while True:
        try:
            port = port_queue.get_nowait()
        except queue.Empty:
            break

        if probe_port(ip, port, timeout):
            if verify_port(ip, port):
                with lock:
                    if port not in open_ports:
                        open_ports.append(port)
                        print_found_port(ip, port, do_banner)

        port_queue.task_done()


def run_scan(ip, ports, do_banner=False, timeout=DEFAULT_TIMEOUT, quick=False):
    global open_ports
    global port_queue

    open_ports = []
    port_queue = queue.Queue()

    start_time = time.time()
    total_ports = len(ports)

    if not quick:
        print(f"\nScanning {ip} ...\n")
        print(f"[*] Timeout:        {timeout}")
        print(f"[*] Threads:        {THREAD_COUNT}")
        print(f"[*] Ports To Scan:  {total_ports}\n")

    for port in ports:
        port_queue.put(port)

    threads = []

    for _ in range(THREAD_COUNT):
        t = threading.Thread(target=worker, args=(ip, timeout, do_banner))
        t.daemon = True
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    elapsed = round(time.time() - start_time, 2)

    print_final_results(ip)

    stats_text = build_basic_stats(total_ports, elapsed)
    print(stats_text)

    return stats_text

# =========================
# ENTROPICAL FLOW ENGINE
# =========================

def normalized_shannon_entropy(values, bucket_count=16):
    if not values:
        return 0.0

    min_val = min(values)
    max_val = max(values)

    if min_val == max_val:
        return 0.0

    buckets = [0] * bucket_count

    for value in values:
        bucket = int(
            ((value - min_val) / (max_val - min_val))
            * (bucket_count - 1)
        )
        buckets[bucket] += 1

    total = len(values)
    entropy = 0.0

    for count in buckets:
        if count == 0:
            continue

        p = count / total
        entropy -= p * math.log2(p)

    max_entropy = math.log2(bucket_count)

    if max_entropy == 0:
        return 0.0

    return round((entropy / max_entropy) * 100, 2)


def calculate_flow_stats(flow_log, total_ports, elapsed, settings):
    scan_order = flow_log["scan_order"]
    jitters = flow_log["jitters"]
    cooldowns = flow_log["cooldowns"]
    batch_sizes = flow_log["batch_sizes"]
    reshuffles = flow_log["reshuffles"]

    step_distances = []

    for i in range(1, len(scan_order)):
        step_distances.append(abs(scan_order[i] - scan_order[i - 1]))

    sequential_neighbor_hits = sum(
        1 for distance in step_distances if distance <= 5
    )

    adjacency_rate = 0.0

    if step_distances:
        adjacency_rate = sequential_neighbor_hits / len(step_distances)

    port_entropy = normalized_shannon_entropy(scan_order)
    step_entropy = normalized_shannon_entropy(step_distances)

    avg_jitter = statistics.mean(jitters) if jitters else 0.0
    min_jitter = min(jitters) if jitters else 0.0
    max_jitter = max(jitters) if jitters else 0.0
    jitter_variance = statistics.pvariance(jitters) if len(jitters) > 1 else 0.0

    avg_cooldown = statistics.mean(cooldowns) if cooldowns else 0.0
    min_cooldown = min(cooldowns) if cooldowns else 0.0
    max_cooldown = max(cooldowns) if cooldowns else 0.0

    avg_batch = statistics.mean(batch_sizes) if batch_sizes else 0.0
    min_batch = min(batch_sizes) if batch_sizes else 0
    max_batch = max(batch_sizes) if batch_sizes else 0

    try:
        pps = round(total_ports / elapsed, 2)
    except ZeroDivisionError:
        pps = total_ports

    flow_disruption_score = round(
        (
            (100 - (adjacency_rate * 100)) * 0.45
            + port_entropy * 0.30
            + step_entropy * 0.25
        ),
        2,
    )

    text = (
        "\n=====================================\n"
        "ENTROPICAL FLOW STATS\n"
        "=====================================\n"
        f"Initial Port Count:        {total_ports}\n"
        f"Ports Scanned:             {len(scan_order)}\n"
        f"Re-shuffles Performed:     {reshuffles}\n"
        f"Batch Count:               {len(batch_sizes)}\n"
        f"Average Batch Size:        {round(avg_batch, 2)}\n"
        f"Smallest Batch Size:       {min_batch}\n"
        f"Largest Batch Size:        {max_batch}\n"
        f"Configured Jitter Range:   {settings['min_jitter']} - {settings['max_jitter']} sec\n"
        f"Observed Min Jitter:       {round(min_jitter, 3)} sec\n"
        f"Observed Max Jitter:       {round(max_jitter, 3)} sec\n"
        f"Average Jitter:            {round(avg_jitter, 3)} sec\n"
        f"Jitter Variance:           {round(jitter_variance, 5)}\n"
        f"Cooldowns Triggered:       {len(cooldowns)}\n"
        f"Average Cooldown:          {round(avg_cooldown, 3)} sec\n"
        f"Shortest Cooldown:         {round(min_cooldown, 3)} sec\n"
        f"Longest Cooldown:          {round(max_cooldown, 3)} sec\n"
        f"Sequential Neighbor Hits:  {sequential_neighbor_hits}\n"
        f"Port Order Entropy:        {port_entropy}%\n"
        f"Step Distance Entropy:     {step_entropy}%\n"
        f"Flow Disruption Score:     {flow_disruption_score}%\n"
    )

    text += (
        "\n=====================================\n"
        "SCAN STATS\n"
        "=====================================\n"
        f"Scan Time:        {round(elapsed, 2)} sec\n"
        f"Ports Scanned:    {total_ports}\n"
        f"Ports/Second:     {pps}\n"
        f"Open Ports Found: {len(open_ports)}\n"
    )

    return text


def run_entropical_flow_scan(ip, ports, do_banner=False, settings=None):
    global open_ports

    open_ports = []

    if settings is None:
        settings = {
            "timeout": DEFAULT_TIMEOUT,
            "min_jitter": 0.20,
            "max_jitter": 2.50,
            "min_batch": 15,
            "max_batch": 60,
            "min_cooldown": 5.0,
            "max_cooldown": 20.0,
        }

    remaining_ports = list(ports)
    random.shuffle(remaining_ports)

    total_ports = len(remaining_ports)
    start_time = time.time()

    flow_log = {
        "scan_order": [],
        "jitters": [],
        "cooldowns": [],
        "batch_sizes": [],
        "reshuffles": 0,
    }

    print(f"\nScanning {ip} with Entropical Flow ...\n")
    print(f"[*] Mode:           Entropical Flow Scan")
    print(f"[*] Timeout:        {settings['timeout']}")
    print(f"[*] Ports To Scan:  {total_ports}")
    print(f"[*] Port Order:     Continuously re-randomized")
    print(f"[*] Jitter Range:   {settings['min_jitter']} - {settings['max_jitter']} sec")
    print(f"[*] Cooldown Range: {settings['min_cooldown']} - {settings['max_cooldown']} sec")
    print(f"[*] Batch Range:    {settings['min_batch']} - {settings['max_batch']} ports\n")

    while remaining_ports:
        random.shuffle(remaining_ports)
        flow_log["reshuffles"] += 1

        batch_size = random.randint(
            settings["min_batch"],
            settings["max_batch"]
        )

        batch = remaining_ports[:batch_size]
        remaining_ports = remaining_ports[batch_size:]

        actual_batch_size = len(batch)
        flow_log["batch_sizes"].append(actual_batch_size)

        for port in batch:
            flow_log["scan_order"].append(port)

            if probe_port(ip, port, settings["timeout"]):
                if verify_port(ip, port):
                    if port not in open_ports:
                        open_ports.append(port)
                        print_found_port(ip, port, do_banner)

            if remaining_ports or port != batch[-1]:
                jitter = random.uniform(
                    settings["min_jitter"],
                    settings["max_jitter"]
                )

                flow_log["jitters"].append(jitter)
                time.sleep(jitter)

        if remaining_ports:
            cooldown = random.uniform(
                settings["min_cooldown"],
                settings["max_cooldown"]
            )

            flow_log["cooldowns"].append(cooldown)

            print(f"[*] Entropical cooldown: {round(cooldown, 2)} sec")
            print(f"[*] Remaining ports:     {len(remaining_ports)}\n")

            time.sleep(cooldown)

    elapsed = time.time() - start_time

    print_final_results(ip)

    stats_text = calculate_flow_stats(
        flow_log,
        total_ports,
        elapsed,
        settings
    )

    print(stats_text)

    return stats_text

# =========================
# SAVE OUTPUT
# =========================

def save_results(ip, stats_text):
    choice = input("\nSave as .txt? (y/N): ").strip().lower()

    if choice != "y":
        return

    filename = input("Output filename: ").strip()

    if "." not in filename:
        filename += ".txt"

    with open(filename, "w") as f:
        f.write(f"PORTS FOUND ON {ip}\n")
        f.write("-------------------------------------\n")

        for port in sorted(open_ports):
            if EPHEMERAL_LOW <= port <= EPHEMERAL_HIGH:
                f.write(f"[OPEN?] {port}/tcp (ephemeral-range)\n")
            else:
                f.write(f"[OPEN]  {port}/tcp\n")

        f.write(stats_text)

    print(f"\n[+] Saved -> {filename}")

# =========================
# MENU
# =========================

def menu(ip):
    while True:
        print(f"""
Target: {ip}

1) Quick Custom Scan
2) Full Scan
3) Common Ports
4) Full Scan + Banner Grab
5) Common + Banner Grab
6) Custom Ports
7) Custom Ports + Banner Grab
8) Entropical Flow Scan
9) Entropical Flow + Banner Grab
10) Exit
""")

        choice = input("Select mode: ").strip()

        if choice == "1":
            ports = prompt_custom_ports()

            run_scan(
                ip,
                ports,
                quick=True
            )

            break

        elif choice == "2":
            timeout = prompt_timeout()

            stats_text = run_scan(
                ip,
                list(range(1, 65536)),
                timeout=timeout
            )

            save_results(ip, stats_text)
            break

        elif choice == "3":
            timeout = prompt_timeout()

            stats_text = run_scan(
                ip,
                COMMON_PORTS,
                timeout=timeout
            )

            save_results(ip, stats_text)
            break

        elif choice == "4":
            timeout = prompt_timeout()

            stats_text = run_scan(
                ip,
                list(range(1, 65536)),
                do_banner=True,
                timeout=timeout
            )

            save_results(ip, stats_text)
            break

        elif choice == "5":
            timeout = prompt_timeout()

            stats_text = run_scan(
                ip,
                COMMON_PORTS,
                do_banner=True,
                timeout=timeout
            )

            save_results(ip, stats_text)
            break

        elif choice == "6":
            ports = prompt_custom_ports()
            timeout = prompt_timeout()

            stats_text = run_scan(
                ip,
                ports,
                timeout=timeout
            )

            save_results(ip, stats_text)
            break

        elif choice == "7":
            ports = prompt_custom_ports()
            timeout = prompt_timeout()

            stats_text = run_scan(
                ip,
                ports,
                do_banner=True,
                timeout=timeout
            )

            save_results(ip, stats_text)
            break

        elif choice == "8":
            ports = prompt_custom_ports()
            settings = prompt_flow_settings()

            stats_text = run_entropical_flow_scan(
                ip,
                ports,
                settings=settings
            )

            save_results(ip, stats_text)
            break

        elif choice == "9":
            ports = prompt_custom_ports()
            settings = prompt_flow_settings()

            stats_text = run_entropical_flow_scan(
                ip,
                ports,
                do_banner=True,
                settings=settings
            )

            save_results(ip, stats_text)
            break

        elif choice == "10":
            sys.exit(0)

        else:
            print("\nInvalid option.\n")

# =========================
# MAIN
# =========================

def main():
    if len(sys.argv) < 2:
        show_help()

        ip = input("\nTarget IP: ").strip()

        menu(ip)
        return

    ip = sys.argv[1]
    flags = sys.argv[2:]

    if "-q" in flags:
        run_scan(
            ip,
            list(range(1, 65536)),
            quick=True
        )

        return

    if "--common" in flags:
        run_scan(
            ip,
            COMMON_PORTS,
            timeout=DEFAULT_TIMEOUT
        )

        return

    if "--banner" in flags:
        run_scan(
            ip,
            list(range(1, 65536)),
            do_banner=True,
            timeout=DEFAULT_TIMEOUT
        )

        return

    if "--ports" in flags:
        try:
            port_arg_index = flags.index("--ports") + 1
            port_text = flags[port_arg_index]
            ports = parse_ports(port_text)

            if not ports:
                print("No valid ports supplied.")
                return

            run_scan(
                ip,
                ports,
                timeout=DEFAULT_TIMEOUT
            )

            return

        except:
            print(
                "Usage: python3 p0rt_p0k3r.py "
                "<ip> --ports 22,80,443,8000-9000"
            )
            return

    if "--flow" in flags:
        ports = prompt_custom_ports()
        settings = prompt_flow_settings()

        run_entropical_flow_scan(
            ip,
            ports,
            settings=settings
        )

        return

    menu(ip)

# =========================

def graceful_shutdown(signum=None, frame=None):
    print("\n\n[!] Ctrl+C detected. Exiting cleanly.")
    sys.exit(130)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, graceful_shutdown)

    try:
        main()
    except KeyboardInterrupt:
        graceful_shutdown()
