# prizm_sec_tools
<img width="1402" height="1122" alt="entropy_gremlin" src="https://github.com/user-attachments/assets/3b121bce-7375-463b-938b-74402878ffbd" />
<img width="1149" height="1369" alt="entropicalflow_info" src="https://github.com/user-attachments/assets/e99e6941-b6fb-46c3-b77e-fd7316478032" />
# P0RT-P0K3R

> Adaptive multi-mode Python port scanner with Entropical Flow scanning, live telemetry, timing entropy, banner grabbing, and flow-analysis metrics.

---

## Features

- Full TCP connect scanning
- Common-port scanning
- Custom port/range scanning
- Multi-threaded scanning engine
- Smart port verification / retry logic
- Live open-port discovery output
- Banner grabbing support
- Scan statistics + timing diagnostics
- Save scan results to `.txt`
- Ephemeral-port detection warnings
- Entropical Flow Scan mode
- Continuous port re-randomization
- Adaptive jitter + cooldown scheduling
- Entropy / flow-behavior analysis metrics

---

# Scan Modes

| Mode | Description |
|---|---|
| Quick Custom Scan | Fast custom-range scan with minimal UI |
| Full Scan | Full `1-65535` threaded scan |
| Common Ports | Scan curated common ports |
| Full Scan + Banner Grab | Full scan with service/banner grabbing |
| Common + Banner Grab | Common-port scan with banner grabbing |
| Custom Ports | Scan user-defined ports/ranges |
| Custom Ports + Banner Grab | Custom scan with banner grabbing |
| Entropical Flow Scan | Stateful adaptive randomized scan engine |
| Entropical Flow + Banner Grab | Flow scan with banner grabbing |

---

# Entropical Flow Scan

The Entropical Flow engine is a behavioral scan scheduler designed to study:
- traffic cadence
- timing entropy
- scan pattern mutation
- IDS/telemetry response behavior
- non-linear traversal patterns

Unlike traditional scanners, Entropical Flow:
- continuously re-randomizes remaining ports during scan execution
- dynamically mutates traversal paths
- injects randomized jitter between probes
- inserts adaptive cooldown periods
- tracks flow metrics throughout the life of the scan

The traversal path evolves continuously rather than following a fixed randomized order.

---

# Entropical Metrics

Flow mode calculates:

- Re-shuffle count
- Average batch size
- Jitter variance
- Cooldown variance
- Sequential neighbor hits
- Port-order entropy
- Step-distance entropy
- Flow disruption score
- Scan throughput statistics

Example:

```text
ENTROPICAL FLOW STATS
-------------------------------------
Initial Port Count:        500
Ports Scanned:             500
Re-shuffles Performed:     9
Average Batch Size:        43.2
Average Jitter:            1.14 sec
Cooldowns Triggered:       6
Flow Disruption Score:     92.4%
```

---

# Installation

## Requirements

- Python 3.9+
- pyfiglet

Install dependencies:

```bash
pip install pyfiglet
```

---

# Usage

## Launch Interactive UI

```bash
python3 pp0ke.py
```

## Scan Specific Host

```bash
python3 pp0ke.py 192.168.2.16
```

## Quick Scan

```bash
python3 pp0ke.py 192.168.2.16 -q
```

## Common Ports

```bash
python3 pp0ke.py 192.168.2.16 --common
```

## Banner Grabbing

```bash
python3 pp0ke.py 192.168.2.16 --banner
```

## Custom Ports

```bash
python3 pp0ke.py 192.168.2.16 --ports 22,80,443
```

## Custom Ranges

```bash
python3 pp0ke.py 192.168.2.16 --ports 1-1000
```

## Mixed Ranges

```bash
python3 pp0ke.py 192.168.2.16 --ports 22,80,443,8000-9000
```

## Entropical Flow Scan

```bash
python3 pp0ke.py 192.168.2.16 --flow
```

---

# Example Output

```text
-------------------------------------
PORT FOUND ON 192.168.2.16
-------------------------------------
[OPEN]  135/tcp

-------------------------------------
PORT FOUND ON 192.168.2.16
-------------------------------------
[OPEN]  139/tcp

-------------------------------------
PORT FOUND ON 192.168.2.16
-------------------------------------
[OPEN]  445/tcp
```

---

# Scan Statistics

Example statistics output:

```text
=====================================
SCAN STATS
=====================================
Scan Time:        0.94 sec
Ports Scanned:    500
Ports/Second:     531.91
Open Ports Found: 3
```

---

# Architecture Notes

## Standard Scan Engine

- Multi-threaded TCP connect scanning
- Shared work queue
- Smart verification logic
- Optimized for throughput

## Entropical Flow Engine

- Stateful deterministic flow scheduler
- Non-threaded by design
- Preserves timing truthfulness
- Allows accurate entropy measurement
- Continuously mutates traversal order

Threading is intentionally avoided in Entropical mode because:
- concurrent probes distort timing analysis
- cooldown semantics become unreliable
- entropy metrics lose integrity
- traversal order ceases to be meaningful

---

# Research Goals

P0RT-P0K3R is part of an ongoing behavioral traffic research effort focused on:
- timing entropy
- adaptive traversal behavior
- traffic pattern mutation
- flow-analysis telemetry
- IDS interaction studies
- chaotic scheduling systems

Future concepts include:
- Fractal-driven scan scheduling
- Mandelbrot traffic synthesis
- Flow visualization rendering
- Telemetry heatmaps
- Suricata correlation overlays
- Entropy replay systems

---

# Legal / Ethical Notice

This tool is intended for:
- authorized testing
- lab environments
- defensive security research
- educational experimentation

Do not scan systems you do not own or have explicit permission to test.

---

# Author

Prizmatik U.G.
<img width="375" height="630" alt="entropic_redact" src="https://github.com/user-attachments/assets/5cc686cd-caa7-44ac-8362-9f04c54f5d79" />
<img width="328" height="658" alt="entropic_redact2" src="https://github.com/user-attachments/assets/4c22f7b3-7519-42b2-ad36-abf7c2703c4c" />
