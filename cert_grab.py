#!/usr/bin/env python3
"""
craigcert.py
TLS certificate extractor / processor

Features:
- Connects to host:port
- Pulls certificate chain using openssl
- Saves raw PEM cert chain
- Saves decoded openssl text output
- Extracts useful fields:
  - subject
  - issuer
  - validity
  - SAN DNS names
  - fingerprints
  - serial
  - signature algorithm
  - public key info
- Saves JSON summary
- Saves deduped SAN/domain list
"""

import json
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path


OUTDIR = Path("cert_reports")


def safe_name(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]+", "_", value.strip())


def run_cmd(cmd, input_text=None, timeout=20):
    return subprocess.run(
        cmd,
        input=input_text,
        text=True,
        capture_output=True,
        timeout=timeout,
        errors="replace",
    )


def fetch_cert_chain(host: str, port: int) -> str:
    cmd = [
        "openssl",
        "s_client",
        "-connect",
        f"{host}:{port}",
        "-servername",
        host,
        "-showcerts",
    ]

    proc = run_cmd(cmd, input_text="", timeout=25)

    combined = proc.stdout + "\n" + proc.stderr

    certs = re.findall(
        r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
        combined,
        flags=re.DOTALL,
    )

    if not certs:
        raise RuntimeError("No PEM certificates found in openssl output.")

    return "\n\n".join(certs) + "\n"


def split_pem_chain(pem_chain: str):
    return re.findall(
        r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
        pem_chain,
        flags=re.DOTALL,
    )


def decode_cert_text(pem: str) -> str:
    proc = run_cmd(
        ["openssl", "x509", "-noout", "-text", "-fingerprint", "-sha256"],
        input_text=pem,
        timeout=15,
    )

    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "openssl x509 decode failed")

    return proc.stdout


def openssl_field(pem: str, args):
    proc = run_cmd(["openssl", "x509", "-noout", *args], input_text=pem, timeout=15)
    return proc.stdout.strip()


def extract_sans(decoded: str):
    sans = []

    match = re.search(
        r"X509v3 Subject Alternative Name:\s*\n\s*(.+)",
        decoded,
        flags=re.MULTILINE,
    )

    if not match:
        return sans

    line = match.group(1).strip()

    for item in line.split(","):
        item = item.strip()
        if item.startswith("DNS:"):
            sans.append(item[4:].strip())

    return sorted(set(sans))


def parse_decoded_cert(pem: str, decoded: str):
    subject = openssl_field(pem, ["-subject"])
    issuer = openssl_field(pem, ["-issuer"])
    dates = openssl_field(pem, ["-dates"])
    serial = openssl_field(pem, ["-serial"])
    fingerprint_sha256 = openssl_field(pem, ["-fingerprint", "-sha256"])
    fingerprint_sha1 = openssl_field(pem, ["-fingerprint", "-sha1"])

    sig_alg = None
    pubkey_alg = None
    pubkey_bits = None

    m = re.search(r"Signature Algorithm:\s*(.+)", decoded)
    if m:
        sig_alg = m.group(1).strip()

    m = re.search(r"Public Key Algorithm:\s*(.+)", decoded)
    if m:
        pubkey_alg = m.group(1).strip()

    m = re.search(r"Public-Key:\s*\((\d+)\s+bit\)", decoded)
    if m:
        pubkey_bits = int(m.group(1))

    not_before = None
    not_after = None

    for line in dates.splitlines():
        if line.startswith("notBefore="):
            not_before = line.split("=", 1)[1]
        elif line.startswith("notAfter="):
            not_after = line.split("=", 1)[1]

    return {
        "subject": subject.replace("subject=", "", 1),
        "issuer": issuer.replace("issuer=", "", 1),
        "serial": serial.replace("serial=", "", 1),
        "not_before": not_before,
        "not_after": not_after,
        "signature_algorithm": sig_alg,
        "public_key_algorithm": pubkey_alg,
        "public_key_bits": pubkey_bits,
        "fingerprint_sha256": fingerprint_sha256.replace("sha256 Fingerprint=", ""),
        "fingerprint_sha1": fingerprint_sha1.replace("sha1 Fingerprint=", ""),
        "subject_alt_names": extract_sans(decoded),
    }


def write_file(path: Path, text: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", errors="replace")


def process_target(host: str, port: int = 443):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = OUTDIR / f"{safe_name(host)}_{port}_{timestamp}"
    base.mkdir(parents=True, exist_ok=True)

    print(f"[+] Connecting to {host}:{port}")
    pem_chain = fetch_cert_chain(host, port)

    raw_chain_path = base / "raw_chain.pem"
    write_file(raw_chain_path, pem_chain)

    certs = split_pem_chain(pem_chain)

    summaries = []
    all_sans = set()
    decoded_all = []

    for i, pem in enumerate(certs, start=1):
        cert_dir = base / f"cert_{i}"
        cert_dir.mkdir(exist_ok=True)

        raw_path = cert_dir / f"cert_{i}.pem"
        decoded_path = cert_dir / f"cert_{i}_decoded.txt"

        write_file(raw_path, pem + "\n")

        decoded = decode_cert_text(pem)
        write_file(decoded_path, decoded)

        parsed = parse_decoded_cert(pem, decoded)
        parsed["chain_index"] = i
        parsed["raw_pem_file"] = str(raw_path)
        parsed["decoded_text_file"] = str(decoded_path)

        summaries.append(parsed)
        all_sans.update(parsed["subject_alt_names"])

        decoded_all.append(f"\n\n===== CERT {i} =====\n\n{decoded}")

    write_file(base / "decoded_chain.txt", "\n".join(decoded_all))

    report = {
        "target": host,
        "port": port,
        "created": datetime.now().isoformat(timespec="seconds"),
        "certificate_count": len(certs),
        "certificates": summaries,
        "all_subject_alt_names": sorted(all_sans),
    }

    write_file(base / "summary.json", json.dumps(report, indent=2))
    write_file(base / "sans.txt", "\n".join(sorted(all_sans)) + "\n")

    print("\n[+] Done.")
    print(f"    Output folder: {base}")
    print(f"    Raw chain:     {raw_chain_path}")
    print(f"    JSON summary:  {base / 'summary.json'}")
    print(f"    SAN list:      {base / 'sans.txt'}")

    if all_sans:
        print("\n[+] SANs found:")
        for san in sorted(all_sans):
            print(f"    - {san}")


def main():
    print("=== CraigCert TLS Extractor / Processor ===\n")

    target = input("Target host or host:port: ").strip()

    if not target:
        print("No target entered.")
        return

    if "://" in target:
        target = target.split("://", 1)[1]

    target = target.strip("/")

    if ":" in target:
        host, port_s = target.rsplit(":", 1)
        port = int(port_s)
    else:
        host = target
        port = 443

    try:
        process_target(host, port)
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
    except Exception as e:
        print(f"\n[!] Error: {e}")


if __name__ == "__main__":
    main()
