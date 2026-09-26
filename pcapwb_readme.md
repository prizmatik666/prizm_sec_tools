# PCAP Workbench

PCAP Workbench is a portable, local-first terminal application for inspecting,
decoding, searching, and correlating packet captures. It is not tied to a
specific vendor, device, IP address, application, or directory layout.

The complete program is contained in `pcap_workbench.py`. It can be copied into
another environment and used against that environment's own captures.

## Features

- Interactive terminal UI and scriptable command-line interface.
- Analyze one capture or summarize every capture in a directory.
- Read captures as packet summaries, decoded protocol trees, decoded hex, raw
  ASCII, raw hex/ASCII, extracted plaintext, or reconstructed streams.
- Follow TCP, UDP, HTTP, and decrypted TLS streams.
- Search decoded summaries and payloads using literal text or regular
  expressions.
- Correlate captures from two sensors or capture systems.
- Infer clock offset from packets observed by both capture systems.
- Report exact matches, fallback flow/time matches, and events visible on only
  one side.
- Use TLS `SSLKEYLOGFILE` files and pcapng decryption-secret blocks.
- Pass advanced Wireshark protocol preferences when other keys or keytabs are
  required.
- Extract transferred HTTP, SMB, TFTP, FTP-DATA, IMF, DICOM, and X.509 objects.
- Export packets matching a Wireshark display filter into a new capture.
- Merge multiple capture files without modifying the originals.
- Produce human-readable reports and structured JSON.
- Display capture metadata, hashes, protocol summaries, endpoints,
  conversations, likely services, TCP health, and event timelines.
- Redact common passwords, authorization values, cookies, tokens, and keys by
  default, with an explicit unredacted mode.

## Requirements

- Python 3.10 or newer.
- TShark, from Wireshark, for analysis, decoding, search, correlation,
  decryption, object extraction, and filtered exports.
- Optional: `tcpdump` for raw ASCII and hex views.
- Optional: `capinfos` for additional capture metadata.
- Optional: `mergecap` for capture merging.

There are no required third-party Python packages. PCAP Workbench processes
files locally and does not upload capture data.

Check the environment with:

```bash
python3 pcap_workbench.py doctor
```

## Starting the interface

From the directory containing the script:

```bash
./pcap_workbench.py
```

or:

```bash
python3 pcap_workbench.py
```

Navigation uses the arrow keys or `j`/`k`. Press Enter to select an item and
`q` or Escape to return to the previous screen.

## Capture selection

The interface has primary and secondary capture directories. Configure these
under **Settings** when working with two sensors or two capture locations.

When **Enter a capture path** is selected, either of these can be entered:

- A capture filename, which is opened directly.
- A directory, which is scanned and displayed as a newest-first capture
  selection list.

Recognized filenames include `.pcap`, `.pcapng`, `.cap`, `.pcap.gz`,
`.pcapng.gz`, and `.cap.gz`. Compressed-format support ultimately depends on the
installed Wireshark version.

## Interactive workflows

### Analyze one capture

Produces a readable report containing:

- Capture size, packet count, time range, duration, and cryptographic hashes.
- Capture format, encapsulation, timestamp precision, and capture metadata.
- Protocol distribution and likely services.
- TCP retransmissions, resets, lost segments, zero windows, and other health
  indicators.
- Top endpoints and conversations.
- HTTP requests and responses.
- DNS activity and TLS server names.
- Noteworthy protocol observations and a significant-event timeline.

### Analyze a directory

Analyzes every recognized capture in the selected primary or secondary
directory and displays a comparable summary row for each file.

### Read capture contents

Available representations include:

- Packet list and one-line summaries.
- Fully decoded protocol trees.
- Decoded protocol trees with packet hex.
- Raw packet bytes as ASCII.
- Raw packet bytes as hex plus ASCII.
- Extracted readable application payloads.
- Reassembled TCP streams in ASCII or hex.
- Reassembled UDP streams in ASCII or hex.
- Reassembled HTTP streams.
- Reassembled decrypted TLS streams.

Stream modes display the discovered streams so the desired conversation can be
selected instead of requiring the stream number to be guessed.

### Search decoded contents

Searches packet summary text and decoded application payloads. Searches can be
literal or regular expressions and can be limited by a Wireshark display
filter.

### Correlate capture systems

The UI can correlate:

- Every primary capture against every secondary capture.
- One selected capture from each side.
- The newest capture from each side.

Correlation compares protocol, directional addresses and ports, packet lengths,
TCP sequence and acknowledgment values, flags, IP IDs, and timestamps. Strong
packet identities are matched first. A flow, length, and time comparison is used
as a fallback.

The workbench can estimate the right-minus-left clock offset from unique shared
packets. A manual offset can also be configured.

### Capture operations

- Extract transferred objects into a new or empty directory.
- Export packets selected by a Wireshark display filter.
- Merge captures from either configured directory.

Input captures are never modified. Existing output captures are not
overwritten.

## Command-line examples

Analyze one capture:

```bash
python3 pcap_workbench.py analyze ./capture.pcapng
```

Create text and JSON reports:

```bash
python3 pcap_workbench.py analyze ./capture.pcapng \
  --output analysis.txt \
  --json analysis.json
```

Summarize a directory:

```bash
python3 pcap_workbench.py directory ./captures
```

Read and decode a capture:

```bash
python3 pcap_workbench.py read capture.pcap --mode summary
python3 pcap_workbench.py read capture.pcap --mode decoded
python3 pcap_workbench.py read capture.pcap --mode decoded-hex
python3 pcap_workbench.py read capture.pcap --mode ascii
python3 pcap_workbench.py read capture.pcap --mode hex
python3 pcap_workbench.py read capture.pcap --mode plaintext
```

Follow streams:

```bash
python3 pcap_workbench.py read capture.pcap --mode follow-tcp-ascii --stream 3
python3 pcap_workbench.py read capture.pcap --mode follow-http --stream 3
python3 pcap_workbench.py read capture.pcap --mode follow-udp-hex --stream 1
```

Search decoded contents:

```bash
python3 pcap_workbench.py search capture.pcap --text example.org
python3 pcap_workbench.py search capture.pcap --text 'user(agent)?' --regex
```

Correlate two capture directories:

```bash
python3 pcap_workbench.py correlate \
  --left-dir ./sensor-a \
  --right-dir ./sensor-b \
  --display-filter 'ip.addr == 10.20.30.40' \
  --window 0.05 \
  --output correlation.txt \
  --json correlation.json
```

Correlate explicitly selected files:

```bash
python3 pcap_workbench.py correlate \
  --left sensor-a.pcapng \
  --right sensor-b.pcapng
```

Extract transferred HTTP objects:

```bash
python3 pcap_workbench.py extract-objects capture.pcapng \
  --protocol http \
  --output-dir ./http-objects
```

Export selected packets:

```bash
python3 pcap_workbench.py filter capture.pcapng \
  --display-filter 'dns || http' \
  --output selected.pcapng
```

Merge captures:

```bash
python3 pcap_workbench.py merge first.pcapng second.pcapng \
  --output combined.pcapng
```

Use `--help` with the program or any subcommand for all available options:

```bash
python3 pcap_workbench.py --help
python3 pcap_workbench.py correlate --help
```

## TLS decryption

Modern TLS normally cannot be decrypted from an ordinary capture alone. The
session secrets must be collected from the client or server. Supply a standard
NSS/Wireshark `SSLKEYLOGFILE`:

```bash
python3 pcap_workbench.py analyze capture.pcapng \
  --tls-keylog ./tls.keys
```

Follow a decrypted TLS stream:

```bash
python3 pcap_workbench.py read capture.pcapng \
  --tls-keylog ./tls.keys \
  --mode follow-tls \
  --stream 0
```

Decryption-secret blocks embedded in pcapng files are used by Wireshark
automatically.

For protocols configured through Wireshark preferences, pass one or more
`name:value` options:

```bash
python3 pcap_workbench.py analyze capture.pcapng \
  --tshark-option 'tcp.relative_sequence_numbers:TRUE'
```

Preference names vary between Wireshark versions. They can be inspected with:

```bash
tshark -G currentprefs
```

PCAP Workbench cannot manufacture missing session secrets, bypass encryption,
or decrypt modern ephemeral TLS using only a server private key.

## Sensitive information

Reports, searches, plaintext readers, and stream views redact common password,
authorization, cookie, token, credential, secret, and key values by default.

To show sensitive values in the UI, enable **Show sensitive values in
text/reports** under Settings. For command-line use:

```bash
python3 pcap_workbench.py read capture.pcap \
  --mode plaintext \
  --show-sensitive
```

Redaction is best-effort and should not be treated as a data-loss-prevention
boundary. Filtered captures, merged captures, and extracted objects remain
byte-faithful and can contain all original secrets. TLS key-log files are also
highly sensitive.

## Saved settings

The Settings screen can save and load a JSON configuration containing:

- Primary and secondary capture directories.
- Correlation display filter, window, and clock-offset mode.
- Analysis display filter.
- TLS key-log path.
- Advanced TShark preferences.
- Sensitive-value display setting.
- Report event limit.

Configuration files are written with owner-only permissions when supported by
the operating system. They contain the TLS key-log path, not the key-log
contents.

Start with a saved configuration using:

```bash
python3 pcap_workbench.py tui --config ./pcap-workbench.json
```

Explicit command-line settings override corresponding saved values.

## Troubleshooting

Run diagnostics first:

```bash
python3 pcap_workbench.py doctor
```

Common issues:

- **TShark not found:** install the Wireshark command-line tools and ensure
  `tshark` is in `PATH`.
- **No raw reader:** install `tcpdump`, or use decoded TShark modes.
- **No merge support:** install `mergecap`, normally distributed with
  Wireshark.
- **TLS remains encrypted:** verify that the key log belongs to the captured
  sessions and was generated before or during those connections.
- **Few correlation matches:** widen the match window and consider clock skew,
  NAT, packet loss, capture truncation, offload, or encapsulation differences.
- **Permission denied:** offline analysis does not require root, but the user
  must have read permission for the captures and key files.

## Scope and limitations

- Findings are descriptive protocol and transport observations for human
  review, not automatic proof of malware or compromise.
- Results depend on the protocol dissectors and capabilities of the installed
  Wireshark version.
- Correlation works best when both sensors preserve the same packet bytes and
  their clocks are reasonably stable.
- Large directories and captures can require significant processing time and
  memory because reports assemble decoded packet information.
- Only inspect captures and key material you are authorized to access.

