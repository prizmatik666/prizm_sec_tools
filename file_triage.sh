#!/usr/bin/env bash

# ==============================================================================
# FileCheck - Automatic File Triage & Hidden-Content Analyzer
# ==============================================================================
#
# FileCheck performs automatic first-pass forensic inspection of a user-supplied
# file. It always prompts for a filename/path and automatically chooses checks
# based on the detected file type. No flags or modes are required.
#
# Checks include:
#   - File type / MIME, size, permissions, timestamps
#   - MD5 / SHA1 / SHA256 / SHA512 hashes
#   - EXIF / metadata
#   - Interesting printable strings
#   - Binwalk embedded signatures and selective extraction
#   - Appended/trailing data
#   - Entropy
#   - Archive/container contents
#   - PNG structure and zsteg analysis
#   - BMP zsteg analysis
#   - JPEG structure and steghide indicators
#   - PDF structure, text, images, and embedded attachments
#   - ZIP / Office container listings
#   - Initial hexadecimal bytes
#
# Findings are indicators, not proof of malicious content. A clean result does
# not rule out encrypted, password-protected, custom, or unsupported hiding
# techniques.
#
# ------------------------------------------------------------------------------
# Recommended requirements - Kali / Debian / Ubuntu
# ------------------------------------------------------------------------------
#
#   sudo apt update
#   sudo apt install -y \
#       file \
#       libimage-exiftool-perl \
#       pngcheck \
#       binwalk \
#       xxd \
#       coreutils \
#       binutils \
#       p7zip-full \
#       unzip \
#       imagemagick \
#       jpeginfo \
#       steghide \
#       poppler-utils \
#       qpdf \
#       python3
#
# Optional PNG/BMP steg support:
#
#   sudo apt install -y ruby-full
#   sudo gem install zsteg
#
# Missing tools are skipped safely and listed in the final summary.
#
# ------------------------------------------------------------------------------
# Usage
# ------------------------------------------------------------------------------
#
#   chmod +x filecheck.sh
#   ./filecheck.sh
#
# Hidden/recovered content is preserved only when found:
#
#   filecheck_artifacts_<filename>_<timestamp>/
#
# At the end, FileCheck asks whether to save the analysis transcript as:
#
#   filecheck_<filename>_<timestamp>.txt
#
# ==============================================================================

set -u

declare -a FINDINGS=()
declare -a OBSERVATIONS=()
declare -a SKIPPED=()

MIME="unknown"
FILE_SIZE="unknown"
SHA256="unavailable"
ARTIFACT_DIR=""
STAMP="$(date +%Y%m%d_%H%M%S)"
WORKDIR="$(mktemp -d -t filecheck.XXXXXXXX)"
REPORT_TMP="$WORKDIR/analysis_transcript.txt"

section() {
    echo
    echo "============================================================================"
    echo "$1"
    echo "============================================================================"
}

have() {
    command -v "$1" >/dev/null 2>&1
}

add_finding() {
    local x="$1" e
    for e in "${FINDINGS[@]}"; do [[ "$e" == "$x" ]] && return; done
    FINDINGS+=("$x")
}

add_observation() {
    local x="$1" e
    for e in "${OBSERVATIONS[@]}"; do [[ "$e" == "$x" ]] && return; done
    OBSERVATIONS+=("$x")
}

skip_tool() {
    local x="$1" e
    for e in "${SKIPPED[@]}"; do [[ "$e" == "$x" ]] && return; done
    SKIPPED+=("$x")
    echo "[SKIP] $x not installed."
}

ensure_artifact_dir() {
    if [[ -z "$ARTIFACT_DIR" ]]; then
        ARTIFACT_DIR="filecheck_artifacts_${SAFE_NAME}_${STAMP}"
        mkdir -p "$ARTIFACT_DIR"
    fi
}

cleanup() {
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

exec > >(tee "$REPORT_TMP") 2>&1

# ------------------------------------------------------------------------------
# Target
# ------------------------------------------------------------------------------

while true; do
    echo
    read -r -e -p "Enter filename/path to analyze: " FILE

    [[ -z "$FILE" ]] && { echo "[-] Filename cannot be empty."; continue; }
    [[ ! -e "$FILE" ]] && { echo "[-] File does not exist: $FILE"; continue; }
    [[ ! -f "$FILE" ]] && { echo "[-] Not a regular file: $FILE"; continue; }
    break
done

if have realpath; then
    FILE="$(realpath -- "$FILE")"
else
    FILE="$(
        cd -- "$(dirname -- "$FILE")" 2>/dev/null &&
        printf '%s/%s\n' "$PWD" "$(basename -- "$FILE")"
    )"
fi

BASENAME="$(basename -- "$FILE")"
SAFE_NAME="$(printf '%s' "$BASENAME" | tr -cs 'A-Za-z0-9._-' '_')"

echo
echo "[+] FileCheck"
echo "[+] Target: $FILE"
echo "[+] Started: $(date -Is)"

# ------------------------------------------------------------------------------
# Identification / filesystem metadata
# ------------------------------------------------------------------------------

section "FILE IDENTIFICATION"

if have file; then
    file "$FILE" || true
    MIME="$(file --brief --mime-type "$FILE" 2>/dev/null || true)"
else
    skip_tool "file"
fi

if have stat; then
    FILE_SIZE="$(stat -c '%s' "$FILE" 2>/dev/null || echo "unknown")"
else
    skip_tool "stat"
fi

echo
echo "MIME type: ${MIME:-unknown}"
echo "Size:      $FILE_SIZE bytes"

section "FILESYSTEM METADATA"

if have stat; then
    stat "$FILE" || true
else
    skip_tool "stat"
fi

# ------------------------------------------------------------------------------
# Hashes
# ------------------------------------------------------------------------------

section "CRYPTOGRAPHIC HASHES"

if have md5sum; then
    printf "MD5:     "; md5sum "$FILE" | awk '{print $1}'
else
    skip_tool "md5sum"
fi

if have sha1sum; then
    printf "SHA1:    "; sha1sum "$FILE" | awk '{print $1}'
else
    skip_tool "sha1sum"
fi

if have sha256sum; then
    SHA256="$(sha256sum "$FILE" | awk '{print $1}')"
    printf "SHA256:  %s\n" "$SHA256"
else
    skip_tool "sha256sum"
fi

if have sha512sum; then
    printf "SHA512:  "; sha512sum "$FILE" | awk '{print $1}'
else
    skip_tool "sha512sum"
fi

# ------------------------------------------------------------------------------
# Metadata
# ------------------------------------------------------------------------------

section "EXIF / METADATA"
EXIF_OUT="$WORKDIR/exiftool.txt"

if have exiftool; then
    exiftool "$FILE" > "$EXIF_OUT" 2>&1 || true
    cat "$EXIF_OUT"

    if grep -Eiq 'trailer data after|extra data after|data after .*end|unknown trailer' "$EXIF_OUT"; then
        add_observation "ExifTool reported data beyond the file's normal logical structure."
    fi
else
    skip_tool "exiftool"
fi

# ------------------------------------------------------------------------------
# Entropy
# ------------------------------------------------------------------------------

section "ENTROPY ANALYSIS"

if have python3; then
    python3 - "$FILE" <<'PY'
import sys, math
from collections import Counter

path = sys.argv[1]
try:
    data = open(path, "rb").read()
except Exception as exc:
    print(f"[!] Unable to calculate entropy: {exc}")
    raise SystemExit

if not data:
    print("File is empty.")
    raise SystemExit

def entropy(buf):
    c = Counter(buf)
    n = len(buf)
    return -sum((v/n) * math.log2(v/n) for v in c.values())

e = entropy(data)
print(f"Shannon entropy: {e:.4f} / 8.0000 bits per byte")

if e >= 7.8:
    print("[*] Very high entropy. This can be normal for compressed media, archives, encrypted data, or packed content.")
elif e >= 7.2:
    print("[*] High entropy. Compression, encoding, encryption, or dense binary content may be present.")
else:
    print("[+] Global entropy is not unusually high.")

chunk = 65536
if len(data) >= chunk * 2:
    hot = []
    for off in range(0, len(data), chunk):
        b = data[off:off+chunk]
        if len(b) >= 4096:
            v = entropy(b)
            if v >= 7.90:
                hot.append((off, len(b), v))
    if hot:
        print("\nVery-high-entropy 64 KiB regions:")
        for off, size, v in hot[:10]:
            print(f"  offset=0x{off:08X} size={size:,} entropy={v:.4f}")
else:
    print("[*] File too small for useful regional entropy analysis.")
PY
else
    skip_tool "python3"
fi

# ------------------------------------------------------------------------------
# Strings
# ------------------------------------------------------------------------------

section "STRING ANALYSIS"
STRINGS_FILE="$WORKDIR/strings.txt"
INTERESTING="$WORKDIR/interesting_strings.txt"

if have strings; then
    strings -a -n 4 "$FILE" > "$STRINGS_FILE" 2>/dev/null || true
    STRING_COUNT="$(wc -l < "$STRINGS_FILE")"
    echo "Printable strings found: $STRING_COUNT"

    # Deliberately omit short binary magic such as MZ/PK here. Those produced
    # false positives in compressed image data and belong in file/binwalk.
    grep -Ein \
        'https?://|ftp://|powershell|cmd\.exe|/bin/(ba)?sh|BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|password|passwd|token|api[_-]?key|secret|authorization:|bearer |base64|eval\(|exec\(|BEGIN CERTIFICATE' \
        "$STRINGS_FILE" > "$INTERESTING" 2>/dev/null || true

    if [[ -s "$INTERESTING" ]]; then
        MATCH_COUNT="$(wc -l < "$INTERESTING")"
        echo
        echo "[*] Interesting string matches: $MATCH_COUNT"
        echo
        head -n 50 "$INTERESTING"
        (( MATCH_COUNT > 50 )) && echo "[*] Display limited to first 50 matches."
        add_observation "Interesting printable-string indicators were found."
    else
        echo "[+] No obvious high-interest string indicators found."
    fi
else
    skip_tool "strings"
fi

# ------------------------------------------------------------------------------
# Binwalk signatures / selective extraction
# ------------------------------------------------------------------------------

section "BINWALK SIGNATURE SCAN"
BINWALK_OUT="$WORKDIR/binwalk.txt"
BINWALK_SUSPICIOUS="$WORKDIR/binwalk_suspicious.txt"
BINWALK_EXTRACT="$WORKDIR/binwalk_extract"
BINWALK_EXTRACT_LOG="$WORKDIR/binwalk_extract.log"

if have binwalk; then
    binwalk "$FILE" > "$BINWALK_OUT" 2>&1 || true
    cat "$BINWALK_OUT"

    awk '$1 ~ /^[0-9]+$/ && $1 != "0" {print}' "$BINWALK_OUT" |
        grep -Ei \
            'Zip archive|RAR archive|7-zip archive|tar archive|gzip compressed|bzip2 compressed|XZ compressed|OpenPGP|PE32|DOS executable|ELF|filesystem|private key|certificate' \
        > "$BINWALK_SUSPICIOUS" 2>/dev/null || true

    if [[ -s "$BINWALK_SUSPICIOUS" ]]; then
        echo
        echo "[!] Noteworthy embedded signatures:"
        cat "$BINWALK_SUSPICIOUS"
        add_finding "Binwalk found a noteworthy embedded object at a non-zero offset."
    fi
else
    skip_tool "binwalk"
fi

section "EMBEDDED CONTENT EXTRACTION"

if have binwalk; then
    if [[ -s "$BINWALK_SUSPICIOUS" ]]; then
        mkdir -p "$BINWALK_EXTRACT"
        echo "[*] Suspicious embedded signature found; attempting automatic extraction."

        (
            cd "$BINWALK_EXTRACT" || exit
            binwalk -e "$FILE" > "$BINWALK_EXTRACT_LOG" 2>&1 || true
        )

        EXTRACT_COUNT="$(find "$BINWALK_EXTRACT" -type f 2>/dev/null | wc -l)"

        if (( EXTRACT_COUNT > 0 )); then
            ensure_artifact_dir
            mkdir -p "$ARTIFACT_DIR/binwalk"
            cp -a "$BINWALK_EXTRACT"/. "$ARTIFACT_DIR/binwalk/" 2>/dev/null || true
            echo "[!] Binwalk recovered $EXTRACT_COUNT file(s)."
            echo "    Preserved under: $ARTIFACT_DIR/binwalk"
            add_finding "Binwalk recovered content associated with a suspicious embedded signature."
        else
            echo "[*] Binwalk did not recover files from the suspicious signature."

            if [[ -s "$BINWALK_EXTRACT_LOG" ]] &&
               grep -Eiq 'error|exception|failed|cannot' "$BINWALK_EXTRACT_LOG"; then
                echo "[*] Binwalk extraction reported an error; signature scanning still completed."
                add_observation "Binwalk extraction encountered an error."
            fi
        fi
    else
        echo "[+] No suspicious embedded signature selected for automatic extraction."
    fi
fi

# ------------------------------------------------------------------------------
# Archive / container inspection
# ------------------------------------------------------------------------------

section "ARCHIVE / CONTAINER INSPECTION"
SEVEN_OUT="$WORKDIR/7zip_listing.txt"

if have 7z; then
    7z l "$FILE" > "$SEVEN_OUT" 2>&1 || true
    SEVEN_TYPE="$(awk -F' = ' '/^Type = /{print $2; exit}' "$SEVEN_OUT")"

    if [[ -n "$SEVEN_TYPE" ]] && ! grep -Eq '^ERROR:' "$SEVEN_OUT"; then
        cat "$SEVEN_OUT"

        if [[ "$MIME" == image/* ]] || [[ "$MIME" == "text/plain" ]]; then
            add_finding "7-Zip recognized a $SEVEN_TYPE container within a file identified as $MIME."
        fi
    else
        echo "[+] File was not recognized as a supported 7-Zip archive/container."
    fi
else
    skip_tool "7z"
fi

if [[ "$MIME" == "application/zip" ]] ||
   [[ "$MIME" == *"openxmlformats"* ]] ||
   [[ "$BASENAME" =~ \.(docx|xlsx|pptx|odt|ods|odp)$ ]]; then

    section "ZIP / OFFICE INTERNAL CONTENTS"

    if have unzip; then
        unzip -l "$FILE" 2>&1 || true
    else
        skip_tool "unzip"
    fi
fi

# ------------------------------------------------------------------------------
# Hex header
# ------------------------------------------------------------------------------

section "HEX HEADER"

if have xxd; then
    xxd -l 256 "$FILE"
elif have hexdump; then
    hexdump -C -n 256 "$FILE"
else
    skip_tool "xxd/hexdump"
fi

# ------------------------------------------------------------------------------
# Trailing / appended data
# ------------------------------------------------------------------------------

section "TRAILING DATA ANALYSIS"
TRAILING_TMP="$WORKDIR/trailing_data.bin"
TRAILING_INFO="$WORKDIR/trailing_info.txt"

if have python3; then
    python3 - "$FILE" "$MIME" "$TRAILING_TMP" > "$TRAILING_INFO" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
mime = sys.argv[2]
out = Path(sys.argv[3])
data = path.read_bytes()

trail = b""
desc = None

if mime == "image/png":
    marker = b"IEND\xaeB`\x82"
    pos = data.rfind(marker)
    if pos >= 0:
        end = pos + len(marker)
        trail = data[end:]
        desc = "PNG IEND"
elif mime == "image/jpeg":
    marker = b"\xff\xd9"
    pos = data.rfind(marker)
    if pos >= 0:
        end = pos + len(marker)
        trail = data[end:]
        desc = "JPEG EOI"
elif mime == "image/gif":
    pos = data.rfind(b"\x3b")
    if pos >= 0:
        end = pos + 1
        trail = data[end:]
        desc = "GIF trailer"

if desc is None:
    print("APPLICABLE=0")
else:
    meaningful = trail.strip(b"\x00\t\r\n ")
    print("APPLICABLE=1")
    print(f"DESCRIPTION={desc}")
    print(f"LOGICAL_END={len(data)-len(trail)}")
    print(f"PHYSICAL_END={len(data)}")
    if meaningful:
        out.write_bytes(trail)
        print("FOUND=1")
        print(f"SIZE={len(trail)}")
    else:
        print("FOUND=0")
PY

    if grep -q '^APPLICABLE=0' "$TRAILING_INFO"; then
        echo "[*] No applicable format-specific trailing-data check."

    elif grep -q '^FOUND=1' "$TRAILING_INFO"; then
        TRAILING_SIZE="$(awk -F= '/^SIZE=/{print $2}' "$TRAILING_INFO")"
        LOGICAL_END="$(awk -F= '/^LOGICAL_END=/{print $2}' "$TRAILING_INFO")"
        PHYSICAL_END="$(awk -F= '/^PHYSICAL_END=/{print $2}' "$TRAILING_INFO")"

        ensure_artifact_dir
        cp "$TRAILING_TMP" "$ARTIFACT_DIR/trailing_data.bin"

        echo "[!] Appended data detected."
        echo "    Logical end: $LOGICAL_END bytes"
        echo "    File size:   $PHYSICAL_END bytes"
        echo "    Extra data:  $TRAILING_SIZE bytes"
        echo "    Recovered:   $ARTIFACT_DIR/trailing_data.bin"

        add_finding "Appended data exists after the file's normal end marker ($TRAILING_SIZE bytes)."

        if have file; then
            printf "    Recovered type: "
            file -b "$ARTIFACT_DIR/trailing_data.bin" || true
        fi

        # Smart follow-up: if the appended blob is an archive, list it and
        # attempt a no-password extraction. Never brute-force passwords.
        if have 7z; then
            TRAILING_7Z="$WORKDIR/trailing_7z.txt"
            7z l "$ARTIFACT_DIR/trailing_data.bin" > "$TRAILING_7Z" 2>&1 || true
            TRAILING_TYPE="$(awk -F' = ' '/^Type = /{print $2; exit}' "$TRAILING_7Z")"

            if [[ -n "$TRAILING_TYPE" ]] && ! grep -Eq '^ERROR:' "$TRAILING_7Z"; then
                echo
                echo "[!] Appended data is readable as a $TRAILING_TYPE container."
                cat "$TRAILING_7Z"
                add_finding "The appended data is readable as a $TRAILING_TYPE container."

                mkdir -p "$ARTIFACT_DIR/trailing_extracted"

                timeout 15 \
                    7z x -y -p"" \
                    -o"$ARTIFACT_DIR/trailing_extracted" \
                    "$ARTIFACT_DIR/trailing_data.bin" \
                    > "$WORKDIR/trailing_extract.log" 2>&1 || true

                TRAILING_EXTRACT_COUNT="$(
                    find "$ARTIFACT_DIR/trailing_extracted" -type f 2>/dev/null | wc -l
                )"

                if (( TRAILING_EXTRACT_COUNT > 0 )); then
                    echo "[!] Recovered $TRAILING_EXTRACT_COUNT file(s) from appended container."
                    echo "    $ARTIFACT_DIR/trailing_extracted"
                    add_finding "File(s) were recovered from the appended container."
                else
                    rmdir "$ARTIFACT_DIR/trailing_extracted" 2>/dev/null || true

                    if grep -Eiq 'password|encrypted|wrong password|data error' "$WORKDIR/trailing_extract.log"; then
                        echo "[*] Appended container appears encrypted/password-protected."
                        add_observation "The appended container appears encrypted or password-protected."
                    fi
                fi
            fi
        fi
    else
        LOGICAL_END="$(awk -F= '/^LOGICAL_END=/{print $2}' "$TRAILING_INFO")"
        PHYSICAL_END="$(awk -F= '/^PHYSICAL_END=/{print $2}' "$TRAILING_INFO")"
        echo "[+] No meaningful data found after the normal file terminator."
        echo "    Logical end: ${LOGICAL_END:-unknown} bytes"
        echo "    File size:   ${PHYSICAL_END:-unknown} bytes"
    fi
else
    skip_tool "python3"
fi

# ------------------------------------------------------------------------------
# Image-specific checks
# ------------------------------------------------------------------------------

if [[ "$MIME" == image/* ]]; then
    section "IMAGE ANALYSIS"

    if have identify; then
        identify -verbose "$FILE" > "$WORKDIR/imagemagick.txt" 2>&1 || true
        identify "$FILE" 2>&1 || true
    else
        skip_tool "identify (ImageMagick)"
    fi
fi

# PNG
if [[ "$MIME" == "image/png" ]]; then
    section "PNG STRUCTURE"
    PNGCHECK_OUT="$WORKDIR/pngcheck.txt"

    if have pngcheck; then
        pngcheck -vv "$FILE" > "$PNGCHECK_OUT" 2>&1 || true

        grep -Ei \
            'File:|chunk (IHDR|PLTE|tRNS|IDAT|IEND)|additional data|error|warning|invalid|unexpected|OK:' \
            "$PNGCHECK_OUT" | head -n 100 || true

        if grep -Eiq 'additional data after IEND|ERRORS DETECTED|CRC error|invalid|unexpected' "$PNGCHECK_OUT"; then
            add_finding "PNG structural analysis reported extra/invalid data."
        fi
    else
        skip_tool "pngcheck"
    fi

    section "PNG STEGANOGRAPHY ANALYSIS"

    if have zsteg; then
        ZSTEG_OUT="$WORKDIR/zsteg.txt"
        ZSTEG_STRONG="$WORKDIR/zsteg_strong.txt"
        ZSTEG_TEXT="$WORKDIR/zsteg_text.txt"

        echo "[*] Scanning PNG channels/bit planes with zsteg."
        zsteg -a "$FILE" > "$ZSTEG_OUT" 2>&1 || true

        # zsteg tries many speculative interpretations. Treat explicit extra
        # data / recognizable embedded objects as findings, but long text-only
        # candidates as weaker observations.
        grep -Ei \
            '(^extradata:|extra data after image end|Zip archive|RAR archive|7-zip archive|gzip compressed|OpenPGP|PE32|ELF|executable|private key)' \
            "$ZSTEG_OUT" > "$ZSTEG_STRONG" 2>/dev/null || true

        grep -Ei \
            'text: ".{24,}"' \
            "$ZSTEG_OUT" > "$ZSTEG_TEXT" 2>/dev/null || true

        if [[ -s "$ZSTEG_STRONG" ]]; then
            echo "[!] zsteg produced strong candidates:"
            head -n 50 "$ZSTEG_STRONG"
            add_finding "zsteg produced a strong hidden-data/extra-data candidate."
        elif [[ -s "$ZSTEG_TEXT" ]]; then
            echo "[*] zsteg produced possible long-text candidates:"
            head -n 20 "$ZSTEG_TEXT"
            add_observation "zsteg produced possible long-text bit-plane candidates."
        else
            echo "[+] No strong zsteg hidden-data indicators surfaced."
        fi
    else
        skip_tool "zsteg"
    fi
fi

# BMP
if [[ "$MIME" == "image/bmp" ]] || [[ "$MIME" == "image/x-ms-bmp" ]]; then
    section "BMP STEGANOGRAPHY ANALYSIS"

    if have zsteg; then
        ZSTEG_OUT="$WORKDIR/zsteg.txt"
        ZSTEG_STRONG="$WORKDIR/zsteg_strong.txt"
        ZSTEG_TEXT="$WORKDIR/zsteg_text.txt"

        zsteg -a "$FILE" > "$ZSTEG_OUT" 2>&1 || true

        grep -Ei \
            '(^extradata:|Zip archive|RAR archive|7-zip archive|gzip compressed|OpenPGP|PE32|ELF|executable|private key)' \
            "$ZSTEG_OUT" > "$ZSTEG_STRONG" 2>/dev/null || true

        grep -Ei \
            'text: ".{24,}"' \
            "$ZSTEG_OUT" > "$ZSTEG_TEXT" 2>/dev/null || true

        if [[ -s "$ZSTEG_STRONG" ]]; then
            echo "[!] zsteg produced strong candidates:"
            head -n 50 "$ZSTEG_STRONG"
            add_finding "zsteg produced a strong hidden-data candidate."
        elif [[ -s "$ZSTEG_TEXT" ]]; then
            echo "[*] zsteg produced possible long-text candidates:"
            head -n 20 "$ZSTEG_TEXT"
            add_observation "zsteg produced possible long-text bit-plane candidates."
        else
            echo "[+] No strong zsteg hidden-data indicators surfaced."
        fi
    else
        skip_tool "zsteg"
    fi
fi

# JPEG
if [[ "$MIME" == "image/jpeg" ]]; then
    section "JPEG STRUCTURE"
    JPEG_OUT="$WORKDIR/jpeginfo.txt"

    if have jpeginfo; then
        jpeginfo -c -v "$FILE" > "$JPEG_OUT" 2>&1 || true
        cat "$JPEG_OUT"

        if grep -Eiq 'ERROR|WARNING|corrupt|extraneous' "$JPEG_OUT"; then
            add_observation "JPEG structural analysis reported a warning or abnormality."
        fi
    else
        skip_tool "jpeginfo"
    fi

    section "JPEG STEGANOGRAPHY INDICATORS"
    STEG_OUT="$WORKDIR/steghide.txt"

    if have steghide; then
        echo "[*] Checking steghide carrier information non-interactively."

        # steghide info normally asks a yes/no question. Feed "y" and specify
        # an empty passphrase so the script cannot block waiting for a terminal.
        printf 'y\n' |
            timeout 8 steghide info -p "" "$FILE" \
            > "$STEG_OUT" 2>&1 || true

        cat "$STEG_OUT"

        if grep -Eiq 'embedded file|embedded data' "$STEG_OUT"; then
            add_finding "steghide confirmed embedded-data information."
        elif grep -Eiq 'wrong passphrase|could not extract|could not get any information|passphrase' "$STEG_OUT"; then
            echo "[*] No steghide payload was confirmed with an empty passphrase."
            echo "[*] Passphrase-protected steghide content cannot be ruled out."
            add_observation "Passphrase-protected steghide content cannot be ruled out."
        else
            echo "[+] steghide did not confirm embedded content."
        fi
    else
        skip_tool "steghide"
    fi
fi

# ------------------------------------------------------------------------------
# PDF
# ------------------------------------------------------------------------------

if [[ "$MIME" == "application/pdf" ]]; then
    section "PDF ANALYSIS"

    if have pdfinfo; then
        pdfinfo "$FILE" > "$WORKDIR/pdfinfo.txt" 2>&1 || true
        cat "$WORKDIR/pdfinfo.txt"
    else
        skip_tool "pdfinfo"
    fi

    if have qpdf; then
        echo
        echo "--- qpdf structural check ---"
        qpdf --check "$FILE" > "$WORKDIR/qpdf.txt" 2>&1 || true
        cat "$WORKDIR/qpdf.txt"

        grep -Eiq 'warning|error|damaged' "$WORKDIR/qpdf.txt" &&
            add_observation "qpdf reported a PDF structural warning."
    else
        skip_tool "qpdf"
    fi

    if have pdfdetach; then
        echo
        echo "--- PDF embedded attachments ---"

        pdfdetach -list "$FILE" > "$WORKDIR/pdfdetach.txt" 2>&1 || true
        cat "$WORKDIR/pdfdetach.txt"

        ATTACHMENTS="$(
            grep -Eic '^[[:space:]]*[0-9]+:' "$WORKDIR/pdfdetach.txt" 2>/dev/null || true
        )"

        if (( ATTACHMENTS > 0 )); then
            ensure_artifact_dir
            mkdir -p "$ARTIFACT_DIR/pdf_attachments"

            pdfdetach -saveall -o "$ARTIFACT_DIR/pdf_attachments" "$FILE" >/dev/null 2>&1 || true

            RECOVERED="$(
                find "$ARTIFACT_DIR/pdf_attachments" -type f 2>/dev/null | wc -l
            )"

            echo "[!] PDF contains $ATTACHMENTS embedded attachment(s)."
            echo "    Recovered: $RECOVERED"
            echo "    Directory: $ARTIFACT_DIR/pdf_attachments"
            add_finding "The PDF contains embedded attachment(s)."
        fi
    else
        skip_tool "pdfdetach"
    fi

    if have pdfimages; then
        echo
        echo "--- PDF image objects ---"
        pdfimages -list "$FILE" 2>&1 || true
    else
        skip_tool "pdfimages"
    fi

    if have pdftotext; then
        pdftotext "$FILE" "$WORKDIR/pdf_text.txt" 2>/dev/null || true
        [[ -s "$WORKDIR/pdf_text.txt" ]] && echo "[+] PDF contains extractable text."
    else
        skip_tool "pdftotext"
    fi
fi

# ------------------------------------------------------------------------------
# Recovered artifacts
# ------------------------------------------------------------------------------

if [[ -n "$ARTIFACT_DIR" ]] && [[ -d "$ARTIFACT_DIR" ]]; then
    section "RECOVERED ARTIFACTS"

    find "$ARTIFACT_DIR" -type f -print 2>/dev/null

    if have file; then
        echo
        echo "--- Recovered file types ---"

        while IFS= read -r ITEM; do
            printf '%s: ' "$ITEM"
            file -b "$ITEM" || true
        done < <(find "$ARTIFACT_DIR" -type f 2>/dev/null)
    fi
fi

# ------------------------------------------------------------------------------
# Final summary
# ------------------------------------------------------------------------------

section "FILECHECK SUMMARY"

echo "File:"
echo "  $FILE"
echo
echo "Type:"
echo "  ${MIME:-unknown}"
echo
echo "Size:"
echo "  $FILE_SIZE bytes"
echo
echo "SHA256:"
echo "  $SHA256"

echo
echo "Noteworthy findings:"

if (( ${#FINDINGS[@]} == 0 )); then
    echo "  [+] No obvious hidden or embedded payload was automatically detected."
else
    NUM=1
    for ITEM in "${FINDINGS[@]}"; do
        echo "  [$NUM] $ITEM"
        NUM=$((NUM + 1))
    done
fi

echo
echo "Other observations:"

if (( ${#OBSERVATIONS[@]} == 0 )); then
    echo "  None"
else
    NUM=1
    for ITEM in "${OBSERVATIONS[@]}"; do
        echo "  [$NUM] $ITEM"
        NUM=$((NUM + 1))
    done
fi

echo
echo "Recovered artifacts:"

if [[ -n "$ARTIFACT_DIR" ]] && [[ -d "$ARTIFACT_DIR" ]]; then
    ACTUAL_COUNT="$(find "$ARTIFACT_DIR" -type f 2>/dev/null | wc -l)"
    echo "  $ACTUAL_COUNT file(s)"
    echo "  $ARTIFACT_DIR"
else
    echo "  None"
fi

echo
echo "Unavailable optional checks:"

if (( ${#SKIPPED[@]} == 0 )); then
    echo "  None"
else
    printf '  %s\n' "${SKIPPED[@]}"
fi

echo
echo "Assessment:"

if (( ${#FINDINGS[@]} == 0 )); then
    echo "  No strong hidden-content indicators were found by the available"
    echo "  automatic checks. This does not rule out encrypted, password-protected,"
    echo "  custom, or unsupported hiding techniques."
else
    echo "  Review recommended: one or more structural, embedded-content, or"
    echo "  steganography indicators were detected. Indicators are not by themselves"
    echo "  proof that the file is malicious."
fi

echo
echo "[+] Analysis completed: $(date -Is)"

# ------------------------------------------------------------------------------
# Optional report
# ------------------------------------------------------------------------------

echo

while true; do
    read -rp "Save analysis as a .txt report? (y/n): " SAVE_REPORT

    case "$SAVE_REPORT" in
        [Yy]*)
            REPORT_NAME="filecheck_${SAFE_NAME}_${STAMP}.txt"

            sleep 0.1
            cp "$REPORT_TMP" "$REPORT_NAME"

            # Add detailed outputs deliberately kept quiet during the terminal
            # run. The user opted into the larger report at this point.
            {
                echo
                echo "============================================================================"
                echo "ADDITIONAL SAVED DETAILS"
                echo "============================================================================"

                for DETAIL in \
                    "$WORKDIR/strings.txt" \
                    "$WORKDIR/binwalk_extract.log" \
                    "$WORKDIR/trailing_extract.log" \
                    "$WORKDIR/zsteg.txt" \
                    "$WORKDIR/pngcheck.txt" \
                    "$WORKDIR/imagemagick.txt" \
                    "$WORKDIR/pdf_text.txt"
                do
                    if [[ -f "$DETAIL" ]] && [[ -s "$DETAIL" ]]; then
                        echo
                        echo "----- $(basename "$DETAIL") -----"
                        cat "$DETAIL"
                    fi
                done
            } >> "$REPORT_NAME"

            echo
            echo "[+] Report saved:"
            echo "    $REPORT_NAME"
            break
            ;;

        [Nn]*)
            echo
            echo "[*] Text report not saved."
            break
            ;;

        *)
            echo "Please answer y or n."
            ;;
    esac
done
