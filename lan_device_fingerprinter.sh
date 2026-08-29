#!/usr/bin/env bash

# ==============================================================================
# LAN Device Fingerprinter
# ==============================================================================
#
# A device-identification and service-enumeration script for Linux/Kali.
#
# Given a single IPv4 address, this script collects:
#
#   - Reachability / ICMP response
#   - ARP neighbor and MAC address
#   - MAC/OUI manufacturer information
#   - Reverse DNS / hostname information
#   - Top TCP ports
#   - Full TCP port scan
#   - Service/version detection
#   - Basic OS fingerprinting
#   - Safe Nmap discovery scripts
#   - Common UDP services
#   - Smart-TV / IoT-related ports
#   - HTTP/HTTPS headers and responses
#   - TLS certificate information
#   - mDNS / Bonjour advertisements
#   - SSDP / UPnP discovery
#   - NetBIOS identity
#   - Basic SNMP identity probes
#   - Common Chromecast / UPnP / device-information endpoints
#
# Results are written to:
#
#   fingerprint_<IP>_<timestamp>/
#
# with a combined report at:
#
#   00_MASTER_REPORT.txt
#
#
# ------------------------------------------------------------------------------
# Requirements
# ------------------------------------------------------------------------------
#
# Kali / Debian / Ubuntu:
#
#   sudo apt update
#   sudo apt install -y \
#       nmap \
#       arp-scan \
#       avahi-utils \
#       dnsutils \
#       curl \
#       openssl \
#       socat \
#       nbtscan \
#       snmp \
#       macchanger
#
#
# ------------------------------------------------------------------------------
# Usage
# ------------------------------------------------------------------------------
#
#   chmod +x fingerprint.sh
#   sudo ./fingerprint.sh
#
# The script will prompt for the target IPv4 address.
#
# Run only against devices and networks you own or are authorized to assess.
#
# ==============================================================================


set -u


# ------------------------------------------------------------------------------
# Helper functions
# ------------------------------------------------------------------------------

section() {
    echo
    echo "============================================================"
    echo "$1"
    echo "============================================================"
}


run() {
    echo
    echo "\$ $*"
    "$@" 2>&1 || true
}


command_exists() {
    command -v "$1" >/dev/null 2>&1
}


# ------------------------------------------------------------------------------
# Target input
# ------------------------------------------------------------------------------

while true; do

    read -rp "Target IPv4 address: " TARGET

    if [[ -z "$TARGET" ]]; then
        echo "Target cannot be empty."
        continue
    fi

    if [[ "$TARGET" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then

        VALID=true

        IFS='.' read -r -a OCTETS <<< "$TARGET"

        for OCTET in "${OCTETS[@]}"; do
            if (( OCTET < 0 || OCTET > 255 )); then
                VALID=false
                break
            fi
        done

        if [[ "$VALID" == true ]]; then
            break
        fi
    fi

    echo "Invalid IPv4 address."
done


# ------------------------------------------------------------------------------
# Output directory
# ------------------------------------------------------------------------------

STAMP="$(date +%Y%m%d_%H%M%S)"
OUT="fingerprint_${TARGET}_${STAMP}"

mkdir -p "$OUT"

MASTER="$OUT/00_MASTER_REPORT.txt"

exec > >(tee -a "$MASTER") 2>&1


# ------------------------------------------------------------------------------
# Initial context
# ------------------------------------------------------------------------------

section "TARGET"

echo "Target:  $TARGET"
echo "Started: $(date -Is)"
echo "Host:    $(hostname)"
echo "User:    $(whoami)"


section "LOCAL NETWORK CONTEXT"

run ip addr
run ip route
run ip neigh


IFACE="$(
    ip route get "$TARGET" 2>/dev/null |
    awk '
        /dev/ {
            for (i=1; i<=NF; i++) {
                if ($i == "dev") {
                    print $(i+1)
                    exit
                }
            }
        }
    '
)"

echo
echo "Likely interface: ${IFACE:-unknown}"


# ------------------------------------------------------------------------------
# Reachability
# ------------------------------------------------------------------------------

section "PING / BASIC REACHABILITY"

run ping -c 4 -W 1 "$TARGET"


# ------------------------------------------------------------------------------
# ARP / MAC identification
# ------------------------------------------------------------------------------

section "ARP / MAC"

if [[ -n "${IFACE:-}" ]] && command_exists arp-scan; then
    run sudo arp-scan --interface="$IFACE" "$TARGET"
fi


run ip neigh show "$TARGET"


MAC="$(
    ip neigh show "$TARGET" 2>/dev/null |
    awk '
        {
            for (i=1; i<=NF; i++) {
                if ($i == "lladdr") {
                    print $(i+1)
                    exit
                }
            }
        }
    '
)"


echo
echo "Detected MAC: ${MAC:-unknown}"


if [[ -n "${MAC:-}" ]]; then

    OUI="$(
        echo "$MAC" |
        cut -d: -f1-3 |
        tr '[:lower:]' '[:upper:]'
    )"

    OUI_COMPACT="$(
        echo "$OUI" |
        tr -d ':'
    )"

    echo "OUI prefix:  $OUI"

    echo
    echo "Vendor lookup:"


    VENDOR_FOUND=false


    # Nmap OUI database
    if [[ -f /usr/share/nmap/nmap-mac-prefixes ]]; then

        MATCH="$(
            grep -i "^${OUI_COMPACT}[[:space:]]" \
                /usr/share/nmap/nmap-mac-prefixes \
                2>/dev/null |
            head -n 1
        )"

        if [[ -n "$MATCH" ]]; then
            echo "  Nmap:       $MATCH"
            VENDOR_FOUND=true
        fi
    fi


    # macchanger database
    #
    # IMPORTANT:
    # Do not print the complete `macchanger -l` database.
    # Only display an entry matching the target OUI.
    if command_exists macchanger; then

        MATCH="$(
            macchanger -l 2>/dev/null |
            grep -i "$OUI" |
            head -n 1
        )"

        if [[ -z "$MATCH" ]]; then

            MATCH="$(
                macchanger -l 2>/dev/null |
                grep -i "$OUI_COMPACT" |
                head -n 1
            )"

        fi

        if [[ -n "$MATCH" ]]; then
            echo "  macchanger: $MATCH"
            VENDOR_FOUND=true
        fi
    fi


    if [[ "$VENDOR_FOUND" == false ]]; then
        echo "  No local OUI vendor match found."
    fi

fi


# ------------------------------------------------------------------------------
# DNS
# ------------------------------------------------------------------------------

section "DNS / HOSTNAME"

run host "$TARGET"
run nslookup "$TARGET"
run dig -x "$TARGET"


# ------------------------------------------------------------------------------
# Fast TCP scan
# ------------------------------------------------------------------------------

section "FAST TCP DISCOVERY"

run sudo nmap \
    -Pn \
    -n \
    --reason \
    -T4 \
    --top-ports 1000 \
    "$TARGET" \
    -oA "$OUT/10_tcp_top1000"


# ------------------------------------------------------------------------------
# Full TCP scan
# ------------------------------------------------------------------------------

section "FULL TCP PORT SCAN"

run sudo nmap \
    -Pn \
    -n \
    -p- \
    --min-rate 1000 \
    --max-retries 2 \
    --reason \
    "$TARGET" \
    -oA "$OUT/20_tcp_all"


OPEN_PORTS="$(
    awk '
        /^[0-9]+\/tcp[[:space:]]+open/ {
            split($1,a,"/")
            printf "%s,",a[1]
        }
    ' "$OUT/20_tcp_all.nmap" 2>/dev/null |
    sed 's/,$//'
)"


echo
echo "Open TCP ports: ${OPEN_PORTS:-none found}"


# ------------------------------------------------------------------------------
# TCP fingerprinting
# ------------------------------------------------------------------------------

if [[ -n "${OPEN_PORTS:-}" ]]; then

    section "TCP SERVICE / VERSION / OS FINGERPRINT"

    run sudo nmap \
        -Pn \
        -n \
        -sV \
        -O \
        --version-all \
        --reason \
        -p "$OPEN_PORTS" \
        "$TARGET" \
        -oA "$OUT/30_tcp_fingerprint"


    section "NMAP SAFE DISCOVERY SCRIPTS"

    run sudo nmap \
        -Pn \
        -n \
        -p "$OPEN_PORTS" \
        --script \
"banner,http-title,http-headers,http-server-header,http-methods,ssl-cert,ssl-enum-ciphers,upnp-info,nbstat" \
        "$TARGET" \
        -oA "$OUT/31_nse_identity"

fi


# ------------------------------------------------------------------------------
# UDP
# ------------------------------------------------------------------------------

section "UDP DISCOVERY"

run sudo nmap \
    -Pn \
    -n \
    -sU \
    --top-ports 100 \
    --version-light \
    --reason \
    "$TARGET" \
    -oA "$OUT/40_udp_top100"


# ------------------------------------------------------------------------------
# Smart TV / IoT service ports
# ------------------------------------------------------------------------------

section "SMART TV / IOT PORT CHECK"

TV_PORTS="80,443,5000,7000,7100,8000,8001,8002,8008,8009,8443,9080,9197,7345,7359,7676,9000,10001,1900,5353,5555,6466,6467,6468,6469"

run sudo nmap \
    -Pn \
    -n \
    -sT \
    -sV \
    --reason \
    -p "$TV_PORTS" \
    "$TARGET" \
    -oA "$OUT/50_tv_iot_ports"


# ------------------------------------------------------------------------------
# HTTP / HTTPS
# ------------------------------------------------------------------------------

section "HTTP / HTTPS ENUMERATION"

WEBPORTS="80 443 5000 7000 7100 8000 8008 8009 8080 8443 9000 9080 9197"


for PORT in $WEBPORTS; do

    if timeout 1 bash -c "echo >/dev/tcp/$TARGET/$PORT" 2>/dev/null; then

        echo
        echo "---------------- PORT $PORT ----------------"


        echo
        echo "HTTP:"

        curl \
            --connect-timeout 3 \
            --max-time 7 \
            -sv \
            "http://$TARGET:$PORT/" \
            -o "$OUT/http_${PORT}_body.txt" \
            2>"$OUT/http_${PORT}_verbose.txt" || true

        cat "$OUT/http_${PORT}_verbose.txt"


        echo
        echo "HTTPS:"

        curl \
            -k \
            --connect-timeout 3 \
            --max-time 7 \
            -sv \
            "https://$TARGET:$PORT/" \
            -o "$OUT/https_${PORT}_body.txt" \
            2>"$OUT/https_${PORT}_verbose.txt" || true

        cat "$OUT/https_${PORT}_verbose.txt"

    fi

done


# ------------------------------------------------------------------------------
# TLS certificates
# ------------------------------------------------------------------------------

section "TLS CERTIFICATES"

for PORT in 443 8443 8009 9080; do

    if timeout 1 bash -c "echo >/dev/tcp/$TARGET/$PORT" 2>/dev/null; then

        echo
        echo "----- TLS $PORT -----"

        timeout 8 openssl s_client \
            -connect "$TARGET:$PORT" \
            -servername "$TARGET" \
            -showcerts \
            </dev/null \
            2>&1 |
            tee "$OUT/tls_${PORT}.txt"


        timeout 8 openssl s_client \
            -connect "$TARGET:$PORT" \
            -servername "$TARGET" \
            </dev/null \
            2>/dev/null |
            openssl x509 \
                -noout \
                -subject \
                -issuer \
                -serial \
                -dates \
                -fingerprint \
                -sha256 \
                2>/dev/null || true

    fi

done


# ------------------------------------------------------------------------------
# mDNS / Bonjour
# ------------------------------------------------------------------------------

section "MDNS / BONJOUR"

if command_exists avahi-browse; then

    echo
    echo "Listening for mDNS advertisements for 10 seconds..."

    timeout 10 avahi-browse \
        -a \
        -r \
        -t \
        2>&1 |
        tee "$OUT/60_avahi.txt"

else

    echo "avahi-browse not installed."

fi


# ------------------------------------------------------------------------------
# Common mDNS service queries
# ------------------------------------------------------------------------------

section "MDNS DIRECT QUERIES"

if command_exists dig; then

    for SERVICE in \
        _googlecast._tcp.local \
        _airplay._tcp.local \
        _raop._tcp.local \
        _spotify-connect._tcp.local \
        _http._tcp.local \
        _https._tcp.local \
        _companion-link._tcp.local \
        _mediaremotetv._tcp.local
    do

        echo
        echo "### $SERVICE"

        timeout 4 dig \
            @224.0.0.251 \
            -p 5353 \
            PTR "$SERVICE" \
            +short || true

    done

fi


# ------------------------------------------------------------------------------
# SSDP / UPnP
# ------------------------------------------------------------------------------

section "SSDP / UPNP DISCOVERY"

if command_exists socat; then

    printf \
'M-SEARCH * HTTP/1.1\r
HOST: 239.255.255.250:1900\r
MAN: "ssdp:discover"\r
MX: 2\r
ST: ssdp:all\r
\r
' |
    timeout 6 socat \
        - UDP4-DATAGRAM:239.255.255.250:1900,ip-multicast-ttl=2 \
        2>&1 |
        tee "$OUT/70_ssdp.txt"

else

    echo "socat not installed."

fi


# ------------------------------------------------------------------------------
# NetBIOS
# ------------------------------------------------------------------------------

section "NETBIOS"

if command_exists nbtscan; then
    run nbtscan -v "$TARGET"
fi


run sudo nmap \
    -Pn \
    -sU \
    -p137 \
    --script nbstat \
    "$TARGET"


# ------------------------------------------------------------------------------
# SNMP identity
# ------------------------------------------------------------------------------

section "SNMP BASIC IDENTITY PROBE"

if command_exists snmpget; then

    for COMMUNITY in public private; do

        echo
        echo "Community: $COMMUNITY"

        timeout 4 snmpget \
            -v2c \
            -c "$COMMUNITY" \
            "$TARGET" \
            1.3.6.1.2.1.1.1.0 \
            1.3.6.1.2.1.1.5.0 \
            2>&1 || true

    done

else

    echo "snmpget not installed."

fi


# ------------------------------------------------------------------------------
# Common device-information endpoints
# ------------------------------------------------------------------------------

section "COMMON DEVICE-ID ENDPOINTS"

PATHS=(
    /
    /ssdp/device-desc.xml
    /device-desc.xml
    /rootDesc.xml
    /description.xml
    /upnp/description.xml
    /setup/eureka_info
    "/setup/eureka_info?options=detail"
    /query/device-info
    /query/apps
    /state/device
    /device
)


for PORT in 80 8000 8008 8009 8080 8443 9000 9080; do

    for PATHNAME in "${PATHS[@]}"; do

        URL="http://${TARGET}:${PORT}${PATHNAME}"

        TMPFILE="$(mktemp)"

        CODE="$(
            curl \
                --connect-timeout 1 \
                --max-time 3 \
                -s \
                -o "$TMPFILE" \
                -w '%{http_code}' \
                "$URL" \
                2>/dev/null || true
        )"


        if [[ "$CODE" != "000" && -n "$CODE" ]]; then

            echo
            echo "[$CODE] $URL"

            head -c 4096 "$TMPFILE"
            echo

        fi


        rm -f "$TMPFILE"

    done

done


# ------------------------------------------------------------------------------
# Final neighbor state
# ------------------------------------------------------------------------------

section "PASSIVE NEIGHBOR CACHE AFTER SCAN"

run ip neigh show "$TARGET"


# ------------------------------------------------------------------------------
# Summary
# ------------------------------------------------------------------------------

section "SUMMARY"

echo "Target:       $TARGET"
echo "MAC:          ${MAC:-unknown}"
echo "Interface:    ${IFACE:-unknown}"
echo "TCP ports:    ${OPEN_PORTS:-none}"

echo
echo "Report directory:"
echo "  $OUT"

echo
echo "Primary report:"
echo "  $MASTER"

echo
echo "Finished:"
echo "  $(date -Is)"
