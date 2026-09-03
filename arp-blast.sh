#!/usr/bin/env bash
# if you use this change the interface to what you're using
# and change the OUI_FILE location to where yours is. I run mine
# and keep the .txt in /usr/local/bin so i can just run sudo arp-blast
# if it fails to run after validating sudo with password - run again and
# should work , idk you can play around with it.
# function: sends an arp request across the LAN to get the devices on network
set -euo pipefail

INTERFACE="wlan1"
OUI_FILE="/usr/local/bin/ieee-oui.txt"

if [[ ! -r "$OUI_FILE" ]]; then
    echo "Error: OUI database is not readable: $OUI_FILE" >&2
    echo "Fix with:" >&2
    echo "  sudo chown root:root '$OUI_FILE'" >&2
    echo "  sudo chmod 644 '$OUI_FILE'" >&2
    exit 1
fi

if ! ip link show "$INTERFACE" &>/dev/null; then
    echo "Error: interface $INTERFACE does not exist." >&2
    exit 1
fi

if [[ "$(cat "/sys/class/net/$INTERFACE/operstate" 2>/dev/null)" != "up" ]]; then
    echo "Warning: $INTERFACE does not appear to be connected." >&2
fi

echo "Scanning local network through $INTERFACE..."
echo

exec sudo arp-scan \
    --interface="$INTERFACE" \
    --ouifile="$OUI_FILE" \
    --localnet
