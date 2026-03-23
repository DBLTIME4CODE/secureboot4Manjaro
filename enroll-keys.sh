#!/bin/bash
# enroll-keys.sh — Enroll sbctl keys into firmware (run after entering Setup Mode)
#
# Before running this:
#   1. Reboot into BIOS (F2 or DEL on ASUS)
#   2. Security → Secure Boot → Reset/Clear Secure Boot Keys
#   3. Save and boot back into Manjaro (Secure Boot still OFF)
#
# Usage: sudo bash enroll-keys.sh
set -euo pipefail

echo "=== Enrolling Secure Boot Keys ==="
echo ""

# Check Setup Mode
if sbctl status | grep -q "Setup Mode:.*Enabled"; then
    echo "Setup Mode: ENABLED — good to go"
else
    echo "WARNING: Setup Mode is DISABLED"
    echo ""
    echo "You need to clear Secure Boot keys in BIOS first:"
    echo "  1. Reboot into BIOS (F2 or DEL)"
    echo "  2. Security → Secure Boot → Reset/Clear Secure Boot Keys"
    echo "  3. Save and boot back into Manjaro"
    echo "  4. Run this script again"
    echo ""
    read -p "Try enrolling anyway? (y/N) " answer
    if [[ "$answer" != "y" && "$answer" != "Y" ]]; then
        exit 1
    fi
fi

echo ""
echo "Enrolling keys (keeping Microsoft keys for compatibility)..."
sbctl enroll-keys -m

echo ""
echo "Current status:"
sbctl status

echo ""
echo "Done! Now:"
echo "  1. Reboot into BIOS"
echo "  2. Enable Secure Boot"
echo "  3. Boot normally"
