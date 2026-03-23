#!/bin/bash
# Secure Boot Setup Script for Manjaro
# Run as root: sudo bash setup.sh

set -e

echo "=== Secure Boot Setup for Manjaro ==="

# 1. Install dependencies
echo "[1/6] Installing dependencies..."
pacman -S --needed --noconfirm sbsigntools mokutil openssl python shim

# 2. Generate keys and sign kernels
echo "[2/6] Generating MOK keys and signing kernels..."
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
cd "$SCRIPT_DIR"
PYTHONPATH=src python -c "from myproject.secureboot import setup_secureboot; setup_secureboot('/var/lib/secureboot')"

# 3. Install shim into EFI boot chain
echo "[3/6] Installing shim bootloader..."
cp /boot/efi/EFI/Manjaro/grubx64.efi /boot/efi/EFI/Manjaro/grubx64.efi.bak
cp /usr/share/shim/shimx64.efi /boot/efi/EFI/Manjaro/BOOTx64.efi
cp /usr/share/shim/mmx64.efi /boot/efi/EFI/Manjaro/mmx64.efi
cp /usr/share/shim/fbx64.efi /boot/efi/EFI/Manjaro/fbx64.efi

# 4. Enroll MOK (prompts for password)
echo "[4/6] Enrolling MOK certificate..."
echo ">>> You will be asked to CREATE a one-time password."
echo ">>> Remember it - you need it on the next reboot."
mokutil --import /var/lib/secureboot/MOK.cer

echo ""
echo "=== Almost done! ==="
echo ""
echo "[5/6] REBOOT now. A blue MOK Manager screen will appear:"
echo "       1. Select 'Enroll MOK'"
echo "       2. Select 'Continue'"
echo "       3. Enter the password you just set"
echo "       4. Select 'Reboot'"
echo ""
echo "[6/6] After reboot, enter BIOS and ENABLE Secure Boot."
echo "       Save and exit. Locked padlock achieved."
echo ""
echo "Run: sudo reboot"