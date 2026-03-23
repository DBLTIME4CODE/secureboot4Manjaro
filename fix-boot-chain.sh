#!/bin/bash
# Fix Secure Boot boot chain for Manjaro
# Run as root: sudo bash fix-boot-chain.sh
set -e

echo '=== Fixing Secure Boot Boot Chain ==='

echo '[1/5] Installing shim to EFI fallback boot path...'
cp /usr/share/shim/shimx64.efi /boot/efi/EFI/BOOT/BOOTX64.EFI
cp /usr/share/shim/mmx64.efi /boot/efi/EFI/BOOT/mmx64.efi
echo 'Shim installed:'
ls -la /boot/efi/EFI/BOOT/BOOTX64.EFI

echo '[2/5] Setting boot order to boot shim first...'
efibootmgr -o 0004,0000,0001,0002,0005,0006,0007
echo 'Boot order set.'

echo '[3/5] Enrolling MOK certificate...'
echo '>>> Create a one-time password. Remember it for the reboot.'
mokutil --import /var/lib/secureboot/MOK.cer

echo '[4/5] Verifying enrollment is pending...'
mokutil --list-new | head -5

echo ''
echo '=== Done! ==='
echo ''
echo '[5/5] REBOOT now: sudo reboot'
echo ''
echo 'On reboot, MOK Manager (blue screen) should appear:'
echo '  1. Select Enroll MOK'
echo '  2. Select Continue'
echo '  3. Enter the password you just set'
echo '  4. Select Reboot'
echo ''
echo 'Then enter BIOS -> Enable Secure Boot -> Save and exit.'
