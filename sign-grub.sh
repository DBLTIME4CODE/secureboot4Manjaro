#!/bin/bash
# Sign GRUB for Secure Boot
# Run as root: sudo bash sign-grub.sh
set -e

echo 'Signing GRUB bootloader...'
sbsign --key /var/lib/secureboot/MOK.key --cert /var/lib/secureboot/MOK.crt --output /boot/efi/EFI/Manjaro/grubx64.efi /boot/efi/EFI/Manjaro/grubx64.efi
echo 'GRUB signed successfully.'

echo 'Verifying signature...'
sbverify --cert /var/lib/secureboot/MOK.crt /boot/efi/EFI/Manjaro/grubx64.efi

echo ''
echo 'Done. Now reboot into BIOS, enable Secure Boot, save and exit.'
echo 'Boot order should be: Manjaro first.'
