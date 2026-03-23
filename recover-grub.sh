#!/bin/bash
# Emergency GRUB recovery - fixes broken boot from shim mess
# Run as root: sudo bash recover-grub.sh
set -e

echo '=== Emergency GRUB Recovery ==='

echo '[1/3] Reinstalling GRUB...'
pacman -S --needed --noconfirm grub
grub-install --target=x86_64-efi --efi-directory=/boot/efi --bootloader-id=Manjaro --removable
echo 'GRUB reinstalled.'

echo '[2/3] Regenerating GRUB config...'
grub-mkconfig -o /boot/grub/grub.cfg
echo 'GRUB config regenerated.'

echo '[3/3] Verifying EFI files...'
ls -la /boot/efi/EFI/Manjaro/grubx64.efi
ls -la /boot/efi/EFI/BOOT/BOOTX64.EFI

echo ''
echo '=== Done ==='
echo 'Reboot now with Secure Boot OFF to verify normal boot works.'
echo 'DO NOT enable Secure Boot yet - just confirm it boots.'
