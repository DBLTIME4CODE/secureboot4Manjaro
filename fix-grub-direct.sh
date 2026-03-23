#!/bin/bash
# Undo shim and set up direct signed GRUB boot
# Run as root: sudo bash fix-grub-direct.sh
set -e

echo '=== Fixing boot chain (removing shim, signing GRUB directly) ==='

echo '[1/4] Restoring original GRUB from backup...'
if [ -f /boot/efi/EFI/Manjaro/grubx64.efi.bak ]; then
  cp /boot/efi/EFI/Manjaro/grubx64.efi.bak /boot/efi/EFI/Manjaro/grubx64.efi
  echo 'Restored from backup.'
else
  echo 'No backup found. Reinstalling GRUB...'
  grub-install --target=x86_64-efi --efi-directory=/boot/efi --bootloader-id=Manjaro
fi

echo '[2/4] Signing GRUB with MOK key...'
sbsign --key /var/lib/secureboot/MOK.key --cert /var/lib/secureboot/MOK.crt --output /boot/efi/EFI/Manjaro/grubx64.efi /boot/efi/EFI/Manjaro/grubx64.efi
echo 'GRUB signed.'

echo '[3/4] Copying signed GRUB to fallback boot path...'
cp /boot/efi/EFI/Manjaro/grubx64.efi /boot/efi/EFI/BOOT/BOOTX64.EFI
echo 'Fallback updated.'

echo '[4/4] Setting boot order (Manjaro first)...'
efibootmgr -o 0000,0004,0001,0002
echo 'Boot order set.'

echo ''
echo '=== Done ==='
echo 'Reboot into BIOS -> Manjaro first -> Secure Boot ON -> F10'
echo 'No shim needed. UEFI trusts your key directly.'
