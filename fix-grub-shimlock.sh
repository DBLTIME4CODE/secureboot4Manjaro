#!/bin/bash
# fix-grub-shimlock.sh — Reinstall GRUB without shim_lock, re-sign, verify
#
# Manjaro's GRUB has a built-in shim_lock verifier that rejects boot
# when shim is not present — even if sbctl keys are properly enrolled.
# This reinstalls GRUB with --disable-shim-lock to fix that.
#
# Usage: sudo bash fix-grub-shimlock.sh
set -euo pipefail

echo "=== Fixing GRUB shim_lock issue ==="
echo ""

echo "[1/4] Reinstalling GRUB without shim_lock..."
grub-install --target=x86_64-efi --efi-directory=/boot/efi --bootloader-id=Manjaro --disable-shim-lock
echo "Done."

echo ""
echo "[2/4] Regenerating GRUB config..."
grub-mkconfig -o /boot/grub/grub.cfg
echo "Done."

echo ""
echo "[3/4] Re-signing all EFI binaries with sbctl..."
# Sign the new GRUB binary
for f in \
    /boot/efi/EFI/Manjaro/grubx64.efi \
    /boot/efi/EFI/BOOT/BOOTX64.EFI \
    /boot/efi/EFI/Manjaro/BOOTx64.efi \
    /boot/efi/EFI/Manjaro/mmx64.efi \
    /boot/efi/EFI/Manjaro/fbx64.efi \
    /boot/efi/EFI/boot/mmx64.efi \
    /boot/vmlinuz-linux \
    /boot/vmlinuz-linux-lts \
    /boot/vmlinuz-linux-zen; do
    if [ -f "$f" ]; then
        echo "  Signing: $f"
        sbctl sign -s "$f" 2>/dev/null || true
    fi
done

# Catch anything else sbctl knows about
sbctl verify 2>&1 | grep "is not signed" | while read -r line; do
    file=$(echo "$line" | sed 's/^✗ //' | sed 's/ is not signed$//')
    if [ -f "$file" ] && [[ "$file" != *.bak ]]; then
        echo "  Signing: $file"
        sbctl sign -s "$file" 2>/dev/null || true
    fi
done

echo ""
echo "[4/4] Verifying..."
sbctl verify

echo ""
echo "=== Done! ==="
echo ""
echo "Now reboot into BIOS, enable Secure Boot, and boot."
