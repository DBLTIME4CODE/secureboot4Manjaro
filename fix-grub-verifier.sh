#!/bin/bash
# fix-grub-verifier.sh — Clean GRUB reinstall with shim_lock disabled + re-sign
#
# Fixes both:
#   - "shim_lock_verifier_init:177: prohibited by secure boot policy"
#   - "grub_verifiers_open:119: verification requested but nobody cares"
#
# Usage: sudo bash fix-grub-verifier.sh
set -euo pipefail

echo "=== Clean GRUB Reinstall for Secure Boot ==="
echo ""

# 1. Ensure GRUB package is current
echo "[1/6] Ensuring GRUB is up to date..."
pacman -S --noconfirm --needed grub efibootmgr
echo "Done."

# 2. Add GRUB_DISABLE_SHIM_LOCK to config if not already there
echo ""
echo "[2/6] Disabling GRUB shim_lock verifier in config..."
if grep -q "GRUB_DISABLE_SHIM_LOCK" /etc/default/grub; then
    echo "  Already set in /etc/default/grub"
else
    echo 'GRUB_DISABLE_SHIM_LOCK="true"' >> /etc/default/grub
    echo "  Added GRUB_DISABLE_SHIM_LOCK=true"
fi

# 3. Reinstall GRUB EFI binary
echo ""
echo "[3/6] Reinstalling GRUB to EFI partition..."
grub-install --target=x86_64-efi --efi-directory=/boot/efi --bootloader-id=Manjaro --disable-shim-lock
echo "Done."

# 4. Regenerate GRUB config
echo ""
echo "[4/6] Regenerating GRUB config..."
grub-mkconfig -o /boot/grub/grub.cfg
echo "Done."

# 5. Re-sign everything
echo ""
echo "[5/6] Re-signing all EFI binaries with sbctl..."
for f in \
    /boot/efi/EFI/Manjaro/grubx64.efi \
    /boot/efi/EFI/BOOT/BOOTX64.EFI \
    /boot/efi/EFI/Manjaro/BOOTx64.efi \
    /boot/efi/EFI/Manjaro/mmx64.efi \
    /boot/efi/EFI/Manjaro/fbx64.efi \
    /boot/efi/EFI/boot/bootx64.efi \
    /boot/efi/EFI/boot/mmx64.efi \
    /boot/vmlinuz-linux \
    /boot/vmlinuz-linux-lts \
    /boot/vmlinuz-linux-zen; do
    if [ -f "$f" ]; then
        echo "  Signing: $f"
        sbctl sign -s "$f" 2>/dev/null || true
    fi
done

# Catch any remaining unsigned files
sbctl verify 2>&1 | grep "is not signed" | while read -r line; do
    file=$(echo "$line" | sed 's/^✗ //' | sed 's/ is not signed$//')
    if [ -f "$file" ] && [[ "$file" != *.bak ]]; then
        echo "  Signing: $file"
        sbctl sign -s "$file" 2>/dev/null || true
    fi
done

# 6. Verify
echo ""
echo "[6/6] Final verification..."
sbctl status
echo ""
sbctl verify

echo ""
echo "=== Done! ==="
echo ""
echo "Now:"
echo "  1. Reboot into BIOS"
echo "  2. Enable Secure Boot"
echo "  3. Boot normally"
