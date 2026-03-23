#!/bin/bash
# sbctl-setup.sh — Secure Boot via sbctl (the Arch/Manjaro way)
# No shim or MOK needed. Enrolls keys directly into UEFI firmware.
#
# Usage: sudo bash sbctl-setup.sh
set -euo pipefail

echo "=== Secure Boot Setup via sbctl ==="
echo ""

# 1. Install sbctl
echo "[1/6] Installing sbctl..."
pacman -S --noconfirm --needed sbctl

# 2. Show current state
echo ""
echo "[2/6] Current Secure Boot status:"
sbctl status

# 3. Create keys (idempotent — skips if they exist)
echo ""
echo "[3/6] Creating Secure Boot keys..."
if sbctl status | grep -q "Setup Mode:.*Enabled"; then
    sbctl create-keys
    echo "Keys created."
else
    echo "Keys already exist or Setup Mode not enabled — checking..."
    sbctl create-keys 2>/dev/null || echo "Keys already exist, skipping."
fi

# 4. Enroll keys into firmware (keeps Microsoft keys with -m)
echo ""
echo "[4/6] Enrolling keys into firmware (keeping Microsoft keys)..."
sbctl enroll-keys -m || echo "Keys may already be enrolled."

# 5. Sign everything that needs it
echo ""
echo "[5/6] Signing EFI binaries and kernels..."

# Common files to sign — sbctl verify will catch anything we miss
for f in \
    /boot/efi/EFI/Manjaro/grubx64.efi \
    /boot/efi/EFI/BOOT/BOOTX64.EFI \
    /boot/vmlinuz-linux \
    /boot/vmlinuz-linux-lts \
    /boot/vmlinuz-linux-zen; do
    if [ -f "$f" ]; then
        echo "  Signing: $f"
        sbctl sign -s "$f" 2>/dev/null || sbctl sign "$f" 2>/dev/null || echo "  (already signed or skipped)"
    fi
done

# Also sign any initramfs if UKI (Unified Kernel Image) is used
for f in /boot/efi/EFI/Linux/*.efi; do
    if [ -f "$f" ]; then
        echo "  Signing UKI: $f"
        sbctl sign -s "$f" 2>/dev/null || true
    fi
done

# 6. Verify
echo ""
echo "[6/6] Verifying all EFI binaries are signed..."
sbctl verify

echo ""
echo "=== Done! ==="
echo ""
echo "Next steps:"
echo "  1. Reboot into BIOS"
echo "  2. Enable Secure Boot"
echo "  3. Boot normally — it should just work"
echo ""
echo "The -s flag made signing persistent — sbctl auto-signs on kernel updates."
