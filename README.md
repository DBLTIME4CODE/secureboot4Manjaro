# Secure Boot Auto-Signing for Manjaro/Arch Linux

> **STATUS: INCOMPLETE**  Keys enroll and binaries sign successfully via sbctl, but Manjaro's GRUB has a compiled-in shim_lock verifier that blocks boot under Secure Boot. The next step is either switching to systemd-boot or installing a patched GRUB from AUR. See Known Issues below.

---

## What It Does (when complete)

| Step | What happens | Status |
|------|-------------|--------|
| **1. sbctl key creation** | Creates Secure Boot signing keys | Working |
| **2. Key enrollment** | Enrolls keys directly into UEFI firmware db (no shim/MOK needed) | Working |
| **3. EFI signing** | Signs all EFI binaries (GRUB, bootloader, kernel) via sbctl | Working |
| **4. Persistent signing** | sbctl auto-signs on kernel updates via -s flag | Working |
| **5. Boot with Secure Boot ON** | GRUB loads kernel under Secure Boot | **BLOCKED** |

## Known Issues

### GRUB shim_lock verifier (BLOCKING)

Manjaro's GRUB package has a shim_lock verifier **compiled into the binary**. When Secure Boot is enabled, GRUB calls shim_lock_verifier_init() which fails because there is no shim in the boot chain (sbctl uses direct firmware key enrollment instead). The --disable-shim-lock flag and GRUB_DISABLE_SHIM_LOCK config option do not remove the compiled-in verifier.

**Error messages seen:**
- kern/efi/sb.c:shim_lock_verifier_init:177: prohibited by secure boot policy
- kern/verifiers.c:grub_verifiers_open:119: verification requested but nobody cares

**Potential fixes (not yet attempted):**
1. Switch to **systemd-boot** (no shim_lock, works cleanly with sbctl)
2. Install **grub-no-verifiers** or patched GRUB from AUR
3. Use **Unified Kernel Images (UKI)** which bypass GRUB entirely

---

## What Works Today

Everything below works correctly with Secure Boot OFF:

- sbctl create-keys  generates signing keys
- sbctl enroll-keys -m  enrolls into firmware (requires Setup Mode)
- sbctl sign -s  signs and persists EFI binaries
- sbctl verify  confirms all binaries are signed
- Python secureboot module  signs kernels (sbsign) and modules (sign-file)
- Pacman hooks  auto-sign on kernel/module updates

---

## Requirements

- **Manjaro** or **Arch Linux**
- **sbctl** (pacman -S sbctl)
- **Python 3.10+** (for the Python module)
- **linux-headers** (for sign-file module signing)
- **zstd** (for .ko.zst compressed modules)

---

## Quick Start (current state)

```bash
# Clone
git clone https://github.com/DBLTIME4CODE/secureboot4Manjaro.git
cd secureboot4Manjaro

# Step 1: Install sbctl and sign everything
sudo bash sbctl-setup.sh

# Step 2: Sign any remaining unsigned files
sudo bash sign-remaining.sh

# Step 3: Enter BIOS -> Security -> Secure Boot -> Clear/Reset keys -> Save -> Boot Manjaro

# Step 4: Enroll your keys into firmware
sudo bash enroll-keys.sh

# Step 5: Fix GRUB shim_lock (reinstall without verifier)
sudo bash fix-grub-verifier.sh

# Step 6: Reboot -> BIOS -> Enable Secure Boot -> Boot
# NOTE: This step currently fails due to GRUB shim_lock. See Known Issues.
```

---

## Helper Scripts

| Script | Purpose | Status |
|--------|---------|--------|
| sbctl-setup.sh | Install sbctl, create keys, sign EFI binaries | Working |
| sign-remaining.sh | Sign any unsigned files flagged by sbctl verify | Working |
| enroll-keys.sh | Enroll sbctl keys into UEFI firmware | Working |
| fix-grub-shimlock.sh | Reinstall GRUB with --disable-shim-lock | Does not fix compiled-in verifier |
| fix-grub-verifier.sh | Clean GRUB reinstall + config + re-sign | Does not fix compiled-in verifier |
| setup.sh | Original MOK/shim approach (deprecated) | Superseded by sbctl |
| fix-boot-chain.sh | Copy shim to EFI path (deprecated) | Superseded by sbctl |
| sign-grub.sh | Sign GRUB with MOK key (deprecated) | Superseded by sbctl |
| run.py | Python CLI for status/setup/sign | Working |

---

## Python Module

The repo also includes a Python secureboot automation module:

```bash
# Check status
sudo python run.py status

# Full Python-based setup (MOK approach - deprecated in favor of sbctl)
sudo python run.py setup

# Re-sign kernels and modules
sudo python run.py sign

# Check EFI boot chain
sudo python run.py check-efi
```

55 tests, all passing. ruff clean. mypy clean.

---

## File Layout

```
sbctl-setup.sh               # Primary setup script (sbctl approach)
sign-remaining.sh             # Sign any unsigned EFI files
enroll-keys.sh                # Enroll keys into firmware
fix-grub-verifier.sh          # Attempt to fix GRUB verifier
run.py                        # Python CLI
src/myproject/
  secureboot.py               # Python secureboot module
  kernel_builder.py            # Shared utilities
  __init__.py
tests/
  test_secureboot.py           # 55 tests
```

---

## License

Do whatever you want with it.
