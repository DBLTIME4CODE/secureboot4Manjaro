# Secure Boot Auto-Signing for Manjaro/Arch Linux

Automates UEFI Secure Boot on Manjaro and Arch Linux - generates MOK keys, signs
kernels and DKMS modules, enrolls the certificate, and installs pacman hooks so
everything stays signed after updates.

---

## What It Does

| Step | What happens |
|------|-------------|
| **1. EFI preflight** | Checks whether shim is installed and in the EFI boot chain (advisory) |
| **2. Key generation** | Creates RSA 4096 MOK key pair (MOK.key + MOK.crt + DER MOK.cer) with 10-year validity |
| **3. Kernel signing** | Signs every /boot/vmlinuz-* with sbsign (PE/COFF format for EFI binaries) |
| **4. Module signing** | Signs .ko and .ko.zst DKMS modules using the kernel sign-file tool (PKCS#7 appended signatures) |
| **5. MOK enrollment** | Registers the DER certificate via mokutil --import (one-time, prompts for password) |
| **6. Kernel hook** | Installs /etc/pacman.d/hooks/99-secureboot.hook - auto-signs kernels on every update |
| **7. DKMS hook** | Installs /etc/pacman.d/hooks/98-secureboot-dkms.hook - auto-signs modules after DKMS rebuilds |

After setup, enable Secure Boot in BIOS and you are done.

---

## Requirements

- **Manjaro** or **Arch Linux** (uses pacman, sbsigntools, mokutil)
- **Python 3.10+**
- **Root access** via sudo
- **linux-headers** package (provides sign-file for module signing)
- **zstd** (if your system has .ko.zst compressed modules - Manjaro default)

---

## Quick Start

```bash
# 1. Install dependencies
sudo pacman -S sbsigntools mokutil openssl linux-headers zstd python

# 2. Clone
git clone https://github.com/DBLTIME4CODE/secureboot4Manjaro.git
cd secureboot4Manjaro

# 3. Run the setup
sudo PYTHONPATH=src python -c "from myproject.secureboot import setup_secureboot; setup_secureboot('/var/lib/secureboot')"

# 4. Enter a one-time MOK enrollment password when prompted
# 5. Reboot - MOK Manager appears - enter password - Enroll MOK
# 6. Enable Secure Boot in BIOS
```

Or use the helper script: `sudo bash setup.sh`

---

## Key Design Decisions

- **Kernels** signed with sbsign (PE/COFF - correct for EFI binaries)
- **Modules** signed with sign-file (PKCS#7 - what the kernel module loader verifies)
- **.ko.zst** modules (Manjaro default) are decompressed before signing and recompressed afterward
- **DER format** used consistently for all mokutil operations
- **Path validation** prevents template injection in hooks and scripts

---

## Security

| Feature | Detail |
|---------|--------|
| Private key permissions | MOK.key = 0o600 |
| Certificate permissions | MOK.crt and MOK.cer = 0o644 |
| No shell=True | All subprocess calls use list-form arguments |
| Path validation | _validate_safe_path() rejects shell metacharacters before template interpolation |
| Idempotent | Safe to run multiple times |

---

## Helper Scripts

| Script | Purpose |
|--------|---------|
| setup.sh | One-command dependency install + setup |
| fix-boot-chain.sh | Copy shim to fallback EFI path |
| sign-grub.sh | Sign GRUB with MOK key |
| fix-grub-direct.sh | Restore/reinstall GRUB, sign directly |
| recover-grub.sh | Emergency GRUB recovery |

---

## Running Tests

```bash
pip install pytest
PYTHONPATH=src pytest tests/test_secureboot.py -q
```

55 tests, all mocked - no real sbsign, mokutil, or root required.

---

## License

Do whatever you want with it.
