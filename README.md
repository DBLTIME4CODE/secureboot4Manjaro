# Secure Boot Auto-Signing for Manjaro/Arch Linux

Automates UEFI Secure Boot on Manjaro and Arch Linux — generates MOK keys, signs kernels and DKMS modules, enrolls the certificate, and installs a pacman hook so everything stays signed after updates.

---

## What It Does

| Step | What happens |
|------|-------------|
| **1. Key generation** | Creates an RSA 4096 MOK key pair (`MOK.key` + `MOK.crt`) with 10-year validity |
| **2. Kernel signing** | Signs every `/boot/vmlinuz-*` with `sbsign` |
| **3. Module signing** | Signs DKMS `.ko` modules in `/lib/modules/` (optional parallel mode) |
| **4. MOK enrollment** | Registers the certificate via `mokutil --import` (one-time, prompts for password) |
| **5. Pacman hook** | Installs `/etc/pacman.d/hooks/99-secureboot.hook` so kernels are auto-signed on every update |

After setup, enable Secure Boot in BIOS and you're done. The padlock icon stays locked.

---

## Requirements

- **Manjaro** or **Arch Linux** (uses `pacman`, `sbsigntools`, `mokutil`)
- **Python 3.10+**
- **Root access** via `sudo`

---

## Quick Start

```bash
# 1. Install dependencies
sudo pacman -S sbsigntools mokutil openssl python

# 2. Clone
git clone https://github.com/DBLTIME4CODE/secureboot4Manjaro.git
cd secureboot4Manjaro

# 3. Run the setup
sudo PYTHONPATH=src python -c "
from myproject.secureboot import setup_secureboot
setup_secureboot('/var/lib/secureboot')
"

# 4. You'll be prompted for a one-time MOK enrollment password — remember it

# 5. Reboot → MOK Manager appears → enter the password → Enroll MOK

# 6. Enable Secure Boot in BIOS → locked padlock ✓
```

---

## How It Works

```
setup_secureboot("/var/lib/secureboot")
         │
         ├─ ensure_tools_installed()     Check sbsign, mokutil, openssl on PATH
         │
         ├─ generate_mok_keys()          Create RSA 4096 key pair (skip if exists)
         │                               Private key: 0o600, Cert: 0o644
         │
         ├─ sign_all_kernels()           Find /boot/vmlinuz-*, sign each with sbsign
         │
         ├─ sign_dkms_modules()          Find /lib/modules/**/*.ko, sign each
         │
         ├─ enroll_mok()                 mokutil --import (skip if already enrolled)
         │
         └─ install_pacman_hook()        Write 99-secureboot.hook to /etc/pacman.d/hooks/
```

---

## Individual Functions

```python
from pathlib import Path
from myproject.secureboot import (
    generate_mok_keys,
    sign_kernel,
    sign_all_kernels,
    sign_dkms_modules,
    enroll_mok,
    is_mok_enrolled,
    install_pacman_hook,
    check_status,
)

# Generate keys (idempotent — skips if they exist)
key, cert = generate_mok_keys("/var/lib/secureboot")

# Sign a specific kernel
sign_kernel("/boot/vmlinuz-linux", key, cert)

# Sign all kernels in /boot
signed = sign_all_kernels("/var/lib/secureboot")

# Sign DKMS modules (parallel mode for 5000+ modules)
sign_dkms_modules("/var/lib/secureboot", parallel=True, max_workers=8)

# Check if MOK is enrolled
if not is_mok_enrolled(cert):
    enroll_mok(cert)  # prompts for password

# Install pacman hook for auto-signing
install_pacman_hook("/var/lib/secureboot")

# Check overall status
status = check_status()
# {'secure_boot_enabled': True, 'keys_present': True,
#  'kernels_signed': ['vmlinuz-linux', 'vmlinuz-linux-lts'],
#  'hook_installed': True}
```

---

## The Pacman Hook

After installation, `/etc/pacman.d/hooks/99-secureboot.hook` contains:

```ini
[Trigger]
Operation = Install
Operation = Upgrade
Type = Path
Target = usr/lib/modules/*/vmlinuz
Target = boot/vmlinuz-*

[Action]
Description = Signing kernels for Secure Boot...
When = PostTransaction
Exec = /usr/bin/sbsign --key /var/lib/secureboot/MOK.key --cert /var/lib/secureboot/MOK.crt --output %f %f
Depends = sbsigntools
```

This fires automatically every time pacman installs or upgrades a kernel.

---

## Security

| Feature | Detail |
|---------|--------|
| **Private key permissions** | `MOK.key` is set to `0o600` (owner read/write only) |
| **Certificate permissions** | `MOK.crt` is set to `0o644` (readable by all, writable by owner) |
| **No `shell=True`** | All subprocess calls use list-form arguments |
| **Input validation** | All paths validated before reaching `sudo`/`sbsign` commands |
| **Idempotent** | Safe to run multiple times — skips existing keys and enrolled certs |

---

## File Layout

```
src/myproject/
├── secureboot.py            # Secure Boot automation module
├── kernel_builder.py        # Shared utilities (run_cmd, validation)
└── __init__.py

tests/
└── test_secureboot.py       # 29 tests (all mocked — runs anywhere)
```

---

## Running Tests

```bash
pip install pytest
PYTHONPATH=src pytest tests/test_secureboot.py -q
```

All tests mock subprocess calls — no real `sbsign`, `mokutil`, or root required.

---

## License

Do whatever you want with it.
