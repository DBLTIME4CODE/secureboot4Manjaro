#!/usr/bin/env python3
"""Simple CLI for Secure Boot automation.

Usage:
    sudo python run.py setup              # Full setup
    sudo python run.py status             # Check current state
    sudo python run.py status /my/keys    # Check with custom key dir
    sudo python run.py sign               # Re-sign all kernels + modules
    sudo python run.py check-efi          # Check shim / EFI boot chain
"""

from __future__ import annotations

import sys
from pathlib import Path

# Add src/ to the import path so you don't need PYTHONPATH
sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from myproject.secureboot import (
    check_efi_shim_chain,
    check_status,
    setup_secureboot,
    sign_all_kernels,
    sign_dkms_modules,
)

DEFAULT_KEY_DIR = "/var/lib/secureboot"


def main() -> None:
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    command = sys.argv[1]
    key_dir = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_KEY_DIR

    if command == "setup":
        result = setup_secureboot(key_dir)
        print("\n=== Setup Complete ===")
        for k, v in result.items():
            print(f"  {k}: {v}")

    elif command == "status":
        status = check_status(key_dir=key_dir)
        print("\n=== Secure Boot Status ===")
        for k, v in status.items():
            print(f"  {k}: {v}")

    elif command == "sign":
        print("Signing kernels...")
        kernels = sign_all_kernels(key_dir)
        print(f"  Signed {len(kernels)} kernel(s)")
        print("Signing modules...")
        modules = sign_dkms_modules(key_dir)
        print(f"  Signed {len(modules)} module(s)")

    elif command == "check-efi":
        result = check_efi_shim_chain()
        print("\n=== EFI Boot Chain ===")
        for k, v in result.items():
            print(f"  {k}: {v}")

    else:
        print(f"Unknown command: {command}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
