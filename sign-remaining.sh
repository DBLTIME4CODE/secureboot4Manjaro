#!/bin/bash
# sign-remaining.sh — Sign all unsigned EFI files that sbctl verify flagged
# Usage: sudo bash sign-remaining.sh
set -euo pipefail

echo "Signing all unsigned EFI binaries..."

# Find and sign every unsigned file sbctl knows about
sbctl verify 2>&1 | grep "is not signed" | while read -r line; do
    file=$(echo "$line" | sed 's/^✗ //' | sed 's/ is not signed$//')
    # Skip .bak files
    if [[ "$file" == *.bak ]]; then
        echo "  Skipping backup: $file"
        continue
    fi
    if [ -f "$file" ]; then
        echo "  Signing: $file"
        sbctl sign -s "$file"
    fi
done

echo ""
echo "Verification:"
sbctl verify
