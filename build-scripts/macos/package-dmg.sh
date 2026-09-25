#!/usr/bin/env bash
# Put the macOS CLI and GUI into a disk image so a browser download keeps
# the executable bit. Loose Mach-O release assets are saved as mode 644 and
# open in TextEdit.
# Usage: package-dmg.sh <artifact-name>
set -euo pipefail

artifact="${1:?artifact name required}"
cli="dist/chia-vault-recover-${artifact}"
gui="dist/chia-vault-recover-gui-${artifact}"
dmg="dist/chia-vault-recover-${artifact}.dmg"

for bin in "$cli" "$gui"; do
  if [ ! -f "$bin" ]; then
    echo "Missing binary to package: $bin" >&2
    exit 1
  fi
  chmod +x "$bin"
done

stage="$(mktemp -d)"
cleanup() { rm -rf "$stage"; }
trap cleanup EXIT

cp "$cli" "$gui" "$stage/"
chmod +x "$stage/"*

rm -f "$dmg"
hdiutil create -volname "Chia Vault Recover" -srcfolder "$stage" -ov -format UDZO "$dmg"
rm -f "$cli" "$gui"
echo "Packaged $dmg"
