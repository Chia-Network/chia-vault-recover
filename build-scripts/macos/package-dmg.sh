#!/usr/bin/env bash
# Put the macOS CLI and GUI app into a disk image so a browser download keeps
# the executable bit and Finder can launch the GUI. Loose Mach-O release
# assets are saved as mode 644 and open in TextEdit, and Gatekeeper will not
# treat them as an app.
# Usage: package-dmg.sh <artifact-name>
set -euo pipefail

artifact="${1:?artifact name required}"
root="$(cd "$(dirname "$0")/../.." && pwd)"
bash "$root/build-scripts/macos/package-app.sh" "$artifact"

cli="dist/chia-vault-recover-${artifact}"
app="dist/Chia Vault Recover.app"
dmg="dist/chia-vault-recover-${artifact}.dmg"

if [ ! -f "$cli" ]; then
  echo "Missing binary to package: $cli" >&2
  exit 1
fi
if [ ! -d "$app" ]; then
  echo "Missing app to package: $app" >&2
  exit 1
fi
chmod +x "$cli"

stage="$(mktemp -d)"
cleanup() { rm -rf "$stage"; }
trap cleanup EXIT

ditto "$cli" "$stage/$(basename "$cli")"
ditto "$app" "$stage/Chia Vault Recover.app"
ln -s /Applications "$stage/Applications"
chmod +x "$stage/$(basename "$cli")" "$stage/Chia Vault Recover.app/Contents/MacOS/chia-vault-recover-gui"

rm -f "$dmg"
hdiutil create -volname "Chia Vault Recover" -srcfolder "$stage" -ov -format UDZO "$dmg"
rm -f "$cli"
rm -rf "$app"
echo "Packaged $dmg"
