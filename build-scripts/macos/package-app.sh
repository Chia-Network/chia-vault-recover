#!/usr/bin/env bash
# Wrap the macOS GUI executable in an application bundle.
# Gatekeeper rejects a Developer ID binary that is not an app
# ("the code is valid but does not seem to be an app"). A notarization
# ticket can be stapled to an app bundle, not to a bare Mach-O.
# Usage: package-app.sh <artifact-name>
set -euo pipefail

artifact="${1:?artifact name required}"
root="$(cd "$(dirname "$0")/../.." && pwd)"
gui="dist/chia-vault-recover-gui-${artifact}"
app="dist/Chia Vault Recover.app"

if [ -d "$app" ]; then
  echo "App bundle already present: $app"
  exit 0
fi

if [ ! -f "$gui" ]; then
  echo "Missing GUI binary to bundle: $gui" >&2
  exit 1
fi

version="$(sed -n 's/^version = "\(.*\)"/\1/p' "$root/Cargo.toml" | head -1)"
if [ -z "$version" ]; then
  echo "Could not read version from $root/Cargo.toml" >&2
  exit 1
fi

mkdir -p "$app/Contents/MacOS"
ditto "$gui" "$app/Contents/MacOS/chia-vault-recover-gui"
chmod +x "$app/Contents/MacOS/chia-vault-recover-gui"
sed "s/__VERSION__/${version}/g" "$root/build-scripts/macos/Info.plist" > "$app/Contents/Info.plist"
plutil -lint "$app/Contents/Info.plist" >/dev/null
rm -f "$gui"
echo "Bundled $app ($version)"
