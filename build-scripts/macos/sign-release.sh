#!/usr/bin/env bash
# Sign the macOS CLI and GUI app in ./dist.
# Run package-app.sh first so the GUI is a bundle. Packaging the disk image
# and notarization are later steps: the image has to exist before it can be
# signed and stapled.
# Required env: APPLE_DEV_ID_APP, APPLE_DEV_ID_APP_PASS,
# APPLE_NOTARIZE_USERNAME, APPLE_NOTARIZE_PASSWORD, APPLE_TEAM_ID.
# Usage: sign-release.sh <artifact-name>
set -euo pipefail

artifact="${1:?artifact name required}"
root="$(cd "$(dirname "$0")/../.." && pwd)"
# shellcheck source=keychain.sh
source "$root/build-scripts/macos/keychain.sh"
entitlements="$root/build-scripts/macos/entitlements.plist"
cli="dist/chia-vault-recover-${artifact}"
app="dist/Chia Vault Recover.app"

trap cleanup_developer_id EXIT

if [ ! -f "$cli" ]; then
  echo "Missing binary to sign: $cli" >&2
  exit 1
fi
if [ ! -d "$app" ]; then
  echo "Missing app to sign: $app (run package-app.sh first)" >&2
  exit 1
fi

import_developer_id

codesign --force --timestamp --options runtime --entitlements "$entitlements" --sign "$IDENTITY" "$cli"
codesign --verify --strict --verbose=2 "$cli"
codesign --force --timestamp --options runtime --entitlements "$entitlements" --sign "$IDENTITY" "$app"
codesign --verify --strict --verbose=2 "$app"
