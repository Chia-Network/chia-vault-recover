#!/usr/bin/env bash
# Sign the two macOS release binaries in ./dist.
# Packaging and notarization are later steps: the disk image has to exist
# before it can be signed and stapled.
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
gui="dist/chia-vault-recover-gui-${artifact}"

trap cleanup_developer_id EXIT

for bin in "$cli" "$gui"; do
  if [ ! -f "$bin" ]; then
    echo "Missing binary to sign: $bin" >&2
    exit 1
  fi
done

import_developer_id

for bin in "$cli" "$gui"; do
  codesign --force --timestamp --options runtime --entitlements "$entitlements" --sign "$IDENTITY" "$bin"
  codesign --verify --strict --verbose=2 "$bin"
done
