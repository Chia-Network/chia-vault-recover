#!/usr/bin/env bash
# Sign, notarize, and staple the macOS release disk image in ./dist.
# Run package-dmg.sh first. Required env: APPLE_DEV_ID_APP, APPLE_DEV_ID_APP_PASS,
# APPLE_NOTARIZE_USERNAME, APPLE_NOTARIZE_PASSWORD, APPLE_TEAM_ID.
# Usage: notarize-dmg.sh <artifact-name>
set -euo pipefail

artifact="${1:?artifact name required}"
root="$(cd "$(dirname "$0")/../.." && pwd)"
# shellcheck source=keychain.sh
source "$root/build-scripts/macos/keychain.sh"
dmg="dist/chia-vault-recover-${artifact}.dmg"

trap cleanup_developer_id EXIT

if [ ! -f "$dmg" ]; then
  echo "Missing disk image to notarize: $dmg" >&2
  exit 1
fi

import_developer_id
codesign --force --timestamp --sign "$IDENTITY" "$dmg"
xcrun notarytool submit "$dmg" --apple-id "$APPLE_NOTARIZE_USERNAME" --password "$APPLE_NOTARIZE_PASSWORD" --team-id "$APPLE_TEAM_ID" --wait
xcrun stapler staple "$dmg"
xcrun stapler validate "$dmg"
