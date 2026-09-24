#!/usr/bin/env bash
# Sign and notarize the two macOS release binaries in ./dist.
# Required env: APPLE_DEV_ID_APP, APPLE_DEV_ID_APP_PASS,
# APPLE_NOTARIZE_USERNAME, APPLE_NOTARIZE_PASSWORD, APPLE_TEAM_ID.
# Usage: sign-release.sh <artifact-name>
set -euo pipefail

artifact="${1:?artifact name required}"
root="$(cd "$(dirname "$0")/../.." && pwd)"
entitlements="$root/build-scripts/macos/entitlements.plist"
cli="dist/chia-vault-recover-${artifact}"
gui="dist/chia-vault-recover-gui-${artifact}"
keychain="signing_temp.keychain"
p12="${RUNNER_TEMP:-/tmp}/apple-dev-id-app.p12"

cleanup() {
  rm -f "$p12"
  security delete-keychain "$keychain" || true
}
trap cleanup EXIT

for var in APPLE_DEV_ID_APP APPLE_DEV_ID_APP_PASS APPLE_NOTARIZE_USERNAME APPLE_NOTARIZE_PASSWORD APPLE_TEAM_ID; do
  if [ -z "${!var}" ]; then
    echo "Release builds require Vault secret code-signing/apple (${var})." >&2
    exit 1
  fi
done

for bin in "$cli" "$gui"; do
  if [ ! -f "$bin" ]; then
    echo "Missing binary to sign: $bin" >&2
    exit 1
  fi
done

security delete-keychain "$keychain" || true
keychain_password="$(openssl rand -base64 32)"
echo "$APPLE_DEV_ID_APP" | base64 --decode > "$p12"
security create-keychain -p "$keychain_password" "$keychain"
security set-keychain-settings -lut 21600 "$keychain"
security unlock-keychain -p "$keychain_password" "$keychain"
security import "$p12" -f pkcs12 -k "$keychain" -P "$APPLE_DEV_ID_APP_PASS" -T /usr/bin/codesign -T /usr/bin/security
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$keychain_password" "$keychain"
security list-keychains -d user -s "$keychain"
rm -f "$p12"

identity="$(security find-identity -v -p codesigning | awk -F'"' '/Developer ID Application/{print $2; exit}')"
if [ -z "$identity" ]; then
  echo "No Developer ID Application identity in $keychain." >&2
  exit 1
fi

for bin in "$cli" "$gui"; do
  codesign --force --timestamp --options runtime --entitlements "$entitlements" --sign "$identity" "$bin"
  codesign --verify --strict --verbose=2 "$bin"
done

stage="$(mktemp -d)"
cp "$cli" "$gui" "$stage/"
zip_path="${RUNNER_TEMP:-/tmp}/macos-notarize.zip"
ditto -c -k "$stage" "$zip_path"
rm -rf "$stage"
xcrun notarytool submit "$zip_path" --apple-id "$APPLE_NOTARIZE_USERNAME" --password "$APPLE_NOTARIZE_PASSWORD" --team-id "$APPLE_TEAM_ID" --wait
rm -f "$zip_path"
