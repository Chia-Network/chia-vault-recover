# Import the Developer ID Application certificate into a temporary keychain.
# Source this file; do not execute it. Caller must set a trap on
# cleanup_developer_id. On success, IDENTITY is the codesign name.

import_developer_id() {
  keychain="signing_temp.keychain"
  p12="${RUNNER_TEMP:-/tmp}/apple-dev-id-app.p12"

  for var in APPLE_DEV_ID_APP APPLE_DEV_ID_APP_PASS APPLE_NOTARIZE_USERNAME APPLE_NOTARIZE_PASSWORD APPLE_TEAM_ID; do
    if [ -z "${!var}" ]; then
      echo "Release builds require Apple signing secret ${var}." >&2
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

  IDENTITY="$(security find-identity -v -p codesigning | awk -F'"' '/Developer ID Application/{print $2; exit}')"
  if [ -z "$IDENTITY" ]; then
    echo "No Developer ID Application identity in $keychain." >&2
    exit 1
  fi
}

cleanup_developer_id() {
  rm -f "${p12:-}"
  if [ -n "${keychain:-}" ]; then
    security delete-keychain "$keychain" || true
  fi
}
