#!/usr/bin/env bash
# Rename dist/* to include the release version before they are uploaded.
# A tag v1.0.0-rc3 becomes chia-vault-recover-1.0.0-rc3-linux-x86_64.
# Pull-request artifact names stay unchanged because this runs only on release.
set -euo pipefail

version="${GITHUB_REF_NAME:-}"
version="${version#v}"
if [ -z "$version" ]; then
  echo "GITHUB_REF_NAME is required to version release assets." >&2
  exit 1
fi

shopt -s nullglob
for path in dist/*; do
  name="$(basename "$path")"
  case "$name" in
    chia-vault-recover-gui-*)
      rest="${name#chia-vault-recover-gui-}"
      dest="dist/chia-vault-recover-gui-${version}-${rest}"
      ;;
    chia-vault-recover-*)
      rest="${name#chia-vault-recover-}"
      dest="dist/chia-vault-recover-${version}-${rest}"
      ;;
    *)
      echo "Unexpected release asset name: $name" >&2
      exit 1
      ;;
  esac
  mv "$path" "$dest"
  echo "Renamed $name -> $(basename "$dest")"
done
