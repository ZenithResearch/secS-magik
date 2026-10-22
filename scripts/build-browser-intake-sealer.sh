#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: $0 OUTPUT_DIRECTORY" >&2
  exit 2
fi

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
output_directory=$1

case "$output_directory" in
  /*) ;;
  *) output_directory="$PWD/$output_directory" ;;
esac

if [ "$output_directory" = "/" ] || [ "$output_directory" = "$repository_root" ]; then
  echo "refusing unsafe output directory" >&2
  exit 2
fi
if [ -e "$output_directory" ]; then
  echo "output directory already exists" >&2
  exit 2
fi
mkdir -p -- "$output_directory"

wasm-pack build \
  --target web \
  --release \
  --no-opt \
  --out-dir "$output_directory" \
  "$repository_root/core" \
  --features uniffi

cp "$repository_root/browser/intake-sealer/index.js" "$output_directory/index.js"
cp "$repository_root/browser/intake-sealer/index.d.ts" "$output_directory/index.d.ts"
cp "$repository_root/browser/intake-sealer/package.json" "$output_directory/package.json"
cp "$repository_root/browser/intake-sealer/README.md" "$output_directory/README.md"
rm -f -- "$output_directory/.gitignore" "$output_directory/libsec_core_bg.wasm.d.ts"

python3 "$repository_root/scripts/hash-browser-intake-sealer.py" "$output_directory"

