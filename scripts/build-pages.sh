#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE_DIR="${1:-$REPO_ROOT/.pages/source}"

if [[ "$SOURCE_DIR" != /* ]]; then
  SOURCE_DIR="$REPO_ROOT/$SOURCE_DIR"
fi

case "$SOURCE_DIR" in
  "$REPO_ROOT"/*|/tmp/*|/private/tmp/*) ;;
  *)
    echo "pages build: refusing output outside the repository or a temporary directory: $SOURCE_DIR" >&2
    exit 2
    ;;
esac

if [[ "$SOURCE_DIR" == "$REPO_ROOT" || "$SOURCE_DIR" == / || -z "$SOURCE_DIR" ]]; then
  echo "pages build: refusing unsafe output directory: $SOURCE_DIR" >&2
  exit 2
fi

BUILD_ROOT="${SOURCE_DIR%/}.build"

if [[ "$BUILD_ROOT" == "$REPO_ROOT" || "$BUILD_ROOT" == / || -z "$BUILD_ROOT" ]]; then
  echo "pages build: refusing unsafe build directory: $BUILD_ROOT" >&2
  exit 2
fi

rm -rf "$SOURCE_DIR" "$BUILD_ROOT"
mkdir -p "$SOURCE_DIR" "$BUILD_ROOT"

copy_markdown() {
  local source_path="$1"
  local target_path="$2"
  mkdir -p "$(dirname "$target_path")"
  {
    echo "---"
    echo "layout: default"
    echo "---"
    echo
    sed '/^---$/d' "$source_path"
  } > "$target_path"
}

{
  echo "---"
  echo "layout: default"
  echo "permalink: /"
  echo "---"
  echo
  sed '/^---$/d' "$REPO_ROOT/README.md"
} > "$SOURCE_DIR/index.md"

while IFS= read -r relative_path; do
  copy_markdown "$REPO_ROOT/$relative_path" "$SOURCE_DIR/$relative_path"
done < <(cd "$REPO_ROOT" && rg --files docs -g '*.md' | sort)

for relative_path in \
  AGENTS.md \
  CHANGELOG.md \
  SECURITY.md \
  core/README.md \
  client/README.md \
  server/README.md \
  panel/README.md \
  examples/README.md \
  scripts/README.md; do
  copy_markdown "$REPO_ROOT/$relative_path" "$SOURCE_DIR/$relative_path"
done

cp "$REPO_ROOT/LICENSE" "$SOURCE_DIR/LICENSE"
cp "$REPO_ROOT/docs/pages/_config.yml" "$SOURCE_DIR/_config.yml"

cargo doc \
  --manifest-path "$REPO_ROOT/Cargo.toml" \
  --workspace \
  --all-features \
  --no-deps \
  --target-dir "$BUILD_ROOT/host"
mkdir -p "$SOURCE_DIR/api"
cp -R "$BUILD_ROOT/host/doc/." "$SOURCE_DIR/api/"
{
  echo '<!doctype html>'
  echo '<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">'
  echo '<title>secS-magik Rust API documentation</title></head><body>'
  echo '<h1>secS-magik Rust API documentation</h1>'
  echo '<p>Generated from the current five-member workspace with dependencies omitted.</p>'
  echo '<ul>'
  echo '<li><a href="libsec_core/">libsec-core</a></li>'
  echo '<li><a href="server/">server</a></li>'
  echo '<li><a href="secs_permissions/">secs-permissions</a></li>'
  echo '<li><a href="panel/">panel</a></li>'
  echo '<li><a href="client/">client binary</a></li>'
  echo '<li><a href="secs_gateway/">secs-gateway binary</a></li>'
  echo '<li><a href="secs_permctl/">secs-permctl binary</a></li>'
  echo '<li><a href="secz/">secz binary</a></li>'
  echo '</ul><p><a href="../">Back to project documentation</a></p></body></html>'
} > "$SOURCE_DIR/api/index.html"

cargo doc \
  --manifest-path "$REPO_ROOT/Cargo.toml" \
  -p libsec-core \
  --features uniffi \
  --target wasm32-unknown-unknown \
  --no-deps \
  --target-dir "$BUILD_ROOT/wasm"
cargo doc \
  --manifest-path "$REPO_ROOT/Cargo.toml" \
  -p panel \
  --target wasm32-unknown-unknown \
  --no-deps \
  --target-dir "$BUILD_ROOT/wasm"
mkdir -p "$SOURCE_DIR/wasm-api"
cp -R "$BUILD_ROOT/wasm/wasm32-unknown-unknown/doc/." "$SOURCE_DIR/wasm-api/"
{
  echo '<!doctype html>'
  echo '<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">'
  echo '<title>secS-magik WASM API documentation</title></head><body>'
  echo '<h1>secS-magik WASM API documentation</h1>'
  echo '<p>Generated for wasm32-unknown-unknown.</p>'
  echo '<ul>'
  echo '<li><a href="libsec_core/">libsec-core tunnel bindings</a></li>'
  echo '<li><a href="panel/">permission panel bindings</a></li>'
  echo '</ul><p><a href="../panel/">Open the browser permission panel</a></p><p><a href="../">Back to project documentation</a></p></body></html>'
} > "$SOURCE_DIR/wasm-api/index.html"

mkdir -p "$SOURCE_DIR/panel"
cp "$REPO_ROOT/panel/www/index.html" "$SOURCE_DIR/panel/index.html"
cp "$REPO_ROOT/panel/www/panel.js" "$SOURCE_DIR/panel/panel.js"
wasm-pack build "$REPO_ROOT/panel" \
  --target web \
  --release \
  --out-dir "$SOURCE_DIR/panel/pkg" \
  --out-name panel

test -s "$SOURCE_DIR/index.md"
test -s "$SOURCE_DIR/api/index.html"
test -s "$SOURCE_DIR/wasm-api/index.html"
test -s "$SOURCE_DIR/panel/index.html"
test -s "$SOURCE_DIR/panel/pkg/panel.js"
test -s "$SOURCE_DIR/panel/pkg/panel_bg.wasm"

echo "pages build: assembled source at $SOURCE_DIR"
