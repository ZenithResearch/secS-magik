#!/usr/bin/env bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
mkdir -p build/holder-grants
rustup toolchain install 1.85.1 --profile minimal --component rustfmt --component clippy
export RUSTUP_TOOLCHAIN=1.85.1
export CARGO_BUILD_JOBS=2
run() { local name=$1; shift; "$@" 2>&1 | tee "build/holder-grants/$name.log"; }
run contract-format cargo fmt --manifest-path crates/secs-grant-contract/Cargo.toml -- --check
run contract-tests cargo test --manifest-path crates/secs-grant-contract/Cargo.toml --locked
run contract-clippy cargo clippy --manifest-path crates/secs-grant-contract/Cargo.toml --locked --all-targets -- -D warnings
run authority-build cargo build --manifest-path tools/holder-grant-authority/Cargo.toml --locked --release
run authority-clippy cargo clippy --manifest-path tools/holder-grant-authority/Cargo.toml --locked --all-targets -- -D warnings
