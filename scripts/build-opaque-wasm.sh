#!/usr/bin/env bash
# Builds web/packages/opaque-wasm (opaque-ke + cs-identity-wire compiled to WASM, M1 contract rev 5 §2.1) and
# writes the wasm-bindgen output to web/packages/opaque-wasm/pkg, which is committed so the web build does not
# need a Rust toolchain.
# Needs: rustup target wasm32-unknown-unknown and wasm-bindgen-cli 0.2.130 (same version as the crate's
# wasm-bindgen dependency) on PATH or in $WASM_BINDGEN.
# Usage: scripts/build-opaque-wasm.sh [--check]   (--check: rebuild and fail if pkg/ differs from the commit)
set -euo pipefail
cd "$(dirname "$0")/.."
root="$(pwd)"
bindgen="${WASM_BINDGEN:-wasm-bindgen}"
want="wasm-bindgen 0.2.130"
if ! have="$("$bindgen" --version 2>/dev/null)" || [[ "$have" != "$want" ]]; then
  echo "build-opaque-wasm: needs $want (found: ${have:-none})" >&2
  exit 2
fi
# Remap absolute paths so the binary is the same on every machine (and leaks no local paths).
# Standard-library sources map to /rustc/<commit-hash>, which is what toolchains without the
# rust-src component (e.g. CI) embed anyway.
sysroot_src="$(rustc --print sysroot)/lib/rustlib/src/rust"
rustc_hash="$(rustc -vV | sed -n 's/^commit-hash: //p')"
RUSTFLAGS="--remap-path-prefix=$root=/cs --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo --remap-path-prefix=$sysroot_src=/rustc/$rustc_hash" \
  cargo build --locked -p cs-opaque-wasm --target wasm32-unknown-unknown --release
out=web/packages/opaque-wasm/pkg
rm -rf "$out"
"$bindgen" --target web --out-dir "$out" --out-name cs_opaque_wasm \
  target/wasm32-unknown-unknown/release/cs_opaque_wasm.wasm
rm -f "$out/.gitignore"
if [[ "${1:-}" == "--check" ]]; then
  git diff --exit-code --stat -- "$out" || { echo "opaque-wasm pkg/ is stale: run scripts/build-opaque-wasm.sh" >&2; exit 1; }
fi
echo "opaque-wasm: $(wc -c < "$out/cs_opaque_wasm_bg.wasm") bytes"
