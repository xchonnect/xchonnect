#!/usr/bin/env bash
# Run the project-local uniffi-bindgen (bindings/uniffi/uniffi-bindgen.rs), which always
# matches the crate's uniffi version. It is built in its own target directory so that
# building it never replaces the library whose interface is being read.
#
#   scripts/uniffi-bindgen.sh generate --library <lib> --language swift --out-dir <dir>
set -euo pipefail
cd "$(dirname "$0")/.."
CARGO_TARGET_DIR=target/uniffi-bindgen \
  cargo build -q -p xchonnect-uniffi --features bindgen --bin uniffi-bindgen --locked
exec target/uniffi-bindgen/debug/uniffi-bindgen "$@"
