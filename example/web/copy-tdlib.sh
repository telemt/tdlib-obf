#!/bin/sh
set -eu

SCRIPT_DIR=$(cd -- "$(dirname -- "$0")" >/dev/null 2>&1 && pwd -P) || exit 1
cd "$SCRIPT_DIR" || exit 1

DEST="tdweb/src/prebuilt/release/"
mkdir -p "$DEST" || exit 1
cp build/wasm/td_wasm.js build/wasm/td_wasm.wasm "$DEST" || exit 1
