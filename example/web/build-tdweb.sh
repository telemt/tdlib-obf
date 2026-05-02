#!/bin/sh
set -eu

SCRIPT_DIR=$(cd -- "$(dirname -- "$0")" >/dev/null 2>&1 && pwd -P) || exit 1
cd "$SCRIPT_DIR" || exit 1

cd tdweb || exit 1
if [ -f package-lock.json ]; then
	npm ci --no-audit --fund=false || exit 1
else
	npm install --no-save --no-audit --fund=false || exit 1
fi
npm run build || exit 1
cd .. || exit 1
