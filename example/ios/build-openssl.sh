#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null && pwd -P)" || exit 1
readonly SCRIPT_DIR
readonly PYTHON_APPLE_SUPPORT_DIR="Python-Apple-support"
readonly PYTHON_APPLE_SUPPORT_REPO="https://github.com/beeware/Python-Apple-support"
readonly PYTHON_APPLE_SUPPORT_COMMIT="6f43aba0ddd5a9f52f39775d0141bd4363614020"

cd "$SCRIPT_DIR" || exit 1

if [ ! -d "$PYTHON_APPLE_SUPPORT_DIR/.git" ]; then
  git clone "$PYTHON_APPLE_SUPPORT_REPO" "$PYTHON_APPLE_SUPPORT_DIR"
fi

cd "$PYTHON_APPLE_SUPPORT_DIR" || exit 1
git fetch --depth 1 origin "$PYTHON_APPLE_SUPPORT_COMMIT"
git checkout --force "$PYTHON_APPLE_SUPPORT_COMMIT" || exit 1
git reset --hard || exit 1
git clean -fdx || exit 1
git apply "$SCRIPT_DIR/Python-Apple-support.patch" || exit 1
cd "$SCRIPT_DIR" || exit 1

platforms=(macOS iOS watchOS tvOS visionOS)

for platform in "${platforms[@]}"; do
  simulators=(0)
  if [[ $platform != "macOS" ]]; then
    simulators+=(1)
  fi

  for simulator in "${simulators[@]}"; do
    target_platform="$platform"
    if [[ $simulator == "1" ]]; then
      target_platform="${platform}-simulator"
    fi

    echo "$target_platform"
    cd "$PYTHON_APPLE_SUPPORT_DIR" || exit 1
    # NB: upstream notes parallel OpenSSL target builds are unreliable here.
    SOURCE_DATE_EPOCH=1 ZERO_AR_DATE=1 make "OpenSSL-$target_platform" || exit 1
    cd "$SCRIPT_DIR" || exit 1

    rm -rf "third_party/openssl/$target_platform" || exit 1
    mkdir -p "third_party/openssl/$target_platform/lib" || exit 1
    cp "./$PYTHON_APPLE_SUPPORT_DIR/merge/$target_platform/openssl/lib/libcrypto.a" "third_party/openssl/$target_platform/lib/" || exit 1
    cp "./$PYTHON_APPLE_SUPPORT_DIR/merge/$target_platform/openssl/lib/libssl.a" "third_party/openssl/$target_platform/lib/" || exit 1
    cp -r "./$PYTHON_APPLE_SUPPORT_DIR/merge/$target_platform/openssl/include/" "third_party/openssl/$target_platform/include" || exit 1
  done
done
