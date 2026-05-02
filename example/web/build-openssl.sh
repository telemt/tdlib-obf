#!/bin/sh
set -eu

SCRIPT_DIR=$(cd -- "$(dirname -- "$0")" >/dev/null 2>&1 && pwd -P) || exit 1
cd "$SCRIPT_DIR" || exit 1

emconfigure true 2> /dev/null || { echo 'emconfigure not found. Install emsdk and add emconfigure and emmake to PATH environment variable. See instruction at https://kripken.github.io/emscripten-site/docs/getting_started/downloads.html. Do not forget to add `emconfigure` and `emmake` to the PATH environment variable via `emsdk/emsdk_env.sh` script.'; exit 1; }
emcc --check 2>&1 | grep -q ' 3.1.1 ' || { echo 'emcc 3.1.1 check failed. Install emsdk and install and activate 3.1.1 tools. See instruction at https://kripken.github.io/emscripten-site/docs/getting_started/downloads.html.'; exit 1; }

OPENSSL_VERSION=openssl-3.0.13
OPENSSL_ARCHIVE="$OPENSSL_VERSION.tar.gz"
OPENSSL_SOURCE_DIR="openssl-$OPENSSL_VERSION"
OPENSSL_SHA256_EXPECTED="e74504ed7035295ec7062b1da16c15b57ff2a03cd2064a28d8c39458cacc45fc"

compute_sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    echo "Error: sha256sum or shasum is required to verify downloads." >&2
    exit 1
  fi
}

download_file() {
  url=$1
  output=$2
  if command -v curl >/dev/null 2>&1; then
    curl -sfL -o "$output" "$url"
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O "$output" "$url"
  else
    echo "Error: curl or wget is required to download OpenSSL." >&2
    exit 1
  fi
}

if [ ! -f "$OPENSSL_ARCHIVE" ]; then
  echo "Downloading OpenSSL sources..."
  download_file "https://github.com/openssl/openssl/archive/refs/tags/$OPENSSL_ARCHIVE" "$OPENSSL_ARCHIVE"
fi

OPENSSL_SHA256_ACTUAL=$(compute_sha256 "$OPENSSL_ARCHIVE")
if [ "$OPENSSL_SHA256_ACTUAL" != "$OPENSSL_SHA256_EXPECTED" ]; then
  echo "Error: OpenSSL archive checksum mismatch for $OPENSSL_ARCHIVE" >&2
  echo "Expected: $OPENSSL_SHA256_EXPECTED" >&2
  echo "Actual:   $OPENSSL_SHA256_ACTUAL" >&2
  exit 1
fi

rm -rf "$OPENSSL_SOURCE_DIR"
echo "Unpacking OpenSSL sources..."
tar xzf "$OPENSSL_ARCHIVE" || exit 1
cd "$OPENSSL_SOURCE_DIR" || exit 1

emconfigure ./Configure linux-generic32 no-shared no-threads no-dso no-engine no-unit-test no-ui || exit 1
sed -i.bak 's/CROSS_COMPILE=.*/CROSS_COMPILE=/g' Makefile || exit 1
sed -i.bak 's/-ldl //g' Makefile || exit 1
sed -i.bak 's/-O3/-Os/g' Makefile || exit 1
echo "Building OpenSSL..."
emmake make depend || exit 1
emmake make -j 4 || exit 1

rm -rf ../build/crypto || exit 1
mkdir -p ../build/crypto/lib || exit 1
cp libcrypto.a libssl.a ../build/crypto/lib/ || exit 1
cp -r include ../build/crypto/ || exit 1
cd .. || exit 1
