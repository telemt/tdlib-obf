#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null && pwd -P)" || exit 1
readonly SCRIPT_DIR

cd "$SCRIPT_DIR" || exit 1
td_path=$(grealpath ../..)

rm -rf build
mkdir -p build
cd build || exit 1

set_cmake_options() {
  local platform=$1
  local openssl_path
  local openssl_crypto_library
  local openssl_ssl_library

  openssl_path=$(grealpath "../third_party/openssl/$platform")
  echo "OpenSSL path = ${openssl_path}"
  openssl_crypto_library="${openssl_path}/lib/libcrypto.a"
  openssl_ssl_library="${openssl_path}/lib/libssl.a"

  options=(
    "-DOPENSSL_FOUND=1"
    "-DOPENSSL_CRYPTO_LIBRARY=${openssl_crypto_library}"
    "-DOPENSSL_SSL_LIBRARY=${openssl_ssl_library}"
    "-DOPENSSL_INCLUDE_DIR=${openssl_path}/include"
    "-DOPENSSL_LIBRARIES=${openssl_crypto_library};${openssl_ssl_library}"
    "-DCMAKE_BUILD_TYPE=Release"
  )
}

platforms=(macOS iOS watchOS tvOS visionOS)
for platform in "${platforms[@]}"; do
  echo "Platform = ${platform}"
  simulators=(0)
  if [[ $platform != "macOS" ]]; then
    simulators+=(1)
  fi

  for simulator in "${simulators[@]}"; do
    local_platform="$platform"
    other_options=()

    if [[ $platform == "macOS" ]]; then
      other_options=("-DCMAKE_OSX_ARCHITECTURES=x86_64;arm64")
    else
      case "$platform" in
      watchOS) ios_platform="WATCH" ;;
      tvOS) ios_platform="TV" ;;
      visionOS) ios_platform="VISION" ;;
      *) ios_platform="" ;;
      esac

      if [[ $simulator == "1" ]]; then
        local_platform="${platform}-simulator"
        ios_platform="${ios_platform}SIMULATOR"
      else
        ios_platform="${ios_platform}OS"
      fi

      echo "iOS platform = ${ios_platform}"
      other_options=(
        "-DIOS_PLATFORM=${ios_platform}"
        "-DCMAKE_TOOLCHAIN_FILE=${td_path}/CMake/iOS.cmake"
        "-DCMAKE_MAKE_PROGRAM=make"
      )
    fi

    set_cmake_options "$local_platform"

    build="build-${local_platform}"
    install="install-${local_platform}"
    rm -rf "$build"
    mkdir -p "$build"
    mkdir -p "$install"
    cd "$build" || exit 1
    cmake "$td_path" "${options[@]}" "${other_options[@]}" "-DCMAKE_INSTALL_PREFIX=../${install}"
    ZERO_AR_DATE=1 make -j3 install || exit 1
    cd .. || exit 1

    install_name_tool -id @rpath/libtdjson.dylib "${install}/lib/libtdjson.dylib"
    mkdir -p "../tdjson/${local_platform}/include"
    rsync --recursive "${install}/include/" "../tdjson/${local_platform}/include/"
    mkdir -p "../tdjson/${local_platform}/lib"
    cp "${install}/lib/libtdjson.dylib" "../tdjson/${local_platform}/lib/"
  done
done

shopt -s nullglob
produced_dylibs=(install-*/lib/libtdjson.dylib)
if [ ${#produced_dylibs[@]} -eq 0 ]; then
  echo "Error: no install-*/lib/libtdjson.dylib outputs were produced."
  exit 1
fi

xcodebuild_frameworks=()
for dylib in "${produced_dylibs[@]}"; do
  xcodebuild_frameworks+=(-library "$(grealpath "${dylib}")")
done

# Make xcframework
xcodebuild -create-xcframework \
  "${xcodebuild_frameworks[@]}" \
  -output "libtdjson.xcframework"

rsync --recursive libtdjson.xcframework ../tdjson/
