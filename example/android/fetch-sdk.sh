#!/usr/bin/env bash

ANDROID_SDK_ROOT=${1:-SDK}
ANDROID_NDK_VERSION=${2:-r27b}

SCRIPT_DIR="$(cd "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null && pwd -P)" || exit 1

ANDROID_NDK_PACKAGE=$ANDROID_NDK_VERSION
if [[ $ANDROID_NDK_VERSION == "r27b" ]]; then
	# sdkmanager package IDs use numeric revisions for r27 releases.
	ANDROID_NDK_PACKAGE=27.1.12297006
fi

if [ -e "$ANDROID_SDK_ROOT" ]; then
	echo "Error: file or directory \"$ANDROID_SDK_ROOT\" already exists. Delete it manually to proceed."
	exit 1
fi

source "$SCRIPT_DIR/check-environment.sh" || exit 1

compute_sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    echo "Error: sha256sum or shasum is required to verify downloads."
    exit 1
  fi
}

SDK_TOOLS_ARCHIVE="commandlinetools-$OS_NAME-13114758_latest.zip"
case "$OS_NAME" in
linux)
  SDK_TOOLS_SHA256="7ec965280a073311c339e571cd5de778b9975026cfcbe79f2b1cdcb1e15317ee"
  ;;
mac)
  SDK_TOOLS_SHA256="5673201e6f3869f418eeed3b5cb6c4be7401502bd0aae1b12a29d164d647a54e"
  ;;
win)
  SDK_TOOLS_SHA256="98b565cb657b012dae6794cefc0f66ae1efb4690c699b78a614b4a6a3505b003"
  ;;
*)
  echo "Error: unsupported OS name '$OS_NAME'."
  exit 1
  ;;
esac

SDKMANAGER="./sdkmanager"
if [[ $OS_NAME == "win" ]]; then
	SDKMANAGER="./sdkmanager.bat"
fi

echo "Downloading SDK Manager..."
mkdir -p "$ANDROID_SDK_ROOT" || exit 1
cd "$ANDROID_SDK_ROOT" || exit 1
$WGET "https://dl.google.com/android/repository/$SDK_TOOLS_ARCHIVE" || exit 1
SDK_TOOLS_SHA256_ACTUAL=$(compute_sha256 "$SDK_TOOLS_ARCHIVE")
if [ "$SDK_TOOLS_SHA256_ACTUAL" != "$SDK_TOOLS_SHA256" ]; then
  echo "Error: Android command-line tools checksum mismatch for $SDK_TOOLS_ARCHIVE"
  echo "Expected: $SDK_TOOLS_SHA256"
  echo "Actual:   $SDK_TOOLS_SHA256_ACTUAL"
  exit 1
fi
mkdir -p cmdline-tools || exit 1
mkdir -p cmdline-tools/latest || exit 1
unzip -qq "$SDK_TOOLS_ARCHIVE" -d cmdline-tools || exit 1
rm "$SDK_TOOLS_ARCHIVE" || exit 1
if [ ! -d cmdline-tools/cmdline-tools ]; then
  echo "Error: unexpected Android command-line tools archive structure."
  exit 1
fi
mv cmdline-tools/cmdline-tools/* cmdline-tools/latest/ || exit 1
rmdir cmdline-tools/cmdline-tools || true

echo "Installing required SDK tools..."
cd cmdline-tools/latest/bin/ || exit 1
yes | $SDKMANAGER --licenses >/dev/null || exit 1
$SDKMANAGER --install "ndk;$ANDROID_NDK_PACKAGE" "cmake;3.22.1" "build-tools;34.0.0" "platforms;android-34" >/dev/null || exit 1
