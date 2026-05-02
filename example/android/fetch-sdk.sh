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

SDKMANAGER="./sdkmanager"
if [[ $OS_NAME == "win" ]]; then
	SDKMANAGER="./sdkmanager.bat"
fi

echo "Downloading SDK Manager..."
mkdir -p "$ANDROID_SDK_ROOT" || exit 1
cd "$ANDROID_SDK_ROOT" || exit 1
$WGET "https://dl.google.com/android/repository/commandlinetools-$OS_NAME-13114758_latest.zip" || exit 1
mkdir -p cmdline-tools || exit 1
unzip -qq "commandlinetools-$OS_NAME-13114758_latest.zip" -d cmdline-tools || exit 1
rm "commandlinetools-$OS_NAME-13114758_latest.zip" || exit 1
mv cmdline-tools/* cmdline-tools/latest/ || exit 1

echo "Installing required SDK tools..."
cd cmdline-tools/latest/bin/ || exit 1
yes | $SDKMANAGER --licenses >/dev/null || exit 1
$SDKMANAGER --install "ndk;$ANDROID_NDK_PACKAGE" "cmake;3.22.1" "build-tools;34.0.0" "platforms;android-34" >/dev/null || exit 1
