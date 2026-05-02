#!/usr/bin/env bash

ANDROID_SDK_ROOT=${1:-SDK}
ANDROID_NDK_VERSION=${2:-r27b}
OPENSSL_INSTALL_DIR=${3:-third-party/openssl}
OPENSSL_VERSION=${4:-openssl-3.0.13}
BUILD_SHARED_LIBS=$5

SCRIPT_DIR="$(cd "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null && pwd -P)" || exit 1

if [ ! -d "$ANDROID_SDK_ROOT" ]; then
	echo "Error: directory \"$ANDROID_SDK_ROOT\" doesn't exist. Run ./fetch-sdk.sh first, or provide a valid path to Android SDK."
	exit 1
fi

if [ -e "$OPENSSL_INSTALL_DIR" ]; then
	echo "Error: file or directory \"$OPENSSL_INSTALL_DIR\" already exists. Delete it manually to proceed."
	exit 1
fi

source "$SCRIPT_DIR/check-environment.sh" || exit 1

is_enabled_flag() {
	case "$1" in
	"" | 0 | [Ff][Aa][Ll][Ss][Ee] | [Nn][Oo] | [Oo][Ff][Ff]) return 1 ;;
	*) return 0 ;;
	esac
}

version_gt() {
	local lhs=$1
	local rhs=$2
	local i
	local lhs_len
	local rhs_len
	local max_len
	local lhs_part
	local rhs_part
	local lhs_parts=()
	local rhs_parts=()
	local IFS=.

	read -r -a lhs_parts <<<"$lhs"
	read -r -a rhs_parts <<<"$rhs"

	lhs_len=${#lhs_parts[@]}
	rhs_len=${#rhs_parts[@]}
	if ((lhs_len > rhs_len)); then
		max_len=$lhs_len
	else
		max_len=$rhs_len
	fi

	for ((i = 0; i < max_len; i++)); do
		lhs_part=${lhs_parts[i]:-0}
		rhs_part=${rhs_parts[i]:-0}
		if ((10#$lhs_part > 10#$rhs_part)); then
			return 0
		fi
		if ((10#$lhs_part < 10#$rhs_part)); then
			return 1
		fi
	done

	return 1
}

resolve_android_ndk_root() {
	local ndk_root=$ANDROID_SDK_ROOT/ndk/$ANDROID_NDK_VERSION
	if [ -d "$ndk_root" ]; then
		echo "$ndk_root"
		return 0
	fi

	if [[ $ANDROID_NDK_VERSION == "r27b" ]]; then
		ndk_root=$ANDROID_SDK_ROOT/ndk/27.1.12297006
		if [ -d "$ndk_root" ]; then
			echo "$ndk_root"
			return 0
		fi
	fi

	if [[ $ANDROID_NDK_VERSION =~ ^r([0-9]+)[a-z]?$ ]]; then
		local ndk_major=${BASH_REMATCH[1]}
		local best_dir=""
		local best_version=""
		local candidate=""
		while IFS= read -r candidate; do
			local candidate_version
			candidate_version=$(basename "$candidate")
			if [[ ! $candidate_version =~ ^${ndk_major}[.][0-9]+([.][0-9]+)*$ ]]; then
				continue
			fi
			if [ -z "$best_version" ] || version_gt "$candidate_version" "$best_version"; then
				best_version=$candidate_version
				best_dir=$candidate
			fi
		done < <(find "$ANDROID_SDK_ROOT/ndk" -mindepth 1 -maxdepth 1 -type d -name "${ndk_major}.*")
		if [ -n "$best_dir" ]; then
			echo "$best_dir"
			return 0
		fi
	fi

	return 1
}

canonicalize_path() {
	local input_path=$1
	local input_dir
	local input_base

	input_dir=$(dirname -- "$input_path")
	input_base=$(basename -- "$input_path")
	cd "$input_dir" >/dev/null || return 1
	printf '%s/%s\n' "$(pwd -P)" "$input_base"
}

if [[ $OS_NAME == "win" ]] && is_enabled_flag "$BUILD_SHARED_LIBS"; then
	echo "Error: OpenSSL shared libraries can't be built on Windows because of 'The command line is too long.' error during build. You can run the script in WSL instead."
	exit 1
fi

mkdir -p "$OPENSSL_INSTALL_DIR" || exit 1

ANDROID_SDK_ROOT=$(canonicalize_path "$ANDROID_SDK_ROOT") || exit 1
OPENSSL_INSTALL_DIR=$(canonicalize_path "$OPENSSL_INSTALL_DIR") || exit 1
ANDROID_NDK_ROOT="$(resolve_android_ndk_root)" || {
	echo "Error: Android NDK \"$ANDROID_NDK_VERSION\" is not installed under \"$ANDROID_SDK_ROOT/ndk\". Run ./fetch-sdk.sh first."
	exit 1
}

ANDROID_NDK_MAJOR=$(basename "$ANDROID_NDK_ROOT")
ANDROID_NDK_MAJOR=${ANDROID_NDK_MAJOR%%.*}
if [[ $ANDROID_NDK_MAJOR =~ ^r([0-9]+)[a-z]?$ ]]; then
	ANDROID_NDK_MAJOR=${BASH_REMATCH[1]}
fi

cd "$SCRIPT_DIR" || exit 1

echo "Downloading OpenSSL sources..."
rm -f "$OPENSSL_VERSION.tar.gz" || exit 1
$WGET "https://github.com/openssl/openssl/archive/refs/tags/$OPENSSL_VERSION.tar.gz" || exit 1
rm -rf "./openssl-$OPENSSL_VERSION" || exit 1
tar xzf "$OPENSSL_VERSION.tar.gz" || exit 1
rm "$OPENSSL_VERSION.tar.gz" || exit 1
cd "openssl-$OPENSSL_VERSION" || exit 1

export ANDROID_NDK_ROOT                   # for OpenSSL 3.*.*
export ANDROID_NDK_HOME=$ANDROID_NDK_ROOT # for OpenSSL 1.1.1
PATH=$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/$HOST_ARCH/bin:$PATH

if ! clang --help >/dev/null 2>&1; then
	echo "Error: failed to run clang from Android NDK."
	if [[ $OS_NAME == "linux" ]]; then
		echo "Prebuilt Android NDK binaries are linked against glibc, so glibc must be installed."
	fi
	exit 1
fi

ANDROID_API32=16
ANDROID_API64=21
if [[ $ANDROID_NDK_MAJOR -ge 24 ]]; then
	ANDROID_API32=19
fi
if [[ $ANDROID_NDK_MAJOR -ge 26 ]]; then
	ANDROID_API32=21
fi

if is_enabled_flag "$BUILD_SHARED_LIBS"; then
	SHARED_BUILD_OPTION="shared"
else
	SHARED_BUILD_OPTION="no-shared"
fi

for ABI in arm64-v8a armeabi-v7a x86_64 x86; do
	if [[ $ABI == "x86" ]]; then
		./Configure android-x86 "${SHARED_BUILD_OPTION}" -U__ANDROID_API__ -D__ANDROID_API__=$ANDROID_API32 || exit 1
	elif [[ $ABI == "x86_64" ]]; then
		LDFLAGS=-Wl,-z,max-page-size=16384 ./Configure android-x86_64 "${SHARED_BUILD_OPTION}" -U__ANDROID_API__ -D__ANDROID_API__=$ANDROID_API64 || exit 1
	elif [[ $ABI == "armeabi-v7a" ]]; then
		./Configure android-arm "${SHARED_BUILD_OPTION}" -U__ANDROID_API__ -D__ANDROID_API__=$ANDROID_API32 -D__ARM_MAX_ARCH__=8 || exit 1
	elif [[ $ABI == "arm64-v8a" ]]; then
		LDFLAGS=-Wl,-z,max-page-size=16384 ./Configure android-arm64 "${SHARED_BUILD_OPTION}" -U__ANDROID_API__ -D__ANDROID_API__=$ANDROID_API64 || exit 1
	fi

	sed -i.bak 's/-O3/-O3 -ffunction-sections -fdata-sections/g' Makefile || exit 1

	make depend -s || exit 1
	make -j4 -s || exit 1

	mkdir -p "$OPENSSL_INSTALL_DIR/$ABI/lib/" || exit 1
	if is_enabled_flag "$BUILD_SHARED_LIBS"; then
		cp libcrypto.so libssl.so "$OPENSSL_INSTALL_DIR/$ABI/lib/" || exit 1
	else
		cp libcrypto.a libssl.a "$OPENSSL_INSTALL_DIR/$ABI/lib/" || exit 1
	fi
	cp -r include "$OPENSSL_INSTALL_DIR/$ABI/" || exit 1

	make distclean || exit 1
done

cd .. || exit 1

rm -rf "./openssl-$OPENSSL_VERSION" || exit 1
