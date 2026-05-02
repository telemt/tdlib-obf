#!/usr/bin/env bash

ANDROID_SDK_ROOT=${1:-SDK}
ANDROID_NDK_VERSION=${2:-r27b}
OPENSSL_INSTALL_DIR=${3:-third-party/openssl}
ANDROID_STL=${4:-c++_static}
TDLIB_INTERFACE=${5:-Java}

SCRIPT_DIR="$(cd "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null && pwd -P)" || exit 1

if [ "$ANDROID_STL" != "c++_static" ] && [ "$ANDROID_STL" != "c++_shared" ]; then
	echo 'Error: ANDROID_STL must be either "c++_static" or "c++_shared".'
	exit 1
fi

if [ "$TDLIB_INTERFACE" != "Java" ] && [ "$TDLIB_INTERFACE" != "JSON" ] && [ "$TDLIB_INTERFACE" != "JSONJava" ]; then
	echo 'Error: TDLIB_INTERFACE must be either "Java", "JSON", or "JSONJava".'
	exit 1
fi

source "$SCRIPT_DIR/check-environment.sh" || exit 1

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

if [ ! -d "$ANDROID_SDK_ROOT" ]; then
	echo "Error: directory \"$ANDROID_SDK_ROOT\" doesn't exist. Run ./fetch-sdk.sh first, or provide a valid path to Android SDK."
	exit 1
fi

if [ ! -d "$OPENSSL_INSTALL_DIR" ]; then
	echo "Error: directory \"$OPENSSL_INSTALL_DIR\" doesn't exists. Run ./build-openssl.sh first."
	exit 1
fi

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

ANDROID_SDK_ROOT=$(canonicalize_path "$ANDROID_SDK_ROOT") || exit 1
ANDROID_NDK_ROOT="$(resolve_android_ndk_root)" || {
	echo "Error: Android NDK \"$ANDROID_NDK_VERSION\" is not installed under \"$ANDROID_SDK_ROOT/ndk\". Run ./fetch-sdk.sh first."
	exit 1
}
OPENSSL_INSTALL_DIR=$(canonicalize_path "$OPENSSL_INSTALL_DIR") || exit 1
PATH=$ANDROID_SDK_ROOT/cmake/3.22.1/bin:$PATH
TDLIB_INTERFACE_OPTIONS=()
if [[ $TDLIB_INTERFACE == "JSON" ]]; then
	TDLIB_INTERFACE_OPTIONS+=("-DTD_ANDROID_JSON=ON")
elif [[ $TDLIB_INTERFACE == "JSONJava" ]]; then
	TDLIB_INTERFACE_OPTIONS+=("-DTD_ANDROID_JSON_JAVA=ON")
fi

cd "$SCRIPT_DIR" || exit 1

echo "Generating TDLib source files..."
mkdir -p "build-native-$TDLIB_INTERFACE" || exit 1
cd "build-native-$TDLIB_INTERFACE" || exit 1
cmake "${TDLIB_INTERFACE_OPTIONS[@]}" -DTD_GENERATE_SOURCE_FILES=ON .. || exit 1
cmake --build . || exit 1
cd .. || exit 1

rm -rf tdlib || exit 1

if [ "$TDLIB_INTERFACE" == "Java" ]; then
	echo "Downloading annotation Java package..."
	rm -f android.jar annotation-1.4.0.jar || exit 1
	$WGET https://maven.google.com/androidx/annotation/annotation/1.4.0/annotation-1.4.0.jar || exit 1

	echo "Generating Java source files..."
	cmake --build "build-native-$TDLIB_INTERFACE" --target tl_generate_java || exit 1
	python3 add_int_def.py org/drinkless/tdlib/TdApi.java || exit 1
	mkdir -p tdlib/java/org/drinkless/tdlib || exit 1
	cp -p {..,tdlib}/java/org/drinkless/tdlib/Client.java || exit 1
	mv {,tdlib/java/}org/drinkless/tdlib/TdApi.java || exit 1
	rm -rf org || exit 1

	echo "Generating Javadoc documentation..."
	cp "$ANDROID_SDK_ROOT/platforms/android-34/android.jar" . || exit 1
	JAVADOC_SEPARATOR=$([ "$OS_NAME" == "win" ] && echo ";" || echo ":")
	javadoc -d tdlib/javadoc -encoding UTF-8 -charset UTF-8 -classpath "android.jar${JAVADOC_SEPARATOR}annotation-1.4.0.jar" -quiet -sourcepath tdlib/java org.drinkless.tdlib || exit 1
	rm android.jar annotation-1.4.0.jar || exit 1
fi
if [ "$TDLIB_INTERFACE" == "JSONJava" ]; then
	mkdir -p tdlib/java/org/drinkless/tdlib || exit 1
	cp -p {..,tdlib}/java/org/drinkless/tdlib/JsonClient.java || exit 1
fi

echo "Building TDLib..."
for ABI in arm64-v8a armeabi-v7a x86_64 x86; do
	mkdir -p tdlib/libs/$ABI/ || exit 1

	mkdir -p "build-$ABI-$TDLIB_INTERFACE" || exit 1
	cd "build-$ABI-$TDLIB_INTERFACE" || exit 1
	cmake -DCMAKE_TOOLCHAIN_FILE="$ANDROID_NDK_ROOT/build/cmake/android.toolchain.cmake" -DOPENSSL_ROOT_DIR="$OPENSSL_INSTALL_DIR/$ABI" -DCMAKE_BUILD_TYPE=RelWithDebInfo -GNinja -DANDROID_ABI=$ABI -DANDROID_STL=$ANDROID_STL -DANDROID_PLATFORM=android-16 "${TDLIB_INTERFACE_OPTIONS[@]}" .. || exit 1
	if [ "$TDLIB_INTERFACE" == "Java" ] || [ "$TDLIB_INTERFACE" == "JSONJava" ]; then
		cmake --build . --target tdjni || exit 1
		cp -p libtd*.so* ../tdlib/libs/$ABI/ || exit 1
	fi
	if [ "$TDLIB_INTERFACE" == "JSON" ]; then
		cmake --build . --target tdjson || exit 1
		cp -p td/libtdjson.so ../tdlib/libs/$ABI/libtdjson.so.debug || exit 1
		"$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/$HOST_ARCH/bin/llvm-strip" --strip-debug --strip-unneeded ../tdlib/libs/$ABI/libtdjson.so.debug -o ../tdlib/libs/$ABI/libtdjson.so || exit 1
	fi
	cd .. || exit 1

	if [[ $ANDROID_STL == "c++_shared" ]]; then
		if [[ $ABI == "arm64-v8a" ]]; then
			FULL_ABI="aarch64-linux-android"
		elif [[ $ABI == "armeabi-v7a" ]]; then
			FULL_ABI="arm-linux-androideabi"
		elif [[ $ABI == "x86_64" ]]; then
			FULL_ABI="x86_64-linux-android"
		elif [[ $ABI == "x86" ]]; then
			FULL_ABI="i686-linux-android"
		fi
		cp "$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/$HOST_ARCH/sysroot/usr/lib/$FULL_ABI/libc++_shared.so" tdlib/libs/$ABI/ || exit 1
		"$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/$HOST_ARCH/bin/llvm-strip" tdlib/libs/$ABI/libc++_shared.so || exit 1
	fi
	if [ -e "$OPENSSL_INSTALL_DIR/$ABI/lib/libcrypto.so" ]; then
		cp "$OPENSSL_INSTALL_DIR/$ABI/lib/libcrypto.so" "$OPENSSL_INSTALL_DIR/$ABI/lib/libssl.so" tdlib/libs/$ABI/ || exit 1
		"$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/$HOST_ARCH/bin/llvm-strip" tdlib/libs/$ABI/libcrypto.so || exit 1
		"$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/$HOST_ARCH/bin/llvm-strip" tdlib/libs/$ABI/libssl.so || exit 1
	fi
done

echo "Compressing..."
rm -f tdlib.zip tdlib-debug.zip || exit 1
jar -cMf tdlib-debug.zip tdlib || exit 1
rm -f tdlib/libs/*/*.debug
jar -cMf tdlib.zip tdlib || exit 1
mv tdlib.zip tdlib-debug.zip tdlib || exit 1

echo "Done."
