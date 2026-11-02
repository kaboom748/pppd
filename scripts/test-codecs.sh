#!/usr/bin/env bash
# Existing single-process, in-memory tests. No link, device or interface is opened.
set -euo pipefail
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
build_only=0
requested=auto
for arg in "$@"; do
  case "$arg" in
    --native) requested=native ;;
    --windows-cross) requested=windows-cross; build_only=1 ;;
    --build-only) build_only=1 ;;
    -h|--help)
      printf '%s\n' 'Usage: bash scripts/test-codecs.sh [--native|--windows-cross] [--build-only]' \
        'Default: native Linux tests or native Windows tests in the MSYS2 UCRT64 shell.' \
        '--windows-cross: build Windows .exe tests on Linux; never execute them there.' \
        'SANITIZE=1: Linux ASAN/UBSAN; USE_SYSTEM_OPENSSL=1: Linux pkg-config libcrypto.'
      exit 0 ;;
    *) printf 'Unknown argument: %s\n' "$arg" >&2; exit 2 ;;
  esac
done
case "$(uname -s)" in
  Linux*)
    if [[ $requested == windows-cross ]]; then
      mode=windows-cross; default_cc=x86_64-w64-mingw32-gcc; extension=.exe
    else
      mode=linux-native; default_cc=gcc; extension=
    fi ;;
  MINGW*|MSYS*)
    [[ $requested != native && $requested != windows-cross && ${MSYSTEM:-} == UCRT64 ]] || {
      echo 'Use the MSYS2 UCRT64 shell without --native/--windows-cross.' >&2; exit 2;
    }
    mode=windows-ucrt64; default_cc=gcc; extension=.exe ;;
  *) echo 'Supported hosts: Linux and Windows MSYS2 UCRT64.' >&2; exit 2 ;;
esac
CC=${CC:-$default_cc}
command -v "$CC" >/dev/null
if [[ $mode == linux-native && $("$CC" -dumpmachine) == *mingw* ]]; then
  echo 'Use a native Linux compiler for --native; Windows cross targets need --windows-cross.' >&2
  exit 2
fi
if [[ $mode != linux-native ]]; then
  [[ $("$CC" -dumpmachine) == x86_64-w64-mingw32 ]] || {
    echo 'This target needs a Windows x64 MinGW-w64 compiler.' >&2; exit 2;
  }
fi
if [[ ${SANITIZE:-0} == 1 && $mode != linux-native ]]; then
  echo 'SANITIZE=1 is implemented only for native Linux tests.' >&2; exit 2
fi
build_root=${CODEC_BUILD_ROOT:-"$repo/.build/codecs-$mode"}
mkdir -p "$build_root/bin" "$build_root/logs"
build_root=$(CDPATH= cd -- "$build_root" && pwd)
bin="$build_root/bin"

flags=(-std=c11 -O2 -g -Wall -Wextra -Wno-unused-parameter)
if [[ ${WARNINGS_AS_ERRORS:-0} == 1 ]]; then flags+=(-Werror); fi
if [[ ${SANITIZE:-0} == 1 ]]; then
  flags+=(-O1 -fno-omit-frame-pointer -fsanitize=address,undefined -fno-sanitize-recover=all)
fi
crypto_flags=()
crypto_libs=()
vj_libs=()
if [[ $mode == linux-native && ${USE_SYSTEM_OPENSSL:-0} == 1 ]]; then
  command -v pkg-config >/dev/null
  pkg-config --exists libcrypto
  # pkg-config output is a controlled compiler flag list, not shell commands.
  read -r -a crypto_flags <<< "$(pkg-config --cflags libcrypto)"
  read -r -a crypto_libs <<< "$(pkg-config --libs libcrypto)"
  printf 'Using system libcrypto %s for native codec tests.\n' "$(pkg-config --modversion libcrypto)"
else
  if [[ $mode == linux-native ]]; then
    prefix=${OPENSSL_PREFIX:-"$build_root/openssl"}
    [[ $prefix == /* ]] || { echo 'OPENSSL_PREFIX must be an absolute shell path.' >&2; exit 2; }
    if [[ ! -f "$prefix/lib/libcrypto.a" ]]; then
      source_dir="$repo/third_party/openssl-3.5.9"
      [[ -f "$source_dir/Configure" && -f "$source_dir/VERSION.dat" ]] || {
        echo 'Complete bundled OpenSSL 3.5.9 source is missing.' >&2; exit 2;
      }
      grep -Eq '^MAJOR=3$' "$source_dir/VERSION.dat"
      grep -Eq '^MINOR=5$' "$source_dir/VERSION.dat"
      grep -Eq '^PATCH=9$' "$source_dir/VERSION.dat"
      mkdir -p "$build_root/openssl-source"
      cp -R "$source_dir/." "$build_root/openssl-source/"
      (
        cd "$build_root/openssl-source"
        CC="$CC" perl Configure "--prefix=$prefix" --libdir=lib \
          no-shared no-module no-tests no-docs no-apps no-dso no-engine
        make -j"${JOBS:-2}" build_libs
        make install_dev
      )
      printf '%s\n' linux-native-codecs > "$prefix/.pppd-build-mode"
    fi
    if [[ -f "$prefix/.pppd-build-mode" ]]; then
      [[ $(cat "$prefix/.pppd-build-mode") == linux-native-codecs ]] || {
        echo 'Do not link a Windows OpenSSL archive into native Linux tests.' >&2; exit 2;
      }
    fi
    crypto_libs+=("$prefix/lib/libcrypto.a" -ldl -pthread)
  else
    prefix=${OPENSSL_PREFIX:-"$repo/.build/$mode/openssl"}
    if [[ ! -f "$prefix/lib/libcrypto.a" ]]; then
      CC="$CC" OPENSSL_PREFIX="$prefix" BUILD_ROOT="$repo/.build/$mode" \
        bash "$repo/scripts/build-openssl.sh"
    fi
    if [[ -f "$prefix/.pppd-build-mode" ]]; then
      [[ $(cat "$prefix/.pppd-build-mode") == "$mode" ]] || {
        echo 'Do not mix Linux-cross/MSVCRT and Windows-UCRT OpenSSL archives.' >&2; exit 2;
      }
    fi
    flags+=(-static -static-libgcc)
    vj_libs+=(-lws2_32)
    crypto_libs+=("$prefix/lib/libcrypto.a" -lws2_32 -liphlpapi -ladvapi32 -lbcrypt
      -lcrypt32 -lncrypt -luser32 -lgdi32 -lole32 -lsetupapi -lcfgmgr32 -lversion -lshell32 -luuid)
  fi
  [[ -f "$prefix/include/openssl/evp.h" && -f "$prefix/lib/libcrypto.a" ]] || {
    echo 'Matching OpenSSL headers and static libcrypto.a are required.' >&2; exit 2;
  }
  crypto_flags+=("-I$prefix/include")
fi

cd "$repo"
printf 'Building the existing VJ codec test (%s).\n' "$mode"
"$CC" "${flags[@]}" -Isrc tests/vj_codec_test.c src/vj_port.c \
  src/vendor/vj-codec/slhc.c "${vj_libs[@]}" -o "$bin/vj-codec-test$extension"
printf 'Building the existing BSD/Deflate codec test (%s).\n' "$mode"
"$CC" "${flags[@]}" -Isrc tests/compress_codec_test.c src/compress_port.c \
  src/vendor/codecs/bsd_comp.c src/vendor/codecs/ppp_deflate.c \
  src/vendor/codecs/zlib_deflate/deflate.c src/vendor/codecs/zlib_deflate/deftree.c \
  src/vendor/codecs/zlib_inflate/inflate.c src/vendor/codecs/zlib_inflate/inffast.c \
  src/vendor/codecs/zlib_inflate/inftrees.c -o "$bin/compress-codec-test$extension"
printf 'Building the existing MPPE codec test (%s).\n' "$mode"
# The test intentionally includes src/mppe_port.c; do not compile that TU twice.
"$CC" "${flags[@]}" -Isrc "${crypto_flags[@]}" tests/mppe_codec_test.c \
  "${crypto_libs[@]}" -o "$bin/mppe-codec-test$extension"
sha256sum "$bin/vj-codec-test$extension" "$bin/compress-codec-test$extension" \
  "$bin/mppe-codec-test$extension" > "$build_root/test-binary-sha256.txt"
if [[ $build_only == 1 ]]; then
  printf 'BUILD ONLY: test binaries are in %s; no test was executed.\n' "$bin"
  exit 0
fi
for suite in vj compress mppe; do
  printf 'Running the existing %s codec test.\n' "$suite"
  if [[ ${SANITIZE:-0} == 1 ]]; then
    ASAN_OPTIONS=${ASAN_OPTIONS:-detect_leaks=1:halt_on_error=1} \
    UBSAN_OPTIONS=${UBSAN_OPTIONS:-halt_on_error=1} \
      "$bin/$suite-codec-test$extension" 2>&1 | tee "$build_root/logs/$suite.txt"
  else
    "$bin/$suite-codec-test$extension" 2>&1 | tee "$build_root/logs/$suite.txt"
  fi
done
printf 'PASS: all three existing in-memory codec suites completed; no PPP link or device was opened.\n'
