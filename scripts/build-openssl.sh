#!/usr/bin/env bash
# Build the complete bundled OpenSSL source as static Windows libraries.
set -euo pipefail
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
case "$(uname -s)" in
  Linux*) mode=windows-cross; default_cc=x86_64-w64-mingw32-gcc; cross=x86_64-w64-mingw32- ;;
  MINGW*|MSYS*)
    [[ ${MSYSTEM:-} == UCRT64 ]] || { echo 'Use the MSYS2 UCRT64 shell.' >&2; exit 2; }
    mode=windows-ucrt64; default_cc=gcc; cross= ;;
  *) echo 'Supported build hosts: Linux or Windows with MSYS2 UCRT64.' >&2; exit 2 ;;
esac
CC=${CC:-$default_cc}
export CC
command -v "$CC" >/dev/null
[[ $("$CC" -dumpmachine) == x86_64-w64-mingw32 ]] || { echo 'A Windows x64 MinGW-w64 compiler is required.' >&2; exit 2; }
source_dir="$repo/third_party/openssl-3.5.9"
[[ -f "$source_dir/Configure" && -f "$source_dir/VERSION.dat" ]] || { echo 'Bundled third_party/openssl-3.5.9 source is missing.' >&2; exit 2; }
grep -Eq '^MAJOR=3$' "$source_dir/VERSION.dat"
grep -Eq '^MINOR=5$' "$source_dir/VERSION.dat"
grep -Eq '^PATCH=9$' "$source_dir/VERSION.dat"
build_root=${BUILD_ROOT:-"$repo/.build/$mode"}
mkdir -p "$build_root"
build_root=$(CDPATH= cd -- "$build_root" && pwd)
prefix=${OPENSSL_PREFIX:-"$build_root/openssl"}
[[ $prefix == /* ]] || { echo 'OPENSSL_PREFIX must be an absolute shell path.' >&2; exit 2; }
build_source="$build_root/openssl-source"
mkdir -p "$build_source"
# Keep generated objects out of the repository's pristine dependency source.
# No source is downloaded and no directory is deleted by this script.
cp -R "$source_dir/." "$build_source/"
cd "$build_source"
configure_args=(mingw64 "--prefix=$prefix" --libdir=lib no-shared no-module no-tests no-docs no-apps no-dso no-engine)
if [[ -n $cross ]]; then
  # OpenSSL prepends CROSS_COMPILE to CC, AR, RANLIB and RC itself.
  # Keep CC unprefixed here to avoid x86_64-...-x86_64-...-gcc.
  [[ $CC == *gcc ]] || { echo 'The Linux cross compiler must end in gcc.' >&2; exit 2; }
  cross=${CC%gcc}
  configure_args+=("--cross-compile-prefix=$cross")
  CC=gcc perl Configure "${configure_args[@]}"
else
  perl Configure "${configure_args[@]}"
fi
make -j"${JOBS:-2}" build_libs
make install_dev
printf '%s\n' "$mode" > "$prefix/.pppd-build-mode"
printf 'Static OpenSSL ready: %s\n' "$prefix"
