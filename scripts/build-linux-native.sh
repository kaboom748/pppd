#!/usr/bin/env bash
# Build the complete bundled upstream native Linux pppd, not the Windows adapter.
set -euo pipefail
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
[[ $(uname -s) == Linux ]] || { echo 'This target requires a Linux host.' >&2; exit 2; }
source_dir="$repo/upstream/ppp"
[[ -f "$source_dir/configure.ac" && -f "$source_dir/pppd/main.c" ]] || { echo 'Complete upstream/ppp source is missing.' >&2; exit 2; }
build_root=${BUILD_ROOT:-"$repo/.build/linux-native"}
mkdir -p "$build_root/source" "$build_root/obj"
build_root=$(CDPATH= cd -- "$build_root" && pwd)
cp -R "$source_dir/." "$build_root/source/"
cd "$build_root/source"
if [[ ! -f configure ]]; then autoreconf -fi; fi
cd "$build_root/obj"
configure_args=(--prefix=/usr/local --sysconfdir=/etc --localstatedir=/var --runstatedir=/run --enable-cbcp)
if [[ ${1:-} == --serial-only ]]; then configure_args+=(--disable-plugins); shift; fi
if [[ ${1:-} == -- ]]; then shift; fi
configure_args+=("$@")
"$build_root/source/configure" "${configure_args[@]}"
make -j"${JOBS:-2}"
sha256sum "$build_root/obj/pppd/pppd" > "$build_root/SHA256SUMS.txt"
printf 'Native Linux executable: %s\n' "$build_root/obj/pppd/pppd"
printf 'No installation, permission changes, kernel-module operation or PPP link was performed.\n'
