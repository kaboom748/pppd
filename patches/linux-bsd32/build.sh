#!/bin/sh
# Build only the corrected native BSD-Compress module. No installation/loading.
set -eu
cd "$(dirname "$0")"
KERNEL_RELEASE=${KERNEL_RELEASE:-6.1.0-53-amd64}
KDIR=${KDIR:-/lib/modules/$KERNEL_RELEASE/build}
test -f "$KDIR/Module.symvers" || { echo "Matching prepared kernel headers/Module.symvers required" >&2; exit 1; }
test -f "$KDIR/include/generated/utsrelease.h" || { echo "Missing generated kernel release" >&2; exit 1; }
grep -F '"'"$KERNEL_RELEASE"'"' "$KDIR/include/generated/utsrelease.h" >/dev/null || { echo "Kernel header release mismatch" >&2; exit 1; }
exec make -C "$KDIR" M="$(pwd)" CC="${CC:-gcc-12}" W=1 KCFLAGS=-Werror modules
