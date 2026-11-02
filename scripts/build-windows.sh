#!/usr/bin/env bash
# Compile the Windows port; this script never opens a serial/network interface.
set -euo pipefail
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
case "$(uname -s)" in
  Linux*) mode=windows-cross; default_cc=x86_64-w64-mingw32-gcc ;;
  MINGW*|MSYS*)
    [[ ${MSYSTEM:-} == UCRT64 ]] || { echo 'Use the MSYS2 UCRT64 shell.' >&2; exit 2; }
    mode=windows-ucrt64; default_cc=gcc ;;
  *) echo 'Supported build hosts: Linux or Windows with MSYS2 UCRT64.' >&2; exit 2 ;;
esac
CC=${CC:-$default_cc}
export CC
command -v "$CC" >/dev/null
[[ $("$CC" -dumpmachine) == x86_64-w64-mingw32 ]] || { echo 'A Windows x64 MinGW-w64 compiler is required.' >&2; exit 2; }
build_root=${BUILD_ROOT:-"$repo/.build/$mode"}
mkdir -p "$build_root"
build_root=$(CDPATH= cd -- "$build_root" && pwd)
export BUILD_ROOT="$build_root"
OPENSSL_PREFIX=${OPENSSL_PREFIX:-"$build_root/openssl"}
export OPENSSL_PREFIX
if [[ ! -f "$OPENSSL_PREFIX/lib/libssl.a" || ! -f "$OPENSSL_PREFIX/lib/libcrypto.a" ]]; then
  bash "$repo/scripts/build-openssl.sh"
fi
[[ -f "$OPENSSL_PREFIX/include/openssl/ssl.h" ]] || { echo 'Static OpenSSL headers are missing.' >&2; exit 2; }
if [[ -f "$OPENSSL_PREFIX/.pppd-build-mode" ]]; then
  [[ $(cat "$OPENSSL_PREFIX/.pppd-build-mode") == "$mode" ]] || { echo 'Do not mix Linux-cross/MSVCRT and MSYS2/UCRT OpenSSL builds.' >&2; exit 2; }
fi
cd "$repo"
flags=(-std=c11 -O2 -Wall -Wextra -Wno-misleading-indentation -Wno-unused-parameter
  -D_WIN32_WINNT=0x0602 -DUNICODE -D_UNICODE -DPPP_WITH_EAPTLS=1 -DPPP_WITH_PEAP=1
  -municode -static -static-libgcc -Wl,--nxcompat,--dynamicbase,--high-entropy-va)
if [[ ${WARNINGS_AS_ERRORS:-0} == 1 ]]; then flags+=(-Werror); fi
sources=(
  src/main.c src/options.c src/platform_win.c src/engine.c
  src/data_port.c src/mppe_port.c src/vj_port.c src/vendor/vj-codec/slhc.c
  src/vendor/ppp/ccp.c src/vendor/codecs/bsd_comp.c src/vendor/codecs/ppp_deflate.c
  src/vendor/codecs/zlib_deflate/deflate.c src/vendor/codecs/zlib_deflate/deftree.c
  src/vendor/codecs/zlib_inflate/inflate.c src/vendor/codecs/zlib_inflate/inffast.c
  src/vendor/codecs/zlib_inflate/inftrees.c src/auth_port.c src/vendor/ppp/cbcp.c
  src/vendor/ppp/fsm.c src/vendor/ppp/lcp.c src/vendor/ppp/ipcp.c
  src/vendor/ppp/ipv6cp.c src/vendor/ppp/eui64.c src/vendor/ppp/upap.c
  src/vendor/ppp/chap.c src/vendor/ppp/chap-md5.c src/vendor/ppp/chap_ms.c
  src/vendor/ppp/crypto_ms.c src/vendor/ppp/eap.c src/vendor/ppp/eap-tls.c
  src/vendor/ppp/tls.c src/vendor/ppp/peap.c src/vendor/ppp/mppe.c
  src/vendor/ppp/crypto.c src/vendor/ppp/ppp-md5.c src/vendor/ppp/ppp-md4.c
  src/vendor/ppp/ppp-sha1.c src/vendor/ppp/ppp-des.c)
"$CC" "${flags[@]}" -I"$OPENSSL_PREFIX/include" -Isrc -Isrc/vendor/ppp \
  "${sources[@]}" -o "$build_root/pppd.exe" \
  "$OPENSSL_PREFIX/lib/libssl.a" "$OPENSSL_PREFIX/lib/libcrypto.a" \
  -lws2_32 -liphlpapi -ladvapi32 -lbcrypt -lcrypt32 -lncrypt -luser32 -lgdi32 \
  -lole32 -lsetupapi -lcfgmgr32 -lversion -lshell32 -luuid
"${OBJDUMP:-${CC%gcc}objdump}" -p "$build_root/pppd.exe" > "$build_root/pe-imports.txt"
sha256sum "$build_root/pppd.exe" > "$build_root/SHA256SUMS.txt"
printf 'Windows x64 executable: %s\n' "$build_root/pppd.exe"
printf 'Place the official amd64 wintun.dll beside it before starting a link.\n'
