# Build on Linux

There are **two different Linux-host build targets**:

| Target | Result | Networking backend |
|---|---|---|
| Cross-compile the Windows port | Windows x64 `pppd.exe` | Windows COM + Wintun; run it on Windows |
| Compile the complete upstream Linux daemon | Native Linux `pppd` | Linux PPP kernel driver and serial line discipline |

The Windows-specific `main.c` and `platform_win.c` are not a new native Linux
backend. The repository therefore retains the complete, pinned upstream ppp
2.5.5 tree separately in `upstream/ppp`. Shared command options have the
same spelling and meaning; platform-only features and device names still differ.

These instructions use Debian/Ubuntu package names. Other distributions require
equivalent packages. The scripts build into `.build`; they do not install pppd,
load kernel modules, open a serial port, or start a connection.
Use a short source/build path without spaces for compatibility with OpenSSL's
build system.

## A. Cross-compile the Windows executable

### 1. Install the build tools

```sh
sudo apt update
sudo apt install build-essential gcc-mingw-w64-x86-64 binutils-mingw-w64-x86-64 perl make coreutils tar
```

Install `git` as well if cloning the repository:

```sh
sudo apt install git
```

Check the tools:

```sh
x86_64-w64-mingw32-gcc -dumpmachine
x86_64-w64-mingw32-gcc --version
x86_64-w64-mingw32-objdump --version
perl -v
```

The compiler target must be `x86_64-w64-mingw32`. A normal Linux `gcc` cannot
build the Windows COM/Wintun backend.

### 2. Build from the repository root

```sh
cd /path/to/pppd
JOBS=2 bash scripts/build-windows.sh
```

The complete OpenSSL 3.5.9 source is bundled in `third_party/openssl-3.5.9`.
The script configures OpenSSL's `mingw64` target with the cross-compiler prefix,
builds static `libssl.a` and `libcrypto.a`, and links them into the program.
PPP Deflate's zlib source is already part of `src/vendor/codecs`; there is no
additional zlib package to find for this target. No source download is needed.

Outputs:

```text
.build/windows-cross/pppd.exe
.build/windows-cross/SHA256SUMS.txt
.build/windows-cross/pe-imports.txt
```

You can inspect PE imports and hashes on Linux, but run the executable on a
real Windows system for startup or COM/Wintun operation. Wine is not claimed
as a supported serial/Wintun runtime.

Copy `pppd.exe` to Windows and put the official **amd64** `wintun.dll` in the
same directory. Do not copy Linux OpenSSL `.so` files or Windows OpenSSL DLLs;
they are not runtime dependencies of this static build.

### Cross-build details

The reference production build used GCC 12-posix MinGW-w64 on Debian 12. The
repository script retains its source list, Win32 target level, EAP-TLS/PEAP
defines, static linkage and PE security flags. It places the result under
`.build` instead of overwriting a previously delivered executable. Warnings
remain visible; use the reference strict-warning policy if desired:

```sh
WARNINGS_AS_ERRORS=1 JOBS=2 bash scripts/build-windows.sh
```

Different compilers, prefixes or link timestamps can change the hash. Read the
qualification report before applying its result to a newly compiled binary.

## B. Compile native Linux pppd

### 1. Install native development dependencies

```sh
sudo apt update
sudo apt install build-essential autoconf automake libtool pkg-config libssl-dev libcrypt-dev
```

These tools generate the Autotools build files from the complete upstream Git
snapshot. Optional native Linux integrations can require additional development
packages, such as `libpam0g-dev`, `libpcap-dev`, or `libsystemd-dev`. The native
upstream ATM plugin includes its own ATM helper headers and code.

### 2. Build

```sh
cd /path/to/pppd
JOBS=2 bash scripts/build-linux-native.sh
```

The script copies the pristine `upstream/ppp` tree into a build directory,
runs Autotools if necessary, and builds pppd and its native utilities. Its
configuration enables CBCP and retains the upstream default Microsoft extensions,
MPPE, IPv6CP, EAP-TLS, PEAP and loadable-plugin build. Optional upstream features
retain their configure defaults; systemd notification and Multilink, for example,
are not enabled unless requested. No Windows-specific limits are being added
to the native Linux source.

For an intentionally smaller serial-only build without loadable plugins:

```sh
BUILD_ROOT="$PWD/.build/linux-serial-only" JOBS=2 bash scripts/build-linux-native.sh --serial-only
```

Additional arguments after `--` are passed to upstream `configure`. For example,
after installing the needed development libraries, a separate native build can
enable Multilink and systemd notification:

```sh
BUILD_ROOT="$PWD/.build/linux-extra" JOBS=2 bash scripts/build-linux-native.sh -- --enable-multilink --enable-systemd
```

Main output:

```text
.build/linux-native/obj/pppd/pppd
```

Check startup without starting a link:

```sh
./.build/linux-native/obj/pppd/pppd --version
./.build/linux-native/obj/pppd/pppd notty show-options
```

`notty show-options` lists the options and exits before opening a PPP backend.
The `notty` flag lets this information-only command work even when stdin is
not a terminal, such as an SSH command or CI job.

The native daemon uses your Linux system's libssl/libcrypto and Linux kernel
PPP implementation. It is not a portable Windows executable and does not use
`wintun.dll`.

### 3. Optional installation

You can run the built daemon by its full path without replacing your distro's
`/usr/sbin/pppd`. To install the native build deliberately:

```sh
cd .build/linux-native/obj
sudo make install
```

This installs beneath `/usr/local`, with PPP configuration beneath `/etc/ppp`
because the script uses `--sysconfdir=/etc`. Review existing files and your
distribution's service configuration before installation. The script never
performs this privileged installation automatically and does not enable setuid.

### 4. Kernel support for an actual serial link

Compilation is separate from having a usable kernel PPP backend. Your kernel
needs PPP, asynchronous serial PPP, IPv6 if used, and the codecs you select.
On a distribution kernel with modular support, the relevant module names are:

```text
ppp_generic
ppp_async
slhc
bsd_comp
ppp_deflate
ppp_mppe
```

The corresponding kernel options include `CONFIG_PPP`, `CONFIG_PPP_ASYNC`,
`CONFIG_SLHC`, `CONFIG_PPP_BSDCOMP`, `CONFIG_PPP_DEFLATE`, and `CONFIG_PPP_MPPE`.
Use your distribution's kernel/module packages. Building pppd does not build or
replace those kernel modules. `/dev/ppp` must be available when you start a link.
Use `sudo` for the documented examples rather than making the binary setuid.

Some Linux kernel versions have the independently documented BSD-Compress
issue observed in the original lab. A kernel-specific correction is separate
from building this native daemon; do not blindly install a module compiled for
the qualification VM into another kernel. See the qualification/kernel-fix
documentation included in this repository.

## C. Build a differently configured upstream Linux daemon

The complete source tree is available for native features beyond the Windows
port. From a separate copy of `upstream/ppp`, the standard sequence is:

```sh
autoreconf -fi
./configure --help
./configure --prefix=/usr/local --sysconfdir=/etc --localstatedir=/var --runstatedir=/run
make -j2
```

Select the integrations you need and install their development libraries.
This is the upstream Linux build system; enabling a Linux plugin does not add
that plugin to `pppd.exe` or make a Linux `.so` loadable on Windows.

Primary source references: the bundled `upstream/ppp/README`,
`README.linux`, `configure.ac`, and OpenSSL's bundled `NOTES-WINDOWS.md`.

## Build verification

The cross-compilation script was run from a clean extracted source package on
Debian 12 with MinGW-w64 GCC 12-posix. It built the complete bundled OpenSSL
3.5.9 source and linked `pppd.exe` successfully. On Windows, the resulting
executable's `--version` and `--help` both exited with status 0 with no sibling
Wintun DLL and with `PATH` limited to Windows system directories. Its PE imports
contained Windows system DLLs, including `msvcrt.dll`, with no external
OpenSSL, MSYS2, GCC or pthread runtime DLL.

The repository's native Linux script was run from a clean extracted source
package on Debian 12 with GCC 12.2.0 and system OpenSSL 3.0.22. Compilation
passed, including 11 shared plugins. The resulting daemon reported `pppd
version 2.5.5`; both `--version` and `notty show-options` completed successfully.
The configure summary confirmed Microsoft extensions, plugins, CBCP, IPv6CP
and EAP-TLS enabled; PAM, pcap, Multilink and systemd were not enabled in that
build. This verifies the build recipe and information commands, not a new
physical-link qualification.
