# Build the Windows port on Windows

This builds a **native Windows x64 `pppd.exe`** with MinGW-w64. MSYS2 is only a
build environment: the resulting application does not require MSYS2, Python,
Cygwin, an OpenSSL DLL, or a compiler on the target computer. A running PPP link
requires the matching official x64 `wintun.dll` beside the executable.

The source tree includes the complete OpenSSL 3.5.9 dependency in
`third_party/openssl-3.5.9`. The build scripts do not download source code. Read
the repository's license/redistribution notices before distributing a combined
binary; a successful build is not a license clearance.

## 1. Install MSYS2 UCRT64

1. Use a 64-bit Windows 10/11 computer.
2. Download the installer from the [official MSYS2 website](https://www.msys2.org/).
3. Install to its usual short path, such as `C:\msys64`.
4. Open **MSYS2 UCRT64** from the Start menu. Do not use the plain MSYS terminal,
   Git Bash, Cygwin, or a Visual Studio/MSVC prompt for this recipe.
5. Update the build environment:

   ```sh
   pacman -Syu
   ```

   If the update requests that the terminal close, close it, reopen **MSYS2
   UCRT64**, and run the update command again until it finishes normally.
6. Install the compiler and build tools:

   ```sh
   pacman -S --needed mingw-w64-ucrt-x86_64-gcc make perl coreutils tar
   ```

   Install `git` as well if you intend to clone rather than extract the repository:

   ```sh
   pacman -S --needed git
   ```

Check the environment before compiling:

```sh
printf '%s\n' "$MSYSTEM"
gcc -dumpmachine
gcc --version
make --version
perl -v
```

Expected: `UCRT64`, an `x86_64-w64-mingw32` compiler target, GNU Make, and Perl.
MSYS2's unprefixed `/usr/bin/gcc` is a different compiler; the UCRT64 shell must
select the native MinGW compiler from `/ucrt64/bin`.

## 2. Obtain this complete repository

Extract the ZIP or clone your published repository into a short development
path **without spaces**, for example `C:\src\pppd`. OpenSSL's build system
requires this restriction for development paths; it does not restrict the
folder from which the completed executable can run. The ZIP contains all project and dependency
source files; no submodule checkout is needed.

In the UCRT64 terminal:

```sh
cd /c/src/pppd
```

The path is an example. Use the path where you actually extracted the repository.

## 3. Compile

```sh
JOBS=2 bash scripts/build-windows.sh
```

The script builds OpenSSL as static libraries, then compiles the Windows host,
the retained pppd protocol code, VJ, BSD-Compress, PPP Deflate/zlib, and MPPE.
EAP-TLS and PEAP are enabled in this build. Assembly support uses the GNU tools
provided by the MinGW toolchain; the recipe does not require Visual Studio.

Outputs:

```text
.build/windows-ucrt64/pppd.exe
.build/windows-ucrt64/SHA256SUMS.txt
.build/windows-ucrt64/pe-imports.txt
```

`JOBS=2` limits parallel compilation. Increase it for a machine with sufficient
CPU and memory. This command does not install a driver, open a COM port, create
an interface, or start a PPP connection.

## 4. Check startup and dependencies

From the same terminal:

```sh
./.build/windows-ucrt64/pppd.exe --version
./.build/windows-ucrt64/pppd.exe --help
cat .build/windows-ucrt64/SHA256SUMS.txt
cat .build/windows-ucrt64/pe-imports.txt
```

`--help` and `--version` do not start a link and do not require elevation or
Wintun. Check the import listing: OpenSSL, zlib, MSYS2, Cygwin, `libgcc_s`, and
`libwinpthread` must not appear as extra runtime DLL dependencies. Windows UCRT
and API-set names are operating-system components, not private application DLLs.

A native UCRT64 build can have different PE imports and a different hash from
the earlier Linux-cross/MSVCRT qualification build. Compiler versions, CRT,
paths and linker timestamps can change the binary. Do not label a new build as
the identical qualified executable merely because its version string matches.

## 5. Prepare a runtime folder

Copy `.build/windows-ucrt64/pppd.exe` into the folder from which you want to use
it. Obtain the official **amd64** Wintun DLL as described in
[Wintun installation](WINTUN.md), and place it in that exact same folder:

```text
my-runtime-folder/
  pppd.exe
  wintun.dll
```

You do not need to add this directory to `PATH`; you can invoke the executable
by its full path. Open an elevated terminal for a real link or `--stop`, install
the appropriate USB/serial driver, and use the real COM port name of that
Windows computer. Runtime credentials/certificates are separate input data
when you select an authentication method that needs them.

## Troubleshooting the build

| Symptom | Check |
|---|---|
| `Use the MSYS2 UCRT64 shell` | Start the UCRT64 terminal, not MSYS/Git Bash. |
| Compiler target is not Windows x64 | Install/select `mingw-w64-ucrt-x86_64-gcc`. |
| OpenSSL headers or static archives missing | Let the script build the bundled dependency; do not point it at Linux ELF libraries. |
| CRT or linker mismatches | Do not reuse the Linux-cross/MSVCRT dependency directory for UCRT64. |
| A new compiler emits warnings | Warnings remain visible. `WARNINGS_AS_ERRORS=1` restores the reference build's `-Werror` policy. |
| Interrupted dependency build | Run the same command again. To isolate a clean attempt without deletion, use a fresh absolute `BUILD_ROOT`. |

Example of a separate build directory:

```sh
BUILD_ROOT="$PWD/.build/windows-ucrt64-second" JOBS=2 bash scripts/build-windows.sh
```

The project has no MSVC project/solution and does not claim a Visual Studio
`cl.exe` build. WSL is supported through the **Linux cross-compilation** recipe,
not as a native MSYS2 build.

## Primary build references

- [MSYS2 installation](https://www.msys2.org/)
- [MSYS2 environments and UCRT64](https://www.msys2.org/docs/environments/)
- [MinGW-w64's MSYS2 setup](https://www.mingw-w64.org/getting-started/msys2/)
- OpenSSL's bundled `third_party/openssl-3.5.9/NOTES-WINDOWS.md`, section
  **Native builds using MinGW**.

## Validation status

The native Windows recipe was executed on 1 November 2026 with MSYS2 UCRT64
GCC 16.2.0, GNU Make
4.4.1 and Perl 5.42.3. The scripts built the bundled OpenSSL 3.5.9 and the
Windows executable successfully. Both `--help` and `--version` exited with
status 0 with no sibling Wintun DLL and with `PATH` limited to Windows system
directories. PE imports contained only Windows/UCRT components, with no
MSYS2, OpenSSL or GCC runtime DLL dependency.

The native build emitted existing diagnostic-truncation and unused-variable
warnings; warnings are visible and are not treated as fatal by default. The
three in-memory codec suites also passed on this compiler: 261 VJ checks;
15 BSD/Deflate configurations covering 7,680 packets and 15,360 malformed
inputs; and 121,340 MPPE assertions. See the [codec test instructions](../tests/README.md)
for their scope. These build, codec and information-command checks do not constitute a
new physical serial-link qualification; the earlier production executable
was built by the Linux MinGW-w64 cross recipe.
