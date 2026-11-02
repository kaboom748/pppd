# Source-package build verification

These checks validate the repository's build recipes and pure codec tests.
They are separate from the original physical-link qualification described in
[QUALIFICATION.md](QUALIFICATION.md). No serial device, PPP interface, Wintun
adapter, radio, VirtualHere assignment or firmware was operated for packaging.

## Native Windows build

The unmodified staged `scripts/build-windows.sh` completed a fresh MSYS2 UCRT64
build with GCC 16.2.0, GNU Make 4.4.1 and Perl 5.42.3, using the bundled OpenSSL
3.5.9 source. OpenSSL and pppd compiled in 348.24 seconds. The executable was
7,849,309 bytes, SHA-256:

```text
59546e82294ee4a7a437009c5350774455e8d00f1eee0d43af4eb54c4b191bf2
```

Both `--version` and `--help` returned zero with `PATH` restricted to Windows
system directories and no sibling Wintun DLL. PE imports contained only Windows
system/UCRT API-set libraries, with no OpenSSL, MSYS2 or libgcc runtime DLL.
This verifies information-command startup; creating an actual link still
requires the sibling x64 Wintun DLL and administrative privileges.

Existing warnings remained visible: two potentially truncated diagnostic
`snprintf` messages in `main.c` and an unused variable in upstream-derived
`ipv6cp.c`. The source was not changed to suppress them. The recipe does not
enable `-Werror` by default for newer compilers.

The repository's `scripts/test-codecs.sh` also compiled and executed all three
in-memory codec suites natively on Windows, with the just-built static OpenSSL:

| Suite | Result |
|---|---|
| VJ | 261 checks, zero failures |
| BSD/Deflate | PASS; 15 configurations, 7,680 packets, 15,360 malformed streams |
| MPPE | PASS; 121,340 assertions |

## Linux-to-Windows cross build

The fresh Linux cross-build recipe also passed on Debian 12 with MinGW-w64
GCC 12-posix and the complete bundled OpenSSL 3.5.9 source. Its Windows
executable was 7,934,059 bytes, SHA-256:

```text
9438e3cb33254d52af4c0fe5f57c0fab9d58d474a4a011823a309fe7378b7121
```

After copying the result to Windows, `--version` and `--help` both returned
zero with only Windows system directories on `PATH` and no sibling Wintun
DLL. PE imports were Windows system libraries, including `msvcrt.dll`, with
no external OpenSSL, MSYS2, GCC or pthread runtime DLL. Existing dependency
and MinGW-header warnings remained visible; the build completed with no
application compiler errors.

## Native Linux build

The source package's native Linux script completed on Debian 12 using GCC
12.2.0 and system OpenSSL 3.0.22. It built upstream pppd 2.5.5 and 11 shared
plugins. The configure summary enabled Microsoft extensions, plugins, CBCP,
IPv6CP and EAP-TLS. PAM, pcap, Multilink and systemd were not enabled in that
build. Both information-only commands completed successfully:

```sh
.build/linux-native/obj/pppd/pppd --version
.build/linux-native/obj/pppd/pppd notty show-options
```

Native ELF executable SHA-256:

```text
441cc26202aea1878a478b414799fecc4a7c8a0013c95b7b18993944fa6eae88
```

The public codec script also passed its native Linux alternative with
`USE_SYSTEM_OPENSSL=1 SANITIZE=1` using libcrypto 3.0.22. VJ completed 261
checks; BSD/Deflate completed 15 configurations, 7,680 packets and 15,360
malformed-input checks; MPPE completed 121,340 assertions. AddressSanitizer,
UndefinedBehaviorSanitizer and leak detection reported no findings.

The script's default native dependency path was then verified separately:
it built static OpenSSL 3.5.9 from the bundled pristine source and passed the
same three suites with `SANITIZE=1`, again with no sanitizer/leak findings.
The project test objects were instrumented; OpenSSL itself was built normally.

## Source identity and reproducibility limits

All 104 Windows `.c`, `.h` and `.inc` files matched
`MANIFEST-WINDOWS-SOURCE.json`. The complete extracted upstream PPP and OpenSSL
trees were checked file by file against their pinned source archives. Project
documentation links and archive file hashes are checked during packaging.

Different compilers, CRTs, build paths and linker timestamps can change a PE or
ELF hash. These rebuilt executables are not the original hardware-qualified
binary merely because their version is 0.4.0. No rebuilt binaries are included
in the public source ZIP, and the compile-only workflow uploads no binary
artifacts. Review [LICENSING.md](LICENSING.md) before redistributing combined
executables.
