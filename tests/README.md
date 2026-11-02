# Optional codec unit tests

These are the three existing C test programs used for the Windows 0.4.0 codec
qualification. Their source files are copied without modification. Each suite
runs in one process with independent in-memory encoder/decoder states. They do
not create a PPP peer, network socket endpoint, serial connection, Wintun
interface, kernel module or ESP/USB/VirtualHere connection. Wintun is not needed
to execute them. They do not test Windows-to-Windows networking.

They exercise the user-space packet engines, not the native Linux kernel PPP
modules or the Windows COM/Wintun adapters. Passing these units alone does not
establish interoperability or an error-free physical link. See the separate
[qualification summary](../docs/QUALIFICATION.md).

| Test source | Coverage and expected successful output |
| --- | --- |
| `vj_codec_test.c` | VJ header reconstruction, contexts, IPv4/TCP options, loss/toss/resynchronization and bounds: `VJ codec: 261 checks, 0 failures` |
| `compress_codec_test.c` | BSD 9-15, Deflate 9-15 and Deflate draft 15; compressible/incompressible history, reset, corruption and capacity checks: JSON `PASS`, 15 cases, 7,680 packets and 15,360 malformed streams |
| `mppe_codec_test.c` | Published RFC3079 initial keys/ciphertext; four 40/128-bit stateful/stateless modes, 20,000 stream packets, maximum MRU, loss/reset, periodic rekey, sequence wrap and malformed input: final `PASS 121340 assertions` |

The MPPE test intentionally includes the private `src/mppe_port.c` translation
unit to check published intermediate values without adding a key-export API to
the product. Do not add that translation unit again to its compiler command.
Only public test-vector keys are embedded; no real user credentials are needed.

## Windows, native execution

Install the MSYS2 UCRT64 build tools described in
[BUILD-WINDOWS.md](../docs/BUILD-WINDOWS.md). Open the **UCRT64** shell at the
repository root, then run:

```bash
bash scripts/test-codecs.sh
```

The script uses the matching static OpenSSL archive at
`.build/windows-ucrt64/openssl`, building it from the bundled source with
`scripts/build-openssl.sh` when absent. It builds normal `main()` test programs,
not the Unicode Windows daemon entry point, and runs their `.exe` files locally.
Outputs are under `.build/codecs-windows-ucrt64/`.

This script does not claim Windows ASAN instrumentation.

## Linux, native execution

Install the compiler, GNU Make and Perl described in
[BUILD-LINUX.md](../docs/BUILD-LINUX.md), then run:

```bash
bash scripts/test-codecs.sh --native
```

By default, the script builds a **native Linux** static libcrypto from the same
complete bundled OpenSSL 3.5.9 source in an isolated
`.build/codecs-linux-native/openssl-source` directory. It never modifies the
pristine dependency source and never installs into system directories. The
Windows-target OpenSSL archive cannot be used by Linux ELF executables.

For the ASAN/UBSAN variant, use:

```bash
SANITIZE=1 bash scripts/test-codecs.sh --native
```

The native project test objects are instrumented. The OpenSSL dependency is
built normally; this is not a claim that all OpenSSL internals were rebuilt with
sanitizers. Leak detection and halt-on-error are enabled by default for the test
processes. Do not disable C assertions with `-DNDEBUG` for these tests.

As an explicit alternative, the same suites can use the distribution's native
libcrypto development package instead of building the bundled dependency:

```bash
sudo apt-get install build-essential pkg-config libssl-dev
USE_SYSTEM_OPENSSL=1 SANITIZE=1 bash scripts/test-codecs.sh --native
```

That alternative prints the actual `pkg-config` libcrypto version; it is not
silently represented as an OpenSSL 3.5.9 test. On Linux, results are under
`.build/codecs-linux-native/`.

## Packaging validation

On 2026-11-01, the packaged script and the three unchanged test sources were
built and executed on native Linux x86-64 with GCC 12.2.0 and kernel
6.1.0-53-amd64. Both commands completed successfully with ASAN, UBSAN and leak
detection enabled:

```bash
USE_SYSTEM_OPENSSL=1 SANITIZE=1 bash scripts/test-codecs.sh --native
JOBS=4 SANITIZE=1 bash scripts/test-codecs.sh --native
```

The first run used system libcrypto 3.0.22. The second built the bundled OpenSSL
3.5.9 dependency from the complete source tree into the script's isolated native
prefix. Each run passed 261 VJ checks; 15 compression cases, 7,680 packets and
15,360 malformed-stream checks; and 121,340 MPPE assertions across 20,000 stream
packets. Neither run reported a sanitizer finding. This validates these native
unit-test build paths; it is not a new physical-link or Windows-to-Windows test.

## Linux cross-compilation of Windows tests

After installing the MinGW-w64 cross compiler from the Linux build guide:

```bash
bash scripts/test-codecs.sh --windows-cross
```

This target builds the three Windows x64 `.exe` files and stops. It does not
execute them under Wine and does not turn cross-compilation into a Windows test
result. Use a Windows UCRT64 build to execute tests natively, or explicitly copy
cross-built test binaries to a suitable Windows test machine yourself.

`--build-only` also suppresses execution for the current host's normal target.
`CODEC_BUILD_ROOT` overrides only the test output directory. `OPENSSL_PREFIX`
must select libraries for the correct target and CRT; the scripts reject known
cross/native/UCRT prefix mismatches. `JOBS` controls dependency compilation
parallelism; `WARNINGS_AS_ERRORS=1` optionally promotes compiler warnings.

## Source terms

The test programs use the original packet engines and their preserved notices.
No license has been replaced or newly assigned to existing files. Read
`../THIRD_PARTY_NOTICES.md` and `../docs/LICENSING.md`, including the current
combined-build redistribution issue, before distributing test executables.
