# Source provenance and scope

## Identity of the qualified Windows source

The public source preserves the Windows 0.4.0 implementation that produced the
qualified executable. The lab executable SHA-256 was:

```text
efc417bb76ba965df98c75583966a3ce8aae0d7d26286bbcc3b3b93ca5711779
```

The DLL used by that lab build was Wintun 0.14.1 x64, SHA-256:

```text
e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce
```

These binaries are not included in this source-only repository ZIP. A different
compiler, dependency build, PE timestamp or toolchain can produce a different
binary hash. The old binary qualification is not a claim that every new build
has already been hardware-tested.

`MANIFEST-WINDOWS-SOURCE.json` records all 104 `.c`, `.h` and `.inc` files in the
released Windows source tree. This is the source/header/include inventory, not
a claim that there are 104 independent compiled translation units. Some
retained original files are provenance inputs; build scripts name the actual
translation units explicitly.

## Upstream inputs

| Input | Pinned identity | Where adaptations are documented |
| --- | --- | --- |
| ppp-project ppp / pppd 2.5.5 | [`4dc474cacfa045d1ee1b10c388d8c864e3ed3b30`](https://github.com/ppp-project/ppp/tree/4dc474cacfa045d1ee1b10c388d8c864e3ed3b30) | `src/vendor/ppp/PROVENANCE.txt`, `CORE-PROVENANCE.txt`, `AUTH-PROVENANCE.txt`, `CCP-PROVENANCE.json` |
| Linux VJ | [`6628e7d4c6b25c8d18f1345e3a20d21829aae7e4`](https://github.com/torvalds/linux/tree/6628e7d4c6b25c8d18f1345e3a20d21829aae7e4) | `src/vendor/vj-codec/PROVENANCE.txt`; retained `.original.*` files and their hashes |
| Linux BSD-Compress / PPP Deflate / PPP zlib | [Linux v6.1](https://github.com/torvalds/linux/tree/v6.1) | `src/vendor/codecs/COMPRESSION-PROVENANCE.json` lists original and adapted hashes, files and URLs |
| Linux MPPE / ARC4 | [Linux v6.1](https://github.com/torvalds/linux/tree/v6.1) | `src/vendor/mppe-codec/PROVENANCE.txt`; original copies under `upstream/` |
| OpenSSL | 3.5.9; original release archive SHA-256 `603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a` | Complete expanded source at `third_party/openssl-3.5.9/` and original license; build guide describes static build |
| Wintun runtime | Tested 0.14.1 x64; supplied separately under its own binary terms | Official download and runtime placement instructions |

The complete upstream ppp source supplied at `upstream/ppp/` for the native Linux
build is a separate tree from `src/vendor/ppp/`, which contains the adapted Windows subset.
The Windows build compiles the adapted subset and native Windows host code.
The native Linux build uses upstream Linux backends and its operating system's
PPP support. It does not compile `platform_win.c` as a Linux interface backend.

## What was adapted

The retained pppd FSM/LCP/IPCP/IPv6CP/authentication/CCP code uses Windows host
callbacks instead of Unix device, script and account services. Native host code
implements COM I/O, asynchronous PPP/FCS framing, queues, timers, Wintun and IP
Helper configuration. Linux-derived packet engines use bounded user-space
buffers and explicit context ownership instead of kernel allocation/module
registration. Their algorithms, origins and corrections are described beside
the source; this is not a complete Linux kernel port.

No external stock-zlib substitution should be made silently: the retained
PPP-aware zlib supports packet-flush and incompressible-history operations.
OpenSSL remains a build dependency of the current code even if TLS-related
features were separately disabled, because the MPPE adapter uses EVP SHA-1.

## Qualification, without public lab identifiers

The English qualification summary describes 11 selected functional Windows to
native-Linux serial profiles, exact file checks, IPv4/IPv6, VJ/BSD/Deflate and
MPPE 40/128. One VJ+MPPE128 TCP session lasted 951.922 seconds. The selected
runs also recorded 11 Windows receive FCS rejections and one Linux receive FCS
rejection; one earlier connection attempt timed out and was retained as failed.
The conclusion is functional interoperability **with reception/startup
reservations**, not an error-free-link guarantee. The short physical stateful
tests each transmitted 192 Windows MPPE frames, below the 256-packet periodic
rekey boundary; deep unit and earlier engine/native-peer tests are separate
evidence for rekey, reset and sequence wrap.

Windows-to-Windows was explicitly deferred by the owner and was not run.
Packaging/build checks do not reopen COM, ESP, USB or VirtualHere links.

Raw bench captures, private host addresses, machine names, account names,
SSH paths, controller state, test secrets and machine-specific scripts are
intentionally excluded from the public repository. Public upstream test
vectors and dummy examples remain identified as such. See `docs/QUALIFICATION.md`
for the public results and their scope.
