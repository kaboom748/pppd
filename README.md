# pppd — a partial native Windows port
<img width="1760" height="1120" alt="pppd-exe-logo-complet" src="https://github.com/user-attachments/assets/7f68c83f-81e3-4e1e-a263-f95fafbc3522" />

Carry IP over a transparent serial link using Linux-style `pppd` options on Windows.

The original goal is simple: attach one computer to each end of two transparent
serial endpoints, including ESP serial radio modems, and pass IP traffic between
the computers. The firmware supplies the transparent byte transport; this
project supplies PPP, IP negotiation, authentication and the Windows network
interface. It does not program or flash the endpoints.

```text
Windows IP applications                         Linux IP applications
          |                                               |
        Wintun                                      kernel PPP
          |                                               |
      pppd.exe                                          pppd
          |                                               |
        COM port <--- transparent serial / ESP link ---> serial device
```

This is a Layer 3 point-to-point IP connection. It does not bridge Ethernet
frames, MAC addresses or VLANs. LAN routing additionally needs OS forwarding
and routing configuration.

## What is supplied

This source package contains the complete Windows 0.4.0 implementation, its
adapted protocol/codec sources, full pinned upstream PPP 2.5.5 sources for a
native Linux build, and the complete OpenSSL 3.5.9 source dependency. Compilation
does not fetch missing project source. Install the documented compiler tools first.

**The Windows implementation is a partial port.** Implemented common options
retain Linux spelling and argument syntax. COM names, Linux device paths,
privileges, platform defaults and process control differ. Windows `--stop` is
an extension; native Linux uses signals. See the detailed
[support matrix](docs/SUPPORT.md) before using an existing Linux configuration.

All project documentation is in English. Preserved implementation diagnostics,
help descriptions and some historical source notes currently include French;
upstream notices and source bytes have been retained.

## Supported scope

| Area | Windows implementation |
|---|---|
| Transport | Asynchronous PPP over an exclusive COM port; configurable baud rate, eight-bit serial format, XON/XOFF or RTS/CTS. |
| Network | LCP, IPv4/IPCP, IPv6/IPv6CP link-local addressing, peer routes, optional IPv4 default route, negotiated DNS. |
| Header compression | Van Jacobson TCP/IPv4 header compression. |
| Payload compression | BSD-Compress and PPP Deflate, up to parameter 15. One CCP method per direction. |
| Traffic encryption | MPPE40/MPPE128, stateless and stateful negotiation; VJ can precede MPPE. |
| Authentication | PAP, CHAP-MD5, MSCHAPv1/v2, supported EAP methods, EAP-TLS and PEAP client. Credentials and peer capabilities still apply. |
| Operation | Foreground/detached instances, retries and timers, explicit option/secret files, diagnostics and controlled stop. |

The Windows host does not implement Linux transports/plugins (PPPoE, PPPoL2TP,
PPPoATM), Ethernet bridging/BCP, synchronous PPP, PTY/socket transport, Unix
scripts, PAM/RADIUS/Winbind integration, demand dialing, multilink, proxy ARP,
or the Linux kernel filtering backend. Predictor, MPPC, ECP and AES/ChaCha20
traffic encryption are absent. The [support matrix](docs/SUPPORT.md) gives
the remaining platform and option limitations.

## Build from source

| Build host | Output | Complete instructions |
|---|---|---|
| Windows 10/11 x64, MSYS2 UCRT64 | Native Windows `pppd.exe` | [Windows, from installation to runtime](docs/BUILD-WINDOWS.md) |
| Linux, MinGW-w64 | Windows `pppd.exe` cross build | [Linux cross compilation](docs/BUILD-LINUX.md#a-cross-compile-the-windows-executable) |
| Linux, native GCC and kernel PPP | Native Linux upstream `pppd` | [Native Linux build](docs/BUILD-LINUX.md#b-compile-native-linux-pppd) |

The Linux-native target builds the complete upstream Linux daemon with its own
Linux backend. It does not turn Wintun into a Linux network driver. Compiler
and build dependencies are separate from runtime dependencies.

## Windows runtime: two files

```text
your-runtime-directory/
  pppd.exe
  wintun.dll
```

Download the official SDK from [wintun.net](https://www.wintun.net/), extract
`wintun/bin/amd64/wintun.dll`, and put it **in the same directory as `pppd.exe`**.
Use the x64 DLL. The executable locates its sibling DLL even when launched
from another working directory. Detailed download, hash and placement steps
are in [WINTUN.md](docs/WINTUN.md).

No implicit `C:\ProgramData\pppd`, config installation, OpenSSL DLL or MSYS2
runtime is required by the Windows executable. Link operations need an elevated
terminal, Windows networking components and a working serial-device driver.
Authentication methods may additionally require your configuration, secrets
and certificates. These are inputs, rather than extra runtime libraries.

## Quick start: 115200, 8N1, XON/XOFF

Use two distinct computers or OS instances. Close other owners of the ports.
`COM10` and `/dev/ttyUSB0` are examples; replace them with the actual devices.
The first example intentionally disables compression/encryption to establish
the basic link.

Windows, elevated Command Prompt:

```cmd
pppd.exe COM10 115200 local nocrtscts xonxoff noauth lock asyncmap a0000 escape 11,13 mtu 1500 mru 1500 noccp novj nomppe noipv6 nodefaultroute lcp-echo-interval 0 lcp-echo-failure 0 persist holdoff 3 maxfail 0 10.253.77.1:10.253.77.2 ifname pppespw linkname ESP-WIN nodetach debug
```

Linux:

```sh
sudo pppd /dev/ttyUSB0 115200 local nocrtscts xonxoff noauth lock asyncmap a0000 escape 11,13 mtu 1500 mru 1500 noccp novj nomppe noipv6 nodefaultroute lcp-echo-interval 0 lcp-echo-failure 0 persist holdoff 3 maxfail 0 10.253.77.2:10.253.77.1 ifname pppespl linkname ESP-LINUX nodetach debug
```

In PowerShell, use `.\pppd.exe`. Eight-bit PPP defaults to 8N1 for these
commands; no Windows-only serial-format token is added to the shared syntax.
Wait for completed authentication/NCP negotiation and the peer route before
starting an application. Stop foreground instances with **Ctrl+C**.

### Maximum supported compression and encryption

The [full paired examples](docs/USAGE.md) include all serial options, credential
preparation, command lines, IPv6, stopping and troubleshooting.

| Desired profile | Common options | Meaning |
|---|---|---|
| Highest payload-compression parameters | `nomppe vj-max-slots 16 deflate 15,15 bsdcomp 15,15` | VJ plus the negotiated Deflate15 or BSD15 compressor. |
| Strongest supported traffic encryption plus compatible compression | `vj-max-slots 16 require-mppe-128 nomppe-40 nomppe-stateful` | VJ plus MPPE128; also configure MSCHAPv2 authentication as shown in the paired example. |

**Deflate/BSD and MPPE cannot be stacked in this release.** Upstream CCP excludes
the other payload compressors when MPPE is required. VJ + MPPE128 is the
simultaneous header-compression/encryption profile. MPPE uses legacy RC4;
128 bits is the highest implemented MPPE setting, not a modern VPN security
claim. TLS-based authentication does not by itself encrypt IP packets.

## Validation and known limits

The unchanged Windows 0.4.0 implementation completed selected physical
Windows-to-native-Linux serial profiles for VJ, BSD, Deflate, MPPE40/128 and
IPv4/IPv6, with exact file checks. One VJ+MPPE128 TCP session lasted 951.922
seconds. There were receive FCS rejections and an earlier connection timeout:
the result is functional interoperability **with reception/startup reservations**.
Windows-to-Windows was not tested. This is no WHQL or independent security
certification. See [qualification scope and results](docs/QUALIFICATION.md).

Fresh compiler checks are recorded separately in
[BUILD-VERIFICATION.md](docs/BUILD-VERIFICATION.md). Rebuilding with another
toolchain does not reproduce the previously qualified binary automatically.

## Repository map

| Path | Contents |
|---|---|
| `src/` | Complete Windows host, adapted pppd subset, codecs, original notices and provenance. |
| `upstream/ppp/` | Complete pinned upstream source for native Linux pppd. |
| `third_party/openssl-3.5.9/` | Complete unmodified OpenSSL dependency source. |
| `scripts/` | Dependency, native Windows, Linux cross and native Linux build scripts. |
| `tests/` | Pure codec tests; no private lab controllers or credentials. |
| `patches/linux-bsd32/` | Optional reference source for the specific Linux BSD decompressor correction used in the lab. |
| `docs/`, `licenses/` | English guides, exact support boundaries, source provenance and retained licenses. |

See [PUBLISHING.md](docs/PUBLISHING.md) for importing the extracted tree into a
new GitHub repository. No account-specific remote is embedded.

`SOURCE-MANIFEST.json` records the source package's file sizes and SHA-256
hashes. On Windows, verify the preserved implementation before building with
`powershell -NoProfile -File scripts/verify-windows-source.ps1`; this needs no
elevation and does not operate a device.

## Licensing status

This is a **source-only distribution**; no executable, DLL or kernel module is
included. Component licenses and notices are preserved. There is a known
GPL-2.0-only / Apache-2.0 compatibility issue in the current combined executable,
and no overall license grant has been identified for the original Windows host
files. This repository does not claim those issues are resolved by bundling
source. Read [LICENSING.md](docs/LICENSING.md), [LICENSE](LICENSE) and
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) before redistributing binaries
or assigning a project-wide license.

