# Supported features and compatibility boundaries

This is a **partial Windows port of Linux pppd**, not a complete replacement for every Unix pppd deployment. The Windows host uses original pppd protocol state machines and adapted codecs, with a native COM/Wintun platform layer. Native Linux pppd continues to use the Linux kernel PPP interfaces and its own platform implementation.

The compatibility objective is to use Linux-style options for the common implemented serial/IP features. The supported subset is the contract. Unsupported facilities are rejected rather than silently emulated.

## Transport and platform

| Facility | Windows port status | Scope |
|---|---|---|
| Asynchronous PPP over serial | Supported | Eight-bit binary PPP on an exclusive Windows COM port. |
| COM device names | Supported | `COM1` through `COM65535`, also `\\.\COMn`; no automatic `/dev` mapping. |
| Baud rate | Configurable | Positive 32-bit decimal value; the serial driver must accept it. 115200 was the physical test setting. |
| 8N1 and XON/XOFF | Supported/tested | `local nocrtscts xonxoff`, ACCM/escape settings described in [USAGE.md](USAGE.md). |
| RTS/CTS hardware flow control | Implemented | `crtscts`; requires suitable wiring, peer configuration and driver support. |
| Parity / stop bits | Configurable Windows serial format | `parity none|odd|even|mark|space`, `stop-bits 1|2`; binary PPP requires eight data bits. These settings are not an assertion that every combination was physically qualified. |
| Interface | Supported | One Wintun Layer 3 interface per running instance. |
| Multiple instances | Supported with distinct resources | Unique COM port, `ifname` and `linkname`; the port/interface/link identities are locked against conflicting instances. |
| Modem dialing, DCD/DTR modem policy | Unsupported | Local transparent serial use only; no Windows chat/dialer equivalent. |
| Synchronous PPP, PTY/notty/socket transport | Unsupported | The Windows executable is a COM transport host. |
| PPPoE, PPPoATM, PPPoL2TP and other Linux transport plugins | Unsupported | These are not converted into COM links by a command alias. |
| Ethernet bridging / BCP / TAP | Unsupported | Wintun carries IP packets, not Ethernet frames or VLANs. |

## IP negotiation and routing

| Facility | Status | Scope |
|---|---|---|
| LCP | Supported | Original negotiation state machine, async framing/FCS, MRU/ACCM, magic number and supported compression negotiation options. |
| IPv4/IPCP | Supported | Static literal unicast local:peer addresses or negotiated addresses; an empty side or `0.0.0.0` requests negotiation. `ipcp-accept-local`, `ipcp-accept-remote` and related implemented negotiation options are available. No hostname-to-address substitution is provided by the Windows parser. |
| IPv6/IPv6CP | Supported with platform limits | Link-local identifiers/addresses and peer route; dual stack or IPv6-only with `noip`. |
| MTU/MRU | Configurable | 128..16384; effective IPv6 MTU must be at least 1280. MPPE subtracts four bytes from effective IP MTU. |
| IPv4 peer route | Supported | Host route to the negotiated peer on the owned Wintun interface. |
| IPv4 default route | Supported/optional | `defaultroute`, with `defaultroute-metric`; only the owned route is managed. `nodefaultroute` leaves the existing default route alone. |
| Received DNS | Supported | `usepeerdns` applies negotiated DNS to the owned interface; its Windows API needs build 19041 or later. |
| DNS/WINS offered to peer | Supported | `ms-dns`, `ms-wins`. |
| Received WINS applied locally | Unsupported | `usepeerwins` is rejected. |
| IPv6 default route and global-prefix provisioning | Not implemented by the Windows host | No automatic IPv6 default route, DHCPv6 relay or global-prefix configuration. OS-managed routing is a separate task. |
| Proxy ARP | Unsupported | `proxyarp` and its variants are not Windows ARP emulations. |
| LAN forwarding/NAT | Operating-system task | The program establishes a point-to-point interface; it is not a router/NAT configuration service. |

## Compression and traffic encryption

| Method | Status | Parameters and limits |
|---|---|---|
| Van Jacobson TCP/IPv4 header compression | Supported | Default 16 slots/CID; `novj`, `novjccomp`, `vj-max-slots 2..16`. Does not compress IPv6 or arbitrary application payloads. |
| BSD-Compress | Supported | `bsdcomp receive[,transmit]`, dictionary bits 9..15; 0 disables a direction; `nobsdcomp` disables both. |
| PPP Deflate | Supported | `deflate receive[,transmit]`, window 9..15; accepted 8 is promoted to 9 as upstream does. Standard and upstream draft negotiation are implemented; `nodeflate`, `nodeflatedraft`. |
| CCP | Supported | Default offers BSD15/Deflate15, with Deflate preferred. `noccp` disables CCP separately from VJ. Compressor and decompressor support must be present in the peer. |
| MPPE40 / MPPE128 | Supported | `require-mppe`, `require-mppe-40`, `require-mppe-128`, `nomppe-40`, `nomppe-128`, `nomppe`, and supported upstream aliases. Requires suitable authentication-derived keys. |
| MPPE stateless/stateful modes | Supported | `nomppe-stateful` / `mppe-stateful`. Allowing stateful mode does not force both directions to select it. Modes are negotiated independently. |
| VJ + Deflate or BSD | Supported | VJ header compression can precede the selected CCP payload compressor. |
| VJ + MPPE | Supported | VJ TCP/IPv4 headers followed by MPPE traffic encryption. This is the implemented simultaneous compression/encryption combination. |
| BSD/Deflate + MPPE together | Unsupported combination | Upstream CCP excludes other CCP compressors when MPPE is required. They cannot be stacked by adding more options. |
| Predictor1/2, MPPC, multilink compression | Unsupported | No codec is invented to substitute for these methods. |
| ECP, AES, ChaCha20 traffic encryption | Unsupported | MPPE uses RC4. TLS-based authentication does not automatically add TLS/AES/ChaCha encryption to IP packets. |

Maximum settings (`15` for BSD/Deflate and 128-bit MPPE) mean the highest implemented parameters, not universally the best ratio or a modern cryptographic security guarantee. Compression may expand or decline incompressible data. MPPE is legacy interoperability encryption.

## Authentication

| Method/facility | Status | Scope |
|---|---|---|
| PAP | Supported | Explicit credentials/secret files, without Unix account/PAM integration. |
| CHAP-MD5 | Supported | Original CHAP protocol code and explicit secrets. Does not supply MPPE keys. |
| MSCHAPv1 / MSCHAPv2 | Supported | Original protocol/key derivation; MSCHAPv2 was used in the physical MPPE examples. |
| EAP-MD5 / EAP-MSCHAPv2 | Supported | Original EAP implementations through the Windows authentication adapter. |
| EAP-TLS | Implemented in the supplied TLS-enabled build | CA/certificate/private-key or PKCS#12 configuration, certificate verification and supported TLS options. Depends on peer support and supplied credentials. |
| PEAP client | Implemented with upstream limitations | CA/peer-name validation and user credentials; upstream retransmission and outgoing fragmented-response limitations remain. No PEAP server claim. |
| `auth` / `noauth`, require/refuse options | Supported | Control whether this endpoint requires peer authentication and which methods it accepts for authenticating itself. `noauth` is not a prohibition on answering a peer's authentication request. |
| `user`, `password`, `name`, `remotename` | Supported with limits | UTF-8 values within 255-byte fields; passwords are redacted in effective-configuration dumps. |
| Explicit `pap-secrets` / `chap-secrets` | Supported with limits | Protected regular local files; server-side secret lookup requires the corresponding configured secret file. CLI `password` is a client credential, not the authenticator's secret database. |
| Secret-file address authorization | Partial | Literal IPv4/CIDR, wildcards and deny rules; unsupported hostname/per-peer option rules are rejected. |
| CBCP callback request | Limited | Requests callback from the peer and then exits with code 14; it does not dial the modem or accept a callback session automatically. |
| PAM, Unix login/account checks, RADIUS, Winbind, NTLM helper | Unsupported | No implicit use of Windows accounts or an external authentication service. |

The shipped build enables EAP-TLS and PEAP through statically linked OpenSSL. A build with those features disabled must not be advertised as supporting their options. Read the build's actual help/catalogue.

## Lifecycle, configuration and diagnostics

| Facility | Status | Windows behavior |
|---|---|---|
| Foreground / detached owner | Supported | `nodetach` keeps the owner attached; otherwise a detached owner is started and its initialization is acknowledged. |
| `persist`, `nopersist`, `holdoff`, `maxfail` | Supported | PPP retry policy; it does not retry a separate application's expired TCP connection. |
| `idle`, `maxconnect` | Supported | Connection lifetime timers. |
| LCP echo/adaptive echo, RTT output | Supported | Implemented LCP timer/count options and `lcp-rtt-file`. |
| LCP/IPCP/IPv6CP/PAP/CHAP/EAP timer options | Supported subset | See the option catalogue for exact names and limits; not every Linux hook is present. |
| `passive`, `silent`, address/control and protocol-field compression flags | Supported | Implemented upstream-style negotiation settings. |
| `debug`, `dump`, `dryrun` | Supported | Dump redacts passwords; dryrun opens neither COM nor Wintun but currently requires elevation. |
| Standalone operation | Supported | Runtime libraries are the executable and its sibling x64 Wintun DLL, plus Windows components. No implicit ProgramData directory or configuration file is required. |
| `file` / `call` | Supported with containment/security limits | Explicitly requested option/peer files, with UTF-8 parsing and checked inclusions. |
| `--config-dir` | Windows extension | Explicit protected local root; its `options` file is optional. No implicit `.ppprc` or `options.<tty>` loading. |
| `--stop linkname` | Windows extension | Protected instance-control IPC and controlled resource removal. Native Linux uses signals/PID tracking. |
| Unix shell scripts and hooks | Unsupported | `connect`, `disconnect`, `ip-up`, `ip-down`, other script execution, PTY scripts and `record` are not silently implemented. |
| Linux binary plugins | Unsupported | `.so` plugins cannot be loaded into this Windows executable. |
| Demand dialing, traffic filters, multilink/bundles | Unsupported | No Linux demand-mode kernel backend, BPF filter stack, bundle manager or PPPoX plugin substitution. |

The explicit Windows configuration root does not change native Linux pppd's `/etc/ppp` behavior. Without `--config-dir`, Windows `call name` reads `peers/name` under the executable directory; explicitly requested relative `file` paths are resolved within that root. `/etc/ppp/` is a Windows-parser alias of the selected root, not a real mounted Unix filesystem.

Windows `ifname` accepts 1..15 ASCII characters; `linkname` accepts 1..63. If omitted, the interface name is derived from the owner PID and the link name defaults to the interface name. Use explicit stable names when an operator needs to stop a detached instance later.

Checked option files use strict UTF-8 (a BOM is accepted), with an inclusion depth limit of 16, 1 MiB aggregate input and 1023-byte words. Escaping the selected root, UNC paths, reparse points, inclusion cycles and unsafe file security are rejected. Secret files have stricter permissions than ordinary configuration data. A configuration input may be optional, while credentials are still necessary for a selected authentication method.

## Same syntax: what is and is not promised

The common examples in [USAGE.md](USAGE.md) use the same pppd option spelling and value syntax on both systems:

```text
115200 local nocrtscts xonxoff lock asyncmap a0000 escape 11,13 mtu 1500 mru 1500
```

Platform-specific endpoint values remain different:

| Item | Windows | Native Linux |
|---|---|---|
| Executable | `pppd.exe` (`pppd` also resolves in Command Prompt) | `pppd` / `/usr/sbin/pppd` |
| Local serial device | `COM10` | `/dev/ttyUSB0` or `/dev/serial/by-id/...` |
| Privilege | Elevated terminal for the link/stop | Root or distribution-specific pppd privilege setup |
| IP direction | This host's address first | This host's address first, so the pair is reversed |
| Configuration discovery | Explicit standalone policy | Native pppd system/user configuration rules |
| Stop detached link | `--stop linkname` | SIGTERM to the verified owning pppd PID |
| Serial-format extensions | Windows `parity` / `data-bits` | Do not assume those extensions are native Linux options |

Defaults are not identical: the Windows program defaults to the documented ESP-friendly local/noauth/XON-XOFF/persist profile, while native pppd defaults and system option files vary. Specify settings explicitly for a reproducible pair. An option supported by a particular Linux release, kernel module or plugin is not thereby implemented by the Windows port.

## Qualification scope

Version 0.4.0 was physically exercised between the real Windows executable/Wintun/COM endpoint and native Linux pppd through the existing ESP serial transport. Eleven selected profiles completed exact file transfers from both TCP initiators, including IPv4/IPv6 profiles and a 951.922-second VJ+MPPE128 TCP session. Separate codec suites ran on Windows and Linux.

These are functional compatibility/integrity results **with reception and startup reservations**, not an error-free transport certificate: selected tests recorded 11 Windows receive FCS rejects and 1 Linux receive FCS reject. One initial MPPE128 TCP connection timed out before any file transfer; a new attempt passed after a documented 60-second settling phase. The precise source of delay/corruption was not localized. Windows-to-Windows physical testing was not performed.

See [QUALIFICATION.md](QUALIFICATION.md) for the authoritative scope, hashes, per-direction stateful modes, reception observations and distinction between physical tests, codec tests and earlier engine/native-Linux interoperability checks. Do not convert a feature being implemented into a claim that all combinations, serial rates, hardware, loads or failure scenarios have been qualified.
