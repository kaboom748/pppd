# Using PPP over a transparent serial link

This project ports part of the Linux `pppd` userspace protocol implementation to a native Windows executable. Its original purpose is to connect two transparent serial endpoints, including two already programmed ESP radio modems, and carry IP packets between the computers attached to them.

```text
Windows applications                   Linux applications
        |                                      |
   Windows IP stack                       Linux IP stack
        |                                      |
   Wintun interface                       PPP interface
        |                                      |
     pppd.exe                               pppd
        |                                      |
      COM10 ---- transparent serial/radio ---- /dev/ttyUSB0
```

This creates a Layer 3 point-to-point IP link. It is not an Ethernet bridge: Ethernet frames, MAC addresses, broadcasts and VLAN tags are not transported as Ethernet. Routing a LAN through the link additionally requires the operating systems to configure forwarding, routes and, if appropriate, NAT.

The Windows port preserves Linux-style option names and argument syntax for the implemented features. The Windows COM device name, native Linux device path, executable invocation and operating-system administration necessarily differ. See [SUPPORT.md](SUPPORT.md) for the exact compatibility limits.

## Before starting

1. On Windows, put the x64 `wintun.dll` **in the same directory as `pppd.exe`**. The executable finds its sibling DLL; the shell's current directory does not select the DLL. Obtain the official DLL as described in the repository README. Do not place an unrelated DLL of the same name on `PATH`.
2. Run link operations from an elevated Windows terminal. Windows 10/11 x64 and a working driver for the serial device are required. A Wintun interface is created for each instance. On Linux, use native `pppd` with the necessary privileges and kernel PPP/compression modules.
3. Identify each computer's actual serial device. `COM10` below belongs to the Windows computer running the executable. It is not a COM port on a Remote Desktop server. `/dev/ttyUSB0` is an example for the other computer; a stable `/dev/serial/by-id/...` path can also be used with native Linux pppd.
4. The serial transport must pass arbitrary eight-bit data transparently. Configure both endpoint firmwares consistently. These examples neither load nor flash firmware and do not send AT initialization commands.
5. Close terminals and other applications that own either serial port. The Windows program opens COM exclusively. Use different serial ports, `ifname` values and `linkname` values for simultaneous instances.
6. Choose two distinct IP addresses that do not overlap existing networks. The examples use Windows `10.253.77.1` and Linux `10.253.77.2`.

Do not validate a radio path by assigning both IP addresses to the same Windows IP stack. Local routing may bypass both serial ports. The documented physical qualification used two different operating-system instances.

## Common serial configuration: 115200, 8N1, XON/XOFF

The examples configure 115200 baud, eight data bits, no parity, one stop bit and software flow control. These are test settings, not a fixed restriction on the executable.

| Token | Meaning |
|---|---|
| `115200` | Serial speed; both UART endpoints must accept it. |
| `local` | Local serial link, without modem carrier-detect handling. |
| `nocrtscts xonxoff` | Disable hardware flow control, then select bidirectional XON/XOFF. Keep this order for these profiles. |
| `asyncmap a0000` | Receive ACCM includes XON and XOFF control characters. The value is hexadecimal. |
| `escape 11,13` | Escape hexadecimal bytes `0x11` and `0x13` in outgoing PPP framing. |
| `mtu 1500 mru 1500` | Requested transmit and receive limits. MPPE subsequently reduces the effective IP MTU by four bytes. |
| `nodefaultroute` | Keep the link from becoming the default IPv4 route. The peer host route is still configured. |
| `lcp-echo-interval 0 lcp-echo-failure 0` | Disable LCP echo monitoring for this slow-radio profile. |
| `persist holdoff 3 maxfail 0` | Retry failed PPP sessions without a finite failure limit, waiting three seconds between attempts. |
| `nodetach debug` | Remain in the foreground and enable protocol diagnostics. |

Eight-bit PPP and the default serial format already give 8N1 for these examples. Do not add Windows-specific `parity` or `data-bits` extensions to a supposedly portable native Linux command. The Windows port can configure parity and one/two stop bits, but the peer and UART driver must support the requested format.

Native Linux pppd may also read `/etc/ppp/options`, user options and other system configuration. Check those files for conflicting settings before using these examples. In particular, an inherited `novj` or `noccp` can disable compression. The Windows standalone mode does not implicitly read an `options` file.

## First connection without compression or encryption

Use this profile to establish a known baseline. It requests no peer authentication and provides no encryption.

Windows, in an elevated Command Prompt:

```cmd
pppd.exe COM10 115200 local nocrtscts xonxoff noauth lock asyncmap a0000 escape 11,13 mtu 1500 mru 1500 noccp novj nomppe noipv6 nodefaultroute lcp-echo-interval 0 lcp-echo-failure 0 persist holdoff 3 maxfail 0 10.253.77.1:10.253.77.2 ifname pppespw linkname ESP-WIN nodetach debug
```

Linux, using native pppd:

```sh
sudo pppd /dev/ttyUSB0 115200 local nocrtscts xonxoff noauth lock asyncmap a0000 escape 11,13 mtu 1500 mru 1500 noccp novj nomppe noipv6 nodefaultroute lcp-echo-interval 0 lcp-echo-failure 0 persist holdoff 3 maxfail 0 10.253.77.2:10.253.77.1 ifname pppespl linkname ESP-LINUX nodetach debug
```

In PowerShell, invoke a program in the current directory as `.\pppd.exe`; the pppd arguments are unchanged. Command Prompt also resolves `pppd` to `pppd.exe` when its directory is the current directory or is on `PATH`. Linux normally invokes the native program as `pppd` or `/usr/sbin/pppd`.

The common options use the same Linux-style syntax. The device name and local:peer address order change because these are two different endpoints.

## Highest supported payload-compression settings

VJ compresses TCP/IPv4 headers. Deflate and BSD-Compress compress PPP data. The highest supported Deflate window and BSD dictionary setting is `15`; this does not mean every packet becomes smaller. Incompressible packets may be sent in their normal form while CCP remains active.

The following profile enables VJ with 16 slots and offers both Deflate15 and BSD15. Deflate is preferred. One CCP data-compression method is negotiated per direction; Deflate and BSD are alternatives, not two stacked payload compressors. The peer must support the selected method.

Windows:

```cmd
pppd.exe COM10 115200 local nocrtscts xonxoff noauth lock asyncmap a0000 escape 11,13 mtu 1500 mru 1500 nomppe vj-max-slots 16 deflate 15,15 bsdcomp 15,15 noipv6 nodefaultroute lcp-echo-interval 0 lcp-echo-failure 0 persist holdoff 3 maxfail 0 10.253.77.1:10.253.77.2 ifname pppespw linkname ESP-WIN nodetach debug
```

Linux:

```sh
sudo pppd /dev/ttyUSB0 115200 local nocrtscts xonxoff noauth lock asyncmap a0000 escape 11,13 mtu 1500 mru 1500 nomppe vj-max-slots 16 deflate 15,15 bsdcomp 15,15 noipv6 nodefaultroute lcp-echo-interval 0 lcp-echo-failure 0 persist holdoff 3 maxfail 0 10.253.77.2:10.253.77.1 ifname pppespl linkname ESP-LINUX nodetach debug
```

For deterministic algorithm selection, replace `deflate 15,15 bsdcomp 15,15` on **both** endpoints with one of these:

```text
deflate 15,15 nobsdcomp
```

```text
bsdcomp 15,15 nodeflate
```

Keep `novj` absent to permit VJ. VJ is enabled by default; `vj-max-slots 16` sets its slot limit. Remove inherited disabling options rather than assuming there is an implemented `vj` or `ccp` enabling token.

This profile does not encrypt payloads. A native Linux peer needs its corresponding kernel codec. The reference VM used a corrected BSD module for its specific 64-bit kernel; see [QUALIFICATION.md](QUALIFICATION.md) rather than assuming that kernel patch is required or appropriate on every Linux installation.

## Strongest supported PPP encryption, with compatible compression

The strongest traffic encryption implemented by this port is **MPPE128**. It uses RC4 and is a legacy interoperability feature; "strongest supported" does not mean AES, ChaCha20, a modern VPN security assessment or a security certification.

MPPE needs keys from a suitable authentication exchange, such as MSCHAPv2. PAP, CHAP-MD5 and `noauth` alone do not provide the required MPPE keys. `noauth` means "do not require the peer to authenticate to me"; it does not stop this endpoint from authenticating to the other endpoint.

**BSD/Deflate and MPPE cannot be active together in this implementation.** The upstream CCP code excludes the other CCP compressors when MPPE is required. VJ is negotiated by IPCP and can run before MPPE, so **VJ + MPPE128** is the available simultaneous header-compression/encryption profile. There is no command that combines maximum BSD/Deflate payload compression and MPPE encryption in this release.

### Configure the Linux authenticator

In this paired example, Linux authenticates Windows using MSCHAPv2. Data still flows in both directions. On Linux, add this line to the native pppd CHAP secret file, normally `/etc/ppp/chap-secrets`:

```text
# client  server  secret                       allowed-client-IP
win       linux   "replace-this-example-secret" 10.253.77.1
```

Use an editor with administrative privileges; do not replace unrelated existing entries. Restrict the file to its owner:

```sh
sudo chown root:root /etc/ppp/chap-secrets
sudo chmod 600 /etc/ppp/chap-secrets
```

The same example secret must appear on the Windows client. `win`, `linux` and the addresses must match the command lines. These are example PPP identities, not Windows or Unix account names.

### Start the endpoints

Start Linux first, optionally with `silent` as shown so it waits for the Windows LCP request:

```sh
sudo pppd /dev/ttyUSB0 115200 local nocrtscts xonxoff noauth lock asyncmap a0000 escape 11,13 mtu 1500 mru 1500 vj-max-slots 16 require-mschap-v2 require-mppe-128 nomppe-40 nomppe-stateful name linux noipv6 nodefaultroute lcp-echo-interval 0 lcp-echo-failure 0 persist holdoff 3 maxfail 0 10.253.77.2:10.253.77.1 ifname pppespl linkname ESP-LINUX silent nodetach debug
```

Then Windows, in an elevated Command Prompt:

```cmd
pppd.exe COM10 115200 local nocrtscts xonxoff noauth lock asyncmap a0000 escape 11,13 mtu 1500 mru 1500 vj-max-slots 16 require-mppe-128 nomppe-40 nomppe-stateful name win user win password "replace-this-example-secret" remotename linux refuse-pap refuse-chap refuse-mschap refuse-eap noipv6 nodefaultroute lcp-echo-interval 0 lcp-echo-failure 0 persist holdoff 3 maxfail 0 10.253.77.1:10.253.77.2 ifname pppespw linkname ESP-WIN nodetach debug
```

The different authentication options specify the authenticator/client roles; they are standard pppd-style options, not a translation to another Windows command language. `refuse-mschap` disables MSCHAPv1, while MSCHAPv2 remains available. `require-mppe-128 nomppe-40` requires 128-bit MPPE rather than permitting a downgrade to 40 bits. `nomppe-stateful` requests the stateless profile used here.

The example places a demonstration password on the command line for clarity. For actual credentials, the Windows client can instead use an explicit, protected `chap-secrets` file as described below. The identities, credentials and certificates are configuration inputs; they are not extra runtime libraries.

Successful negotiation should identify MSCHAPv2, MPPE128, the VJ IPCP option and the negotiated IP addresses. If mandatory MPPE cannot be established, IP must not be opened in clear text. Do not remove `require-mppe-128` merely to make an authentication error disappear.

### Stateful MPPE

`mppe-stateful` **allows** stateful MPPE; the initial receive preference remains stateless, matching upstream pppd behavior. It does not force both directions into stateful mode. Inspect both CCP Configure-Ack directions. The qualification's stateful-acceptance fixtures obtained Windows-to-Linux H0 and Linux-to-Windows H1; do not describe those as H0 in both directions.

## Explicit credentials on Windows

Windows client authentication can read the secret from a protected file instead of `password ...`. For example:

```text
win linux "replace-this-example-secret" 10.253.77.1
```

Place it at an absolute path, for example `C:/ppp-config/chap-secrets`, and replace `password "replace-this-example-secret"` with:

```text
chap-secrets C:/ppp-config/chap-secrets
```

The Windows authenticator also requires a secret file: its server-side CHAP lookup does not use the client's `password` option as a server credential database. For an authenticator named `winserver`, a Linux client named `linuxclient` and peer address `10.253.77.2`, use:

```text
linuxclient winserver "replace-this-example-secret" 10.253.77.2
```

The corresponding Windows authentication options include:

```text
name winserver require-mschap-v2 require-mppe-128 nomppe-40 chap-secrets C:/ppp-config/chap-secrets
```

The client uses `user linuxclient password ... remotename winserver`. Set the local:peer addresses for the actual endpoint. A Windows-to-Windows physical test was not performed in this release's qualification; configuring a second authenticator is not a claim that such a test passed.

Secret files must be regular local files with an inspectable DACL, owned by the running user, SYSTEM or Administrators. Their read/write permissions must not grant another identity access. Broad inherited Users/Everyone grants are rejected. Configuration files and inclusions also have protection and path-containment checks; see [SUPPORT.md](SUPPORT.md).

Native Linux pppd traditionally uses its system secret files. Do not copy Windows `--config-dir` into a native Linux command. Explicit `chap-secrets`/`pap-secrets` filename options depend on the native pppd release; the tested Linux 2.4.9 peer used `/etc/ppp/chap-secrets`.

## IPv6

For dual-stack PPP, replace `noipv6` on both endpoints with:

```text
# Windows
+ipv6 ipv6 ::1,::2
# Linux
+ipv6 ipv6 ::2,::1
```

The Windows port configures link-local IPv6 and the peer route. Use the interface scope when addressing a link-local peer, for example `fe80::2%<Windows-interface-index>` or `fe80::1%pppespl`. VJ applies only to TCP/IPv4 headers; it does not compress IPv6 headers. Deflate or MPPE can process IPv6 PPP payloads.

IPv6 requires an effective MTU of at least 1280. When using MPPE, configure MTU and peer MRU to at least 1284 because MPPE subtracts four bytes from the IP MTU. The examples request 1500, giving an effective MPPE IP MTU of 1496.

## Wait for the network, then verify it

On Windows, `STARTED` means that the owner process and resources were initialized. It does not prove that authentication or IPCP/IPv6CP is complete. Wait for `UP` and inspect the interface and selected route:

```powershell
Get-NetAdapter -Name pppespw
Get-NetIPAddress -InterfaceAlias pppespw
Find-NetRoute -RemoteIPAddress 10.253.77.2
```

On Linux:

```sh
ip address show dev pppespl
ip route get 10.253.77.1
```

Then test from Windows to the Linux peer:

```cmd
ping 10.253.77.2
```

Scope firewall rules to the PPP interface, peer IP, program and required protocol/port if needed. Do not disable the firewall globally as a connection test.

The physical test transport showed large delays and rejected frames. One early Windows TCP connection expired while its SYN took about 20 seconds to reach Linux. Later profiles waited at least 60 seconds after the route became ready before starting traffic. That is a documented bench condition, not a delay hardcoded into pppd or proof that the delay source was identified. Give the link time to settle and use application connection retries suitable for the actual transport.

PPP rejects frames whose FCS is invalid. TCP may recover by retransmission; UDP applications do not receive equivalent automatic recovery from PPP. Read [QUALIFICATION.md](QUALIFICATION.md) for the measured integrity results and reception/startup reservations.

## Stop the connection

For the foreground `nodetach` examples, press **Ctrl+C** on either operating system and allow cleanup to finish.

Without `nodetach`, the Windows owner is detached. Stop the specific Windows link from an elevated terminal:

```cmd
pppd.exe --stop ESP-WIN
```

`--stop` is a Windows extension and waits for the owned adapter/resource cleanup. Native Linux pppd does not implement it. On Linux, send SIGTERM to the verified pppd PID for that link, using its recorded PID or verified link-specific PID file:

```sh
sudo kill -TERM <the-verified-pppd-PID>
```

Avoid a broad `killall`/`pkill` if other PPP links are in use. Forced termination, a crash or sudden device removal does not provide the same cleanup guarantee as controlled termination.

## Diagnostics and common errors

| Observation | What to check |
|---|---|
| COM open failure | Correct local COM number, serial driver, exclusive owner, VirtualHere ownership if used. |
| Windows privilege error | Start the terminal as Administrator; help/version alone do not require elevation. |
| Wintun load failure | Matching x64 `wintun.dll` beside the executable, rather than only in the current directory or elsewhere on PATH. |
| LCP never completes | Endpoint baud/framing/flow settings, transparent transport, XOFF/CTS state, peer readiness and actual received bytes. |
| Authentication failure | PPP identities, secret-file client/server columns, explicit Windows secret path, protected file permissions and common authentication methods. |
| Mandatory MPPE does not open IP | Successful key-generating authentication and a common permitted MPPE key width/mode. |
| Compression not negotiated | No inherited `noccp`/`novj`, enabled peer algorithms and native Linux kernel codec support. Inspect CCP/IPCP rather than assuming command-line intent was accepted. |
| TCP timeout although PPP is UP | Selected route, firewall scope, real packet delivery delay, initial OS traffic and transport errors. An UP interface alone does not prove application delivery. |
| FCS rejects | Preserve both endpoints' counters and traffic evidence. A native Linux TX record is taken before the bytes cross the physical path, so its valid FCS cannot prove error-free Windows reception. |
| Unexpected configuration-path error | Use the current standalone build, or supply an existing protected directory only if intentionally using `--config-dir`. A ProgramData directory is not required in standalone mode. |

`--help` and `show-options` expose the implemented option catalogue. `dump` prints effective configuration and continues; `dryrun` validates configuration without opening COM/Wintun, but currently still requires elevation on Windows. Passwords are redacted in configuration dumps.
