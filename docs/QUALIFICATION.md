# Qualification of the Windows 0.4.0 implementation

This document summarizes the completed lab evidence without publishing private
host identities, credentials or captures. The result is **functional
Windows-to-native-Linux serial interoperability with reception/startup
reservations**. It is not an error-free radio-link guarantee, WHQL approval,
or independent cryptographic certification.

## Identity and environment

The original qualified Windows x64 executable had SHA-256:

```text
efc417bb76ba965df98c75583966a3ce8aae0d7d26286bbcc3b3b93ca5711779
```

It used Wintun 0.14.1 amd64, SHA-256:

```text
e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce
```

The native Linux reference was pppd 2.4.9 on Debian 12, Linux
6.1.0-53-amd64. The physical transport consisted of two preprogrammed ESP
serial endpoints at 115200, 8N1, XON/XOFF. No firmware was flashed.

The lab's 64-bit Linux BSD decompressor used a specific fixed-width correction.
Its reference module identity was `0.4.0-bsd32`, SHA-256
`a778f272f7a3be5d6d02345204c9f58afcc254aa91da6363a3246ea14ce7baca`.
Only its source/patch is supplied in [patches/linux-bsd32](../patches/linux-bsd32/README.md).
This is not a generic instruction to replace every Linux BSD module.

## Physical serial profiles

Across 13 attempts, 12 completed the functional traffic checks and one initial
MPPE128 connection attempt failed. The final selected set contains these 11
successful profiles:

| Profile | Address families | Result |
|---|---|---|
| No compression/encryption | IPv4 | Passed functional checks |
| VJ | IPv4 | Passed functional checks |
| BSD-Compress15 | IPv4 | Passed functional checks |
| Deflate15 | IPv4 | Passed functional checks |
| MPPE40 stateless | IPv4 | Passed functional checks |
| MPPE128 stateless | IPv4 | Passed after the retained earlier failure |
| VJ + MPPE128 stateless | IPv4 | Passed, including endurance session |
| Deflate15 | IPv4 and IPv6 | Passed both address families |
| VJ + MPPE128 stateless | IPv4 and IPv6 | Passed both address families |
| MPPE40 stateful acceptance | IPv4 | Passed; directional modes below |
| MPPE128 stateful acceptance | IPv4 | Passed; directional modes below |

Each selected profile checked files with exact hashes and traffic initiated
from both sides. The VJ+MPPE128 endurance run maintained one TCP socket for
951.922 seconds (15 minutes 51.922 seconds), with the same PPP process and no
NCP renegotiation.

`mppe-stateful` allows rather than forces stateful mode. The physical
stateful-acceptance cases negotiated H0 from Windows to Linux and H1 from
Linux to Windows. Each sent 192 Windows MPPE packets, below the 256-packet
periodic rekey boundary. These physical runs alone do not demonstrate
long-duration H0 rekey/wrap behavior.

## Recorded reservations

- Selected runs recorded 11 Windows receive FCS rejections: five over the
  endurance link's full lifetime and six in the final baseline case. Linux
  recorded one receive FCS rejection in the final baseline. Zero errors in a
  Linux transmit recording made before physical FCS generation do not prove
  zero Windows receive FCS errors.
- Windows invalid-frame, oversize-frame and data-drop counters were zero in
  the selected runs. File hashes were exact and TCP recovered, despite the
  receive FCS errors. The source of each physical receive error was not isolated.
- An initial MPPE128 application connection failed with Windows error 10060
  after 21.031 seconds and transferred no files. Offline decryption proved
  valid IPv4/TCP: the SYN reached Linux roughly 20 seconds late and Linux
  replied immediately. The stage responsible for the delay was not proven;
  neither ESP flow control nor a particular driver/queue was established as
  the cause. A subsequent run passed with the same binary/profile after at
  least 60 seconds of settling time.

`persist` retries PPP; it does not restart an application's expired TCP
connection. `STARTED` is an initialization acknowledgment, not proof of an
established IP path. Check negotiated state and routing before application
traffic, and allow application retries on a slow transport.

## Separate codec and engine evidence

Fresh pure-codec runs completed on Windows and on Linux with
AddressSanitizer/UndefinedBehaviorSanitizer and leak checking:

| Test family | Scope |
|---|---|
| VJ | 261 checks |
| BSD/Deflate | 15 configurations, 7,680 valid frames, 15,360 malformed-input checks |
| MPPE | Four modes, 20,000 packets, 121,340 assertions, including RFC 3079 vectors, rekey, loss/reset and sequence wrap |

Earlier engine/native-pppd interoperability ran 28 cases from Windows and 28
from Linux; a separate 35-case regression and PEAP work also preceded the
physical campaign. These are protocol/engine evidence, not additional fresh
physical-radio passes. The pure codec test sources are provided under
[`tests`](../tests/README.md).

A prior two-file startup check covered paths containing spaces and an accented
character, with an unrelated current directory. `--help` and `--version`
succeeded, and PE imports contained Windows system libraries. That was a
startup check, not a newly established live link from every copied directory.

## What remains unqualified

Windows-to-Windows physical testing was explicitly deferred and was not run.
No universal claim is made for every Windows version, UART driver, baud rate,
serial format, radio firmware, Linux kernel module or authentication peer.
The partial support boundaries in [SUPPORT.md](SUPPORT.md) still apply.

Fresh compilation and information-only checks for this repository are recorded
in [BUILD-VERIFICATION.md](BUILD-VERIFICATION.md). A compiler rebuild can have a
different hash and is not automatically the original hardware-qualified binary.
Packaging did not reopen COM ports, start PPP links, change VirtualHere
assignments or flash ESP firmware.
