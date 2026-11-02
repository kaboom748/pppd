# Obtaining and placing wintun.dll

The Windows port uses [Wintun](https://www.wintun.net/) to exchange IP packets
with the Windows network stack. The driver DLL is a runtime dependency. It is
loaded dynamically and is not needed to compile the program.

## Official download

1. Open the official [Wintun download page](https://www.wintun.net/).
2. Download the official prebuilt SDK ZIP. The version used for qualification
   was [Wintun 0.14.1](https://www.wintun.net/builds/wintun-0.14.1.zip).
3. Extract the archive and read its `wintun/LICENSE.txt` and `wintun/README.md`.
4. Select **`wintun/bin/amd64/wintun.dll`**. This port builds a Windows x64
   executable. The x86, ARM and ARM64 copies are different architectures.
5. Copy that file beside the `pppd.exe` you built:

```text
C:\ppp\pppd.exe
C:\ppp\wintun.dll
```

The DLL must be in the executable's directory, even if you launch the program
from another working directory. Putting it only in the current directory or
somewhere on `PATH` does not satisfy the sibling-DLL requirement. No global
copy to `System32` is required.

For the pinned 0.14.1 download, the SHA-256 values are:

| File | SHA-256 |
|---|---|
| `wintun-0.14.1.zip` | `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51` |
| `wintun/bin/amd64/wintun.dll` | `e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce` |

Check a downloaded file with PowerShell:

```powershell
Get-FileHash .\wintun-0.14.1.zip -Algorithm SHA256
Get-FileHash .\wintun\bin\amd64\wintun.dll -Algorithm SHA256
```

These hashes identify that release, not any future release. The official
prebuilt DLLs are signed; retain the binary license supplied with the release.
The Wintun source license and the prebuilt-binary terms differ. This repository
includes the SDK API header and notices, but no DLL.

## Runtime requirements

Use Windows 10/11 x64, an elevated terminal for creating/stopping a link, and
the driver needed by your USB/serial adapter. The supplied build statically
links OpenSSL and compiler runtime support; it does not need OpenSSL DLLs or
an MSYS2 installation on the target computer. Windows system libraries remain
operating-system requirements. Applying negotiated DNS uses Windows APIs
available from build 19041.

For an unauthenticated static serial link, `pppd.exe` plus its sibling
`wintun.dll` are the application runtime files. Explicit option files,
credentials and certificates are needed only for the features you select.
