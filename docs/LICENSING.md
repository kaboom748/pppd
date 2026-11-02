# Licensing and redistribution status

## Source package

The ZIP is a **source-only component aggregate**. It preserves the individual
licenses, original copyright statements and adaptation records. It does not
contain `pppd.exe`, `wintun.dll`, prebuilt codec tests, or a compiled kernel
module. It does not replace the per-file licenses with MIT, BSD, GPLv3, or any
other blanket label.

The original Windows host/adaptation files have no identified project-wide
license grant. The repository owner must choose terms for original code they
own if they want to grant others rights beyond what copyright law otherwise
allows. A choice for new code does not override third-party rights.

## Existing combined-build licensing issue

The qualified Windows build links these components into one executable:

- `src/vendor/codecs/ppp_deflate.c` explicitly says `GPL-2.0-only`.
- `zlib_compat.h` identifies copied GPL-2.0 Linux bit-reversal code.
- OpenSSL 3.5.9 uses Apache License 2.0; retained pppd DES code also identifies
  Apache-licensed OpenSSL-derived portions.
- ARC4 is GPL-2.0-or-later, while the MPPE engine has a permissive alternative.

The Apache Software Foundation's compatibility explanation states that Apache
2.0 is compatible with GPLv3, but not GPLv2. Choosing GPLv3 for original port
files does not turn the existing GPL-2.0-only files into GPLv3 files. The UAPI
Linux-syscall-note exception does not apply to every kernel implementation file.
Therefore this package does **not** represent the current combined executable
as legally cleared for binary redistribution. Review and resolve the actual
component permissions before publishing compiled releases. No codec has been
removed, substituted, relicensed, or changed to conceal this issue.

Official sources:

- [Apache License 2.0 / GPL compatibility](https://www.apache.org/licenses/GPL-compatibility.html)
- [OpenSSL release licensing](https://openssl-library.org/source/license/)
- [Linux v6.1 bitrev.h](https://github.com/torvalds/linux/blob/v6.1/include/linux/bitrev.h)
- [Linux v6.1 PPP Deflate source](https://github.com/torvalds/linux/blob/v6.1/drivers/net/ppp/ppp_deflate.c)

This is a factual inventory of the supplied source and upstream statements, not
a new permission from any copyright holder or a legal clearance opinion.

## Wintun is separate

Get the DLL from the official [Wintun download site](https://www.wintun.net/).
The source license and prebuilt-binary license are not interchangeable. Keep
the license that accompanies the DLL version you distribute. The DLL is not
included in this source ZIP. An end user places the matching x64 `wintun.dll`
next to the Windows `pppd.exe` they build.

## Keeping notices

Keep this file, `LICENSE`, `THIRD_PARTY_NOTICES.md`, `licenses/`, original source
headers, upstream `COPYING` files and complete bundled dependency source trees
together. `licenses/SOURCE-NOTICES.txt` collects original source notice blocks;
the full source files remain authoritative.
