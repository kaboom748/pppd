# Third-party notices

This is a source distribution of a **partial Windows port**. It contains a
mixture of copyright and license terms. The notices in individual files are
authoritative; the table below is an index, not a replacement license.

| Component | Source in this repository | Origin and retained terms |
| --- | --- | --- |
| pppd protocol and authentication code | `src/vendor/ppp/` | ppp-project pppd 2.5.5, commit `4dc474cacfa045d1ee1b10c388d8c864e3ed3b30`; individual BSD-style/CMU/author notices. The upstream `COPYING` file explicitly directs readers to individual files. Full upstream Linux source has additional licenses for its optional components. |
| VJ TCP/IPv4 header compression | `src/vendor/vj-codec/` | Linux source pinned at `6628e7d4c6b25c8d18f1345e3a20d21829aae7e4`; Van Jacobson/University of California, Berkeley notices retained in `slhc.c` and its header; original UAPI headers have their own GPL-with-syscall-note terms. |
| BSD-Compress | `src/vendor/codecs/bsd_comp.c` | Linux v6.1; Regents of the University of California notice retained, including its historical advertising acknowledgment and subsequent Berkeley-change comment. |
| PPP Deflate wrapper | `src/vendor/codecs/ppp_deflate.c` | Linux v6.1; Paul Mackerras, explicit `GPL-2.0-only` identifier. |
| PPP packet-flush zlib | `src/vendor/codecs/zlib_*`, `zlib.h`, `zconf.h`, `zutil.h` | Linux v6.1's modified zlib; Jean-loup Gailly/Mark Adler notice in `zlib.h` and corresponding per-file notices. This is the PPP-aware kernel variant, not an interchangeable stock zlib dependency. |
| Bit reversal adaptation | `src/vendor/codecs/zlib_compat.h` | Explicitly identifies Linux v6.1 `include/linux/bitrev.h` and GPL-2.0 origin. |
| MPPE packet engine | `src/vendor/mppe-codec/ppp_mppe.c` | Linux v6.1; Frank Cusack/Google permissive notice, with alternative GPL-2.0-or-later terms, retained in full. |
| ARC4 | `src/vendor/mppe-codec/arc4.c`, `arc4.h` | Linux v6.1; `GPL-2.0-or-later` / `GPL-2.0+` identifiers retained. |
| UAPI compression definitions | `src/vendor/codecs/ppp_comp_defs.h` and retained original UAPI headers | GPL-2.0 or GPL-2.0-or-later **with Linux-syscall-note**, as identified per file. The exception is for UAPI use; it does not generally relicense kernel implementation code. |
| OpenSSL | Complete bundled `third_party/openssl-3.5.9/` source; statically linked when the Windows target is built | Apache License 2.0. Keep the original source license/notice files and `licenses/OpenSSL-Apache-2.0.txt`. Some retained pppd crypto files also identify Apache-licensed OpenSSL-derived portions. |
| Wintun | Downloaded separately; no DLL is included in this source-only repository package | WireGuard project. Source and prebuilt binaries have different distribution terms. `licenses/Wintun-Prebuilt-Binaries.txt` preserves the terms supplied with the tested DLL; obtain and inspect the terms supplied with any DLL you download. |
| Optional native Linux BSD fix | Optional BSD-fix source/patch directory | The original kernel source and its notices are retained. The optional module is not part of the Windows executable and no prebuilt `.ko` is included in this public source package. |

The Windows host, COM/Wintun/IPC adapters and option catalogue are port-specific
code, rather than a copied Linux kernel backend. Their existing files do not
carry a separate project-wide license grant. Do not assume this index supplies
one. See [Licensing and redistribution](docs/LICENSING.md).

## Required acknowledgments

This product includes software developed by Computing Services at Carnegie Mellon University (http://www.cmu.edu/computing/).

This product includes software developed by Pedro Roque Marques <pedro_m@yahoo.com>.

This product includes software developed by Paul Mackerras <paulus@ozlabs.org>.

This product includes software developed by the University of California, Berkeley and its contributors.

The fallback MD5 code identifies the RSA Data Security, Inc. MD5 Message-Digest
Algorithm and contains its original notice. The modified implementation is
derived from the RSA Data Security, Inc. MD5 Message-Digest Algorithm; retain
that notice when copying it.

Original notices are also collected without translation in
`licenses/SOURCE-NOTICES.txt`. Altered source files remain marked as adaptations
and their provenance records identify changes. No upstream contributor endorses
this port merely because their code is included.
