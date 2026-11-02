# Optional Linux BSD-Compress reference correction

These are the source and patch used to correct the reference lab's **Linux
kernel BSD-Compress decompressor**, independently of the Windows executable.
They are supplied for source completeness and diagnosis, not installed by the
project's build scripts.

The reference source is Linux v6.1 `drivers/net/ppp/bsd_comp.c`. Its original
algorithm needs a 32-bit bit accumulator. The patch makes that width explicit
and uses unsigned operands where appropriate; the complete source comparison
is in `bsd32.patch`. Original notices are retained.

| File | Purpose |
|---|---|
| `bsd_comp.original.c` | Unmodified reference kernel source. |
| `bsd_comp.c` | Corrected source used in the lab. |
| `bsd32.patch` | Source delta for review. |
| `Makefile`, `build.sh` | Build-only external-module recipe, pinned by default to the lab kernel. |
| `COPYING`, `GPL-2.0` | Retained notices/terms. |

The qualification kernel was `6.1.0-53-amd64`, built with GCC 12. A module
compiled for that kernel must not be copied into a different kernel. No
prebuilt `.ko`, privileged installer, module-loader or boot-time persistence
script is included here.

To reproduce the **build only** on the matching system, install the exact
prepared kernel headers, `make` and the matching compiler, then run:

```sh
cd patches/linux-bsd32
KERNEL_RELEASE=6.1.0-53-amd64 CC=gcc-12 sh build.sh
```

The script checks `Module.symvers` and the generated kernel-release header.
`KDIR` can name another prepared header tree, but porting/reviewing the patch
for another kernel is a separate task. Signing, installation, unloading a
module that is in use, and Secure Boot policy are deliberately outside this
build-only recipe. Prefer an appropriate distribution kernel correction when
one is available. Native Linux PPP uses kernel codecs; rebuilding userspace
pppd does not by itself change this decompressor.

See [the qualification summary](../../docs/QUALIFICATION.md) for the result's
exact scope.
