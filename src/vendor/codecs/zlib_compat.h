/* Userspace substitutes for Linux kernel facilities used by its PPP zlib.
 * bitrev32 is the constant bit-reversal sequence from Linux v6.1
 * include/linux/bitrev.h (GPL-2.0). */
#ifndef PPP_ZLIB_COMPAT_H
#define PPP_ZLIB_COMPAT_H
#include "codec_compat.h"
#include <assert.h>
#define max(a,b) ((a)>(b)?(a):(b))
#define min(a,b) ((a)<(b)?(a):(b))
#define BUG_ON(x) assert(!(x))
#define IS_ENABLED(x) 0
#if defined(__GNUC__) && __GNUC__ >= 7
#define fallthrough __attribute__((fallthrough))
#else
#define fallthrough ((void)0)
#endif
static inline u32 bitrev32(u32 x){
 x=(x>>16)|(x<<16);
 x=((x&0xFF00FF00u)>>8)|((x&0x00FF00FFu)<<8);
 x=((x&0xF0F0F0F0u)>>4)|((x&0x0F0F0F0Fu)<<4);
 x=((x&0xCCCCCCCCu)>>2)|((x&0x33333333u)<<2);
 return ((x&0xAAAAAAAAu)>>1)|((x&0x55555555u)<<1);
}
#endif
