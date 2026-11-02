/* Userspace host adapter for the Linux v6.1 PPP compressor callback ABI.
 * Structure layout/constants originate in include/linux/ppp-comp.h and
 * include/uapi/linux/ppp_defs.h; algorithms remain in their original files. */
#ifndef PPP_CODEC_COMPAT_H
#define PPP_CODEC_COMPAT_H
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <limits.h>
#include "ppp_comp_defs.h"
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
#define PPP_HDRLEN 4
#define PPP_ADDRESS(p) ((p)[0])
#define PPP_CONTROL(p) ((p)[1])
#define PPP_PROTOCOL(p) ((((unsigned)(p)[2])<<8)|(p)[3])
#define PPP_COMP 0xfd
#define PPP_IP 0x21
#define DECOMP_ERROR (-1)
#define DECOMP_FATALERROR (-2)
#define GFP_KERNEL 0
#define GFP_ATOMIC 0
#define THIS_MODULE NULL
#define KERN_ERR ""
#define KERN_DEBUG ""
#define KERN_INFO ""
#define kmalloc(n, flags) malloc(n)
#define kzalloc(n, flags) calloc(1,(n))
#define kfree(p) free(p)
#define vmalloc(n) malloc(n)
#define vfree(p) free(p)
#define array_size(a,b) ((size_t)(a)*(size_t)(b))
#if !defined(__LITTLE_ENDIAN) && !defined(__BIG_ENDIAN)
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define __BIG_ENDIAN 1
#else
#define __LITTLE_ENDIAN 1
#endif
#endif
static inline int ppp_codec_printk(const char *fmt,...) {(void)fmt;return 0;}
#define printk ppp_codec_printk
static inline unsigned get_unaligned_be16(const void *v){const uint8_t*p=(const uint8_t*)v;return ((unsigned)p[0]<<8)|p[1];}
static inline void put_unaligned_be16(unsigned n,void*v){uint8_t*p=(uint8_t*)v;p[0]=(uint8_t)(n>>8);p[1]=(uint8_t)n;}
struct compstat {
 uint32_t unc_bytes,unc_packets,comp_bytes,comp_packets,inc_bytes,inc_packets;
 uint32_t in_count,bytes_out;double ratio;
};
struct compressor {
 int compress_proto;
 void *(*comp_alloc)(unsigned char*,int);
 void (*comp_free)(void*);
 int (*comp_init)(void*,unsigned char*,int,int,int,int);
 void (*comp_reset)(void*);
 int (*compress)(void*,unsigned char*,unsigned char*,int,int);
 void (*comp_stat)(void*,struct compstat*);
 void *(*decomp_alloc)(unsigned char*,int);
 void (*decomp_free)(void*);
 int (*decomp_init)(void*,unsigned char*,int,int,int,int,int);
 void (*decomp_reset)(void*);
 int (*decompress)(void*,unsigned char*,int,unsigned char*,int);
 void (*incomp)(void*,unsigned char*,int);
 void (*decomp_stat)(void*,struct compstat*);
 void *owner;unsigned int comp_extra;
};
const struct compressor *ppp_bsd_compressor(void);
const struct compressor *ppp_deflate_compressor(int method);
#endif
