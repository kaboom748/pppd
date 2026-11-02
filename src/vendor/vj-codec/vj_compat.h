#ifndef PPP_VJ_COMPAT_H
#define PPP_VJ_COMPAT_H
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif
typedef uint8_t __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint16_t __be16;
typedef uint32_t __be32;
typedef uint16_t __sum16;
/* Layouts retained from Linux UAPI ip.h/tcp.h. Packed wire access also makes
 * the kernel code's byte-buffer casts safe for unaligned host input. */
struct __attribute__((packed)) iphdr {
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
 __u8 version:4,ihl:4;
#else
 __u8 ihl:4,version:4;
#endif
 __u8 tos; __be16 tot_len,id,frag_off; __u8 ttl,protocol;
 __sum16 check; __be32 saddr,daddr;
};
struct __attribute__((packed)) tcphdr {
 __be16 source,dest; __be32 seq,ack_seq;
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
 __u16 doff:4,res1:3,ae:1,cwr:1,ece:1,urg:1,ack:1,psh:1,rst:1,syn:1,fin:1;
#else
 __u16 ae:1,res1:3,doff:4,fin:1,syn:1,rst:1,psh:1,ack:1,urg:1,ece:1,cwr:1;
#endif
 __be16 window; __sum16 check; __be16 urg_ptr;
};
_Static_assert(sizeof(struct iphdr)==20,"IPv4 wire layout");
_Static_assert(sizeof(struct tcphdr)==20,"TCP wire layout");
#define GFP_KERNEL 0
#define kzalloc(n,flags) calloc(1,(n))
#define kzalloc_obj(type) ((type *)calloc(1,sizeof(type)))
#define kfree free
#define ERR_PTR(err) NULL
#define IS_ERR_OR_NULL(ptr) (!(ptr))
static inline __sum16 ppp_vj_load_sum16(const void *p){__sum16 v;memcpy(&v,p,sizeof(v));return v;}
static inline void ppp_vj_store_sum16(void *p,__sum16 v){memcpy(p,&v,sizeof(v));}
#define put_unaligned(value,p) ppp_vj_store_sum16((p),(value))
/* Portable equivalent of ip_fast_csum. Return a network-order 16-bit value. */
static inline __sum16 ip_fast_csum(const void *p,unsigned ihl){
 const uint8_t *b=(const uint8_t *)p;uint32_t sum=0;
 for(unsigned i=0;i<ihl*4;i+=2)sum+=((unsigned)b[i]<<8)|b[i+1];
 while(sum>>16)sum=(sum&65535)+(sum>>16);
 return htons((uint16_t)~sum);
}
#endif
