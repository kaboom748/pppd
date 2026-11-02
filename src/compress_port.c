/* Bounded userspace host for the original Linux PPP compressor callbacks. */
#include "compress_port.h"
#include "vendor/codecs/codec_compat.h"
struct PppCompression {const struct compressor *codec;void *state;int receive,method;unsigned mru;};
PppCompression *ppp_comp_create(int method,const uint8_t *option,size_t length,int receive,unsigned mru){
 const struct compressor *codec;
 if(!option||length<2||length>32||option[0]!=method||option[1]!=length||mru<128||mru>16384)return NULL;
 if(method==CI_BSD_COMPRESS)codec=ppp_bsd_compressor();
 else if(method==CI_DEFLATE||method==CI_DEFLATE_DRAFT)codec=ppp_deflate_compressor(method);
 else return NULL;
 uint8_t opt[32];memcpy(opt,option,length);
 PppCompression *p=(PppCompression*)calloc(1,sizeof(*p));if(!p)return NULL;
 p->codec=codec;p->receive=!!receive;p->method=method;p->mru=mru;
 p->state=p->receive?codec->decomp_alloc(opt,(int)length):codec->comp_alloc(opt,(int)length);
 if(!p->state){free(p);return NULL;}
 int ok=p->receive?codec->decomp_init(p->state,opt,(int)length,0,0,(int)mru,0):codec->comp_init(p->state,opt,(int)length,0,0,0);
 if(!ok){ppp_comp_destroy(p);return NULL;}return p;
}
void ppp_comp_destroy(PppCompression *p){if(!p)return;if(p->state){if(p->receive)p->codec->decomp_free(p->state);else p->codec->comp_free(p->state);}free(p);}
void ppp_comp_reset(PppCompression *p){if(p){if(p->receive)p->codec->decomp_reset(p->state);else p->codec->comp_reset(p->state);}}
int ppp_comp_method(const PppCompression *p){return p?p->method:0;}
static int valid(const uint8_t *frame,size_t n){return frame&&n>=4&&n<=16388&&frame[0]==255&&frame[1]==3&&!(frame[2]&1)&&(frame[3]&1);}
int ppp_comp_compress(PppCompression *p,const uint8_t *frame,size_t n,uint8_t *out,size_t cap){
 if(!p||p->receive||!valid(frame,n)||n<7||n>p->mru+4u||!out||cap<8||cap>INT_MAX)return -1;
 /* Kernel callbacks mutate only their private context; frame data is read-only. */
 return p->codec->compress(p->state,(uint8_t*)frame,out,(int)n,(int)cap);
}
int ppp_comp_decompress(PppCompression *p,const uint8_t *frame,size_t n,uint8_t *out,size_t cap){
 if(!p||!p->receive||!valid(frame,n)||n<7||frame[2]!=0||frame[3]!=PPP_COMP||!out||cap<4||cap>INT_MAX)return DECOMP_ERROR;
 if(cap>p->mru+4u)cap=p->mru+4u;
 return p->codec->decompress(p->state,(uint8_t*)frame,(int)n,out,(int)cap);
}
void ppp_comp_incomp(PppCompression *p,const uint8_t *frame,size_t n){if(p&&p->receive&&valid(frame,n)&&n<=p->mru+4u)p->codec->incomp(p->state,(uint8_t*)frame,(int)n);}
