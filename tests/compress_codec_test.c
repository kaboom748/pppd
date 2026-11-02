/* Stateful compression validation. Interoperability is tested separately
 * against a native Linux pppd: this harness alone does not establish it. */
#include "compress_port.h"
#include "vendor/codecs/codec_compat.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static uint32_t rng=0xdec0de12u;
static uint8_t nextbyte(void){rng^=rng<<13;rng^=rng>>17;rng^=rng<<5;return (uint8_t)rng;}
static unsigned cases,packets,compressed,incompressible,malformed;
static void scenario(int method,int bits){
 uint8_t opt[4]={(uint8_t)method,3,0,0};size_t optlen=3;
 if(method==CI_BSD_COMPRESS)opt[2]=(uint8_t)BSD_MAKE_OPT(1,bits);
 else{opt[1]=4;optlen=4;opt[2]=(uint8_t)DEFLATE_MAKE_OPT(bits);}
 PppCompression *tx=ppp_comp_create(method,opt,optlen,0,16384),*rx=ppp_comp_create(method,opt,optlen,1,16384);
 assert(tx&&rx);assert(ppp_comp_method(tx)==method);
 uint8_t frame[16388],encoded[17000],decoded[16388];unsigned localcomp=0,localinc=0;
 for(unsigned j=0;j<512;j++){
  size_t len=24u+(j*173u)%16365u;
  frame[0]=255;frame[1]=3;frame[2]=0;frame[3]=(j%7)?0x21:0x57;
  for(size_t i=4;i<len;i++)frame[i]=(j%3)?(uint8_t)(j+i%23):nextbyte();
  int n=ppp_comp_compress(tx,frame,len,encoded,sizeof(encoded));assert(n>=0);
  if(n){int count=ppp_comp_decompress(rx,encoded,(size_t)n,decoded,sizeof(decoded));if(count!=(int)len)fprintf(stderr,"method=%d bits=%d packet=%u original=%zu compressed=%d decoded=%d\n",method,bits,j,len,n,count);assert(count==(int)len);assert(!memcmp(frame,decoded,len));compressed++;localcomp++;}
  else{ppp_comp_incomp(rx,frame,len);incompressible++;localinc++;}
  packets++;
  if(j==255){ppp_comp_reset(tx);ppp_comp_reset(rx);}
 }
 assert(localcomp&&localinc);
 /* A lost packet must not silently produce a different original packet. */
 ppp_comp_reset(tx);ppp_comp_reset(rx);
 memset(frame,'A',1504);frame[0]=255;frame[1]=3;frame[2]=0;frame[3]=0x21;
 int count=ppp_comp_compress(tx,frame,1504,encoded,sizeof(encoded));assert(count>6);
 encoded[4]^=1;assert(ppp_comp_decompress(rx,encoded,(size_t)count,decoded,sizeof(decoded))==-1);
 ppp_comp_reset(tx);ppp_comp_reset(rx);
 count=ppp_comp_compress(tx,frame,1504,encoded,sizeof(encoded));assert(count>6);
 assert(ppp_comp_decompress(rx,encoded,(size_t)count,decoded,sizeof(decoded))==1504);assert(!memcmp(frame,decoded,1504));
 /* Exercise corrupt streams with matching sequence numbers and tight bounds. */
 for(unsigned j=0;j<1024;j++){
  ppp_comp_reset(rx);size_t n=7+j%127;for(size_t i=0;i<n;i++)encoded[i]=nextbyte();
  encoded[0]=255;encoded[1]=3;encoded[2]=0;encoded[3]=PPP_COMP;encoded[4]=encoded[5]=0;
  count=ppp_comp_decompress(rx,encoded,n,decoded,64);assert(count<=64);assert(count>=-2);malformed++;
 }
 assert(ppp_comp_compress(tx,frame,5,encoded,sizeof(encoded))==-1);
 assert(ppp_comp_decompress(rx,encoded,6,decoded,sizeof(decoded))==-1);
 assert(ppp_comp_create(method,opt,1,0,1500)==NULL);
 ppp_comp_destroy(tx);ppp_comp_destroy(rx);cases++;
}
int main(void){
 for(int bits=9;bits<=15;bits++)scenario(CI_BSD_COMPRESS,bits);
 for(int bits=9;bits<=15;bits++)scenario(CI_DEFLATE,bits);
 scenario(CI_DEFLATE_DRAFT,15);
 printf("{\"result\":\"PASS\",\"cases\":%u,\"packets\":%u,\"compressed\":%u,\"incompressible\":%u,\"malformed\":%u}\n",cases,packets,compressed,incompressible,malformed);
 return 0;
}
