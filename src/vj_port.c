/* Windows/Linux userspace adapter around the unchanged VJ state machine.
 * Origin and exact host-only adaptations: vendor/vj-codec/PROVENANCE.txt. */
#include "vj_port.h"
#include "vendor/vj-codec/vj_compat.h"
#include "vendor/vj-codec/slhc_vj.h"
#define VJ_MAX_IP 65535u
#define VJ_HEADROOM 128u
struct PppVj {
 struct slcompress *state;
 unsigned receive_slots,transmit_slots;
 int compress_cid;
 uint8_t input[VJ_MAX_IP+VJ_HEADROOM],encoded[VJ_MAX_IP+VJ_HEADROOM];
};
PppVj *ppp_vj_create(unsigned receive_slots,unsigned transmit_slots,int compress_cid){
 if(receive_slots>255||transmit_slots>255)return NULL;
 PppVj *v=(PppVj *)calloc(1,sizeof(*v));if(!v)return NULL;
 v->state=slhc_init((int)receive_slots,(int)transmit_slots);
 if(!v->state){free(v);return NULL;}
 v->receive_slots=receive_slots;v->transmit_slots=transmit_slots;v->compress_cid=!!compress_cid;return v;
}
void ppp_vj_destroy(PppVj *v){if(v){slhc_free(v->state);memset(v,0,sizeof(*v));free(v);}}
void ppp_vj_toss(PppVj *v){if(v)slhc_toss(v->state);}
int ppp_vj_encode(PppVj *v,const uint8_t *input,size_t length,uint8_t *output,size_t capacity,uint16_t *protocol){
 if(!v||!input||!output||!protocol||length<20||length>VJ_MAX_IP||capacity<length||input[0]>>4!=4)return -1;
 unsigned ihl=(input[0]&15u)*4u;
 if(ihl<20||ihl>length||(((unsigned)input[2]<<8)|input[3])!=length)return -1;
 memcpy(v->input,input,length);uint8_t *packet=v->input;int n=(int)length;
 *protocol=0x21;
 if(v->transmit_slots){
  n=slhc_compress(v->state,v->input,(int)length,v->encoded,&packet,v->compress_cid);
  if(n<=0||(size_t)n>length)return -1;
  if(packet[0]&SL_TYPE_COMPRESSED_TCP){*protocol=0x2d;packet[0]&=(uint8_t)~SL_TYPE_COMPRESSED_TCP;}
  else if((packet[0]&0xf0)==SL_TYPE_UNCOMPRESSED_TCP){*protocol=0x2f;packet[0]&=0x4f;}
 }
 memcpy(output,packet,(size_t)n);return n;
}
int ppp_vj_decode(PppVj *v,uint16_t protocol,const uint8_t *input,size_t length,uint8_t *output,size_t capacity){
 if(!v||!input||!output||!length||length>VJ_MAX_IP||!v->receive_slots||(protocol!=0x2d&&protocol!=0x2f))return -1;
 memcpy(v->input,input,length);int n;
 if(protocol==0x2f){
  if((input[0]>>4)!=4){ppp_vj_toss(v);return -1;}
  n=slhc_remember(v->state,v->input,(int)length);
 }else n=slhc_uncompress(v->state,v->input,(int)length);
 if(n<20||(unsigned)n>VJ_MAX_IP||(size_t)n>capacity||(v->input[0]>>4)!=4||(((unsigned)v->input[2]<<8)|v->input[3])!=(unsigned)n){ppp_vj_toss(v);return -1;}
 memcpy(output,v->input,(size_t)n);return n;
}
