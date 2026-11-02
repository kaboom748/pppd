/* Userspace host for the original Linux PPP compressor callback ABI.
 * Negotiation lives in upstream ccp.c; algorithms live in vendor/codecs.
 * CCP observation follows Linux v6.1 ppp_generic.c:ppp_ccp_peek.
 * The host uses bounded contiguous buffers in place of sk_buff and ioctl.
 */
#include "vendor/ppp/pppd-private.h"
#include "vendor/ppp/fsm.h"
#include "vendor/ppp/ccp.h"
#include "vendor/ppp/ccp_host.h"
#include "vendor/ppp/lcp.h"
#include "vendor/codecs/codec_compat.h"
#include "data_port.h"
#include "mppe_port.h"
#include "vj_port.h"
typedef struct Codec {const struct compressor *ops;void *state;int run;} Codec;
static struct {Codec tx,rx;PppVj *vj;unsigned mru,mtu;int open,up,required,rx_error,rx_fatal,fault;} d;
static unsigned protocol(const uint8_t*p){return ((unsigned)p[2]<<8)|p[3];}
static void free_codec(Codec*c,int receive){if(c->state){if(receive)c->ops->decomp_free(c->state);else c->ops->comp_free(c->state);}memset(c,0,sizeof(*c));}
void ppp_data_destroy(void){free_codec(&d.tx,0);free_codec(&d.rx,1);ppp_vj_destroy(d.vj);memset(&d,0,sizeof(d));}
void ppp_data_init(const PppDataOptions *o,unsigned mru,unsigned mtu){ppp_data_destroy();d.mru=mru;d.mtu=mtu;d.required=o->mppe_required;}
void ppp_data_set_mru(unsigned n){if(n>=128&&n<=16384)d.mru=n;}
int ppp_data_fault(void){return d.fault;}
int ppp_data_encrypted_ready(void){return d.up&&d.rx.run&&d.tx.run&&d.rx.ops&&d.tx.ops&&d.rx.ops->compress_proto==CI_MPPE&&d.tx.ops->compress_proto==CI_MPPE;}
int ppp_data_vj_config(unsigned rx,unsigned tx,int cid){ppp_vj_destroy(d.vj);d.vj=NULL;if(!rx&&!tx)return 1;d.vj=ppp_vj_create(rx,tx,cid);return d.vj!=NULL;}
void ppp_data_loss(void){ppp_vj_toss(d.vj);}
int ccp_test(int unit,unsigned char *opt,int n,int transmit){
 (void)unit;if(!opt||n<2||opt[1]<2||opt[1]>n||n>22)return 0;
 const struct compressor *ops=NULL;
 if(opt[0]==CI_BSD_COMPRESS)ops=ppp_bsd_compressor();
 else if(opt[0]==CI_DEFLATE||opt[0]==CI_DEFLATE_DRAFT)ops=ppp_deflate_compressor(opt[0]);
 else if(opt[0]==CI_MPPE)ops=ppp_mppe_compressor();
 if(!ops)return 0;
 void *state=transmit?ops->comp_alloc(opt,n):ops->decomp_alloc(opt,n);if(!state)return 0;
 Codec *c=transmit?&d.tx:&d.rx;free_codec(c,!transmit);c->ops=ops;c->state=state;return 1;
}
void ccp_flags_set(int unit,int open,int up){(void)unit;d.open=open;d.up=up;if(!open){free_codec(&d.tx,0);free_codec(&d.rx,1);d.rx_error=d.rx_fatal=0;}}
int ccp_fatal_error(int unit){(void)unit;return d.rx_fatal;}
/* Called only for structurally valid CCP packets. Information starts at code. */
void ppp_data_ccp_peek(const uint8_t *p,size_t n,int inbound){
 if(n<4)return;unsigned len=((unsigned)p[2]<<8)|p[3];if(len<4||len>n)return;
 switch(p[0]){
 case CONFREQ:if(inbound)d.tx.run=0;else d.rx.run=0;break;
 case TERMREQ:case TERMACK:d.tx.run=d.rx.run=0;break;
 case CONFACK:{
  if(!d.open||d.up||len<6||p[5]<2||p[5]>len-4)break;
  Codec*c=inbound?&d.rx:&d.tx;if(!c->state||c->ops->compress_proto!=p[4])break;
  int ok=inbound?c->ops->decomp_init(c->state,(unsigned char*)p+4,(int)len-4,0,0,(int)d.mru,0):c->ops->comp_init(c->state,(unsigned char*)p+4,(int)len-4,0,0,0);
  c->run=ok;if(inbound&&ok)d.rx_error=d.rx_fatal=0;if(!ok&&d.required)d.fault=1;break;}
 case 15:if(!d.up)break;if(inbound){if(d.rx.run&&d.rx.state)d.rx.ops->decomp_reset(d.rx.state);d.rx_error=0;}else if(d.tx.run&&d.tx.state)d.tx.ops->comp_reset(d.tx.state);break;
 }
}
int ppp_data_send(const uint8_t *p,size_t n,uint8_t *out,size_t cap){
 if(n<4||n>cap||n>16388)return -1;unsigned proto=protocol(p);
 if(d.required&&!ppp_data_encrypted_ready())return -1;
 uint8_t vj[16388];const uint8_t *plain=p;size_t plain_n=n;
 if(proto==PPP_IP&&d.vj){uint16_t vp=PPP_IP;memcpy(vj,p,4);int z=ppp_vj_encode(d.vj,p+4,n-4,vj+4,sizeof(vj)-4,&vp);if(z<0)return -1;vj[2]=(uint8_t)(vp>>8);vj[3]=(uint8_t)vp;plain=vj;plain_n=(size_t)z+4;}
 if(d.tx.run&&d.tx.state){int z=d.tx.ops->compress(d.tx.state,(unsigned char*)plain,out,(int)plain_n,(int)cap);if(z>0&&d.up)return z;if(z<0){d.fault=1;return -1;}if(d.required){d.fault=1;return -1;}}
 if(plain_n>cap)return -1;memcpy(out,plain,plain_n);return (int)plain_n;
}
int ppp_data_receive(const uint8_t *p,size_t n,uint8_t *out,size_t cap){
 if(n<7||n>16388||cap<8)return -1;unsigned proto=protocol(p);uint8_t unpacked[16388];const uint8_t *plain=p;size_t plain_n=n;
 if(proto==PPP_COMP){
  if(!d.rx.run||!d.rx.state||d.rx_fatal)return -1;
  /* Linux still passes compressed frames to pppd while SC_DC_ERROR is set.
   * Repeated indications set RREQ_REPEAT, allowing CCP to retry a lost
   * Reset-Ack instead of leaving reception permanently suspended. */
  if(d.rx_error){if(ccp_protent.datainput)ccp_protent.datainput(0,NULL,0);return -1;}
  int z=d.rx.ops->decompress(d.rx.state,(unsigned char*)p,(int)n,unpacked,(int)(d.mru+4<sizeof(unpacked)?d.mru+4:sizeof(unpacked)));
  if(z<4){d.rx_error=1;d.rx_fatal=z==DECOMP_FATALERROR;ppp_data_loss();if(ccp_protent.datainput)ccp_protent.datainput(0,NULL,0);return -1;}
  plain=unpacked;plain_n=(size_t)z;proto=protocol(plain);
 }else{
  if(d.required)return -1;
  if(d.rx.run&&d.rx.state&&!d.rx_error&&!d.rx_fatal&&d.rx.ops->incomp)d.rx.ops->incomp(d.rx.state,(unsigned char*)p,(int)n);
 }
 if(plain_n>cap||plain_n>4+d.mru)return -1;
 if(proto==0x2d||proto==0x2f){if(!d.vj)return -1;memcpy(out,plain,4);int z=ppp_vj_decode(d.vj,(uint16_t)proto,plain+4,plain_n-4,out+4,cap-4);if(z<0||z>(int)d.mru)return -1;out[2]=0;out[3]=PPP_IP;return z+4;}
 memcpy(out,plain,plain_n);return (int)plain_n;
}
