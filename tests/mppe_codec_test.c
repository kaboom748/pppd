/* Packet-codec tests; including the private TU permits checking published
 * RFC3079 intermediate keys without adding key-export APIs to the product. */
#include "../src/mppe_port.c"
#include <assert.h>

static const unsigned char master[16]={0x8b,0x7c,0xdc,0x14,0x9b,0x99,0x3a,0x1b,0xa1,0x18,0xcb,0x15,0x3f,0x56,0xdc,0xcb};
static unsigned checks;
#define CHECK(c) do {++checks;if(!(c)){fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#c);exit(1);}}while(0)
static void ci(unsigned char o[22],int strong,int stateful) {
 memset(o,0,22);o[0]=18;o[1]=6;o[2]=stateful?0:1;o[5]=strong?0x40:0x20;memcpy(o+6,master,16);
}
static void *newstate(unsigned char o[22],int receive) {
 const struct compressor *c=ppp_mppe_compressor();void *s=c->comp_alloc(o,22);CHECK(s!=NULL);
 CHECK(receive?c->decomp_init(s,o,6,0,0,16384,0):c->comp_init(s,o,6,0,0,0));return s;
}
static void packet(unsigned char *p,int length,unsigned id) {
 p[0]=255;p[1]=3;p[2]=0;p[3]=(id&1)?0x57:0x21;
 for(int i=4;i<length;i++)p[i]=(unsigned char)(i*13u+id*31u);
}
static void vectors(void) {
 static const unsigned char sessions[2][16]={
  {0xd1,0x26,0x9e,0xc4,0x9f,0xa6,0x2e,0x3e},
  {0x40,0x5c,0xb2,0x24,0x7a,0x79,0x56,0xe6,0xe2,0x11,0x00,0x7a,0xe2,0x7b,0x22,0xd4}};
 static const unsigned char ciphertext[2][12]={
  {0x92,0x91,0x37,0x91,0x7e,0x58,0x03,0xd6,0x68,0xd7,0x58,0x98},
  {0x81,0x84,0x83,0x17,0xdf,0x68,0x84,0x62,0x72,0xfb,0x5a,0xbe}};
 for(int strong=0;strong<2;strong++) {
  unsigned char o[22],actual[12];ci(o,strong,1);struct ppp_mppe_state *s=newstate(o,0);
  CHECK(memcmp(s->session_key,sessions[strong],s->keylen)==0);
  struct arc4_ctx cipher=s->arc4;arc4_crypt(&cipher,actual,(const unsigned char*)"test message",12);
  CHECK(memcmp(actual,ciphertext[strong],12)==0);mppe_free(s);
 }
 puts("PASS RFC3079 40/128 initial-session-key and ciphertext vectors");
}
static void streams(void) {
 const struct compressor*c=ppp_mppe_compressor();
 for(int strong=0;strong<2;strong++)for(int stateful=0;stateful<2;stateful++) {
  unsigned char o[22],p[16400],encrypted[16404],decoded[16404];ci(o,strong,stateful);
  void*tx=newstate(o,0);void*rx=newstate(o,1);
  for(unsigned i=0;i<5000;i++) {
   int n=(i==4000)?16388:20+(int)(i%1500);packet(p,n,i);
   int k=c->compress(tx,p,encrypted,n,sizeof(encrypted));CHECK(k==n+4);
   CHECK(encrypted[2]==0&&encrypted[3]==0xfd);CHECK((encrypted[4]&0x10)!=0);
   CHECK((((unsigned)encrypted[4]&15)<<8|encrypted[5])==(i&4095));
   int j=c->decompress(rx,encrypted,k,decoded,sizeof(decoded));CHECK(j==n);CHECK(memcmp(p,decoded,n)==0);
   if(i==123) {c->comp_reset(tx);c->comp_reset(tx);c->decomp_reset(rx);}
  }
  struct compstat st;c->comp_stat(tx,&st);CHECK(st.comp_packets==5000);
  c->comp_free(tx);c->decomp_free(rx);
 }
 puts("PASS 4 modes, 20000 packets, maximum-MRU, reset, periodic rekey and sequence wrap");
}
static void loss(void) {
 const struct compressor*c=ppp_mppe_compressor();
 for(int strong=0;strong<2;strong++)for(int stateful=0;stateful<2;stateful++) {
  unsigned char o[22],p[100],e[104],d[104];ci(o,strong,stateful);void*tx=newstate(o,0);void*rx=newstate(o,1);
  packet(p,100,0);int k=c->compress(tx,p,e,100,sizeof(e));CHECK(k==104);CHECK(c->decompress(rx,e,k,d,sizeof(d))==100);
  for(unsigned i=1;i<301;i++){packet(p,100,i);CHECK(c->compress(tx,p,e,100,sizeof(e))==104);}
  int got=c->decompress(rx,e,104,d,sizeof(d));
  if(!stateful)CHECK(got==100&&memcmp(p,d,100)==0);
  else {
   CHECK(got==DECOMP_ERROR);packet(p,100,301);CHECK(c->compress(tx,p,e,100,sizeof(e))==104);
   CHECK(c->decompress(rx,e,104,d,sizeof(d))==DECOMP_ERROR);
   c->comp_reset(tx);packet(p,100,302);CHECK(c->compress(tx,p,e,100,sizeof(e))==104);CHECK(e[4]&0x80);
   CHECK(c->decompress(rx,e,104,d,sizeof(d))==100);CHECK(memcmp(p,d,100)==0);
  }
  c->comp_free(tx);c->decomp_free(rx);
 }
 puts("PASS loss across rekey interval and stateful CCP reset recovery");
}
static void malformed(void) {
 const struct compressor*c=ppp_mppe_compressor();unsigned char o[22],bad[22],p[100],e[104],d[104];ci(o,1,0);
 for(int n=0;n<22;n++)CHECK(c->comp_alloc(o,n)==NULL);
 const unsigned char values[]={0,1,0x80,0x41,0x50};
 for(unsigned i=0;i<sizeof(values);i++){memcpy(bad,o,22);bad[5]=values[i];CHECK(c->comp_alloc(bad,22)==NULL);}
 memcpy(bad,o,22);bad[2]=2;CHECK(c->comp_alloc(bad,22)==NULL);
 memcpy(bad,o,22);bad[5]=0x60;void*probe=c->comp_alloc(bad,22);CHECK(probe!=NULL);
 CHECK(!c->comp_init(probe,bad,6,0,0,0));bad[5]=0x40;CHECK(c->comp_init(probe,bad,6,0,0,0));c->comp_free(probe);
 void*tx=newstate(o,0);void*rx=newstate(o,1);packet(p,100,0);
 for(int n=0;n<4;n++)CHECK(c->compress(tx,p,e,n,sizeof(e))<0);
 CHECK(c->compress(tx,p,e,100,103)<0);CHECK(c->compress(tx,NULL,e,100,104)<0);
 CHECK(c->compress(tx,p,e,INT_MAX,INT_MAX)<0);
 CHECK(c->compress(tx,p,e,100,sizeof(e))==104);
 for(int n=0;n<=6;n++)CHECK(c->decompress(rx,e,n,d,sizeof(d))<0);
 CHECK(c->decompress(rx,e,104,d,99)<0);
 unsigned char save=e[4];e[4]|=0x40;CHECK(c->decompress(rx,e,104,d,104)<0);e[4]=save;
 CHECK(c->decompress(rx,e,104,d,sizeof(d))==100);CHECK(memcmp(p,d,100)==0);
 c->comp_free(tx);c->decomp_free(rx);c->comp_free(NULL);
 /* Repeated invalid control bits reach the original Linux fatal threshold. */
 rx=newstate(o,1);e[4]&=(unsigned char)~0x10;
 for(unsigned i=0;i<15;i++)CHECK(c->decompress(rx,e,104,d,sizeof(d))==DECOMP_ERROR);
 CHECK(c->decompress(rx,e,104,d,sizeof(d))==DECOMP_FATALERROR);c->decomp_free(rx);
 puts("PASS truncated/unsupported/ambiguous inputs, capacities, no premature state mutation, fatal threshold");
}
int main(void) {vectors();streams();loss();malformed();printf("PASS %u assertions\n",checks);return 0;}
