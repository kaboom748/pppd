/* Native Windows/Linux-test host for the pinned pppd 2.5.5 FSM/LCP/IPCP.
 * PPP async framing is implemented here, independently from Linux kernel code.
 * All state belongs to one process and one event-loop thread. */
#include "engine.h"
#include "data_port.h"
#include "vendor/ppp/pppd-private.h"
#include "vendor/ppp/fsm.h"
#include "vendor/ppp/ccp.h"
#include "vendor/ppp/ccp_host.h"
#include "vendor/ppp/lcp.h"
#include "vendor/ppp/ipcp.h"
#include "vendor/ppp/core_extra.h"
#include "vendor/ppp/ipv6cp.h"
#include "vendor/ppp/upap.h"
#include "vendor/ppp/chap.h"
#include "vendor/ppp/eap.h"
#include "vendor/ppp/cbcp.h"
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

#define TIMER_CAP 64
#define RX_CAP (PPP_ENGINE_MAX_MRU+6)
#define FRAME_CAP PPP_ENGINE_MAX_WIRE
typedef struct Timer {void(*fn)(void*);void *arg;uint64_t at;int used;} Timer;
static struct {
 PppConfig config;PppOps ops;int initialized,started,up,up4,up6,dead,last_error,phase;
 int ncp4_finished,ncp6_finished,maxconnect_started,networks_started;
 uint64_t now;uint32_t last_tick;int tick_set;
 uint64_t last_data_tx,last_data_rx;
 uint64_t rx_data_frames;
 Timer timers[TIMER_CAP];
 uint8_t rx[RX_CAP];size_t rx_len;int escaped,discard,rx_started;
 uint32_t rx_accm,tx_accm;int rx_pfc,rx_acfc,tx_pfc,tx_acfc;
 uint16_t tx_limit,rx_limit,mtu;uint32_t local_ip,peer_ip,random;
 uint8_t local_id[8],peer_id[8];
 PppCounters counters;
} e;
unsigned char outpacket_buf[PPP_ENGINE_MAX_MRU+4];
int debug,listen_time=0;
int demand=0;
struct protent *protocols[]={&lcp_protent,&ipcp_protent,&ipv6cp_protent,&pap_protent,&chap_protent,&eap_protent,&cbcp_protent,&ccp_protent,NULL};
extern int lcp_echo_interval,lcp_echo_fails,lcp_loopbackfail;
extern bool lcp_echo_adaptive,usepeerdns,usepeerwins;
extern char *lcp_rtt_file;

static uint16_t fcs_step(uint16_t f,uint8_t b){
 f^=b;for(unsigned i=0;i<8;i++)f=(uint16_t)((f>>1)^((f&1)?0x8408:0));return f;
}
static void log_line(const char *fmt,...){
 if(!e.ops.log)return;
 char line[1024];va_list ap;va_start(ap,fmt);vsnprintf(line,sizeof(line),fmt,ap);va_end(ap);e.ops.log(e.ops.ctx,line);
}
/* Original auth.c connect_time_expired, retaining its close/status behavior. */
static void connect_time_expired(void *arg){
 (void)arg;info("Connect time expired");ppp_set_status(12);lcp_close(0,"Connect time expired");
}
/* Original auth.c check_idle decision, with host activity timestamps replacing
 * get_idle_time(/dev/ppp). LCP Echo/auth/control frames do not count as data. */
static void check_idle(void *arg){
 (void)arg;
 uint64_t itime=MIN(e.now-e.last_data_tx,e.now-e.last_data_rx)/1000;
 int64_t tlim=(int64_t)e.config.idle-(int64_t)itime;
 if(tlim<=0){notice("Terminating connection due to lack of activity.");ppp_set_status(11);lcp_close(0,"Link inactive");}
 else TIMEOUT(check_idle,NULL,(int)tlim);
}
/* Original utils.c formatter, ported with authentication, understands pppd's
 * %I/%B/%P/%v extensions. Never feed these diagnostic formats to CRT printf. */
static void upstream_log(const char *fmt,va_list ap){
 if(e.ops.log){char line[2048];vslprintf(line,sizeof(line),fmt,ap);e.ops.log(e.ops.ctx,line);}
}
void dbglog(const char *fmt,...){if(debug){va_list ap;va_start(ap,fmt);upstream_log(fmt,ap);va_end(ap);}}
void info(const char *fmt,...){va_list ap;va_start(ap,fmt);upstream_log(fmt,ap);va_end(ap);}
void notice(const char *fmt,...){va_list ap;va_start(ap,fmt);upstream_log(fmt,ap);va_end(ap);}
void warn(const char *fmt,...){va_list ap;va_start(ap,fmt);upstream_log(fmt,ap);va_end(ap);}
void error(const char *fmt,...){va_list ap;va_start(ap,fmt);upstream_log(fmt,ap);va_end(ap);}
void fatal(const char *fmt,...){va_list ap;va_start(ap,fmt);upstream_log(fmt,ap);va_end(ap);e.last_error=1;e.dead=1;}
char *ip_ntoa(uint32_t ip){static char b[16];const uint8_t*p=(const uint8_t*)&ip;snprintf(b,sizeof(b),"%u.%u.%u.%u",p[0],p[1],p[2],p[3]);return b;}
uint32_t magic(void){uint32_t x=e.random;x^=x<<13;x^=x>>17;x^=x<<5;e.random=x?x:0x47217b51;return e.random;}
const char *protocol_name(int p){return p==PPP_CCP?"CCP":p==PPP_COMP?"Compressed":p==PPP_LCP?"LCP":p==PPP_IPCP?"IPCP":p==PPP_IPV6CP?"IPv6CP":p==PPP_IP?"IPv4":p==PPP_IPV6?"IPv6":p==PPP_PAP?"PAP":p==PPP_CHAP?"CHAP":p==PPP_EAP?"EAP":p==PPP_CBCP?"CBCP":NULL;}
void new_phase(int p){e.phase=p;}
int in_phase(int p){return e.phase==p;}
void ppp_set_status(int s){e.last_error=s;}
void ppp_untimeout(void(*fn)(void*),void*arg){for(unsigned i=0;i<TIMER_CAP;i++)if(e.timers[i].used&&e.timers[i].fn==fn&&e.timers[i].arg==arg)e.timers[i].used=0;}
void ppp_timeout(void(*fn)(void*),void*arg,int sec,int usec){
 for(unsigned i=0;i<TIMER_CAP;i++)if(!e.timers[i].used){e.timers[i]=(Timer){fn,arg,e.now+(uint64_t)sec*1000+(unsigned)(usec+999)/1000,1};return;}
 e.last_error=1;e.dead=1;log_line("PPP timer capacity exhausted");
}
int ppp_send_config(int unit,int mtu,uint32_t accm,int pfc,int acfc){
 (void)unit;e.tx_limit=(uint16_t)MIN(mtu,(int)PPP_ENGINE_MAX_MRU);e.tx_accm=accm;e.tx_pfc=pfc;e.tx_acfc=acfc;return 0;
}
int ppp_recv_config(int unit,int mru,uint32_t accm,int pfc,int acfc){
 (void)unit;e.rx_limit=(uint16_t)MIN(mru,(int)PPP_ENGINE_MAX_MRU);e.rx_accm=accm;e.rx_pfc=pfc;e.rx_acfc=acfc;ppp_data_set_mru(e.rx_limit);return 0;
}
void ppp_set_mtu(int unit,int mtu){(void)unit;e.mtu=(uint16_t)MIN(mtu,e.config.mtu);}
int ppp_bad_ip_addr(uint32_t ip){uint32_t h=ntohl(ip);return !h||(h>>24)==127||(h>>28)>=14||h==0xffffffffu;}
void link_required(int unit){(void)unit;}
void link_established(int unit){
 log_line("LCP OPENED; entering authentication phase");
 e.phase=PHASE_AUTHENTICATE;ppp_auth_start(unit);
}
void continue_networks(int unit){
 if(e.networks_started||e.dead||e.phase==PHASE_TERMINATE)return;
 if(e.config.data.mppe_required&&!ppp_data_encrypted_ready())return;
 e.networks_started=1;
 e.ncp4_finished=e.config.ipv4_disabled;e.ncp6_finished=!e.config.ipv6_enabled;
 if(!e.config.ipv4_disabled){ipcp_protent.lowerup(unit);ipcp_protent.open(unit);}
 if(e.config.ipv6_enabled){ipv6cp_protent.lowerup(unit);ipv6cp_protent.open(unit);}
}
void ppp_engine_network_start(int unit){
 e.phase=PHASE_NETWORK;log_line("Authentication complete; starting network protocols");
 if(e.config.data.ccp_enabled){ccp_protent.lowerup(unit);ccp_protent.open(unit);}
 if(!e.config.data.mppe_required)continue_networks(unit);
}
int ppp_get_mtu(int unit){(void)unit;return MIN(e.config.mtu,e.tx_limit);}
static void report_down(void){
 if(e.up4){e.up4=0;if(e.ops.status)e.ops.status(e.ops.ctx,0,e.local_ip,e.peer_ip,e.mtu);}
 if(e.up6){e.up6=0;if(e.ops.status_ipv6)e.ops.status_ipv6(e.ops.ctx,0,e.local_id,e.peer_id,e.mtu);}
 e.up=0;
}
void link_down(int unit){
 UNTIMEOUT(connect_time_expired,NULL);UNTIMEOUT(check_idle,NULL);e.maxconnect_started=0;
 report_down();ccp_protent.lowerdown(unit);ccp_flags_set(unit,0,0);ppp_auth_lowerdown(unit);ipcp_protent.lowerdown(unit);ipv6cp_protent.lowerdown(unit);ppp_data_init(&e.config.data,e.config.mru,e.config.mtu);e.networks_started=0;e.phase=PHASE_ESTABLISH;
}
void link_terminated(int unit){(void)unit;report_down();e.dead=1;e.phase=PHASE_DEAD;log_line("PPP link terminated");}
int sifaddr(int unit,uint32_t local,uint32_t peer,uint32_t mask){
 (void)unit;(void)mask;if(!local||!peer)return 0;
 if(!e.config.ipcp_accept_local&&e.config.local_ip_be&&local!=e.config.local_ip_be)return 0;
 if(!e.config.ipcp_accept_remote&&e.config.peer_ip_be&&peer!=e.config.peer_ip_be)return 0;
 e.local_ip=local;e.peer_ip=peer;return 1;
}
int cifaddr(int unit,uint32_t local,uint32_t peer){(void)unit;(void)local;(void)peer;return 1;}
void np_up(int unit,int protocol){
 (void)unit;e.up=1;e.phase=PHASE_RUNNING;
 if(!e.maxconnect_started){e.maxconnect_started=1;e.last_data_tx=e.last_data_rx=e.now;
  if(e.config.maxconnect)TIMEOUT(connect_time_expired,NULL,(int)e.config.maxconnect);
  if(e.config.idle)TIMEOUT(check_idle,NULL,(int)e.config.idle);}
 if(protocol==PPP_IP){if(!ppp_data_vj_config(ipcp_gotoptions[unit].neg_vj?ipcp_gotoptions[unit].maxslotindex+1:0,ipcp_hisoptions[unit].neg_vj?ipcp_hisoptions[unit].maxslotindex+1:0,ipcp_hisoptions[unit].cflag)){lcp_close(unit,"VJ allocation failed");return;}e.up4=1;log_line("IPCP OPENED; IPv4 forwarding enabled");
  if(e.ops.status)e.ops.status(e.ops.ctx,1,e.local_ip,e.peer_ip,e.mtu);}
 else if(protocol==PPP_IPV6){e.up6=1;log_line("IPv6CP OPENED; IPv6 forwarding enabled");
  if(e.ops.status_ipv6)e.ops.status_ipv6(e.ops.ctx,1,e.local_id,e.peer_id,e.mtu);}
}
void np_down(int unit,int protocol){
 (void)unit;
 if(protocol==PPP_IP&&e.up4){ppp_data_vj_config(0,0,0);e.up4=0;if(e.ops.status)e.ops.status(e.ops.ctx,0,e.local_ip,e.peer_ip,e.mtu);}
 if(protocol==PPP_IPV6&&e.up6){e.up6=0;if(e.ops.status_ipv6)e.ops.status_ipv6(e.ops.ctx,0,e.local_id,e.peer_id,e.mtu);}
 e.up=e.up4||e.up6;
}
void np_finished(int unit,int protocol){
 if(protocol==PPP_IP)e.ncp4_finished=1;
 if(protocol==PPP_IPV6)e.ncp6_finished=1;
 if(e.ncp4_finished&&e.ncp6_finished&&!e.dead&&e.phase!=PHASE_TERMINATE)lcp_close(unit,"No network protocols running");
}
int get_ppp_stats(int unit,struct pppd_stats *s){
 (void)unit;if(!s)return 0;
 /* Linux PPP interface statistics count network data, not LCP/auth frames. */
 s->pkts_in=(unsigned)e.rx_data_frames;s->pkts_out=(unsigned)(e.counters.tx_ipv4+e.counters.tx_ipv6);return 1;
}
int ppp_core_monotonic(struct timespec *ts){ts->tv_sec=(time_t)(e.now/1000);ts->tv_nsec=(long)(e.now%1000)*1000000L;return 0;}
void ppp_core_network_parameters(const uint32_t *dns,const uint32_t *wins){if(e.ops.network_parameters)e.ops.network_parameters(e.ops.ctx,dns,wins);}
int ppp_core_sif6addr(int unit,eui64_t local,eui64_t peer){
 if(e.mtu<1280||e.tx_limit<1280||e.rx_limit<1280){
  log_line("IPv6CP cannot open: negotiated PPP MTU/MRU is below 1280");return 0;
 }
 (void)unit;if(eui64_iszero(local)||eui64_iszero(peer)||eui64_equals(local,peer)||!e.ops.status_ipv6)return 0;
 memcpy(e.local_id,local.e8,8);memcpy(e.peer_id,peer.e8,8);return 1;
}
int ppp_core_cif6addr(int unit){(void)unit;return 1;}

static int encode(const uint8_t *packet,size_t n){
 if(n<4||n>PPP_ENGINE_MAX_MRU+4||packet[0]!=255||packet[1]!=3)return -1;
 unsigned proto=((unsigned)packet[2]<<8)|packet[3];int lcp=proto==PPP_LCP;
 size_t start=(!lcp&&e.tx_acfc)?2:0;
 uint8_t body[RX_CAP],wire[FRAME_CAP];size_t bn=0,wn=0;
 for(size_t i=start;i<n;i++){
  if(i==2&&!lcp&&e.tx_pfc&&packet[2]==0)continue;
  body[bn++]=packet[i];
 }
 uint16_t fcs=0xffff;for(size_t i=0;i<bn;i++)fcs=fcs_step(fcs,body[i]);fcs^=0xffff;
 body[bn++]=(uint8_t)fcs;body[bn++]=(uint8_t)(fcs>>8);
 uint32_t accm=e.tx_accm;
 if(lcp&&n>=5&&packet[4]>=1&&packet[4]<=7)accm=0xffffffffu;
 wire[wn++]=0x7e;
 for(size_t i=0;i<bn;i++){
  uint8_t b=body[i];int escape=b==0x7d||b==0x7e||(b<32&&(accm&(1u<<b)))||(e.config.transmit_accm[b>>3]&(1u<<(b&7)));
  if(escape){if(wn+2>=sizeof(wire))return -1;wire[wn++]=0x7d;wire[wn++]=b^0x20;}
  else {if(wn+1>=sizeof(wire))return -1;wire[wn++]=b;}
 }
 wire[wn++]=0x7e;
 if(!e.ops.write_serial||e.ops.write_serial(e.ops.ctx,wire,wn)){e.counters.tx_dropped++;return -1;}
 if(proto==PPP_CCP)ppp_data_ccp_peek(packet+4,n-4,0);
 e.counters.tx_frames++;if(proto==PPP_IP){e.counters.tx_ipv4++;e.last_data_tx=e.now;}
 if(proto==PPP_IPV6){e.counters.tx_ipv6++;e.last_data_tx=e.now;}
 if(debug)log_line("PPP TX protocol=%04x code=%u id=%u information=%zu wire=%zu",proto,n>4?packet[4]:0,n>5?packet[5]:0,n-4,wn);
 return 0;
}
void output(int unit,uint8_t *packet,int n){(void)unit;if(n>=0&&encode(packet,(size_t)n))log_line("PPP control packet discarded: bounded serial queue full or invalid frame");}

static void decode_frame(void){
 size_t n=e.rx_len;if(n<3){if(n)e.counters.rx_invalid++;return;}
 uint16_t f=0xffff;for(size_t i=0;i<n;i++)f=fcs_step(f,e.rx[i]);
 if(f!=0xf0b8){ppp_data_loss();e.counters.rx_fcs_errors++;return;}n-=2;
 size_t pos=0;if(n>=2&&e.rx[0]==255&&e.rx[1]==3)pos=2;else if(!e.rx_acfc){e.counters.rx_invalid++;return;}
 if(pos>=n){e.counters.rx_invalid++;return;}
 uint16_t proto;
 if(e.rx[pos]&1){if(!e.rx_pfc){e.counters.rx_invalid++;return;}proto=e.rx[pos++];}
 else{if(pos+2>n||!(e.rx[pos+1]&1)){e.counters.rx_invalid++;return;}proto=(uint16_t)((e.rx[pos]<<8)|e.rx[pos+1]);pos+=2;}
 size_t info_len=n-pos;if(info_len>e.rx_limit||info_len>PPP_ENGINE_MAX_MRU){ppp_data_loss();e.counters.rx_oversize++;return;}
 uint8_t *payload=e.rx+pos;
 uint8_t normalized[PPP_ENGINE_MAX_MRU+4],decoded[PPP_ENGINE_MAX_MRU+4];
 e.counters.rx_frames++;
 if(debug)log_line("PPP RX protocol=%04x code=%u id=%u information=%zu",proto,info_len?payload[0]:0,info_len>1?payload[1]:0,info_len);
 if(proto<0x4000){
  if(e.phase<PHASE_NETWORK||e.phase>PHASE_RUNNING){e.counters.rx_dropped++;return;}
  normalized[0]=255;normalized[1]=3;normalized[2]=(uint8_t)(proto>>8);normalized[3]=(uint8_t)proto;memcpy(normalized+4,payload,info_len);
  int z=ppp_data_receive(normalized,info_len+4,decoded,sizeof(decoded));if(z<4){e.counters.rx_dropped++;return;}
  proto=(uint16_t)(((unsigned)decoded[2]<<8)|decoded[3]);if(proto>=0x4000||decoded[0]!=255||decoded[1]!=3){e.counters.rx_invalid++;return;}payload=decoded+4;info_len=(size_t)z-4;
 }
 if(proto==PPP_IP){
  if(!e.up4){e.counters.rx_dropped++;return;}
  if(info_len<20||(payload[0]>>4)!=4||((payload[0]&15)*4u)<20||((payload[0]&15)*4u)>info_len){e.counters.rx_invalid++;return;}
  size_t ip_len=((size_t)payload[2]<<8)|payload[3];
  if(ip_len<(payload[0]&15)*4u||ip_len>info_len){e.counters.rx_invalid++;return;}
  e.last_data_rx=e.now;e.rx_data_frames++;
  if(e.ops.receive_ip&&e.ops.receive_ip(e.ops.ctx,payload,ip_len)==0)e.counters.rx_ipv4++;else e.counters.rx_dropped++;
  return;
 }
 if(proto==PPP_IPV6){
  if(!e.up6){e.counters.rx_dropped++;return;}
  if(info_len<40||(payload[0]>>4)!=6){e.counters.rx_invalid++;return;}
  size_t ip_len=40+(((size_t)payload[4]<<8)|payload[5]);
  if(ip_len>info_len){e.counters.rx_invalid++;return;}
  e.last_data_rx=e.now;e.rx_data_frames++;
  if(e.ops.receive_ip&&e.ops.receive_ip(e.ops.ctx,payload,ip_len)==0)e.counters.rx_ipv6++;else e.counters.rx_dropped++;
  return;
 }
 if(proto==PPP_LCP||proto==PPP_IPCP||proto==PPP_IPV6CP||proto==PPP_PAP||proto==PPP_CHAP||proto==PPP_EAP||proto==PPP_CBCP||proto==PPP_CCP){
  if(info_len<4||(((unsigned)payload[2]<<8)|payload[3])<4||(((unsigned)payload[2]<<8)|payload[3])>info_len){e.counters.rx_invalid++;return;}
  if(proto==PPP_CCP&&!e.config.data.ccp_enabled)goto unsupported;
  if(proto==PPP_LCP)lcp_protent.input(0,payload,(int)info_len);
  else if(lcp_fsm[0].state==OPENED){
   if((proto==PPP_IPCP&&e.config.ipv4_disabled)||(proto==PPP_IPV6CP&&!e.config.ipv6_enabled))goto unsupported;
   if(proto==PPP_CCP&&e.phase>=PHASE_NETWORK&&e.phase<=PHASE_RUNNING){ppp_data_ccp_peek(payload,info_len,1);ccp_protent.input(0,payload,(int)info_len);}
   else if(proto==PPP_IPCP&&!e.config.ipv4_disabled&&e.phase>=PHASE_NETWORK&&e.phase<=PHASE_RUNNING)ipcp_protent.input(0,payload,(int)info_len);
   else if(proto==PPP_IPV6CP&&e.config.ipv6_enabled&&e.phase>=PHASE_NETWORK&&e.phase<=PHASE_RUNNING)ipv6cp_protent.input(0,payload,(int)info_len);
   else if(proto==PPP_PAP||proto==PPP_CHAP||proto==PPP_EAP||proto==PPP_CBCP){
    if(!ppp_auth_dispatch(proto,payload,(int)info_len))goto unsupported;
   }
  }
  return;
 }
unsupported:
 if(lcp_fsm[0].state==OPENED){
  normalized[0]=255;normalized[1]=3;normalized[2]=(uint8_t)(proto>>8);normalized[3]=(uint8_t)proto;
  memcpy(normalized+4,payload,info_len);lcp_sprotrej(0,normalized,(int)info_len+4);
 }
}
void ppp_engine_serial_input(const uint8_t *bytes,size_t length){
 if(!e.initialized||e.dead)return;
 for(size_t i=0;i<length;i++){
  uint8_t b=bytes[i];
  if(b==0x7e){
   if(e.rx_started&&!e.discard&&!e.escaped)decode_frame();else if(e.escaped){ppp_data_loss();e.counters.rx_invalid++;}
   e.rx_started=1;e.rx_len=0;e.discard=0;e.escaped=0;continue;
  }
  if(!e.rx_started||e.discard)continue;
  if(b<32&&(e.rx_accm&(1u<<b)))continue; /* Raw ACCM filtering must preserve ESC state. */
  if(e.escaped){b^=0x20;e.escaped=0;}else if(b==0x7d){e.escaped=1;continue;}
  if(e.rx_len==sizeof(e.rx)){ppp_data_loss();e.discard=1;e.counters.rx_oversize++;continue;}
  e.rx[e.rx_len++]=b;
 }
}
int ppp_engine_init(const PppConfig *config,const PppOps *ops){
 if(!config||!ops||!ops->write_serial||config->mru<128||config->mru>PPP_ENGINE_MAX_MRU||config->mtu<128||config->mtu>PPP_ENGINE_MAX_MRU)return -1;
 if(config->ipv4_disabled&&!config->ipv6_enabled)return -1;
 if(config->ipv6_enabled&&(config->mtu<1280||config->mru<1280||!ops->status_ipv6))return -1;
 if(e.initialized)return -1;
 memset(&e,0,sizeof(e));e.config=*config;e.ops=*ops;e.initialized=1;e.dead=1;
 e.random=0x92a41b37u^config->local_ip_be^config->peer_ip_be^(uint32_t)(uintptr_t)&e^(uint32_t)time(NULL)^(uint32_t)clock();
#ifdef _WIN32
 e.random^=GetCurrentProcessId()^GetTickCount();
#else
 e.random^=(uint32_t)getpid();
#endif
 e.local_ip=config->local_ip_be;e.peer_ip=config->peer_ip_be;e.mtu=config->mtu;e.tx_limit=config->mtu;e.rx_limit=config->mru;e.rx_accm=e.tx_accm=0xffffffffu;debug=config->debug;
 ppp_data_init(&config->data,config->mru,config->mtu);
 memset(ccp_fsm,0,sizeof(fsm));memset(lcp_fsm,0,sizeof(fsm));memset(ipcp_fsm,0,sizeof(fsm));memset(ipv6cp_fsm,0,sizeof(fsm));
 PppAuthConfig auth_config=config->auth;auth_config.peer_ip_be=config->peer_ip_be;
 if(ppp_auth_configure(&auth_config)){e.initialized=0;return -1;}
 ppp_auth_init();lcp_protent.init(0);ipcp_protent.init(0);ipv6cp_protent.init(0);ccp_protent.init(0);
 ccp_protent.enabled_flag=config->data.ccp_enabled;
 require_mppe=config->data.mppe_required;refuse_mppe_stateful=!config->data.mppe_stateful;
 ccp_wantoptions[0].bsd_compress=config->data.bsd_receive_bits!=0;ccp_wantoptions[0].bsd_bits=config->data.bsd_receive_bits;
 ccp_allowoptions[0].bsd_compress=config->data.bsd_allow_bits!=0;ccp_allowoptions[0].bsd_bits=config->data.bsd_allow_bits;
 ccp_wantoptions[0].deflate=config->data.deflate_receive_bits!=0;ccp_wantoptions[0].deflate_size=config->data.deflate_receive_bits;
 ccp_allowoptions[0].deflate=config->data.deflate_allow_bits!=0;ccp_allowoptions[0].deflate_size=config->data.deflate_allow_bits;
 ccp_wantoptions[0].deflate_correct=ccp_allowoptions[0].deflate_correct=config->data.deflate_correct;
 ccp_wantoptions[0].deflate_draft=ccp_allowoptions[0].deflate_draft=config->data.deflate_draft;
 ccp_wantoptions[0].mppe=require_mppe?((config->data.mppe_allow_40?1:0)|(config->data.mppe_allow_128?2:0)):0;
 if(config->data.ccp_timeout)ccp_fsm[0].timeouttime=(int)config->data.ccp_timeout;
 if(config->data.ccp_max_configure)ccp_fsm[0].maxconfreqtransmits=(int)config->data.ccp_max_configure;
 if(config->data.ccp_max_terminate)ccp_fsm[0].maxtermtransmits=(int)config->data.ccp_max_terminate;
 if(config->data.ccp_max_failure)ccp_fsm[0].maxnakloops=(int)config->data.ccp_max_failure;
 ipcp_protent.enabled_flag=!config->ipv4_disabled;ipv6cp_protent.enabled_flag=config->ipv6_enabled;
 lcp_wantoptions[0].mru=config->mru;lcp_wantoptions[0].asyncmap=config->receive_accm;
 lcp_allowoptions[0].mru=config->mtu;lcp_allowoptions[0].neg_lqr=0;lcp_allowoptions[0].neg_cbcp=0;auth_reset(0);
 lcp_wantoptions[0].passive=config->passive;lcp_wantoptions[0].silent=config->silent;
 lcp_wantoptions[0].neg_accompression=lcp_allowoptions[0].neg_accompression=!config->noaccomp;
 lcp_wantoptions[0].neg_pcompression=lcp_allowoptions[0].neg_pcompression=!config->nopcomp;
 lcp_wantoptions[0].neg_magicnumber=lcp_allowoptions[0].neg_magicnumber=!config->nomagic;
 if(config->asyncmap_disabled){lcp_wantoptions[0].neg_asyncmap=lcp_allowoptions[0].neg_asyncmap=0;lcp_wantoptions[0].asyncmap=0xffffffffu;}
 if(config->default_mru){lcp_wantoptions[0].neg_mru=lcp_allowoptions[0].neg_mru=0;lcp_wantoptions[0].mru=1500;}
 extern bool lax_recv;lax_recv=config->receive_all;
 lcp_echo_interval=(int)config->echo_interval;lcp_echo_fails=(int)config->echo_failure;lcp_echo_adaptive=config->echo_adaptive;
 lcp_rtt_file=e.config.rtt_file[0]?e.config.rtt_file:NULL;
 lcp_loopbackfail=config->lcp_loopback_failure?(int)config->lcp_loopback_failure:DEFLOOPBACKFAIL;
 if(config->lcp_timeout)lcp_fsm[0].timeouttime=(int)config->lcp_timeout;
 if(config->lcp_max_configure)lcp_fsm[0].maxconfreqtransmits=(int)config->lcp_max_configure;
 if(config->lcp_max_terminate)lcp_fsm[0].maxtermtransmits=(int)config->lcp_max_terminate;
 if(config->lcp_max_failure)lcp_fsm[0].maxnakloops=(int)config->lcp_max_failure;
 ipcp_wantoptions[0].neg_vj=ipcp_allowoptions[0].neg_vj=config->data.vj_enabled;
 ipcp_wantoptions[0].maxslotindex=ipcp_allowoptions[0].maxslotindex=(unsigned char)(config->data.vj_slots?config->data.vj_slots-1:15);
 ipcp_wantoptions[0].cflag=ipcp_allowoptions[0].cflag=config->data.vj_cid;
 ipcp_wantoptions[0].ouraddr=config->local_ip_be;ipcp_wantoptions[0].hisaddr=config->peer_ip_be;
 ipcp_wantoptions[0].old_addrs=!config->ipcp_no_addresses;ipcp_allowoptions[0].old_addrs=!config->ipcp_no_addresses;
 ipcp_wantoptions[0].neg_addr=!config->ipcp_no_address;ipcp_allowoptions[0].neg_addr=!config->ipcp_no_address;
 ipcp_wantoptions[0].accept_local=config->ipcp_accept_local||!config->local_ip_be;
 ipcp_wantoptions[0].accept_remote=config->ipcp_accept_remote||!config->peer_ip_be;
 usepeerdns=config->usepeerdns;usepeerwins=config->usepeerwins;
 memcpy(ipcp_allowoptions[0].dnsaddr,config->dns,sizeof(config->dns));memcpy(ipcp_allowoptions[0].winsaddr,config->wins,sizeof(config->wins));
 if(config->ipcp_timeout)ipcp_fsm[0].timeouttime=(int)config->ipcp_timeout;
 if(config->ipcp_max_configure)ipcp_fsm[0].maxconfreqtransmits=(int)config->ipcp_max_configure;
 if(config->ipcp_max_terminate)ipcp_fsm[0].maxtermtransmits=(int)config->ipcp_max_terminate;
 if(config->ipcp_max_failure)ipcp_fsm[0].maxnakloops=(int)config->ipcp_max_failure;
 memcpy(ipv6cp_wantoptions[0].ourid.e8,config->ipv6_local_id,8);memcpy(ipv6cp_wantoptions[0].hisid.e8,config->ipv6_peer_id,8);
 if(config->ipv6_use_ipaddr){
  if(eui64_iszero(ipv6cp_wantoptions[0].ourid)&&config->local_ip_be)eui64_set32(ipv6cp_wantoptions[0].ourid,ntohl(config->local_ip_be));
  if(eui64_iszero(ipv6cp_wantoptions[0].hisid)&&config->peer_ip_be)eui64_set32(ipv6cp_wantoptions[0].hisid,ntohl(config->peer_ip_be));}
 ipv6cp_wantoptions[0].opt_local=!eui64_iszero(ipv6cp_wantoptions[0].ourid);ipv6cp_wantoptions[0].opt_remote=!eui64_iszero(ipv6cp_wantoptions[0].hisid);
 ipv6cp_wantoptions[0].accept_local=config->ipv6_accept_local;ipv6cp_wantoptions[0].accept_remote=config->ipv6_accept_remote;
 ipv6cp_wantoptions[0].neg_ifaceid=!config->ipv6_no_send;
 if(config->ipv6cp_timeout)ipv6cp_fsm[0].timeouttime=(int)config->ipv6cp_timeout;
 if(config->ipv6cp_max_configure)ipv6cp_fsm[0].maxconfreqtransmits=(int)config->ipv6cp_max_configure;
 if(config->ipv6cp_max_terminate)ipv6cp_fsm[0].maxtermtransmits=(int)config->ipv6cp_max_terminate;
 if(config->ipv6cp_max_failure)ipv6cp_fsm[0].maxnakloops=(int)config->ipv6cp_max_failure;
 return 0;
}
int ppp_engine_start(void){if(!e.initialized||e.started)return -1;e.started=1;e.dead=0;e.phase=PHASE_ESTABLISH;lcp_open(0);lcp_lowerup(0);return e.last_error?-1:0;}
void ppp_engine_poll(uint32_t now_ms){
 if(!e.initialized)return;
 if(ppp_data_fault()&&!e.dead&&e.phase!=PHASE_TERMINATE){e.last_error=10;lcp_close(0,"PPP data codec failure");}
 if(!e.tick_set){e.last_tick=now_ms;e.tick_set=1;}else{e.now+=(uint32_t)(now_ms-e.last_tick);e.last_tick=now_ms;}
 for(unsigned steps=0;steps<128&&!e.dead;steps++){
  int found=-1;for(unsigned i=0;i<TIMER_CAP;i++)if(e.timers[i].used&&e.timers[i].at<=e.now&&(found<0||e.timers[i].at<e.timers[found].at))found=(int)i;
  if(found<0)break;
  Timer t=e.timers[found];e.timers[found].used=0;t.fn(t.arg);
 }
}
int ppp_engine_send_ipv4(const uint8_t *bytes,size_t length){
 if(!e.up4||!bytes||length<20||length>e.mtu||length>e.tx_limit||length>PPP_ENGINE_MAX_MRU||(bytes[0]>>4)!=4||(bytes[0]&15)<5||(size_t)(bytes[0]&15)*4>length||(((size_t)bytes[2]<<8)|bytes[3])!=length)return -1;
 uint8_t packet[PPP_ENGINE_MAX_MRU+4]={255,3,0,0x21};memcpy(packet+4,bytes,length);uint8_t transformed[PPP_ENGINE_MAX_MRU+4];int z=ppp_data_send(packet,length+4,transformed,sizeof(transformed));if(z<4)return -1;int r=encode(transformed,(size_t)z);if(!r){e.last_data_tx=e.now;if(transformed[3]!=0x21)e.counters.tx_ipv4++;}return r;
}
int ppp_engine_send_ip(const uint8_t *bytes,size_t length){
 if(!bytes||!length)return -1;
 if((bytes[0]>>4)==4)return ppp_engine_send_ipv4(bytes,length);
 if(!e.up6||length<40||length>e.mtu||length>e.tx_limit||length>PPP_ENGINE_MAX_MRU||(bytes[0]>>4)!=6||40+(((size_t)bytes[4]<<8)|bytes[5])!=length)return -1;
 uint8_t packet[PPP_ENGINE_MAX_MRU+4]={255,3,0,0x57};memcpy(packet+4,bytes,length);uint8_t transformed[PPP_ENGINE_MAX_MRU+4];int z=ppp_data_send(packet,length+4,transformed,sizeof(transformed));if(z<4)return -1;int r=encode(transformed,(size_t)z);if(!r){e.last_data_tx=e.now;if(transformed[3]!=0x57)e.counters.tx_ipv6++;}return r;
}
void ppp_engine_close(void){if(e.initialized&&!e.dead)lcp_close(0,"User request");}
void ppp_engine_destroy(void){
 if(!e.initialized)return;
 lcp_lowerdown(0);ppp_auth_lowerdown(0);report_down();
 memset(e.timers,0,sizeof(e.timers));ppp_explicit_bzero(&e.config.auth,sizeof(e.config.auth));
 ppp_data_destroy();e.initialized=0;e.dead=1;e.started=0;
}
int ppp_engine_is_up(void){return e.up;}
int ppp_engine_is_dead(void){return e.dead;}
int ppp_engine_last_error(void){return e.last_error;}
void ppp_engine_get_counters(PppCounters *out){if(out)*out=e.counters;}
