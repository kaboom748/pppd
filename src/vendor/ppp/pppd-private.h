/* Minimal Windows host contract for the retained pppd 2.5.5 negotiation code.
 * No Unix file descriptors, authentication engines, scripts or IP stack. */
#ifndef PPP_PPPD_PRIVATE_H
#define PPP_PPPD_PRIVATE_H
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "pppdconf.h"
#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif
typedef unsigned char u_char;
typedef unsigned short u_short;
typedef unsigned int u_int;
typedef uint32_t u_int32_t;
/* Avoid collisions with libc's unrelated error(3)/warn(3) in native tests. */
#define error ppp_core_error
#define warn ppp_core_warn
#define info ppp_core_info
#define notice ppp_core_notice
#define fatal ppp_core_fatal
#define dbglog ppp_core_dbglog
#define NUM_PPP 1
#define PPP_HDRLEN 4
#define PPP_MRU 1500
#define PPP_MTU 1500
#define PPP_ALLSTATIONS 0xff
#define PPP_UI 3
#define PPP_IP 0x21
#define PPP_IPV6 0x0057
#define PPP_LCP 0xc021
#define PPP_IPCP 0x8021
#define PPP_LQR 0xc025
#define PPP_PAP 0xc023
#define PPP_CHAP 0xc223
#define PPP_EAP 0xc227
#define PPP_CBCP 0xc029
#define PPP_MP 0x003d
#define PPP_CCP 0x80fd
#define PPP_COMP 0xfd
#define MAXNAMELEN 256
#define EXIT_NEGOTIATION_FAILED 10
#define EXIT_PEER_DEAD 15
#define EXIT_LOOPBACK 17
#define PHASE_DEAD 0
#define PHASE_ESTABLISH 4
#define PHASE_NETWORK 7
#define PHASE_RUNNING 8
#define PHASE_TERMINATE 9
#define PHASE_MASTER 12
#ifndef MIN
#define MIN(a,b) ((a)<(b)?(a):(b))
#endif
#ifndef MAX
#define MAX(a,b) ((a)>(b)?(a):(b))
#endif
#define GETCHAR(c,p) do{(c)=*(p)++;}while(0)
#define PUTCHAR(c,p) do{*(p)++=(u_char)(c);}while(0)
#define GETSHORT(s,p) do{(s)=*(p)++<<8;(s)|=*(p)++;}while(0)
#define PUTSHORT(s,p) do{*(p)++=(u_char)((s)>>8);*(p)++=(u_char)(s);}while(0)
#define GETLONG(s,p) do{(s)=(uint32_t)*(p)++<<24;(s)|=(uint32_t)*(p)++<<16;(s)|=(uint32_t)*(p)++<<8;(s)|=*(p)++;}while(0)
#define PUTLONG(s,p) do{*(p)++=(u_char)((s)>>24);*(p)++=(u_char)((s)>>16);*(p)++=(u_char)((s)>>8);*(p)++=(u_char)(s);}while(0)
#define INCPTR(n,p) ((p)+=(n))
#define DECPTR(n,p) ((p)-=(n))
#define BCOPY(s,d,n) memmove(d,s,n)
#define BZERO(s,n) memset(s,0,n)
#define BCMP(a,b,n) memcmp(a,b,n)
#define MAKEHEADER(p,t) do{PUTCHAR(PPP_ALLSTATIONS,p);PUTCHAR(PPP_UI,p);PUTSHORT(t,p);}while(0)
#define TIMEOUT(r,a,t) ppp_timeout(r,a,t,0)
#define UNTIMEOUT(r,a) ppp_untimeout(r,a)
#define FSMDEBUG(x) do{if(debug)dbglog x;}while(0)
#define LCPDEBUG(x) do{if(debug)dbglog x;}while(0)
#define IPCPDEBUG(x) do{if(debug)dbglog x;}while(0)
#define PRINTMSG(m,l) do{(void)(m);(void)(l);}while(0)
struct protent {
 unsigned short protocol; void(*init)(int);void(*input)(int,u_char*,int);
 void(*protrej)(int);void(*lowerup)(int);void(*lowerdown)(int);void(*open)(int);void(*close)(int,char*);
 int(*printpkt)(u_char*,int,void(*)(void*,char*,...),void*);void(*datainput)(int,u_char*,int);
 bool enabled_flag;char *name,*data_name;void *options;void(*check_options)(void);int(*demand_conf)(int);int(*active_pkt)(u_char*,int);
};
extern struct protent *protocols[];
extern unsigned char outpacket_buf[];
/* Values for auth_pending, auth_done */
#define PAP_WITHPEER	0x1
#define PAP_PEER	0x2
#define CHAP_WITHPEER	0x4
#define CHAP_PEER	0x8
#define EAP_WITHPEER	0x10
#define EAP_PEER	0x20

/* Values for auth_done only */
#define CHAP_MD5_WITHPEER	0x40
#define CHAP_MD5_PEER		0x80
#define CHAP_MS_SHIFT		8	/* LSB position for MS auths */
#define CHAP_MS_WITHPEER	0x100
#define CHAP_MS_PEER		0x200
#define CHAP_MS2_WITHPEER	0x400
#define CHAP_MS2_PEER		0x800



extern int auth_done[NUM_PPP];
extern int debug,listen_time;
extern bool multilink;
void output(int,u_char*,int);
void ppp_timeout(void(*)(void*),void*,int,int);
void ppp_untimeout(void(*)(void*),void*);
int ppp_send_config(int,int,uint32_t,int,int);
int ppp_recv_config(int,int,uint32_t,int,int);
void ppp_set_mtu(int,int);
void link_established(int);
void link_down(int);
void link_required(int);
void link_terminated(int);
void auth_reset(int);
int auth_ip_addr(int,uint32_t);
int ppp_bad_ip_addr(uint32_t);
void np_up(int,int);
void np_down(int,int);
void np_finished(int,int);
int sifaddr(int,uint32_t,uint32_t,uint32_t);
int cifaddr(int,uint32_t,uint32_t);
uint32_t magic(void);
const char *protocol_name(int);
int in_phase(int);
void new_phase(int);
void ppp_set_status(int);
void dbglog(const char*,...);
void info(const char*,...);
void notice(const char*,...);
void warn(const char*,...);
void error(const char*,...);
void fatal(const char*,...);
int slprintf(char*,int,const char*,...);
int vslprintf(char*,int,const char*,va_list);
size_t strlcpy(char*,const char*,size_t);
size_t strlcat(char*,const char*,size_t);
void print_string(char*,int,void(*)(void*,char*,...),void*);
#define MAXWORDLEN 1024
#define MAXSECRETLEN 256
#define PHASE_AUTHENTICATE 5
#define EXIT_PEER_AUTH_FAILED 11
#define EXIT_AUTH_TOPEER_FAILED 19
#define EXIT_CALLBACK 14
#define UPAPDEBUG(x) do { if(debug)dbglog x; } while(0)
typedef void (*printer_func)(void*,char*,...);
struct wordlist { struct wordlist *next; char *word; };
extern char user[MAXNAMELEN],passwd[MAXSECRETLEN],our_name[MAXNAMELEN],remote_name[MAXNAMELEN];
extern bool explicit_remote,session_mgmt,persist,auth_required;
extern char devnam[];
extern char remote_number[];
void auth_peer_fail(int,int);
void auth_peer_success(int,int,int,char*,int);
void auth_withpeer_fail(int,int);
void auth_withpeer_success(int,int,int);
int check_passwd(int,char*,int,char*,int,char**);
int get_secret(int,char*,char*,char*,int*,int);
int auth_number(void);
void ppp_explicit_bzero(void*,size_t);
void novm(const char*);
double ppp_auth_drand48(void);
#define drand48 ppp_auth_drand48
void start_networks(int);
#if defined(PPP_WITH_EAPTLS) || defined(PPP_WITH_PEAP)
#define TLS_VERIFY_NONE "none"
#define TLS_VERIFY_NAME "name"
#define TLS_VERIFY_SUBJECT "subject"
#define TLS_VERIFY_SUFFIX "suffix"
extern char *crl_dir,*crl_file,*ca_path,*cacert_file,*max_tls_version,*tls_verify_method,*pkcs12_file;
extern bool tls_verify_key_usage;
extern char tls_key_password[MAXSECRETLEN];
#endif
char *ip_ntoa(uint32_t);
#endif
