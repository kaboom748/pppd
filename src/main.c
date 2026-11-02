/* Native Windows PPP launcher and per-process owner. See LICENSES/ upstream notices. */
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0602
#include <winsock2.h>
#include <windows.h>
#include <sddl.h>
#include <bcrypt.h>
#include <objbase.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <wchar.h>
#include <io.h>
#include <fcntl.h>
#include "options.h"
#include "engine.h"
#include "platform_win.h"

#define VERSION "0.4.0"
#define IPC_MAGIC 0x50505057u
#define FRAME_CAP PPP_ENGINE_MAX_WIRE
typedef struct Identity { DWORD pid; FILETIME created; GUID uuid; char guid[40]; } Identity;
typedef struct Message { uint32_t magic,version,command,status; Identity identity; int exit_code; char code[64],detail[768]; } Message;
_Static_assert(sizeof(Message)<=4096,"IPC messages must remain bounded to 4 KiB");
typedef struct Frame { size_t size; unsigned char bytes[FRAME_CAP]; } Frame;
typedef struct Queue { Frame frame[32]; unsigned head,count,limit; uint64_t drops; } Queue;
typedef struct Control { HANDLE pipe,event; OVERLAPPED ov; int phase,waiting,stop_client; Message request; Identity identity; } Control;
typedef struct Runtime {
 AppOptions options; WinPort *port; WinTun *tun; Queue control,data;
 HANDLE stop,link_lock,if_lock,com_lock; Control ipc; Identity identity;
 int core_active,sending_data,link_ready,ip_pending,remove_ip_pending,ip_up,fatal,closing;
 uint32_t local_ip,peer_ip; uint16_t mtu;
 int ip6_up,ip6_pending,remove_ip6_pending,link6_ready,dns_pending;
 uint8_t ipv6_local[8],ipv6_peer[8]; uint32_t dns[2],wins[2];
 uint64_t ip_tx,ip_rx,ip_drop,serial_tx,serial_rx; FILE *journal;
 uint64_t failed_attempts;
 PppCounters ppp_total; ULONGLONG stats_at;
} Runtime;
static HANDLE console_stop;
static volatile LONG accelerated_close;
static FILE *journal;
static char last_error_code[64]="E_INTERNAL";
static char last_error_detail[2048]="Erreur interne";

static void json_string(FILE *f,const char *s) {
 fputc('"',f); unsigned count=0;
 for(;*s && count<1800;s++,count++) { unsigned char c=(unsigned char)*s;
  unsigned width=c>=0xf0?4:c>=0xe0?3:c>=0xc0?2:1;if(count+width>1800)break;
  if(c=='"'||c=='\\') { fputc('\\',f);fputc(c,f); }
  else if(c<32) fprintf(f,"\\u%04x",c); else fputc(c,f);
 } fputc('"',f);
}
static void record(const char *level,const char *code,int result,const char *message) {
 if(!strcmp(level,"ERROR")){snprintf(last_error_code,sizeof(last_error_code),"%s",code);snprintf(last_error_detail,sizeof(last_error_detail),"%s",message);}
 FILE *targets[2]={stderr,journal};
 for(unsigned i=0;i<2;i++) if(targets[i] && (i==0 || targets[i]!=targets[0])) {
  FILE *f=targets[i]; fputs("{\"level\":",f);json_string(f,level);
  fputs(",\"code\":",f);json_string(f,code); if(result>=0)fprintf(f,",\"exit\":%d",result);
  fputs(",\"message\":",f);json_string(f,message); fputs("}\n",f);fflush(f);
 }
}
static int error(const char *code,int result,const char *message) {record("ERROR",code,result,message);return result;}
static BOOL WINAPI on_console(DWORD type) {
 if(type==CTRL_C_EVENT||type==CTRL_BREAK_EVENT||type==CTRL_CLOSE_EVENT||type==CTRL_SHUTDOWN_EVENT||type==CTRL_LOGOFF_EVENT) {
  if(type!=CTRL_C_EVENT&&type!=CTRL_BREAK_EVENT)InterlockedExchange(&accelerated_close,1);
  if(console_stop)SetEvent(console_stop);
  /* CTRL_CLOSE terminates the process after this handler returns. Give the
     owner loop a bounded interval, leaving cleanup in its own thread. */
  if(type==CTRL_CLOSE_EVENT)Sleep(4500);
  return TRUE;
 } return FALSE;
}
static wchar_t *to_wide(const char *s) {
 int n=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,s,-1,NULL,0);
 if(!n)return NULL; wchar_t *w=calloc((size_t)n,sizeof(*w));
 if(w)MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,s,-1,w,n); return w;
}
static char *to_utf8(const wchar_t *s) {
 int n=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,s,-1,NULL,0,NULL,NULL);
 if(!n)return NULL;char *b=malloc((size_t)n);
 if(b)WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,s,-1,b,n,NULL,NULL);return b;
}
static int elevated(void) {
 HANDLE token;TOKEN_ELEVATION e;DWORD n;
 if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token))return 0;
 int ok=GetTokenInformation(token,TokenElevation,&e,sizeof(e),&n)&&e.TokenIsElevated;
 CloseHandle(token);return ok;
}
static int security(SECURITY_ATTRIBUTES *sa,PSECURITY_DESCRIPTOR *sd) {
 HANDLE token=NULL;DWORD n=0;TOKEN_USER *u=NULL;LPWSTR sid=NULL;wchar_t acl[512];int ok=0;
 if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token))goto done;
 GetTokenInformation(token,TokenUser,NULL,0,&n);u=malloc(n);
 if(!u||!GetTokenInformation(token,TokenUser,u,n,&n)||!ConvertSidToStringSidW(u->User.Sid,&sid))goto done;
 if(swprintf(acl,512,L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;%ls)",sid)<0)goto done;
 if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(acl,SDDL_REVISION_1,sd,NULL))goto done;
 sa->nLength=sizeof(*sa);sa->lpSecurityDescriptor=*sd;sa->bInheritHandle=FALSE;ok=1;
done: if(sid)LocalFree(sid);free(u);if(token)CloseHandle(token);return ok;
}
static void lower_ascii(char *s) {for(;*s;s++)if(*s>='A'&&*s<='Z')*s=(char)(*s+32);}
static int key_for(const AppOptions *o,char hex[65]) {
 /* Portable instances have one machine-wide linkname namespace. Their IPC
    identity never depends on current directory, executable location, or an
    optional file root lazily used by call/file. */
 wchar_t *root=to_wide(o->config_explicit?o->config_dir:"pppd-portable-v1"); if(!root)return -1;
 /* Invariant Unicode case folding makes roots/identities insensitive to case. */
 size_t n=wcslen(root);CharLowerBuffW(root,(DWORD)n);
 char name[64];snprintf(name,sizeof(name),"%s",o->linkname);lower_ascii(name);
 BCRYPT_ALG_HANDLE alg=NULL;BCRYPT_HASH_HANDLE hash=NULL;UCHAR digest[32];int rc=-1;
 if(BCryptOpenAlgorithmProvider(&alg,BCRYPT_SHA256_ALGORITHM,NULL,0)<0)goto done;
 if(BCryptCreateHash(alg,&hash,NULL,0,NULL,0,0)<0)goto done;
 if(BCryptHashData(hash,(PUCHAR)root,(ULONG)(n*sizeof(wchar_t)),0)<0)goto done;
 UCHAR separator[2]={0,0};if(BCryptHashData(hash,separator,2,0)<0)goto done;
 if(BCryptHashData(hash,(PUCHAR)name,(ULONG)strlen(name),0)<0||BCryptFinishHash(hash,digest,32,0)<0)goto done;
 for(unsigned i=0;i<32;i++)sprintf(hex+2*i,"%02x",digest[i]);hex[64]=0;rc=0;
done: if(hash)BCryptDestroyHash(hash);if(alg)BCryptCloseAlgorithmProvider(alg,0);free(root);return rc;
}
static HANDLE reserve(const char *category,const char *identity,SECURITY_ATTRIBUTES *sa) {
 char name[256];snprintf(name,sizeof(name),"Global\\pppd-%s-%s",category,identity);lower_ascii(name+7);
 wchar_t *w=to_wide(name);if(!w)return NULL; HANDLE h=CreateMutexW(sa,FALSE,w);DWORD code=GetLastError();free(w);
 if(h&&code==ERROR_ALREADY_EXISTS){CloseHandle(h);SetLastError(ERROR_ALREADY_EXISTS);return NULL;}return h;
}
static int pipe_name(const AppOptions *o,wchar_t out[128]) {
 char key[65];if(key_for(o,key))return -1;swprintf(out,128,L"\\\\.\\pipe\\pppd-%hs",key);return 0;
}
static int write_message(HANDLE pipe,const Message *message) {
 OVERLAPPED ov={0};DWORD n=0;ov.hEvent=CreateEventW(NULL,TRUE,FALSE,NULL);if(!ov.hEvent)return -1;
 BOOL ok=WriteFile(pipe,message,sizeof(*message),&n,&ov);
 if(!ok&&GetLastError()==ERROR_IO_PENDING) {
  if(WaitForSingleObject(ov.hEvent,200)!=WAIT_OBJECT_0)CancelIoEx(pipe,&ov);
  ok=GetOverlappedResult(pipe,&ov,&n,TRUE);
 }
 CloseHandle(ov.hEvent);return ok&&n==sizeof(*message)?0:-1;
}
static void control_reset(Control *c) {
 CancelIoEx(c->pipe,&c->ov);if(c->waiting){DWORD n;GetOverlappedResult(c->pipe,&c->ov,&n,TRUE);}
 DisconnectNamedPipe(c->pipe);c->phase=0;c->waiting=0;ResetEvent(c->event);
 memset(&c->ov,0,sizeof(c->ov));c->ov.hEvent=c->event;
}
static int control_start(Control *c,const AppOptions *o,SECURITY_ATTRIBUTES *sa,Identity identity) {
 wchar_t name[128];if(pipe_name(o,name))return -1;memset(c,0,sizeof(*c));c->identity=identity;
 c->event=CreateEventW(NULL,TRUE,FALSE,NULL);if(!c->event)return -1;c->ov.hEvent=c->event;
 c->pipe=CreateNamedPipeW(name,PIPE_ACCESS_DUPLEX|FILE_FLAG_OVERLAPPED|FILE_FLAG_FIRST_PIPE_INSTANCE,
   PIPE_TYPE_MESSAGE|PIPE_READMODE_MESSAGE|PIPE_WAIT|PIPE_REJECT_REMOTE_CLIENTS,1,4096,4096,0,sa);
 return c->pipe==INVALID_HANDLE_VALUE?-1:0;
}
static void control_poll(Control *c,HANDLE stop,int closing) {
 if(c->stop_client)return;
 DWORD n=0;BOOL ok;
 if(c->waiting){if(WaitForSingleObject(c->event,0)!=WAIT_OBJECT_0)return;
  ok=GetOverlappedResult(c->pipe,&c->ov,&n,FALSE);c->waiting=0;
  if(!ok){control_reset(c);return;}
  if(c->phase==1)c->phase=2;else if(c->phase==3)c->phase=4;
 }
 if(c->phase==0){ResetEvent(c->event);ok=ConnectNamedPipe(c->pipe,&c->ov);
  if(ok||GetLastError()==ERROR_PIPE_CONNECTED)c->phase=2;
  else if(GetLastError()==ERROR_IO_PENDING){c->phase=1;c->waiting=1;return;}
  else {control_reset(c);return;}}
 if(c->phase==2){ResetEvent(c->event);memset(&c->request,0,sizeof(c->request));
  ok=ReadFile(c->pipe,&c->request,sizeof(c->request),&n,&c->ov);
  if(ok)c->phase=4;else if(GetLastError()==ERROR_IO_PENDING){c->phase=3;c->waiting=1;return;}
  else {control_reset(c);return;}}
 if(c->phase==4){Message reply={0};reply.magic=IPC_MAGIC;reply.version=1;reply.identity=c->identity;
  if(n!=sizeof(Message)||c->request.magic!=IPC_MAGIC||c->request.version!=1){control_reset(c);return;}
  if(c->request.command==1)reply.status=closing?1:0;
  else if(c->request.command==2&&!memcmp(&c->request.identity,&c->identity,sizeof(Identity))) {
   reply.status=1;c->stop_client=1;SetEvent(stop);
  }else {control_reset(c);return;}
  if(write_message(c->pipe,&reply)){c->stop_client=0;control_reset(c);return;}
  c->phase=2;
 }
}
static void control_finish(Control *c,int removed) {
 if(c->pipe&&c->pipe!=INVALID_HANDLE_VALUE){
  if(c->stop_client){Message reply={0};reply.magic=IPC_MAGIC;reply.version=1;reply.identity=c->identity;
   reply.status=removed?2:3;reply.exit_code=removed?0:1;write_message(c->pipe,&reply);}
  CancelIoEx(c->pipe,NULL);if(c->waiting){DWORD n;GetOverlappedResult(c->pipe,&c->ov,&n,TRUE);}
  DisconnectNamedPipe(c->pipe);CloseHandle(c->pipe);
 }if(c->event)CloseHandle(c->event);
}
static int client_transfer(HANDLE pipe,Message *message,int reading,ULONGLONG deadline) {
 OVERLAPPED ov={0};DWORD n=0;ov.hEvent=CreateEventW(NULL,TRUE,FALSE,NULL);if(!ov.hEvent)return -1;
 BOOL ok=reading?ReadFile(pipe,message,sizeof(*message),&n,&ov):WriteFile(pipe,message,sizeof(*message),&n,&ov);
 if(!ok&&GetLastError()==ERROR_IO_PENDING){ULONGLONG now=GetTickCount64();DWORD wait=now<deadline?(DWORD)(deadline-now):0;
  if(WaitForSingleObject(ov.hEvent,wait)!=WAIT_OBJECT_0){CancelIoEx(pipe,&ov);GetOverlappedResult(pipe,&ov,&n,TRUE);CloseHandle(ov.hEvent);return -1;}
  ok=GetOverlappedResult(pipe,&ov,&n,FALSE);
 }CloseHandle(ov.hEvent);return ok&&n==sizeof(*message)?0:-1;
}
static int stop_client(AppOptions *o) {
 wchar_t name[128];snprintf(o->linkname,sizeof(o->linkname),"%s",o->stop_name);
 if(pipe_name(o,name))return error("E_INTERNAL",1,"Identite de controle invalide");
 ULONGLONG deadline=GetTickCount64()+15000;HANDLE pipe;
 do {pipe=CreateFileW(name,GENERIC_READ|GENERIC_WRITE,0,NULL,OPEN_EXISTING,FILE_FLAG_OVERLAPPED,NULL);
  if(pipe!=INVALID_HANDLE_VALUE)break;DWORD code=GetLastError();
  if(code!=ERROR_PIPE_BUSY)return error("E_INSTANCE_NOT_FOUND",1,"Instance absente dans cet espace de controle");
  WaitNamedPipeW(name,100);
 }while(GetTickCount64()<deadline);
 if(pipe==INVALID_HANDLE_VALUE)return error("E_STOP_TIMEOUT",1,"Delai de connexion IPC depasse");
 DWORD mode=PIPE_READMODE_MESSAGE;SetNamedPipeHandleState(pipe,&mode,NULL,NULL);
 Message m={0};m.magic=IPC_MAGIC;m.version=1;m.command=1;int result=1;
 if(client_transfer(pipe,&m,0,deadline)||client_transfer(pipe,&m,1,deadline))goto timeout;
 ULONG server=0;HANDLE process=NULL;FILETIME created,exit,kernel,user;
 if(m.magic!=IPC_MAGIC||m.version!=1||!GetNamedPipeServerProcessId(pipe,&server)||server!=m.identity.pid)goto bad;
 process=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,server);
 if(!process)goto bad;
 BOOL verified=GetProcessTimes(process,&created,&exit,&kernel,&user)&&!memcmp(&created,&m.identity.created,sizeof(created));CloseHandle(process);
 if(!verified)goto bad;
 Identity expected=m.identity;
 m.command=2;if(client_transfer(pipe,&m,0,deadline)||client_transfer(pipe,&m,1,deadline))goto timeout;
 if(m.magic!=IPC_MAGIC||m.version!=1||memcmp(&expected,&m.identity,sizeof(expected))||m.status!=1)goto bad;
 if(client_transfer(pipe,&m,1,deadline))goto timeout;
 if(m.magic!=IPC_MAGIC||m.version!=1||memcmp(&expected,&m.identity,sizeof(expected)))goto bad;
 if(m.status==2){puts("REMOVED");result=0;}else result=error("E_ADAPTER_REMOVE",1,"Le retrait de la carte n'est pas confirme");
 goto done;
timeout:result=error("E_STOP_TIMEOUT",1,"Delai de 15 secondes sans confirmation REMOVED");goto done;
bad:result=error("E_INTERNAL",1,"Identite ou protocole IPC invalide");
done:CloseHandle(pipe);return result;
}
static int push(Queue *q,const uint8_t *data,size_t n) {
 if(n>FRAME_CAP||q->count>=q->limit){q->drops++;return -1;}
 Frame *f=&q->frame[(q->head+q->count)%32];f->size=n;memcpy(f->bytes,data,n);q->count++;return 0;
}
static int output_serial(void *ctx,const uint8_t *data,size_t n) {
 Runtime *r=ctx;return push(r->sending_data?&r->data:&r->control,data,n);
}
static int input_ip(void *ctx,const uint8_t *data,size_t n) {
 Runtime *r=ctx;unsigned version=n?data[0]>>4:0;
 if(n<20||((version!=4||!r->ip_up)&&(version!=6||!r->ip6_up))){r->ip_drop++;return -1;}
 int rc=win_tun_send(r->tun,data,n);
 if(rc){r->ip_drop++;if(rc<0){record("ERROR","E_WINTUN_API",4,win_tun_error(r->tun));r->fatal=4;}return -1;}r->ip_rx++;return 0;
}
static void link_status(void *ctx,int up,uint32_t local,uint32_t peer,uint16_t mtu) {
 Runtime *r=ctx;r->link_ready=up;r->local_ip=local;r->peer_ip=peer;r->mtu=mtu;r->ip_pending=1;
 if(up)r->failed_attempts=0; /* auth.c np_up resets num_unsuccessful. */
 /* Close the data gate inside the callback; IP Helper work happens after the
    upstream core returns, avoiding reentrant negotiation callbacks. */
 if(!up){r->ip_up=0;r->remove_ip_pending=1;r->data.head=r->data.count=0;}
}
static void link_status6(void *ctx,int up,const uint8_t local[8],const uint8_t peer[8],uint16_t mtu) {
 Runtime *r=ctx;r->link6_ready=up;r->ip6_pending=1;r->mtu=mtu;
 if(up)r->failed_attempts=0;
 memcpy(r->ipv6_local,local,8);memcpy(r->ipv6_peer,peer,8);
 if(!up){r->ip6_up=0;r->remove_ip6_pending=1;r->data.head=r->data.count=0;}
}
static void network_parameters(void *ctx,const uint32_t dns[2],const uint32_t wins[2]) {
 Runtime *r=ctx;memcpy(r->dns,dns,sizeof(r->dns));memcpy(r->wins,wins,sizeof(r->wins));r->dns_pending=1;
}
static void core_log(void *ctx,const char *message){Runtime *r=ctx;if(r->options.debug)record("DEBUG","PPP",-1,message);}
static PppCounters total_counters(Runtime *r,int collect) {
 PppCounters current={0};if(r->core_active)ppp_engine_get_counters(&current);
#define ADD_COUNTER(field) current.field+=r->ppp_total.field
 ADD_COUNTER(tx_frames);ADD_COUNTER(rx_frames);ADD_COUNTER(tx_ipv4);ADD_COUNTER(rx_ipv4);ADD_COUNTER(rx_fcs_errors);ADD_COUNTER(rx_invalid);ADD_COUNTER(rx_oversize);ADD_COUNTER(tx_dropped);ADD_COUNTER(rx_dropped);ADD_COUNTER(tx_ipv6);ADD_COUNTER(rx_ipv6);
#undef ADD_COUNTER
 if(collect)r->ppp_total=current;return current;
}
static void log_counters(Runtime *r) {
 PppCounters c=total_counters(r,0);char message[1024];
 snprintf(message,sizeof(message),"IP_TX=%llu IP_RX=%llu IP_DROP=%llu SERIAL_TX=%llu SERIAL_RX=%llu CTRL_DROP=%llu DATA_DROP=%llu PPP_TX=%llu PPP_RX=%llu PPP_IP_TX=%llu PPP_IP_RX=%llu FCS_ERRORS=%llu INVALID=%llu OVERSIZE=%llu",
  (unsigned long long)r->ip_tx,(unsigned long long)r->ip_rx,(unsigned long long)r->ip_drop,(unsigned long long)r->serial_tx,(unsigned long long)r->serial_rx,(unsigned long long)r->control.drops,(unsigned long long)r->data.drops,
  (unsigned long long)c.tx_frames,(unsigned long long)c.rx_frames,(unsigned long long)c.tx_ipv4,(unsigned long long)c.rx_ipv4,(unsigned long long)c.rx_fcs_errors,(unsigned long long)c.rx_invalid,(unsigned long long)c.rx_oversize);
 record("INFO","COUNTERS",-1,message);
}
static int core_prepare(Runtime *r) {
 PppConfig c={0};
 c.local_ip_be=r->options.local_ip_be;
 c.peer_ip_be=r->options.peer_ip_be;
 c.mtu=r->options.mtu;
 c.mru=r->options.mru;
 c.receive_accm=r->options.receive_accm;
 c.echo_interval=r->options.echo_interval;
 c.echo_failure=r->options.echo_failure;
 c.debug=r->options.debug;
 c.echo_adaptive=r->options.echo_adaptive;
 c.passive=r->options.passive;
 c.silent=r->options.silent;
 c.noaccomp=r->options.noaccomp;
 c.nopcomp=r->options.nopcomp;
 c.nomagic=r->options.nomagic;
 c.asyncmap_disabled=r->options.asyncmap_disabled;
 c.lcp_timeout=r->options.lcp_timeout;
 c.lcp_max_configure=r->options.lcp_max_configure;
 c.lcp_max_terminate=r->options.lcp_max_terminate;
 c.lcp_max_failure=r->options.lcp_max_failure;
 c.lcp_loopback_failure=r->options.lcp_loopback_failure;
 c.ipcp_timeout=r->options.ipcp_timeout;
 c.ipcp_max_configure=r->options.ipcp_max_configure;
 c.ipcp_max_terminate=r->options.ipcp_max_terminate;
 c.ipcp_max_failure=r->options.ipcp_max_failure;
 c.ipcp_accept_local=r->options.ipcp_accept_local;
 c.ipcp_accept_remote=r->options.ipcp_accept_remote;
 c.usepeerdns=r->options.usepeerdns;
 c.usepeerwins=r->options.usepeerwins;
 c.ipv4_disabled=r->options.ipv4_disabled;
 c.ipv6_enabled=r->options.ipv6_enabled;
 c.ipv6_accept_local=r->options.ipv6_accept_local;
 c.ipv6_accept_remote=r->options.ipv6_accept_remote;
 c.ipv6cp_timeout=r->options.ipv6cp_timeout;
 c.ipv6cp_max_configure=r->options.ipv6cp_max_configure;
 c.ipv6cp_max_terminate=r->options.ipv6cp_max_terminate;
 c.ipv6cp_max_failure=r->options.ipv6cp_max_failure;
 c.maxconnect=r->options.maxconnect;
 c.idle=r->options.idle;
 c.default_mru=r->options.default_mru;
 c.receive_all=r->options.receive_all;
 c.ipcp_no_address=r->options.ipcp_no_address;
 c.ipcp_no_addresses=r->options.ipcp_no_addresses;
 c.ipv6_use_ipaddr=r->options.ipv6_use_ipaddr;
 c.ipv6_no_send=r->options.ipv6_no_send;
 memcpy(c.transmit_accm,r->options.transmit_accm,sizeof(c.transmit_accm));
 memcpy(c.dns,r->options.dns,sizeof(c.dns));
 memcpy(c.wins,r->options.wins,sizeof(c.wins));
 memcpy(c.ipv6_local_id,r->options.ipv6_local_id,sizeof(c.ipv6_local_id));
 memcpy(c.ipv6_peer_id,r->options.ipv6_peer_id,sizeof(c.ipv6_peer_id));
 memcpy(c.rtt_file,r->options.rtt_file,sizeof(c.rtt_file));
 c.auth=r->options.auth;c.data=r->options.data;
 PppOps ops={0};ops.ctx=r;ops.write_serial=output_serial;ops.receive_ip=input_ip;
 ops.status=link_status;ops.log=core_log;ops.status_ipv6=link_status6;ops.network_parameters=network_parameters;
 if(ppp_engine_init(&c,&ops))return -1;r->core_active=1;ppp_engine_poll(GetTickCount());return 0;
}
static int service(Runtime *r) {
 if(win_port_poll(r->port)<0)return -1;
 uint8_t buffer[PPP_ENGINE_MAX_MRU];for(unsigned i=0;i<32;i++) {int n=win_port_read(r->port,buffer,sizeof(buffer));
  if(n<0)return -1;if(!n)break;r->serial_rx+=(unsigned)n;ppp_engine_serial_input(buffer,(size_t)n);}
 ppp_engine_poll(GetTickCount());
 if(r->remove_ip_pending){r->remove_ip_pending=0;
  if(win_tun_clear_ip(r->tun)){record("ERROR","E_IPV4_CONFIG",4,win_tun_error(r->tun));r->fatal=4;}
  /* Discard packets from the old IP epoch before any new address/route is
     published, even if down/up callbacks occurred in one input batch. */
  for(unsigned i=0;i<32768;i++){int n=win_tun_read(r->tun,buffer,sizeof(buffer));if(!n)break;
   if(n<0){record("ERROR","E_WINTUN_API",4,win_tun_error(r->tun));r->fatal=4;break;}r->ip_drop++;}
  if(r->fatal){r->ip_up=0;return 0;}
 }
 if(r->ip_pending){r->ip_pending=0;
  if(!r->link_ready){r->data.head=r->data.count=0;if(win_tun_clear_ip(r->tun)){record("ERROR","E_IPV4_CONFIG",4,win_tun_error(r->tun));r->fatal=4;return 0;}}
  else if(!r->closing){if(win_tun_set_ip(r->tun,r->local_ip,r->peer_ip,r->mtu)){record("ERROR","E_IPV4_CONFIG",4,win_tun_error(r->tun));r->fatal=4;}
   else {r->ip_up=1;r->dns_pending=1;
    if(r->options.default_route&&win_tun_set_default_route(r->tun,r->options.default_route_metric)){record("ERROR","E_ROUTE_CONFIG",4,win_tun_error(r->tun));r->fatal=4;return 0;}
    char detail[256],local[16],peer[16];options_format_ip(r->local_ip,local);options_format_ip(r->peer_ip,peer);
    snprintf(detail,sizeof(detail),"UP %s %s:%s MTU %u",r->options.ifname,local,peer,r->mtu);record("INFO","UP",-1,detail);}}
 }
 if(r->remove_ip6_pending){r->remove_ip6_pending=0;if(win_tun_clear_ipv6(r->tun)){record("ERROR","E_IPV6_CONFIG",4,win_tun_error(r->tun));r->fatal=4;return 0;}}
 if(r->ip6_pending){r->ip6_pending=0;
  if(!r->link6_ready){if(win_tun_clear_ipv6(r->tun)){record("ERROR","E_IPV6_CONFIG",4,win_tun_error(r->tun));r->fatal=4;return 0;}}
  else if(!r->closing){if(win_tun_set_ipv6(r->tun,r->ipv6_local,r->ipv6_peer,r->mtu)){record("ERROR","E_IPV6_CONFIG",4,win_tun_error(r->tun));r->fatal=4;return 0;}
   r->ip6_up=1;record("INFO","UP_IPV6",-1,"IPv6CP OPENED; owned IPv6 link-local address and peer route configured");}
 }
 if(r->dns_pending&&r->ip_up){r->dns_pending=0;
  if(r->options.usepeerdns&&win_tun_set_dns(r->tun,r->dns)){record("ERROR","E_DNS_CONFIG",4,win_tun_error(r->tun));r->fatal=4;return 0;}
 }
 /* A control frame always wins over data, but an active serial frame is never
    interleaved with another frame, including during software flow pause. */
 if(!win_port_queued(r->port)){Queue *q=r->control.count?&r->control:&r->data;
  if(r->closing&&q==&r->data)q=NULL;
  if(q&&q->count){Frame *f=&q->frame[q->head];if(win_port_queue(r->port,f->bytes,f->size))return -1;
   r->serial_tx+=f->size;q->head=(q->head+1)%32;q->count--;}}
 for(unsigned i=0;i<16;i++){int n=win_tun_read(r->tun,buffer,sizeof(buffer));
  if(n<0){record("ERROR","E_WINTUN_API",4,win_tun_error(r->tun));r->fatal=4;break;}if(!n)break;
  if(r->closing||((buffer[0]>>4)==4?!r->ip_up:(buffer[0]>>4)==6?!r->ip6_up:1)||r->data.count>=r->data.limit){r->ip_drop++;continue;}
  r->sending_data=1;int rc=ppp_engine_send_ip(buffer,(size_t)n);r->sending_data=0;
  if(rc)r->ip_drop++;else r->ip_tx++;
 }return 0;
}
static int owner_journal(Runtime *r,SECURITY_ATTRIBUTES *sa) {
 if(!r->options.config_explicit){
  /* Logging is best-effort in portable mode. A missing/unwritable TEMP must
     never turn into a configuration prerequisite or an adapter failure. */
  wchar_t temporary[32768],path[32768],instance[40];
  DWORD count=GetTempPathW(32768,temporary);
  if(!count||count>=32768||!StringFromGUID2(&r->identity.uuid,instance,40))return 0;
  for(DWORD i=0;i<count;i++)if(temporary[i]==L'/')temporary[i]=L'\\';
  int length;
  if(!wcsncmp(temporary,L"\\\\?\\",4))
   length=swprintf(path,32768,L"%lspppd-%lu-%ls.log",temporary,(unsigned long)GetCurrentProcessId(),instance);
  else if(temporary[0]==L'\\'&&temporary[1]==L'\\')
   length=swprintf(path,32768,L"\\\\?\\UNC\\%lspppd-%lu-%ls.log",temporary+2,(unsigned long)GetCurrentProcessId(),instance);
  else if(count>=3&&temporary[1]==L':'&&temporary[2]==L'\\')
   length=swprintf(path,32768,L"\\\\?\\%lspppd-%lu-%ls.log",temporary,(unsigned long)GetCurrentProcessId(),instance);
  else return 0;
  if(length<0||length>=32768)return 0;
  HANDLE file=CreateFileW(path,FILE_APPEND_DATA,FILE_SHARE_READ,sa,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);
  if(file==INVALID_HANDLE_VALUE)return 0;
  int fd=_open_osfhandle((intptr_t)file,_O_APPEND|_O_BINARY|_O_WRONLY);
  if(fd<0){CloseHandle(file);return 0;}
  r->journal=_fdopen(fd,"ab");if(!r->journal){_close(fd);return 0;}
  journal=r->journal;return 0;
 }
 wchar_t *root=to_wide(r->options.config_dir);if(!root)return -1;
 wchar_t directory[2300],path[2500];swprintf(directory,2300,L"\\\\?\\%ls\\logs",root);free(root);
 if(!CreateDirectoryW(directory,sa)&&GetLastError()!=ERROR_ALREADY_EXISTS)return -1;
 wchar_t instance[40];if(!StringFromGUID2(&r->identity.uuid,instance,40))return -1;
 swprintf(path,2500,L"%ls\\%hs-%lu-%ls.log",directory,r->options.linkname,(unsigned long)GetCurrentProcessId(),instance);
 HANDLE file=CreateFileW(path,FILE_APPEND_DATA,FILE_SHARE_READ,sa,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);
 if(file==INVALID_HANDLE_VALUE)return -1;
 int fd=_open_osfhandle((intptr_t)file,_O_APPEND|_O_BINARY|_O_WRONLY);
 if(fd<0){CloseHandle(file);return -1;}r->journal=_fdopen(fd,"ab");
 if(!r->journal){_close(fd);return -1;}journal=r->journal;return 0;
}
static void started_message(Message *m,Runtime *r,int exit_code,const char *detail) {
 memset(m,0,sizeof(*m));m->magic=IPC_MAGIC;m->version=1;m->identity=r->identity;m->exit_code=exit_code;
 snprintf(m->detail,sizeof(m->detail),"%s",exit_code?last_error_detail:(detail?detail:""));
 if(exit_code)snprintf(m->code,sizeof(m->code),"%s",last_error_code);
}
static int owner(AppOptions *options,HANDLE ready,HANDLE ack,HANDLE parent) {
 Runtime *r=calloc(1,sizeof(*r));if(!r)return error("E_INTERNAL",1,"Memoire insuffisante");
 r->options=*options;r->control.limit=32;r->data.limit=8;
 SECURITY_ATTRIBUTES sa={0};PSECURITY_DESCRIPTOR sd=NULL;char message[1024],key[65];int result=1,reported=0;
 r->identity.pid=GetCurrentProcessId();FILETIME e,k,u;
 if(!GetProcessTimes(GetCurrentProcess(),&r->identity.created,&e,&k,&u)||FAILED(CoCreateGuid(&r->identity.uuid))){error("E_INTERNAL",1,"Creation de l'identite de processus impossible");goto done;}
 if(!security(&sa,&sd)){error("E_INTERNAL",1,"Creation des DACL impossible");goto done;}
 r->stop=CreateEventW(&sa,TRUE,FALSE,NULL);if(!r->stop)goto done;console_stop=r->stop;
 if(options->nodetach)SetConsoleCtrlHandler(on_console,TRUE);
 if(key_for(options,key))goto done;
 r->link_lock=reserve("link",key,&sa);r->if_lock=reserve("if",options->ifname,&sa);
 if(!r->link_lock||!r->if_lock){result=error("E_INSTANCE_CONFLICT",6,"ifname ou linkname deja reserve");goto done;}
 r->com_lock=reserve("port",options->device,&sa);
 if(!r->com_lock){result=error("E_PORT_BUSY",6,"Port COM deja reserve par une autre instance");goto done;}
 if(owner_journal(r,&sa)){result=error("E_CFG_PATH",2,"Creation du journal d'instance impossible");goto done;}
 if(win_tun_check_library(message,sizeof(message))){result=error("E_WINTUN_LOAD",4,message);goto done;}
 r->failed_attempts=1; /* Count an attempt before acquiring its transport. */
 r->port=win_port_open(options,FRAME_CAP,message,sizeof(message));
 if(!r->port){int busy=win_port_last_error_code()==ERROR_SHARING_VIOLATION||win_port_last_error_code()==ERROR_ACCESS_DENIED;
  result=error(busy?"E_PORT_BUSY":win_port_last_error_stage(),busy?6:7,message);goto done;}
 r->tun=win_tun_open(options->ifname,message,sizeof(message));
 if(!r->tun){result=error("E_ADAPTER_CREATE",4,message);goto done;}
 win_tun_guid(r->tun,r->identity.guid);
 if(core_prepare(r)){result=error("E_INTERNAL",1,"Initialisation du coeur PPP impossible");goto done;}
 if(control_start(&r->ipc,options,&sa,r->identity)){result=error("E_INTERNAL",1,"Creation du canal IPC impossible");goto done;}
 wchar_t uuid_wide[40];char uuid_text[48]="";StringFromGUID2(&r->identity.uuid,uuid_wide,40);
 WideCharToMultiByte(CP_UTF8,0,uuid_wide,-1,uuid_text,sizeof(uuid_text),NULL,NULL);
 snprintf(message,sizeof(message),"STARTED linkname=%s PID=%lu UUID=%s ifname=%s GUID=%s",options->linkname,(unsigned long)r->identity.pid,uuid_text,options->ifname,r->identity.guid);
 if(ready){Message m;DWORD n;started_message(&m,r,0,message);
  if(!WriteFile(ready,&m,sizeof(m),&n,NULL)||n!=sizeof(m))goto done;reported=1;
  /* The owner does not negotiate until delivery is acknowledged. Parent death
     or an absent acknowledgement always rolls resources back. */
  ULONGLONG limit=GetTickCount64()+60000;char accepted=0;
  while(GetTickCount64()<limit){DWORD available=0;
   int parent_dead=parent&&WaitForSingleObject(parent,0)==WAIT_OBJECT_0;
   if(!PeekNamedPipe(ack,NULL,0,NULL,&available,NULL))break;
   if(available){if(ReadFile(ack,&accepted,1,&n,NULL)&&n==1&&accepted=='A')break;accepted=0;break;}
   if(parent_dead)break;Sleep(5);
  }
  if(accepted!='A'){result=error("E_START_TIMEOUT",1,"Lanceur termine ou livraison non acquittee");goto done;}
  CloseHandle(ready);ready=NULL;CloseHandle(ack);ack=NULL;if(parent){CloseHandle(parent);parent=NULL;}
 }record("INFO","STARTED",-1,message);
 if(ppp_engine_start()){result=error("E_INTERNAL",1,"Demarrage du coeur PPP impossible");goto done;}
 result=5;
 for(;;){control_poll(&r->ipc,r->stop,r->closing);
  if(WaitForSingleObject(r->stop,0)==WAIT_OBJECT_0)break;
  int service_result=service(r);if(r->fatal){result=r->fatal;break;}
  if(service_result<0||ppp_engine_is_dead()){
   int reason=ppp_engine_last_error();
   record("WARN","RETRY_WAIT",-1,win_port_error(r->port));r->ip_up=0;r->ip6_up=0;
   if(win_tun_clear_ipv6(r->tun)){result=error("E_IPV6_CONFIG",4,win_tun_error(r->tun));break;}
   if(win_tun_clear_ip(r->tun)){result=error("E_IPV4_CONFIG",4,win_tun_error(r->tun));break;}
   total_counters(r,1);ppp_engine_destroy();r->core_active=0;win_port_close(r->port);r->port=NULL;r->control.count=r->data.count=0;r->control.head=r->data.head=0;
   if(reason==14||!options->persist||(options->maxfail&&r->failed_attempts>=options->maxfail)){result=error("E_PPP_NEGOTIATION",reason?reason:10,"Liaison terminee sans reprise possible");break;}
   do {ULONGLONG until=GetTickCount64()+(ULONGLONG)((reason==11||reason==12)?0:options->holdoff)*1000;
    while(GetTickCount64()<until&&WaitForSingleObject(r->stop,0)!=WAIT_OBJECT_0){control_poll(&r->ipc,r->stop,0);Sleep(10);}
    control_poll(&r->ipc,r->stop,0); /* Also service STOP when holdoff is zero. */
    if(WaitForSingleObject(r->stop,0)==WAIT_OBJECT_0)break;
    if(r->failed_attempts!=UINT64_MAX)r->failed_attempts++;
    r->port=win_port_open(options,FRAME_CAP,message,sizeof(message));
    if(!r->port&&options->maxfail&&r->failed_attempts>=options->maxfail){
     result=error(win_port_last_error_stage(),7,message);break;
    }
   }while(!r->port);
   if(!r->port)break;if(core_prepare(r)||ppp_engine_start()){result=error("E_INTERNAL",1,"Reinitialisation PPP impossible");break;}
  }
  if(r->fatal){result=r->fatal;break;}if(GetTickCount64()>=r->stats_at){log_counters(r);r->stats_at=GetTickCount64()+10000;}Sleep(5);
 }
done:
 r->closing=1;r->ip_up=0;r->ip6_up=0;r->data.head=r->data.count=0;
 if(r->core_active){ppp_engine_close();ULONGLONG deadline=GetTickCount64()+(accelerated_close?0:2000);
  while(r->port&&!ppp_engine_is_dead()&&GetTickCount64()<deadline){control_poll(&r->ipc,r->stop,1);if(service(r)<0)break;Sleep(5);}
  total_counters(r,1);ppp_engine_destroy();r->core_active=0;
 }
 if(r->tun&&win_tun_clear_ipv6(r->tun)){error("E_IPV6_CONFIG",1,win_tun_error(r->tun));result=1;}
 if(r->tun&&win_tun_clear_ip(r->tun)){error("E_IPV4_CONFIG",1,win_tun_error(r->tun));result=1;}
 if(r->port)win_port_close(r->port);
 int removed=1;if(r->tun&&win_tun_close(r->tun)){removed=0;result=error("E_ADAPTER_REMOVE",1,win_tun_close_error());}
 if(ready&&!reported){Message m;DWORD n;started_message(&m,r,result,"Le proprietaire a echoue avant STARTED");WriteFile(ready,&m,sizeof(m),&n,NULL);}
 control_finish(&r->ipc,removed);
 log_counters(r);if(result==5)record("INFO","STOP_REQUESTED",5,"Arret utilisateur maitrise");
 if(removed)record("INFO","REMOVED",-1,"Retrait de la carte confirme");
 if(r->com_lock)CloseHandle(r->com_lock);if(r->if_lock)CloseHandle(r->if_lock);if(r->link_lock)CloseHandle(r->link_lock);
 if(sd)LocalFree(sd);if(ready)CloseHandle(ready);if(ack)CloseHandle(ack);if(parent)CloseHandle(parent);
 console_stop=NULL;if(options->nodetach)SetConsoleCtrlHandler(on_console,FALSE);if(r->stop)CloseHandle(r->stop);
 journal=NULL;if(r->journal)fclose(r->journal);free(r);return result;
}
static int append_quote(wchar_t *out,size_t capacity,const wchar_t *argument) {
 size_t n=wcslen(out);if(n+3>=capacity)return -1;if(n)out[n++]=L' ';out[n++]=L'"';
 unsigned slashes=0;for(const wchar_t *p=argument;;p++){
  if(*p==L'\\'){slashes++;continue;}
  unsigned copies=slashes;if(!*p||*p==L'"')copies*=2;
  while(copies--){if(n+3>=capacity)return -1;out[n++]=L'\\';}slashes=0;
  if(!*p)break;if(*p==L'"'){if(n+3>=capacity)return -1;out[n++]=L'\\';}
  if(n+3>=capacity)return -1;out[n++]=*p;
 }out[n++]=L'"';out[n]=0;return 0;
}
static int launch_owner(int argc,wchar_t **argv) {
 SECURITY_ATTRIBUTES sa={sizeof(sa),NULL,TRUE};HANDLE ready_read=NULL,ready_write=NULL,ack_read=NULL,ack_write=NULL,parent=NULL;
 PROCESS_INFORMATION process={0};STARTUPINFOEXW startup={0};startup.StartupInfo.cb=sizeof(startup);wchar_t path[32768],command[32768]=L"",internal[256];int result=1;
 if(!CreatePipe(&ready_read,&ready_write,&sa,4096)||!CreatePipe(&ack_read,&ack_write,&sa,4096))goto done;
 SetHandleInformation(ready_read,HANDLE_FLAG_INHERIT,0);SetHandleInformation(ack_write,HANDLE_FLAG_INHERIT,0);
 if(!DuplicateHandle(GetCurrentProcess(),GetCurrentProcess(),GetCurrentProcess(),&parent,SYNCHRONIZE,TRUE,0))goto done;
 if(!GetModuleFileNameW(NULL,path,32768))goto done;
 if(append_quote(command,32768,path))goto done;
 for(int i=1;i<argc;i++)if(append_quote(command,32768,argv[i]))goto done;
 swprintf(internal,256,L"--_owner=%llu,%llu,%llu",(unsigned long long)(uintptr_t)ready_write,(unsigned long long)(uintptr_t)ack_read,(unsigned long long)(uintptr_t)parent);
 if(append_quote(command,32768,internal))goto done;
 SIZE_T size=0;InitializeProcThreadAttributeList(NULL,1,0,&size);startup.lpAttributeList=malloc(size);
 HANDLE inherited[3]={ready_write,ack_read,parent};
 if(!startup.lpAttributeList||!InitializeProcThreadAttributeList(startup.lpAttributeList,1,0,&size)||
 !UpdateProcThreadAttribute(startup.lpAttributeList,0,PROC_THREAD_ATTRIBUTE_HANDLE_LIST,inherited,sizeof(inherited),NULL,NULL))goto done;
 if(!CreateProcessW(path,command,NULL,NULL,TRUE,DETACHED_PROCESS|CREATE_NEW_PROCESS_GROUP|EXTENDED_STARTUPINFO_PRESENT,NULL,NULL,&startup.StartupInfo,&process))goto done;
 CloseHandle(ready_write);ready_write=NULL;CloseHandle(ack_read);ack_read=NULL;CloseHandle(parent);parent=NULL;
 ULONGLONG deadline=GetTickCount64()+60000;Message m={0};int received=0;DWORD n;
 while(GetTickCount64()<deadline){DWORD available=0;if(!PeekNamedPipe(ready_read,NULL,0,NULL,&available,NULL))break;
  if(available>=sizeof(m)){received=ReadFile(ready_read,&m,sizeof(m),&n,NULL)&&n==sizeof(m);break;}
  if(WaitForSingleObject(process.hProcess,0)==WAIT_OBJECT_0)break;Sleep(10);
 }
 if(!received){result=error("E_START_TIMEOUT",1,"Proprietaire termine ou delai de demarrage de 60 secondes depasse");goto done;}
 if(m.exit_code){result=error(m.code[0]?m.code:"E_INTERNAL",m.exit_code,m.detail);goto done;}
 if(m.magic!=IPC_MAGIC||m.version!=1){result=error("E_INTERNAL",1,"Handshake de demarrage invalide");goto done;}
 char accepted='A';if(!WriteFile(ack_write,&accepted,1,&n,NULL)||n!=1)goto done;
 puts(m.detail);result=0;
done:
 if(startup.lpAttributeList){DeleteProcThreadAttributeList(startup.lpAttributeList);free(startup.lpAttributeList);}
 if(ready_read)CloseHandle(ready_read);if(ready_write)CloseHandle(ready_write);if(ack_read)CloseHandle(ack_read);if(ack_write)CloseHandle(ack_write);if(parent)CloseHandle(parent);
 if(process.hThread)CloseHandle(process.hThread);if(process.hProcess)CloseHandle(process.hProcess);return result;
}
static int early_failure(HANDLE ready,HANDLE ack,HANDLE parent,const char *code,int exit_code,const char *detail) {
 if(ready&&GetFileType(ready)==FILE_TYPE_PIPE){Message m={0};DWORD n;m.magic=IPC_MAGIC;m.version=1;m.exit_code=exit_code;
  snprintf(m.code,sizeof(m.code),"%s",code);snprintf(m.detail,sizeof(m.detail),"%s",detail);WriteFile(ready,&m,sizeof(m),&n,NULL);}
 if(ready)CloseHandle(ready);if(ack)CloseHandle(ack);if(parent)CloseHandle(parent);
 return error(code,exit_code,detail);
}
int wmain(int argc,wchar_t **argv) {
 AppOptions o;options_defaults(&o);char message[2048];HANDLE ready=NULL,ack=NULL,parent=NULL;
 int n=argc-1;
 if(n&&wcsncmp(argv[argc-1],L"--_owner=",9)==0){unsigned long long a,b,c;wchar_t extra;
  if(swscanf(argv[argc-1]+9,L"%llu,%llu,%llu%c",&a,&b,&c,&extra)!=3)return error("E_CLI_MODE",2,"Argument interne invalide");
  ready=(HANDLE)(uintptr_t)a;ack=(HANDLE)(uintptr_t)b;parent=(HANDLE)(uintptr_t)c;n--;
  if(GetFileType(ready)!=FILE_TYPE_PIPE||GetFileType(ack)!=FILE_TYPE_PIPE)return error("E_CLI_MODE",2,"Canal parent absent");
 }
 if(!n&&!ready){options_help();return 2;}
 char **arguments=calloc((size_t)n+1,sizeof(*arguments));if(!arguments)return 1;
 for(int i=0;i<n;i++){arguments[i]=to_utf8(argv[i+1]);if(!arguments[i])return error("E_OPT_VALUE",2,"Argument Unicode invalide");}
 int parsed=options_parse(&o,n,(const char *const*)arguments,message,sizeof(message));
 for(int i=0;i<n;i++)free(arguments[i]);free(arguments);
 if(parsed)return early_failure(ready,ack,parent,options_error_code(),2,message);
 if(o.help){options_help();return argc>1?0:2;}
 if(o.version){puts("pppd.exe " VERSION " | pppd 2.5.5 | PPP serie IPv4/IPv6 et authentification | Windows x64");return 0;}
 if(!elevated())return early_failure(ready,ack,parent,"E_PRIVILEGE",3,"La liaison et --stop exigent un terminal Windows eleve");
 if(o.stop_name[0])return stop_client(&o);
 if(o.dump||o.dry_run)options_print(&o);if(o.dry_run)return 0;
 if(!ready&&!o.nodetach)return launch_owner(argc,argv);
 return owner(&o,ready,ack,parent);
}
