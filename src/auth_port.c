/* Windows host glue for the ORIGINAL pppd 2.5.5 packet/state machines.
 * No authentication result is invented here. PAP compares a real secret;
 * CHAP/EAP verify their packets in the upstream implementations.
 * Upstream license notices are preserved in vendor/ppp/AUTH-PROVENANCE.txt. */
#include "vendor/ppp/pppd-private.h"
#include "auth_port.h"
#include "vendor/ppp/fsm.h"
#include "vendor/ppp/lcp.h"
#include "vendor/ppp/upap.h"
#include "vendor/ppp/chap.h"
#include "vendor/ppp/chap_ms.h"
#include "vendor/ppp/eap.h"
#include "vendor/ppp/crypto.h"
#include "vendor/ppp/mppe.h"
#include "vendor/ppp/cbcp.h"
#include "vendor/ppp/options.h"
#ifdef PPP_WITH_EAPTLS
#include "vendor/ppp/eap-tls.h"
#endif
#ifdef PPP_WITH_PEAP
#include "vendor/ppp/peap.h"
#endif
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <sys/stat.h>
#ifdef _WIN32
#include <windows.h>
#include <ws2tcpip.h>
#include <aclapi.h>
#include <bcrypt.h>
#include <io.h>
#include <fcntl.h>
#else
#include <unistd.h>
#include <sys/random.h>
#endif

static PppAuthConfig config;
static unsigned pending;
static int auth_active,auth_failed,network_started,crypto_started;
int auth_done[NUM_PPP];
static int certificate_auth;
static int auth_initialized;
static int dispatch_depth,lowerdown_deferred;
static int callback_started;
extern int ppp_cbcp_set(char **);
static struct wordlist *authorized;
char user[MAXNAMELEN],passwd[MAXSECRETLEN],our_name[MAXNAMELEN],remote_name[MAXNAMELEN];
bool explicit_remote,session_mgmt,persist,auth_required;
char devnam[32]="COM";
char remote_number[256]="";
#if defined(PPP_WITH_EAPTLS) || defined(PPP_WITH_PEAP)
char *crl_dir,*crl_file,*ca_path,*cacert_file,*max_tls_version,*pkcs12_file;
char *tls_verify_method=TLS_VERIFY_NAME;
bool tls_verify_key_usage=1;
char tls_key_password[MAXSECRETLEN];
#endif
chap_check_hook_fn *chap_check_hook;
chap_passwd_hook_fn *chap_passwd_hook;
extern int chap_server_timeout_time,chap_client_timeout_time,chap_max_transmits,chap_rechallenge_time,chapms_strip_domain;
static void free_wordlist(struct wordlist*);
static int ppp_check_access(int,const char*,int);
static FILE *open_secret(const char*);
#define PPP_FT_SECRET 1
#define ISWILD(s) ((s)[0]=='*' && (s)[1]==0)
#define NONWILD_CLIENT 2
#define NONWILD_SERVER 1
#include "vendor/ppp/auth_upstream.inc"

void ppp_explicit_bzero(void *p,size_t n){volatile unsigned char *v=p;while(n--)*v++=0;}
void novm(const char *s){fatal("Out of memory: %s",s);}
void ppp_add_options(struct option *o){(void)o; /* Registered in the Windows CLI. */}
void ppp_option_error(char *fmt,...){char b[1024];va_list a;va_start(a,fmt);vslprintf(b,sizeof(b),fmt,a);va_end(a);error("%s",b);}
void random_bytes(unsigned char *p,int n){
#ifdef _WIN32
    if(n<0||BCryptGenRandom(NULL,p,(ULONG)n,BCRYPT_USE_SYSTEM_PREFERRED_RNG)!=0){fatal("Operating-system random generator failed");abort();}
#else
    while(n>0){ssize_t k=getrandom(p,(size_t)n,0);if(k<0&&errno==EINTR)continue;if(k<=0){fatal("Operating-system random generator failed");abort();}p+=k;n-=(int)k;}
#endif
}
double ppp_auth_drand48(void){uint32_t r;random_bytes((unsigned char*)&r,sizeof(r));return (double)r/4294967296.0;}
void print_string(char *p,int n,printer_func printer,void *arg){int i;printer(arg,"\"");for(i=0;i<n;i++){unsigned char c=(unsigned char)p[i];if(c=='"'||c=='\\')printer(arg,"\\%c",c);else if(c>=32&&c<127)printer(arg,"%c",c);else printer(arg,"\\x%02x",c);}printer(arg,"\"");}

/* System account/PAM checks are deliberately not part of this host. */
int session_start(const int flags,const char *u,const char *p,const char *t,char **m){(void)flags;(void)u;(void)p;(void)t;if(m)*m="System account authentication is unavailable";return 0;}

static int ppp_check_access(int fd,const char *path,int kind){
    (void)kind;
#ifdef _WIN32
    HANDLE h=(HANDLE)_get_osfhandle(fd);BY_HANDLE_FILE_INFORMATION fi;
    PSECURITY_DESCRIPTOR sd=NULL;PACL acl=NULL;PSID owner=NULL;DWORD rc,i;
    unsigned char system_sid[SECURITY_MAX_SID_SIZE],admin_sid[SECURITY_MAX_SID_SIZE];DWORD sn=sizeof(system_sid),an=sizeof(admin_sid);
    HANDLE token=NULL;TOKEN_USER *tu=NULL;DWORD needed=0;int owner_ok=0;
    if(h==INVALID_HANDLE_VALUE||!GetFileInformationByHandle(h,&fi)||(fi.dwFileAttributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT)))return 0;
    rc=GetSecurityInfo(h,SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,&owner,NULL,&acl,NULL,&sd);
    if(rc!=ERROR_SUCCESS||!acl||!owner){if(sd)LocalFree(sd);error("Cannot inspect secret file security");return 0;}
    if(!CreateWellKnownSid(WinLocalSystemSid,NULL,system_sid,&sn)||!CreateWellKnownSid(WinBuiltinAdministratorsSid,NULL,admin_sid,&an)){LocalFree(sd);return 0;}
    if(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token)){GetTokenInformation(token,TokenUser,NULL,0,&needed);tu=malloc(needed);if(tu&&GetTokenInformation(token,TokenUser,tu,needed,&needed))owner_ok=EqualSid(owner,tu->User.Sid);free(tu);CloseHandle(token);}
    if(!owner_ok&&!EqualSid(owner,system_sid)&&!EqualSid(owner,admin_sid)){LocalFree(sd);error("Secret file belongs to another identity: %s",path);return 0;}
    for(i=0;i<acl->AceCount;i++){void *a=NULL;ACE_HEADER *ah;if(!GetAce(acl,i,&a)){LocalFree(sd);return 0;}ah=a;
        if(ah->AceType==ACCESS_ALLOWED_ACE_TYPE){ACCESS_ALLOWED_ACE *ace=a;PSID sid=&ace->SidStart;
            if((ace->Mask&(FILE_READ_DATA|FILE_WRITE_DATA|FILE_APPEND_DATA|WRITE_DAC|WRITE_OWNER|GENERIC_ALL|GENERIC_READ|GENERIC_WRITE))&&!EqualSid(sid,owner)&&!EqualSid(sid,system_sid)&&!EqualSid(sid,admin_sid)){LocalFree(sd);error("Secret file grants access to an additional identity: %s",path);return 0;}}
        else if(ah->AceType!=ACCESS_DENIED_ACE_TYPE&&ah->AceType!=SYSTEM_AUDIT_ACE_TYPE){LocalFree(sd);error("Unsupported secret file ACL: %s",path);return 0;}
    }LocalFree(sd);return 1;
#else
    struct stat st;if(fstat(fd,&st)||!S_ISREG(st.st_mode)||(st.st_uid!=0&&st.st_uid!=geteuid())||(st.st_mode&077)){error("Unsafe permissions on secret file: %s",path);return 0;}return 1;
#endif
}
static FILE *open_secret(const char *path){
    FILE *f;
#ifdef _WIN32
    wchar_t w[2048];HANDLE h;int fd;
    if(!MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,path,-1,w,2048))return NULL;
    h=CreateFileW(w,GENERIC_READ|READ_CONTROL,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,NULL);
    if(h==INVALID_HANDLE_VALUE)return NULL;
    fd=_open_osfhandle((intptr_t)h,_O_RDONLY|_O_TEXT);if(fd<0){CloseHandle(h);return NULL;}
    f=_fdopen(fd,"r");if(!f){_close(fd);return NULL;}
#else
    f=fopen(path,"r");if(!f)return NULL;
#endif
    if(!ppp_check_access(fileno(f),path,PPP_FT_SECRET)){fclose(f);return NULL;}return f;
}

/* Authorized address tokens are parsed by the original secret-file reader.
 * This host accepts literal IPv4/CIDR, '*' and '-' and rejects unsupported
 * per-peer options/hostname rules rather than silently granting permission. */
static int address_rule(const char *s,uint32_t *network,uint32_t *mask,int *permit){
    char b[64],*slash,*end;unsigned long bits=32;struct in_addr a;
    *permit=1;if(*s=='!'){*permit=0;s++;}if(!strcmp(s,"*")){*network=0;*mask=0;return 1;}
    if(!strcmp(s,"-")){*permit=0;*network=0;*mask=0;return 1;}
    if(strlen(s)>=sizeof(b))return 0;strcpy(b,s);slash=strchr(b,'/');if(slash){*slash++=0;bits=strtoul(slash,&end,10);if(!*slash||*end||bits>32)return 0;}
    if(inet_pton(AF_INET,b,&a)!=1)return 0;*mask=bits?0xffffffffu<<(32-bits):0;*network=ntohl(a.s_addr)&*mask;return 1;
}
static int keep_authorization(struct wordlist *a,struct wordlist *opts){
    struct wordlist *p;uint32_t n,m;int allow;
    if(opts){error("Per-peer secret-file options are not supported");free_wordlist(a);free_wordlist(opts);return 0;}
    for(p=a;p;p=p->next)if(!address_rule(p->word,&n,&m,&allow)){error("Unsupported address rule in secret file");free_wordlist(a);return 0;}
    free_wordlist(authorized);authorized=a;return 1;
}
int auth_ip_addr(int unit,uint32_t addr){
    struct wordlist *p;uint32_t n,m,h=ntohl(addr);int allow;(void)unit;
    if(ppp_bad_ip_addr(addr))return 0;if(!config.require_mask)return 1;
    if(!auth_active||auth_failed||(pending&1u))return 0;
    if(certificate_auth)return addr==config.peer_ip_be;
    for(p=authorized;p;p=p->next)if(address_rule(p->word,&n,&m,&allow)&&((h&m)==n))return allow;return 0;
}
static int lookup_secret(const char *path,char *client,char *server,char *secret,int is_server){
    FILE *f;struct wordlist *a=NULL,*o=NULL;int found;
    if(!*path)return 0;f=open_secret(path);if(!f){error("Cannot open the configured secret file securely");return 0;}
    found=scan_authfile(f,client,server,secret,&a,&o,(char*)path);fclose(f);
    if(found<0){free_wordlist(a);free_wordlist(o);return 0;}
    if(is_server)return keep_authorization(a,o);free_wordlist(a);free_wordlist(o);return 1;
}
int get_secret(int unit,char *client,char *server,char *secret,int *length,int is_server){
    char b[MAXWORDLEN];size_t n;(void)unit;
#ifdef PPP_WITH_EAPTLS
    /* With an explicit local certificate, EAP's existing fallback selects TLS. */
    if(is_server&&(config.cert[0]||config.pkcs12[0])&&eap_states[unit].es_server.ea_state==eapIdentify)return 0;
#endif
    memset(b,0,sizeof(b));if(!is_server&&passwd[0])strlcpy(b,passwd,sizeof(b));
    else if(!lookup_secret(config.chap_secrets,client,server,b,is_server))return 0;
    n=strlen(b);if(n>MAXSECRETLEN){ppp_explicit_bzero(b,sizeof(b));error("Authentication secret is too long");return 0;}
    memcpy(secret,b,n);*length=(int)n;ppp_explicit_bzero(b,sizeof(b));return 1;
}
int check_passwd(int unit,char *u,int un,char *p,int pn,char **message){
    char client[MAXNAMELEN],expected[MAXWORDLEN];size_t n;unsigned char diff=0;int i;
    (void)unit;*message="Authentication failed";
    if(un<0||un>=MAXNAMELEN||pn<0||pn>=MAXSECRETLEN||memchr(u,0,(size_t)un))return UPAP_AUTHNAK;
    memcpy(client,u,(size_t)un);client[un]=0;
    if(!lookup_secret(config.pap_secrets,client,our_name,expected,1))return UPAP_AUTHNAK;
    n=strlen(expected);if(n!=(size_t)pn){ppp_explicit_bzero(expected,sizeof(expected));return UPAP_AUTHNAK;}
    for(i=0;i<pn;i++)diff|=(unsigned char)(expected[i]^p[i]);ppp_explicit_bzero(expected,sizeof(expected));
    if(diff)return UPAP_AUTHNAK;*message="Authentication succeeded";return UPAP_AUTHACK;
}
int auth_number(void){return 1; /* No caller-number policy exists in this COM host. */}

static unsigned chap_bits(unsigned mask){unsigned m=0;if(mask&PPP_AUTH_CHAP_MD5)m|=MDTYPE_MD5;if(mask&PPP_AUTH_MSCHAP)m|=MDTYPE_MICROSOFT;if(mask&PPP_AUTH_MSCHAPV2)m|=MDTYPE_MICROSOFT_V2;return m;}
int ppp_auth_configure(const PppAuthConfig *c){
    if(!c)return -1;
#define CHECK_STRING(s) if(!memchr(c->s,0,sizeof(c->s)))return -1
    CHECK_STRING(user);CHECK_STRING(password);CHECK_STRING(name);CHECK_STRING(remotename);CHECK_STRING(pap_secrets);CHECK_STRING(chap_secrets);CHECK_STRING(ca);CHECK_STRING(cert);CHECK_STRING(key);CHECK_STRING(key_password);CHECK_STRING(capath);CHECK_STRING(crl_dir);CHECK_STRING(crl_file);CHECK_STRING(pkcs12);CHECK_STRING(max_tls_version);CHECK_STRING(tls_verify_method);CHECK_STRING(callback);
#undef CHECK_STRING
    if((c->require_mask|c->refuse_mask)&~PPP_AUTH_ALL)return -1;
#if !defined(PPP_WITH_EAPTLS) && !defined(PPP_WITH_PEAP)
    if(c->ca[0]||c->capath[0]||c->crl_dir[0]||c->crl_file[0]||c->max_tls_version[0]||c->tls_verify_method[0]){error("This build has no TLS authentication support");return -1;}
#endif
#ifndef PPP_WITH_EAPTLS
    if(c->cert[0]||c->key[0]||c->key_password[0]||c->pkcs12[0]||c->need_peer_eap){error("This build has no EAP-TLS authentication support");return -1;}
#endif
    config=*c;strlcpy(user,c->user,sizeof(user));strlcpy(passwd,c->password,sizeof(passwd));strlcpy(our_name,c->name[0]?c->name:(c->user[0]?c->user:"pppd"),sizeof(our_name));
    auth_required=c->require_mask!=0;
    if(!user[0])strlcpy(user,our_name,sizeof(user));strlcpy(remote_name,c->remotename,sizeof(remote_name));explicit_remote=remote_name[0]!=0;
#if defined(PPP_WITH_EAPTLS) || defined(PPP_WITH_PEAP)
    if(strlen(c->ca)>=MAXWORDLEN||strlen(c->cert)>=MAXWORDLEN||strlen(c->key)>=MAXWORDLEN||strlen(c->capath)>=MAXWORDLEN||strlen(c->pkcs12)>=MAXWORDLEN)return -1;
    if(c->tls_verify_method[0]&&strcmp(c->tls_verify_method,"name")&&strcmp(c->tls_verify_method,"subject")&&strcmp(c->tls_verify_method,"suffix")&&strcmp(c->tls_verify_method,"none"))return -1;
    if(c->max_tls_version[0]&&strcmp(c->max_tls_version,"1.0")&&strcmp(c->max_tls_version,"1.1")&&strcmp(c->max_tls_version,"1.2")&&strcmp(c->max_tls_version,"1.3"))return -1;
    cacert_file=config.ca[0]?config.ca:NULL;ca_path=config.capath[0]?config.capath:NULL;crl_dir=config.crl_dir[0]?config.crl_dir:NULL;crl_file=config.crl_file[0]?config.crl_file:NULL;
    pkcs12_file=config.pkcs12[0]?config.pkcs12:NULL;max_tls_version=config.max_tls_version[0]?config.max_tls_version:NULL;tls_verify_method=config.tls_verify_method[0]?config.tls_verify_method:TLS_VERIFY_NAME;tls_verify_key_usage=config.tls_verify_key_usage!=0;
    strlcpy(tls_key_password,config.key_password[0]?config.key_password:config.password,sizeof(tls_key_password));
#endif
    if(!crypto_started){if(!PPP_crypto_init())return -1;crypto_started=1;}return 0;
}
void auth_reset(int unit){
    lcp_options *wo=&lcp_wantoptions[unit],*ao=&lcp_allowoptions[unit];unsigned accept=PPP_AUTH_ALL&~config.refuse_mask;
    wo->neg_upap=(config.require_mask&PPP_AUTH_PAP)!=0;wo->neg_chap=chap_bits(config.require_mask)!=0;wo->chap_mdtype=(unsigned char)chap_bits(config.require_mask);wo->neg_eap=(config.require_mask&PPP_AUTH_EAP)!=0;
    ao->neg_upap=(accept&PPP_AUTH_PAP)!=0;ao->neg_chap=chap_bits(accept)!=0;ao->chap_mdtype=(unsigned char)chap_bits(accept);ao->neg_eap=(accept&PPP_AUTH_EAP)!=0;
    wo->neg_cbcp=config.callback[0]!=0;ao->neg_cbcp=0;
}
void ppp_auth_init(void){
    if(auth_initialized)ppp_auth_lowerdown(0);auth_initialized=1;
    pap_protent.init(0);chap_protent.init(0);eap_protent.init(0);
    free(cbcp[0].us_number);cbcp[0].us_number=NULL;cbcp_protent.init(0);cbcp_protent.enabled_flag=0;
    if(config.callback[0]){char *number=config.callback;ppp_cbcp_set(&number);}
    upap[0].us_timeouttime=config.pap_restart>0?config.pap_restart:3;upap[0].us_reqtimeout=config.pap_timeout;upap[0].us_maxtransmits=config.pap_max_authreq>0?config.pap_max_authreq:10;
    chap_server_timeout_time=config.chap_restart>0?config.chap_restart:3;chap_client_timeout_time=config.chap_timeout;chap_max_transmits=config.chap_max_challenge>0?config.chap_max_challenge:10;chap_rechallenge_time=config.chap_interval;chapms_strip_domain=config.chapms_strip_domain;
    eap_states[0].es_server.ea_timeout=config.eap_restart>0?config.eap_restart:3;eap_states[0].es_server.ea_maxrequests=config.eap_max_sreq>0?config.eap_max_sreq:10;
    eap_states[0].es_client.ea_timeout=config.eap_timeout;eap_states[0].es_client.ea_maxrequests=config.eap_max_rreq>0?config.eap_max_rreq:20;eap_states[0].es_rechallenge=config.eap_interval;
    pending=0;auth_done[0]=0;auth_active=auth_failed=network_started=certificate_auth=callback_started=0;free_wordlist(authorized);authorized=NULL;mppe_clear_keys();
}
static void maybe_network(int unit){if(auth_active&&!auth_failed&&!pending&&!network_started){if(lcp_gotoptions[unit].neg_cbcp){if(!callback_started){callback_started=1;cbcp_protent.lowerup(unit);cbcp_protent.open(unit);}return;}network_started=1;ppp_engine_network_start(unit);}}
void ppp_auth_start(int unit){
    lcp_options *go=&lcp_gotoptions[unit],*ho=&lcp_hisoptions[unit];
    pending=0;auth_done[unit]=0;auth_active=1;auth_failed=network_started=0;
    if(config.need_peer_eap&&!ho->neg_eap){auth_withpeer_fail(unit,PPP_EAP);return;}
    if(config.require_mask&&!go->neg_eap&&!go->neg_chap&&!go->neg_upap){auth_peer_fail(unit,0);return;}
    if(go->neg_eap||go->neg_chap||go->neg_upap)pending|=1;if(ho->neg_eap||ho->neg_chap||ho->neg_upap)pending|=2;
    pap_protent.lowerup(unit);chap_protent.lowerup(unit);eap_protent.lowerup(unit);new_phase(PHASE_AUTHENTICATE);
    if(go->neg_eap)eap_authpeer(unit,our_name);else if(go->neg_chap)chap_auth_peer(unit,our_name,CHAP_DIGEST(go->chap_mdtype));else if(go->neg_upap)upap_authpeer(unit);
    if(ho->neg_eap)eap_authwithpeer(unit,user);else if(ho->neg_chap)chap_auth_with_peer(unit,user,CHAP_DIGEST(ho->chap_mdtype));else if(ho->neg_upap){
        if(!passwd[0]){char b[MAXWORDLEN];if(!lookup_secret(config.pap_secrets,user,remote_name[0]?remote_name:NULL,b,0)||strlen(b)>=sizeof(passwd)){auth_withpeer_fail(unit,PPP_PAP);return;}strlcpy(passwd,b,sizeof(passwd));ppp_explicit_bzero(b,sizeof(b));}
        upap_authwithpeer(unit,user,passwd);
    }maybe_network(unit);
}
void auth_peer_fail(int unit,int proto){(void)proto;auth_failed=1;ppp_set_status(EXIT_PEER_AUTH_FAILED);lcp_close(unit,"Peer authentication failed");}
void auth_withpeer_fail(int unit,int proto){(void)proto;auth_failed=1;ppp_set_status(EXIT_AUTH_TOPEER_FAILED);lcp_close(unit,"Authentication to peer failed");}
static int auth_bits(int proto,int digest,int peer){if(proto==PPP_PAP)return peer?PAP_PEER:PAP_WITHPEER;if(proto==PPP_EAP)return peer?EAP_PEER:EAP_WITHPEER;int b=peer?CHAP_PEER:CHAP_WITHPEER;if(digest==0x80)b|=peer?CHAP_MS_PEER:CHAP_MS_WITHPEER;else if(digest==0x81)b|=peer?CHAP_MS2_PEER:CHAP_MS2_WITHPEER;else b|=peer?CHAP_MD5_PEER:CHAP_MD5_WITHPEER;return b;}
void auth_peer_success(int unit,int proto,int digest,char *name,int len){(void)name;(void)len;if(!auth_active||!(pending&1))return;auth_done[unit]|=auth_bits(proto,digest,1);pending&=~1u;maybe_network(unit);}
void auth_withpeer_success(int unit,int proto,int digest){if(!auth_active||!(pending&2))return;auth_done[unit]|=auth_bits(proto,digest,0);pending&=~2u;maybe_network(unit);}
void ppp_auth_lowerdown(int unit){
    eap_state *esp=&eap_states[unit];auth_active=0;pending=0;
    if(dispatch_depth){lowerdown_deferred=1;return;}lowerdown_deferred=0;
    pap_protent.lowerdown(unit);chap_protent.lowerdown(unit);eap_protent.lowerdown(unit);
    if(esp->es_server.ea_peer&&esp->es_server.ea_peer!=remote_name)free(esp->es_server.ea_peer);esp->es_server.ea_peer=NULL;
    free(esp->es_client.ea_peer);esp->es_client.ea_peer=NULL;
#ifdef PPP_WITH_EAPTLS
    if(esp->es_server.ea_session)eaptls_free_session(esp->es_server.ea_session);esp->es_server.ea_session=NULL;
    if(esp->es_client.ea_session)eaptls_free_session(esp->es_client.ea_session);esp->es_client.ea_session=NULL;
#endif
#ifdef PPP_WITH_PEAP
    peap_finish(&esp->ea_peap);
#endif
    free_wordlist(authorized);authorized=NULL;mppe_clear_keys();
}
int ppp_auth_dispatch(unsigned short protocol,const unsigned char *payload,int length){
    struct protent *p=NULL;unsigned char *copy;
    if(protocol==PPP_PAP)p=&pap_protent;else if(protocol==PPP_CHAP)p=&chap_protent;else if(protocol==PPP_EAP)p=&eap_protent;else if(protocol==PPP_CBCP&&cbcp_protent.enabled_flag&&callback_started&&!pending)p=&cbcp_protent;else return 0;
    if(!auth_active||auth_failed||length<0||length>16384)return 1;
    copy=malloc(length?(size_t)length:1);if(!copy){auth_peer_fail(0,protocol);return 1;}memcpy(copy,payload,(size_t)length);dispatch_depth++;p->input(0,copy,length);dispatch_depth--;ppp_explicit_bzero(copy,(size_t)length);free(copy);if(!dispatch_depth&&lowerdown_deferred)ppp_auth_lowerdown(0);return 1;
}
void start_networks(int unit){if(auth_active&&!auth_failed&&!pending&&!network_started){network_started=1;ppp_engine_network_start(unit);}}
#ifdef PPP_WITH_EAPTLS
int get_eaptls_secret(int unit,char *client,char *server,char *clicert,char *servcert,char *cacert,char *capath,char *key,char *p12,int is_server){
    (void)unit;(void)server;clicert[0]=servcert[0]=cacert[0]=capath[0]=key[0]=p12[0]=0;
    if(!config.pkcs12[0]&&(!(config.ca[0]||config.capath[0])||!config.cert[0]||!config.key[0]))return 0;
    if(is_server&&(!client||(config.remotename[0]&&strcmp(client,config.remotename))||!config.peer_ip_be))return 0;
    strlcpy(is_server?servcert:clicert,config.cert,MAXWORDLEN);strlcpy(cacert,config.ca,MAXWORDLEN);strlcpy(capath,config.capath,MAXWORDLEN);strlcpy(key,config.key,MAXWORDLEN);strlcpy(p12,config.pkcs12,MAXWORDLEN);
    if(is_server)certificate_auth=1;return 1;
}
#endif
