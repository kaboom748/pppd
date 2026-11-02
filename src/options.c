/* Windows configuration and catalogue for the Microburst PPP port.
 * The catalogue is shared by help and recognition; no unavailable handler runs.
 */
#define WIN32_LEAN_AND_MEAN
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0602
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <aclapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <stdint.h>
#include <limits.h>
#include <errno.h>
#include "options.h"
#include "vendor/ppp/pppdconf.h"

#define CONFIG_LIMIT (1024u*1024u)
#define INCLUDE_LIMIT 16
#define WORD_LIMIT 1023
#define PATH_CAP 4096
#define NATIVE_PATH_CAP (PATH_CAP+4)
typedef struct OptionMeta {
 const char *name,*syntax,*status,*detail,*context,*source,*guard,*alias;
} OptionMeta;
#include "catalogue.inc"
typedef struct Source {
 char description[2400]; unsigned line,argument;
} Source;
typedef struct Identity { DWORD volume,index_hi,index_lo; } Identity;
typedef struct Parse {
 AppOptions *o; char *error; size_t error_size; wchar_t root[PATH_CAP];
 unsigned depth; size_t total; Identity chain[INCLUDE_LIMIT];
 Source source, provenance[24],include_source[INCLUDE_LIMIT];
} Parse;
static const char *last_error="E_INTERNAL";
static Source last_provenance[24];
enum { P_DEVICE,P_BAUD,P_BITS,P_PARITY,P_STOP,P_FLOW,P_IP,P_MTU,P_MRU,P_ACCM,
 P_ESCAPE,P_ECHOI,P_ECHOF,P_HOLDOFF,P_MAXFAIL,P_IFNAME,P_LINKNAME,P_DEBUG,
 P_DUMP,P_PERSIST,P_DRYRUN,P_NODETACH };

const char *options_error_code(void) { return last_error; }
static int errorf(Parse *p,const char *code,const char *fmt,...) {
 char message[2600]; va_list ap; va_start(ap,fmt);
 vsnprintf(message,sizeof(message),fmt,ap); va_end(ap); last_error=code;
 if(!p->error||!p->error_size)return -1;
 if(p->source.description[0]) snprintf(p->error,p->error_size,"%s (%s, ligne %u, argument %u)",message,p->source.description,p->source.line,p->source.argument);
 else snprintf(p->error,p->error_size,"%s",message);
 for(unsigned i=0;i<p->depth;i++) {
  const Source *s=&p->include_source[i];size_t used=strlen(p->error);
  if(used+1>=p->error_size)break;
  snprintf(p->error+used,p->error_size-used," %s %s:%u",i?"->":"via",s->description,s->line);
 }
 return -1;
}
static int mark(Parse *p,int field) { p->provenance[field]=p->source; return 0; }
static int to_wide(const char *s,wchar_t *out,size_t cap) {
 return MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,s,-1,out,(int)cap)>0?0:-1;
}
static int to_utf8(const wchar_t *s,char *out,size_t cap) {
 return WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,s,-1,out,(int)cap,NULL,NULL)>0?0:-1;
}
static int valid_utf8(const char *s,size_t size) {
 if(size>INT_MAX || memchr(s,0,size)) return 0;
 if(!size) return 1;
 return MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,s,(int)size,NULL,0)>0;
}
static int copy_string(Parse *p,char *dest,size_t cap,const char *value,const char *name) {
 if(strlen(value)>=cap) return errorf(p,"E_OPT_VALUE","Valeur trop longue pour %s",name);
 memcpy(dest,value,strlen(value)+1); return 0;
}
static int is_decimal(const char *s) {
 if(!*s) return 0;
 for(;*s;s++) if(*s<'0'||*s>'9') return 0;
 return 1;
}
static int number(Parse *p,const char *s,unsigned base,uint32_t *out,const char *name) {
 uint64_t n=0; int digits=0;
 if(base==16 && s[0]=='0' && (s[1]=='x'||s[1]=='X')) s+=2;
 for(;*s;s++) {
  unsigned d; if(*s>='0'&&*s<='9') d=(unsigned)(*s-'0');
  else if(base==16&&*s>='a'&&*s<='f') d=(unsigned)(*s-'a'+10);
  else if(base==16&&*s>='A'&&*s<='F') d=(unsigned)(*s-'A'+10);
  else return errorf(p,"E_OPT_VALUE","Entier malforme pour %s",name);
  if(d>=base || n>(UINT32_MAX-d)/base) return errorf(p,"E_OPT_VALUE","Entier hors limites pour %s",name);
  n=n*base+d; digits++;
 }
 if(!digits) return errorf(p,"E_OPT_VALUE","Entier manquant pour %s",name);
 *out=(uint32_t)n; return 0;
}
static int exact_number(Parse *p,const char *s,unsigned base,uint32_t expected,const char *name) {
 uint32_t n; if(number(p,s,base,&n,name)) return -1;
 if(n!=expected) return errorf(p,"E_OPT_VALUE_UNSUPPORTED","Valeur non supportee pour %s; attendu %lu",name,(unsigned long)expected);
 return 0;
}
static int identifier(const char *s,size_t max,int first_alnum) {
 size_t n=strlen(s); if(!n||n>max||!strcmp(s,".")||!strcmp(s,"..")) return 0;
 for(size_t i=0;i<n;i++) {
  unsigned char c=(unsigned char)s[i];
  if((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')) continue;
  if((first_alnum&&i==0)||(c!='_'&&c!='-'&&c!='.')) return 0;
 }
 return 1;
}
static int ipv4(const char *s,uint32_t *out) {
 uint8_t b[4];
 for(unsigned i=0;i<4;i++) {
  unsigned n=0,d=0; if(*s<'0'||*s>'9') return -1;
  while(*s>='0'&&*s<='9') { n=n*10+(unsigned)(*s++-'0'); if(++d>3||n>255) return -1; }
  b[i]=(uint8_t)n; if(i<3 && *s++!='.') return -1;
 }
 if(*s||b[0]==0||b[0]==127||b[0]>=224) return -1;
 memcpy(out,b,4); return 0;
}
void options_format_ip(uint32_t ip,char out[16]) {
 uint8_t b[4];memcpy(b,&ip,4);snprintf(out,16,"%u.%u.%u.%u",b[0],b[1],b[2],b[3]);
}
void options_defaults(AppOptions *o) {
 memset(o,0,sizeof(*o)); o->baud=115200;o->data_bits=8;o->stop_bits=1;o->flow=1;
 o->mtu=o->mru=1500;o->receive_accm=0x000a0000;o->holdoff=3;o->persist=1;
 o->data.ccp_enabled=o->data.vj_enabled=o->data.vj_cid=1;o->data.vj_slots=16;
 o->data.bsd_receive_bits=o->data.bsd_allow_bits=15;
 o->data.deflate_receive_bits=o->data.deflate_allow_bits=15;
 o->data.deflate_correct=o->data.deflate_draft=1;
 o->data.mppe_allow_40=o->data.mppe_allow_128=1;
 o->data.ccp_timeout=3;o->data.ccp_max_configure=10;o->data.ccp_max_terminate=2;o->data.ccp_max_failure=10;
 o->lcp_timeout=o->ipcp_timeout=3;
 o->lcp_max_configure=o->ipcp_max_configure=10;
 o->lcp_max_terminate=o->ipcp_max_terminate=2;
 o->lcp_max_failure=o->ipcp_max_failure=10;o->lcp_loopback_failure=10;
 o->ipv6cp_timeout=3;o->ipv6cp_max_configure=10;o->ipv6cp_max_terminate=2;o->ipv6cp_max_failure=10;
 o->auth.timeout=3;o->auth.max_transmits=10;
 o->auth.pap_restart=3;o->auth.pap_timeout=30;o->auth.pap_max_authreq=10;
 o->auth.chap_restart=3;o->auth.chap_timeout=60;o->auth.chap_max_challenge=10;
 o->auth.eap_restart=3;o->auth.eap_timeout=20;o->auth.eap_max_sreq=10;o->auth.eap_max_rreq=20;
#ifdef PPP_WITH_EAPTLS
 o->auth.eap_max_sreq=30;
#endif
#if defined(PPP_WITH_EAPTLS) || defined(PPP_WITH_PEAP)
 strcpy(o->auth.max_tls_version,"1.2");strcpy(o->auth.tls_verify_method,"name");o->auth.tls_verify_key_usage=1;
#endif
 o->transmit_accm[0x11/8]|=(uint8_t)(1u<<(0x11%8));
 o->transmit_accm[0x13/8]|=(uint8_t)(1u<<(0x13%8));
}
static const OptionMeta *find_option(const char *name) {
 for(size_t i=0;i<sizeof(catalogue)/sizeof(catalogue[0]);i++)
  if(!strchr(catalogue[i].name,' ')&&!strcmp(name,catalogue[i].name)) return &catalogue[i];
 return NULL;
}
static int tls_option_kind(const char *name) {
 if(!strcmp(name,"ca")||!strcmp(name,"capath")||!strcmp(name,"crl-dir")||!strcmp(name,"crl")||
    !strcmp(name,"max-tls-version")||!strcmp(name,"tls-verify-key-usage")||!strcmp(name,"tls-verify-method"))return 1;
 if(!strcmp(name,"cert")||!strcmp(name,"key")||!strcmp(name,"pkcs12")||!strcmp(name,"need-peer-eap"))return 2;
 return 0;
}
static const char *effective_status(const OptionMeta *meta) {
 int kind=tls_option_kind(meta->name);(void)kind;
#if !defined(PPP_WITH_EAPTLS) && !defined(PPP_WITH_PEAP)
 if(kind==1)return "UNSUPPORTED";
#endif
#ifndef PPP_WITH_EAPTLS
 if(kind==2)return "UNSUPPORTED";
#endif
 return meta->status;
}
/* A protected root/file must not have a writable grant to an unrelated SID.
 * Actual SIDs and Windows ACL masks are used; CRT Unix permission bits are not.
 */
static int protected_object(Parse *p,HANDLE h) {
 PSID owner=NULL; PACL dacl=NULL; PSECURITY_DESCRIPTOR sd=NULL;
 DWORD r=GetSecurityInfo(h,SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,&owner,NULL,&dacl,NULL,&sd);
 if(r!=ERROR_SUCCESS||!dacl) { if(sd)LocalFree(sd);return errorf(p,"E_CFG_PATH","DACL de configuration absente ou illisible"); }
 HANDLE token=NULL; DWORD need=0; TOKEN_USER *user=NULL; BYTE admin_buf[SECURITY_MAX_SID_SIZE],system_buf[SECURITY_MAX_SID_SIZE];
 DWORD admin_size=sizeof(admin_buf),system_size=sizeof(system_buf); int ok=1;
 if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token)) ok=0;
 if(ok) { GetTokenInformation(token,TokenUser,NULL,0,&need);user=(TOKEN_USER*)malloc(need);if(!user||!GetTokenInformation(token,TokenUser,user,need,&need))ok=0; }
 if(!CreateWellKnownSid(WinBuiltinAdministratorsSid,NULL,admin_buf,&admin_size)||!CreateWellKnownSid(WinLocalSystemSid,NULL,system_buf,&system_size))ok=0;
 if(ok&&(!owner||(!EqualSid(owner,user->User.Sid)&&!EqualSid(owner,admin_buf)&&!EqualSid(owner,system_buf))))ok=0;
 const DWORD writes=GENERIC_WRITE|GENERIC_ALL|WRITE_DAC|WRITE_OWNER|DELETE|FILE_WRITE_DATA|FILE_APPEND_DATA|FILE_WRITE_EA|FILE_WRITE_ATTRIBUTES|FILE_DELETE_CHILD;
 for(DWORD i=0;ok&&i<dacl->AceCount;i++) {
  void *raw=NULL;if(!GetAce(dacl,i,&raw)){ok=0;break;}
  ACE_HEADER *header=(ACE_HEADER*)raw;
  if(header->AceFlags&INHERIT_ONLY_ACE)continue;
  if(header->AceType==ACCESS_ALLOWED_ACE_TYPE) {
   ACCESS_ALLOWED_ACE *a=(ACCESS_ALLOWED_ACE*)raw; PSID sid=(PSID)&a->SidStart;
   if((a->Mask&writes)&&!EqualSid(sid,user->User.Sid)&&!EqualSid(sid,admin_buf)&&!EqualSid(sid,system_buf)) ok=0;
  } else if(header->AceType==ACCESS_ALLOWED_OBJECT_ACE_TYPE||header->AceType==ACCESS_ALLOWED_CALLBACK_ACE_TYPE||header->AceType==ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE) {
   /* Unknown conditional/object write grants cannot establish this contract. */
   ACCESS_MASK mask=*(ACCESS_MASK*)((BYTE*)raw+sizeof(ACE_HEADER));if(mask&writes)ok=0;
  }
 }
 if(token)CloseHandle(token);
 free(user);LocalFree(sd);
 return ok?0:errorf(p,"E_CFG_PATH","Configuration modifiable par un principal non autorise");
}
/* GetFullPathNameW resolves relative components before this boundary. Only
 * fully qualified local drive paths enter the extended Win32 namespace.
 * This preserves real directories named con and removes MAX_PATH truncation;
 * the canonical identity used for containment/IPC remains a plain DOS path.
 */
static int native_path(Parse *p,const wchar_t *path,wchar_t out[NATIVE_PATH_CAP]) {
 size_t n=wcslen(path);
 if(n<3||n>=PATH_CAP||path[1]!=L':'||path[2]!=L'\\')return errorf(p,"E_CFG_PATH","Chemin absolu local requis");
 memcpy(out,L"\\\\?\\",4*sizeof(wchar_t));memcpy(out+4,path,(n+1)*sizeof(wchar_t));return 0;
}
static void normalize_slashes(wchar_t *path) {
 for(;*path;path++)if(*path==L'/')*path=L'\\';
}
static int no_reparse(Parse *p,const wchar_t *path) {
 wchar_t part[PATH_CAP];size_t n=wcslen(path);
 if(n>=PATH_CAP||n<3||path[1]!=L':'||(path[2]!=L'\\'&&path[2]!=L'/'))return errorf(p,"E_CFG_PATH","Chemin absolu local requis");
 memcpy(part,path,(n+1)*sizeof(wchar_t));normalize_slashes(part);
 wchar_t drive[4]={part[0],L':',L'\\',0};if(GetDriveTypeW(drive)==DRIVE_REMOTE)return errorf(p,"E_CFG_PATH","Chemin reseau interdit");
 for(size_t i=3;i<=n;i++)if(part[i]==L'\\'||part[i]==0) {
  wchar_t c=part[i],native[NATIVE_PATH_CAP];part[i]=0;
  if(native_path(p,part,native)){part[i]=c;return -1;}
  DWORD attrs=GetFileAttributesW(native);part[i]=c;
  if(attrs!=INVALID_FILE_ATTRIBUTES&&(attrs&FILE_ATTRIBUTE_REPARSE_POINT))return errorf(p,"E_CFG_PATH","Reparse point interdit dans la configuration");
 }
 return 0;
}
static int final_path(Parse *p,HANDLE h,wchar_t out[PATH_CAP]) {
 wchar_t raw[PATH_CAP];DWORD n=GetFinalPathNameByHandleW(h,raw,PATH_CAP,FILE_NAME_NORMALIZED|VOLUME_NAME_DOS);
 if(!n||n>=PATH_CAP)return errorf(p,"E_CFG_PATH","Impossible de canoniser la configuration");
 const wchar_t *s=raw;if(!wcsncmp(s,L"\\\\?\\",4))s+=4;
 if(wcslen(s)<3||s[1]!=L':')return errorf(p,"E_CFG_PATH","Objet final non local");
 wcscpy(out,s);size_t len=wcslen(out);while(len>3&&out[len-1]==L'\\')out[--len]=0;return 0;
}
static int canonical_root(Parse *p,const char *utf8) {
 wchar_t path[PATH_CAP],absolute[PATH_CAP],native[NATIVE_PATH_CAP];
 if(to_wide(utf8,path,PATH_CAP))return errorf(p,"E_CFG_PATH","Chemin de configuration UTF-8 incorrect");
 if(wcslen(path)<3||path[1]!=L':'||(path[2]!=L'/'&&path[2]!=L'\\'))return errorf(p,"E_CFG_PATH","Racine absolue locale requise");
 normalize_slashes(path);
 DWORD n=GetFullPathNameW(path,PATH_CAP,absolute,NULL);
 if(!n||n>=PATH_CAP)return errorf(p,"E_CFG_PATH","Racine impossible a canoniser");
 if(no_reparse(p,absolute))return -1;
 if(native_path(p,absolute,native))return -1;
 HANDLE h=CreateFileW(native,READ_CONTROL|FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,NULL,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,NULL);
 if(h==INVALID_HANDLE_VALUE)return errorf(p,"E_CFG_PATH","Racine de configuration absente ou inaccessible : %.1500s (Win32 %lu)",utf8,(unsigned long)GetLastError());
 BY_HANDLE_FILE_INFORMATION info;int rc=0;
 if(!GetFileInformationByHandle(h,&info)||!(info.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY))rc=errorf(p,"E_CFG_PATH","La racine doit etre un repertoire");
 if(!rc)rc=protected_object(p,h);
 if(!rc)rc=final_path(p,h,p->root);
 CloseHandle(h);
 if(!rc&&to_utf8(p->root,p->o->config_dir,sizeof(p->o->config_dir)))rc=errorf(p,"E_CFG_PATH","Racine trop longue");
 return rc;
}
static int root_contains(Parse *p,const wchar_t *path) {
 size_t n=wcslen(p->root);return !_wcsnicmp(path,p->root,n)&&(path[n]==L'\\'||path[n]==0||(n==3&&p->root[2]==L'\\'));
}
/* Only an explicit file/call requests a filesystem root in portable mode.
 * Direct CLI, information and stop never inspect the executable directory or
 * any machine configuration. File lookup is rooted beside the executable,
 * independently of the caller's working directory. */
static int file_root(Parse *p) {
 if(p->root[0])return 0;
 wchar_t executable[PATH_CAP];DWORD n=GetModuleFileNameW(NULL,executable,PATH_CAP);
 if(!n||n>=PATH_CAP)return errorf(p,"E_CFG_PATH","Dossier de l'executable indisponible");
 wchar_t *path=executable;if(!wcsncmp(path,L"\\\\?\\",4))path+=4;
 normalize_slashes(path);wchar_t *last=wcsrchr(path,L'\\');
 if(!last)return errorf(p,"E_CFG_PATH","Dossier de l'executable invalide");
 if(last==path+2)last[1]=0;else *last=0;
 char utf8[PATH_CAP];if(to_utf8(path,utf8,sizeof(utf8)))return errorf(p,"E_CFG_PATH","Dossier de l'executable trop long");
 return canonical_root(p,utf8);
}
static int parse_words(Parse*,int,const char *const*,const unsigned*,unsigned);
static int load_file(Parse *p,const char *value,int peer,unsigned priority,int optional) {
 wchar_t path[PATH_CAP],absolute[PATH_CAP],final[PATH_CAP],native[NATIVE_PATH_CAP];char relative[PATH_CAP];
 if(file_root(p))return -1;
 if(p->depth>=INCLUDE_LIMIT)return errorf(p,"E_CFG_LIMIT","Profondeur d'inclusion superieure a 16");
 if(peer) {
  if(!identifier(value,63,0))return errorf(p,"E_CFG_PATH","Nom de profil call invalide");
  snprintf(relative,sizeof(relative),"peers/%s",value);value=relative;
 } else if(!strncmp(value,"/etc/ppp/",9))value+=9;
 if(to_wide(value,path,PATH_CAP))return errorf(p,"E_CFG_PATH","Chemin d'inclusion UTF-8 incorrect");
 if(wcslen(path)>2&&path[1]==L':') {
  if(wcslen(path)<3||(path[2]!=L'/'&&path[2]!=L'\\'))return errorf(p,"E_CFG_PATH","Chemin relatif au lecteur interdit");
  wcscpy(absolute,path);
 } else {
  if(path[0]==L'/'||path[0]==L'\\')return errorf(p,"E_CFG_PATH","Chemin absolu non Windows ou reseau interdit");
  if(swprintf(absolute,PATH_CAP,L"%ls\\%ls",p->root,path)<0)return errorf(p,"E_CFG_PATH","Chemin d'inclusion trop long");
 }
 normalize_slashes(absolute);
 DWORD n=GetFullPathNameW(absolute,PATH_CAP,path,NULL);
 if(!n||n>=PATH_CAP||!root_contains(p,path))return errorf(p,"E_CFG_PATH","Inclusion hors de la racine autorisee");
 if(no_reparse(p,path))return -1;
 if(native_path(p,path,native))return -1;
 HANDLE h=CreateFileW(native,GENERIC_READ|READ_CONTROL,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,NULL);
 if(h==INVALID_HANDLE_VALUE) {
  DWORD e=GetLastError();if(optional&&(e==ERROR_FILE_NOT_FOUND||e==ERROR_PATH_NOT_FOUND))return 0;
  return errorf(p,"E_CFG_READ","Fichier de configuration inaccessible (Win32 %lu)",(unsigned long)e);
 }
 int rc=final_path(p,h,final);BY_HANDLE_FILE_INFORMATION info;memset(&info,0,sizeof(info));
 if(!rc&&(!root_contains(p,final)||!GetFileInformationByHandle(h,&info)||(info.dwFileAttributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT))))rc=errorf(p,"E_CFG_PATH","Objet d'inclusion final invalide");
 if(!rc)rc=protected_object(p,h);
 Identity id={info.dwVolumeSerialNumber,info.nFileIndexHigh,info.nFileIndexLow};
 for(unsigned i=0;!rc&&i<p->depth;i++)if(!memcmp(&id,&p->chain[i],sizeof(id)))rc=errorf(p,"E_CFG_CYCLE","Cycle d'inclusion detecte par identite de fichier");
 LARGE_INTEGER size;if(!rc&&(!GetFileSizeEx(h,&size)||size.QuadPart<0||(uint64_t)size.QuadPart>CONFIG_LIMIT-p->total))rc=errorf(p,"E_CFG_LIMIT","Volume total de configuration superieur a 1 MiB");
 char *data=NULL;if(!rc){data=(char*)malloc((size_t)size.QuadPart+1);if(!data)rc=errorf(p,"E_INTERNAL","Memoire insuffisante");}
 if(!rc) { DWORD got=0;if(!ReadFile(h,data,(DWORD)size.QuadPart,&got,NULL)||got!=(DWORD)size.QuadPart)rc=errorf(p,"E_CFG_READ","Lecture incomplete de la configuration");else {p->total+=got;data[got]=0;if(!valid_utf8(data,got))rc=errorf(p,"E_CFG_READ","UTF-8 incorrect ou NUL dans la configuration");} }
 CloseHandle(h);if(rc){free(data);return -1;}
 size_t bytes=(size_t)size.QuadPart;
 char **words=(char**)calloc(bytes+1,sizeof(char*));unsigned *lines=(unsigned*)calloc(bytes+1,sizeof(unsigned));
 if(!words||!lines){free(data);free(words);free(lines);return errorf(p,"E_INTERNAL","Memoire insuffisante");}
 Source old=p->source;
 if(to_utf8(final,p->source.description,sizeof(p->source.description))){free(words);free(lines);free(data);return errorf(p,"E_CFG_PATH","Nom de configuration trop long");}
 char *s=data,*out=data;int count=0;unsigned line=1;
 if(bytes>=3&&(unsigned char)s[0]==0xef&&(unsigned char)s[1]==0xbb&&(unsigned char)s[2]==0xbf)s+=3;
 while(*s&&!rc) {
  while(*s&&isspace((unsigned char)*s)){if(*s=='\n')line++;s++;}
  if(*s=='#'){while(*s&&*s!='\n')s++;continue;}if(!*s)break;
  words[count]=out;lines[count++]=line;p->source.line=line;p->source.argument=0;char quote=0;size_t length=0;
  while(*s) {
   if(!quote&&(isspace((unsigned char)*s)||*s=='#'))break;
   if(*s=='\''||*s=='"') {if(!quote){quote=*s++;continue;}if(quote==*s){quote=0;s++;continue;}}
   char c=*s++;
   if(c=='\\') {
    if(!*s){rc=errorf(p,"E_CFG_READ","Echappement incomplet en fin de fichier");break;}
    c=*s++;
    if(c=='\r'&&*s=='\n'){s++;line++;continue;}
    if(c=='\n'){line++;continue;}
    if(c=='n')c='\n';else if(c=='r')c='\r';else if(c=='t')c='\t';else if(c=='b')c='\b';else if(c=='f')c='\f';else if(c=='s')c=' ';
    else if(c>='0'&&c<='7') {
     unsigned escaped=(unsigned)(c-'0');for(unsigned digits=1;digits<3&&*s>='0'&&*s<='7';digits++)escaped=escaped*8+(unsigned)(*s++-'0');
     c=(char)escaped;
    } else if(c=='x') {
     unsigned escaped=0,digits=0;while(digits<2&&isxdigit((unsigned char)*s)) {unsigned d=(unsigned char)*s++;escaped=escaped*16+(d<='9'?d-'0':(d<='F'?d-'A'+10:d-'a'+10));digits++;}
     if(digits)c=(char)escaped;
    }
    if(!c){rc=errorf(p,"E_CFG_READ","NUL decode dans la configuration");break;}
   }
   if(c=='\n')line++;
   if(++length>WORD_LIMIT){rc=errorf(p,"E_CFG_LIMIT","Mot de configuration superieur a 1023 octets");break;}*out++=c;
  }
  if(!rc&&quote)rc=errorf(p,"E_CFG_READ","Quote non fermee dans la configuration");
  if(*s=='#'){while(*s&&*s!='\n')s++;}
  else if(*s){if(*s=='\n')line++;s++;}
  *out++=0;
 }
 if(!rc) {
  p->include_source[p->depth]=old;p->chain[p->depth++]=id;
  rc=parse_words(p,count,(const char*const*)words,lines,priority);p->depth--;
 }
 p->source=old;free(words);free(lines);free(data);return rc;
}
static int parse_escape(Parse *p,const char *value) {
 uint8_t map[32];memcpy(map,p->o->transmit_accm,sizeof(map));const char *s=value;
 /* Preserve tty.c:setescape's additive map and comma/space separators. */
 while(*s) {
  while(*s==','||*s==' '||*s=='\t')s++;
  if(!*s)break;
  const char *start=s;
  while(*s&&*s!=','&&*s!=' '&&*s!='\t')s++;
  const char *end=s;
  if(end==start||end-start>10)return errorf(p,"E_OPT_VALUE","Liste escape malformee");
  char token[12];memcpy(token,start,(size_t)(end-start));token[end-start]=0;uint32_t n;
  if(number(p,token,16,&n,"escape"))return -1;
  if(n>255)return errorf(p,"E_OPT_VALUE_UNSUPPORTED","Octet escape hors limites");
  map[n/8]|=(uint8_t)(1u<<(n%8));
 }
 if(map[0x5e/8]&(1u<<(0x5e%8)))return errorf(p,"E_OPT_VALUE","escape refuse 5e comme pppd original");
 memcpy(p->o->transmit_accm,map,sizeof(map));return mark(p,P_ESCAPE);
}
/* The protocol machines and their defaults remain upstream. This table only
 * maps the Windows CLI to their existing configuration fields. */
static unsigned *unsigned_option(AppOptions *o,const char *key,unsigned *minimum) {
 *minimum=0;
#define UOPT(name,field,min) if(!strcmp(key,name)){*minimum=min;return &o->field;}
 UOPT("lcp-echo-interval",echo_interval,0) UOPT("lcp-echo-failure",echo_failure,0)
 UOPT("lcp-restart",lcp_timeout,1) UOPT("lcp-max-configure",lcp_max_configure,1)
 UOPT("lcp-max-terminate",lcp_max_terminate,0) UOPT("lcp-max-failure",lcp_max_failure,0)
 UOPT("ipcp-restart",ipcp_timeout,1) UOPT("ipcp-max-configure",ipcp_max_configure,1)
 UOPT("ipcp-max-terminate",ipcp_max_terminate,0) UOPT("ipcp-max-failure",ipcp_max_failure,0)
 UOPT("ipv6cp-restart",ipv6cp_timeout,1) UOPT("ipv6cp-max-configure",ipv6cp_max_configure,1)
 UOPT("ipv6cp-max-terminate",ipv6cp_max_terminate,0) UOPT("ipv6cp-max-failure",ipv6cp_max_failure,0)
 UOPT("holdoff",holdoff,0) UOPT("maxfail",maxfail,0) UOPT("maxconnect",maxconnect,0)
 UOPT("idle",idle,0)
 UOPT("defaultroute-metric",default_route_metric,0)
#undef UOPT
 return NULL;
}
static int *auth_integer(PppAuthConfig *a,const char *key,unsigned *minimum) {
 *minimum=0;
#define AOPT(name,field,min) if(!strcmp(key,name)){*minimum=min;return &a->field;}
 AOPT("pap-restart",pap_restart,1) AOPT("pap-timeout",pap_timeout,0) AOPT("pap-max-authreq",pap_max_authreq,1)
 AOPT("chap-restart",chap_restart,1) AOPT("chap-timeout",chap_timeout,0) AOPT("chap-max-challenge",chap_max_challenge,1)
 AOPT("chap-interval",chap_interval,0) AOPT("eap-restart",eap_restart,1) AOPT("eap-timeout",eap_timeout,0)
 AOPT("eap-max-sreq",eap_max_sreq,1) AOPT("eap-max-rreq",eap_max_rreq,1) AOPT("eap-interval",eap_interval,0)
#undef AOPT
 return NULL;
}
static uint32_t auth_method(const char *key,const char *prefix) {
 size_t n=strlen(prefix);if(strncmp(key,prefix,n))return 0;key+=n;
 if(!strcmp(key,"pap"))return PPP_AUTH_PAP;
 if(!strcmp(key,"chap"))return PPP_AUTH_CHAP_MD5;
 if(!strcmp(key,"mschap"))return PPP_AUTH_MSCHAP;
 if(!strcmp(key,"mschap-v2"))return PPP_AUTH_MSCHAPV2;
 if(!strcmp(key,"eap"))return PPP_AUTH_EAP;
 return 0;
}
/* Original ccp.c:setbsdcomp/setdeflate parsing semantics, mapped to host
 * fields. A zero value disables one direction. Deflate window8 is promoted
 * to9 by upstream to avoid the historic zlib window8 bug. */
static int compression_pair(Parse *p,const char *value,int deflate) {
 char *end=NULL;unsigned long r,a;
 if(!value||!isdigit((unsigned char)value[0]))return errorf(p,"E_OPT_VALUE","Parametre de compression invalide");
 errno=0;r=strtoul(value,&end,0);a=r;
 if(errno||end==value)return errorf(p,"E_OPT_VALUE","Parametre de compression invalide");
 if(*end==','){
  const char *second=end+1;
  if(!isdigit((unsigned char)second[0]))return errorf(p,"E_OPT_VALUE","Deuxieme valeur de compression invalide");
  errno=0;a=strtoul(second,&end,0);
  if(errno||end==second)return errorf(p,"E_OPT_VALUE","Deuxieme valeur de compression invalide");
 }
 unsigned low=deflate?8:9;
 if(*end||(r&&(r<low||r>15))||(a&&(a<low||a>15)))return errorf(p,"E_OPT_VALUE","Compression: valeurs 0 ou %u..15 requises",low);
 if(deflate){if(r==8)r=9;if(a==8)a=9;p->o->data.deflate_receive_bits=(int)r;p->o->data.deflate_allow_bits=(int)a;}
 else{p->o->data.bsd_receive_bits=(int)r;p->o->data.bsd_allow_bits=(int)a;}
 return 0;
}
static int parse_ipv6_ids(Parse *p,const char *value) {
 char pair[128];if(copy_string(p,pair,sizeof(pair),value,"ipv6"))return -1;
 char *remote=strchr(pair,',');if(remote)*remote++=0;
 if(remote&&strchr(remote,','))return errorf(p,"E_OPT_VALUE","ipv6 attend <identifiant-local>,<identifiant-pair>");
 char *sides[2]={pair,remote};uint8_t *ids[2]={p->o->ipv6_local_id,p->o->ipv6_peer_id};
 for(unsigned i=0;i<2;i++)if(sides[i]&&sides[i][0]) {
  IN6_ADDR address;uint8_t zero[8]={0};
  if(InetPtonA(AF_INET6,sides[i],&address)!=1||memcmp(address.u.Byte,zero,8)||!memcmp(address.u.Byte+8,zero,8))
   return errorf(p,"E_OPT_VALUE","Identifiant IPv6 non nul de 64 bits requis (exemple ::1,::2)");
  memcpy(ids[i],address.u.Byte+8,8);
 }
 p->o->ipv6_enabled=1;return 0;
}
static int parse_words(Parse *p,int argc,const char *const *argv,const unsigned *lines,unsigned priority) {
 (void)priority; /* Initial file is parsed first; inclusions retain caller order/priority. */
 AppOptions *o=p->o;
 for(int i=0;i<argc;i++) {
  const char *name=argv[i],*value=NULL;p->source.line=lines?lines[i]:0;p->source.argument=lines?0:(unsigned)i+1;
  if(!valid_utf8(name,strlen(name)))return errorf(p,"E_OPT_VALUE","Argument UTF-8 incorrect");
  if(!strcmp(name,"--config-dir")||!strcmp(name,"--stop")||!strcmp(name,"--help")||!strcmp(name,"-h")||!strcmp(name,"show-options")||!strcmp(name,"--version")||!strcmp(name,"-v"))return errorf(p,"E_CLI_MODE","Commande autonome utilisee dans une liaison ou un fichier");
  const OptionMeta *meta=find_option(name);
  if(meta&&!strcmp(effective_status(meta),"UNSUPPORTED"))return errorf(p,"E_OPT_UNSUPPORTED","Option non supportee : %s",name);
  const char *key=meta&&*meta->alias?meta->alias:name;
  unsigned minimum=0;unsigned *unsigned_target=unsigned_option(o,key,&minimum);unsigned auth_minimum=0;int *auth_target=auth_integer(&o->auth,key,&auth_minimum);
  if(meta&&(strstr(meta->syntax," <")||unsigned_target||auth_target||!strcmp(key,"data-bits"))) {
   if(++i>=argc)return errorf(p,"E_OPT_ARG_MISSING","Argument manquant pour %s",name);
   value=argv[i];
   if(!valid_utf8(value,strlen(value)))return errorf(p,"E_OPT_VALUE","Argument UTF-8 incorrect pour %s",name);
  }
  if(!strcmp(key,"file")||!strcmp(key,"call")){if(load_file(p,value,!strcmp(key,"call"),priority,0))return -1;continue;}
  if(!strcmp(key,"local")||!strcmp(key,"lock"))continue;
  if(!strcmp(key,"noccp")){o->data.ccp_enabled=0;continue;}
  if(!strcmp(key,"novj")){o->data.vj_enabled=0;continue;}
  if(!strcmp(key,"novjccomp")){o->data.vj_cid=0;continue;}
  if(!strcmp(key,"vj-max-slots")){
   char *end;errno=0;unsigned long n=strtoul(value,&end,0);
   if(errno||end==value||*end||n<2||n>16)return errorf(p,"E_OPT_VALUE","vj-max-slots accepte 2..16");
   o->data.vj_slots=(unsigned)n;continue;
  }
  if(!strcmp(key,"bsdcomp")||!strcmp(key,"deflate")){if(compression_pair(p,value,!strcmp(key,"deflate")))return -1;continue;}
  if(!strcmp(key,"nobsdcomp")){o->data.bsd_receive_bits=o->data.bsd_allow_bits=0;continue;}
  if(!strcmp(key,"nodeflate")){o->data.deflate_receive_bits=o->data.deflate_allow_bits=0;continue;}
  if(!strcmp(key,"nodeflatedraft")){o->data.deflate_draft=0;continue;}
  if(!strcmp(key,"require-mppe")){o->data.mppe_required=o->data.mppe_allow_40=o->data.mppe_allow_128=1;continue;}
  if(!strcmp(key,"require-mppe-40")||!strcmp(key,"require-mppe-128")){
   if(!o->data.mppe_required)o->data.mppe_allow_40=o->data.mppe_allow_128=0;
   o->data.mppe_required=1;
   if(!strcmp(key,"require-mppe-40"))o->data.mppe_allow_40=1;else o->data.mppe_allow_128=1;
   continue;
  }
  if(!strcmp(key,"nomppe")){o->data.mppe_required=o->data.mppe_allow_40=o->data.mppe_allow_128=0;continue;}
  if(!strcmp(key,"nomppe-40")){o->data.mppe_allow_40=0;continue;}
  if(!strcmp(key,"nomppe-128")){o->data.mppe_allow_128=0;continue;}
  if(!strcmp(key,"mppe-stateful")){o->data.mppe_stateful=1;continue;}
  if(!strcmp(key,"nomppe-stateful")){o->data.mppe_stateful=0;continue;}
  if(unsigned_target||auth_target) {
   uint32_t n;if(number(p,value,10,&n,name))return -1;
   unsigned lower=unsigned_target?minimum:auth_minimum;
   if(n<lower||n>INT_MAX)return errorf(p,"E_OPT_VALUE","%s accepte %u..%d",name,lower,INT_MAX);
   if(unsigned_target)*unsigned_target=n;else *auth_target=(int)n;
   if(!strcmp(key,"lcp-echo-interval"))mark(p,P_ECHOI);else if(!strcmp(key,"lcp-echo-failure"))mark(p,P_ECHOF);
   else if(!strcmp(key,"holdoff"))mark(p,P_HOLDOFF);else if(!strcmp(key,"maxfail"))mark(p,P_MAXFAIL);
   continue;
  }
  if(!strcmp(key,"auth")){o->auth.require_mask=PPP_AUTH_ALL;continue;}
  if(!strcmp(key,"noauth")){o->auth.require_mask=0;continue;}
  uint32_t method=auth_method(key,"require-");if(method){o->auth.require_mask|=method;continue;}
  method=auth_method(key,"refuse-");if(method){o->auth.refuse_mask|=method;continue;}
  if(!strcmp(key,"chapms-strip-domain")){o->auth.chapms_strip_domain=1;continue;}
  char *auth_string=NULL;size_t auth_size=0;
#define ASTRING(option,field) if(!strcmp(key,option)){auth_string=o->auth.field;auth_size=sizeof(o->auth.field);}
  ASTRING("user",user) ASTRING("password",password) ASTRING("name",name) ASTRING("remotename",remotename)
  ASTRING("pap-secrets",pap_secrets) ASTRING("chap-secrets",chap_secrets)
  ASTRING("ca",ca) ASTRING("capath",capath) ASTRING("crl-dir",crl_dir) ASTRING("crl",crl_file)
  ASTRING("cert",cert) ASTRING("key",key) ASTRING("pkcs12",pkcs12) ASTRING("callback",callback)
#undef ASTRING
  if(auth_string){if(copy_string(p,auth_string,auth_size,value,name))return -1;continue;}
  if(!strcmp(key,"max-tls-version")){
   if(strcmp(value,"1.0")&&strcmp(value,"1.1")&&strcmp(value,"1.2")&&strcmp(value,"1.3"))return errorf(p,"E_OPT_VALUE","max-tls-version accepte 1.0,1.1,1.2,1.3");
   strcpy(o->auth.max_tls_version,value);continue;
  }
  if(!strcmp(key,"tls-verify-method")){
   if(strcmp(value,"none")&&strcmp(value,"subject")&&strcmp(value,"name")&&strcmp(value,"suffix"))return errorf(p,"E_OPT_VALUE","tls-verify-method accepte none,subject,name,suffix");
   strcpy(o->auth.tls_verify_method,value);continue;
  }
  if(!strcmp(key,"tls-verify-key-usage")){o->auth.tls_verify_key_usage=1;continue;}
  if(!strcmp(key,"need-peer-eap")){o->auth.need_peer_eap=1;continue;}
  if(!strcmp(key,"lcp-rtt-file")){if(copy_string(p,o->rtt_file,sizeof(o->rtt_file),value,name))return -1;continue;}
  if(!strcmp(key,"passive")){o->passive=1;continue;}
  if(!strcmp(key,"silent")){o->silent=1;continue;}
  if(!strcmp(key,"noaccomp")){o->noaccomp=1;continue;}
  if(!strcmp(key,"nopcomp")){o->nopcomp=1;continue;}
  if(!strcmp(key,"nomagic")){o->nomagic=1;continue;}
  if(!strcmp(key,"default-asyncmap")){o->asyncmap_disabled=1;o->receive_accm=UINT32_MAX;continue;}
  if(!strcmp(key,"default-mru")){o->default_mru=1;o->mru=1500;continue;}
  if(!strcmp(key,"receive-all")){o->receive_all=1;continue;}
  if(!strcmp(key,"lcp-echo-adaptive")){o->echo_adaptive=1;continue;}
  if(!strcmp(key,"ipcp-accept-local")){o->ipcp_accept_local=1;continue;}
  if(!strcmp(key,"ipcp-accept-remote")){o->ipcp_accept_remote=1;continue;}
  if(!strcmp(key,"ipcp-no-address")){o->ipcp_no_address=1;continue;}
  if(!strcmp(key,"ipcp-no-addresses")){o->ipcp_no_addresses=1;continue;}
  if(!strcmp(key,"noipdefault"))continue; /* No hostname-derived address in this native port. */
  if(!strcmp(key,"usepeerdns")){o->usepeerdns=1;continue;}
  if(!strcmp(key,"noip")){o->ipv4_disabled=1;continue;}
  if(!strcmp(key,"+ipv6")){o->ipv6_enabled=1;continue;}
  if(!strcmp(key,"noipv6")){o->ipv6_enabled=0;continue;}
  if(!strcmp(key,"ipv6")){if(parse_ipv6_ids(p,value))return -1;continue;}
  if(!strcmp(key,"ipv6cp-accept-local")){o->ipv6_accept_local=1;continue;}
  if(!strcmp(key,"ipv6cp-accept-remote")){o->ipv6_accept_remote=1;continue;}
  if(!strcmp(key,"ipv6cp-use-ipaddr")){o->ipv6_use_ipaddr=1;continue;}
  if(!strcmp(key,"ipv6cp-nosend")){o->ipv6_no_send=1;continue;}
  if(!strcmp(key,"defaultroute")){o->default_route=1;continue;}
  if(!strcmp(key,"nodefaultroute")){o->default_route=0;continue;}
  if(!strcmp(key,"ms-dns")||!strcmp(key,"ms-wins")) {
   uint32_t address;if(ipv4(value,&address))return errorf(p,"E_OPT_VALUE","Adresse IPv4 unicast requise pour %s",name);
   uint32_t *addresses=!strcmp(key,"ms-dns")?o->dns:o->wins;
   if(!addresses[0])addresses[0]=addresses[1]=address;else addresses[1]=address;
   continue;
  }
  if(!strcmp(key,"nocrtscts")){o->flow=0;mark(p,P_FLOW);continue;}
  if(!strcmp(key,"xonxoff")){o->flow=1;mark(p,P_FLOW);continue;}
  if(!strcmp(key,"crtscts")){o->flow=2;mark(p,P_FLOW);continue;}
  if(!strcmp(key,"nodetach")){o->nodetach=1;mark(p,P_NODETACH);continue;}
  if(!strcmp(key,"persist")){o->persist=1;mark(p,P_PERSIST);continue;}
  if(!strcmp(key,"nopersist")){o->persist=0;mark(p,P_PERSIST);continue;}
  if(!strcmp(key,"debug")){if(o->debug<INT_MAX)o->debug++;mark(p,P_DEBUG);continue;}
  if(!strcmp(key,"dump")){o->dump=1;mark(p,P_DUMP);continue;}
  if(!strcmp(key,"dryrun")){o->dry_run=1;mark(p,P_DRYRUN);continue;}
  if(!strcmp(key,"ifname")||!strcmp(key,"linkname")) {
   size_t max=!strcmp(key,"ifname")?15:63;if(!identifier(value,max,1))return errorf(p,"E_OPT_VALUE","Identifiant ASCII invalide pour %s",name);
   if(!strcmp(key,"ifname")){strcpy(o->ifname,value);mark(p,P_IFNAME);}else{strcpy(o->linkname,value);mark(p,P_LINKNAME);}continue;
  }
  if(!strcmp(key,"escape")){if(parse_escape(p,value))return -1;continue;}
  if(!strcmp(key,"asyncmap")){uint32_t n;if(number(p,value,16,&n,name))return -1;o->receive_accm|=n;mark(p,P_ACCM);continue;}
  if(!strcmp(key,"mtu")||!strcmp(key,"mru")){
   uint32_t n;if(number(p,value,10,&n,name))return -1;
   if(n<128||n>16384)return errorf(p,"E_OPT_VALUE_UNSUPPORTED","%s accepte 128..16384",name);
   if(!strcmp(key,"mtu"))o->mtu=(uint16_t)n;else{o->mru=(uint16_t)n;o->default_mru=0;}
   mark(p,!strcmp(key,"mtu")?P_MTU:P_MRU);continue;
  }
  if(!strcmp(key,"stop-bits")){uint32_t n;if(number(p,value,10,&n,name))return -1;if(n!=1&&n!=2)return errorf(p,"E_OPT_VALUE_UNSUPPORTED","stop-bits accepte 1 ou 2");o->stop_bits=n;mark(p,P_STOP);continue;}
  if(!strcmp(key,"data-bits")){if(exact_number(p,value,10,8,name))return -1;o->data_bits=8;mark(p,P_BITS);continue;}
  if(!strcmp(key,"parity")) {
   static const char *const parity[]={"none","odd","even","mark","space"};int n;
   for(n=0;n<5;n++)if(!strcmp(value,parity[n]))break;
   if(n==5)return errorf(p,"E_OPT_VALUE_UNSUPPORTED","parity accepte none, odd, even, mark ou space");
   o->parity=n;mark(p,P_PARITY);continue;
  }
  const char *port=name;if(!_strnicmp(port,"\\\\.\\",4))port+=4;
  if(!_strnicmp(port,"COM",3)) {
   uint32_t n;if(number(p,port+3,10,&n,"COM"))return -1;
   if(n<1||n>65535)return errorf(p,"E_OPT_VALUE_UNSUPPORTED","COM doit etre compris entre 1 et 65535");
   snprintf(o->device,sizeof(o->device),"COM%lu",(unsigned long)n);mark(p,P_DEVICE);continue;
  }
  if(is_decimal(name)){uint32_t n;if(number(p,name,10,&n,"baud"))return -1;if(!n)return errorf(p,"E_OPT_VALUE_UNSUPPORTED","La vitesse doit etre positive");o->baud=n;mark(p,P_BAUD);continue;}
  if(strchr(name,':')) {
   char pair[64];if(copy_string(p,pair,sizeof(pair),name,"paire IPv4"))return -1;char *colon=strchr(pair,':');
   *colon++=0;
   uint32_t local=0,peer=0;
   if(strchr(colon,':')||(*pair&&strcmp(pair,"0.0.0.0")&&ipv4(pair,&local))||(*colon&&strcmp(colon,"0.0.0.0")&&ipv4(colon,&peer))||(local&&local==peer))
    return errorf(p,"E_OPT_VALUE","Paire IPv4 unicast distincte requise; cote vide ou 0.0.0.0 pour negocier");
   o->local_ip_be=local;o->peer_ip_be=peer;mark(p,P_IP);continue;
  }
  return errorf(p,"E_OPT_UNKNOWN","Option inconnue : %.100s",name);
 }
 return 0;
}
int options_parse(AppOptions *o,int argc,const char *const *argv,char *error,size_t error_size) {
 Parse p;memset(&p,0,sizeof(p));p.o=o;p.error=error;p.error_size=error_size;last_error="E_INTERNAL";if(error_size)error[0]=0;
 for(size_t i=0;i<sizeof(p.provenance)/sizeof(p.provenance[0]);i++)strcpy(p.provenance[i].description,"defaut MICROBURST");
 if(!argc){o->help=1;return errorf(&p,"E_CLI_MODE","Aucun argument; COM et paire IPv4 requis");}
 for(int i=0;i<argc;i++) {
  int help=!strcmp(argv[i],"--help")||!strcmp(argv[i],"-h")||!strcmp(argv[i],"show-options");
  int version=!strcmp(argv[i],"--version")||!strcmp(argv[i],"-v");
  if(help||version){if(argc!=1)return errorf(&p,"E_CLI_MODE","Commande d'information autonome requise");o->help=help;o->version=version;return 0;}
 }
 const char *root=NULL;int start=0;
 o->config_explicit=0;o->config_dir[0]=0;
 if(!strcmp(argv[0],"--config-dir")){if(argc<3)return errorf(&p,"E_CLI_MODE","--config-dir requiert une racine et une commande");root=argv[1];o->config_explicit=1;start=2;}
 for(int i=start;i<argc;i++)if(!strcmp(argv[i],"--config-dir"))return errorf(&p,"E_CLI_MODE","--config-dir doit apparaitre une fois en tete de CLI");
 if(root&&canonical_root(&p,root))return -1;
 if(!strcmp(argv[start],"--stop")) {
  if(argc-start!=2)return errorf(&p,"E_CLI_MODE","--stop est exclusif des options de liaison");
  if(!identifier(argv[start+1],63,1))return errorf(&p,"E_OPT_VALUE","linkname d'arret invalide");
  strcpy(o->stop_name,argv[start+1]);return 0;
 }
 for(int i=start;i<argc;i++)if(!strcmp(argv[i],"--stop"))return errorf(&p,"E_CLI_MODE","--stop est exclusif des options de liaison");
 if(o->config_explicit&&load_file(&p,"options",0,1,1))return -1;
 strcpy(p.source.description,"CLI");
 if(parse_words(&p,argc-start,argv+start,NULL,2))return -1;
 if(o->data.mppe_required&&(!o->data.ccp_enabled||(!o->data.mppe_allow_40&&!o->data.mppe_allow_128)))return errorf(&p,"E_CFG_PROFILE","MPPE obligatoire exige CCP et au moins un mode 40/128 bits");
 if(!o->device[0])return errorf(&p,"E_CFG_PROFILE","Port COM obligatoire");
 if(o->ipv4_disabled&&!o->ipv6_enabled)return errorf(&p,"E_CFG_PROFILE","Au moins IPv4 ou IPv6 doit etre active");
 if(o->ipv6_enabled&&(o->mtu<1280||o->mru<1280))return errorf(&p,"E_OPT_VALUE","IPv6 exige mtu et mru >= 1280");
 if(!o->local_ip_be)o->ipcp_accept_local=1;
 if(!o->peer_ip_be)o->ipcp_accept_remote=1;
 if(!o->ifname[0])snprintf(o->ifname,sizeof(o->ifname),"ppp%lu",(unsigned long)GetCurrentProcessId());
 if(!o->linkname[0])strcpy(o->linkname,o->ifname);
 memcpy(last_provenance,p.provenance,sizeof(last_provenance));return 0;
}
static void print_source(const char *key,int index) {
 const Source *s=&last_provenance[index];printf("# %s: %s",key,s->description[0]?s->description:"defaut MICROBURST");
 if(s->line)printf(":%u",s->line);
 if(s->argument)printf(" argument %u",s->argument);
 putchar('\n');
}
static void print_quoted_option(const char *name,const char *value) {
 printf("%s \"",name);
 for(const unsigned char *s=(const unsigned char*)value;*s;s++){
  if(*s=='\\'||*s=='\"')printf("\\%c",*s);
  else if(*s=='\n')fputs("\\n",stdout);else if(*s=='\r')fputs("\\r",stdout);else if(*s=='\t')fputs("\\t",stdout);
  else if(*s<32||*s==127)printf("\\x%02x",*s);else putchar(*s);
 }
 puts("\"");
}
void options_print(const AppOptions *o) {
 char local[16],peer[16];options_format_ip(o->local_ip_be,local);options_format_ip(o->peer_ip_be,peer);
 static const char *const parity[]={"none","odd","even","mark","space"};
 if(o->config_explicit)printf("# Configuration effective; racine explicite %s\n",o->config_dir);
 else if(o->config_dir[0])printf("# Mode autonome; fichiers demandes explicitement sous %s\n",o->config_dir);
 else puts("# Mode autonome; configuration uniquement en ligne de commande, aucun fichier implicite");
 printf("%s\n",o->device);print_source("device",P_DEVICE);
 printf("%u\n",o->baud);print_source("baud",P_BAUD);
 printf("data-bits %u\n",o->data_bits);print_source("data-bits",P_BITS);
 printf("parity %s\n",parity[o->parity]);print_source("parity",P_PARITY);
 printf("stop-bits %u\n",o->stop_bits);print_source("stop-bits",P_STOP);
 printf("%s\n",o->flow==1?"xonxoff":(o->flow==2?"crtscts":"nocrtscts"));print_source("flow",P_FLOW);
 printf("%s:%s\n",local,peer);print_source("IPv4",P_IP);
 printf("ifname %s\n",o->ifname);print_source("ifname",P_IFNAME);
 printf("linkname %s\n",o->linkname);print_source("linkname",P_LINKNAME);
 puts("local\nlock");
 if(!o->data.ccp_enabled)puts("noccp");
 if(!o->data.vj_enabled)puts("novj");
 if(!o->data.vj_cid)puts("novjccomp");
 printf("vj-max-slots %u\n",o->data.vj_slots);
 printf("bsdcomp %d,%d\ndeflate %d,%d\n",o->data.bsd_receive_bits,o->data.bsd_allow_bits,o->data.deflate_receive_bits,o->data.deflate_allow_bits);
 if(!o->data.deflate_draft)puts("nodeflatedraft");
 if(o->data.mppe_required){
  if(o->data.mppe_allow_40)puts("require-mppe-40");
  if(o->data.mppe_allow_128)puts("require-mppe-128");
 }else puts("nomppe");
 puts(o->data.mppe_stateful?"mppe-stateful":"nomppe-stateful");
 puts(o->ipv4_disabled?"noip":"# IPv4 actif");
 puts(o->ipv6_enabled?"+ipv6":"noipv6");
 puts(o->default_route?"defaultroute":"nodefaultroute");
 if(o->default_route_metric)printf("defaultroute-metric %u\n",o->default_route_metric);
 if(!o->auth.require_mask)puts("noauth");
 static const struct {uint32_t mask;const char *suffix;} methods[]={
  {PPP_AUTH_PAP,"pap"},{PPP_AUTH_CHAP_MD5,"chap"},{PPP_AUTH_MSCHAP,"mschap"},{PPP_AUTH_MSCHAPV2,"mschap-v2"},{PPP_AUTH_EAP,"eap"}};
 for(size_t i=0;i<sizeof(methods)/sizeof(methods[0]);i++){
  if(o->auth.require_mask&methods[i].mask)printf("require-%s\n",methods[i].suffix);
  if(o->auth.refuse_mask&methods[i].mask)printf("refuse-%s\n",methods[i].suffix);
 }
 if(o->auth.user[0])print_quoted_option("user",o->auth.user);
 if(o->auth.name[0])print_quoted_option("name",o->auth.name);
 if(o->auth.remotename[0])print_quoted_option("remotename",o->auth.remotename);
 if(o->auth.password[0])puts("# password [redacted]");
 if(o->auth.pap_secrets[0])print_quoted_option("pap-secrets",o->auth.pap_secrets);
 if(o->auth.chap_secrets[0])print_quoted_option("chap-secrets",o->auth.chap_secrets);
 if(o->auth.callback[0])print_quoted_option("callback",o->auth.callback);
 if(o->auth.ca[0])print_quoted_option("ca",o->auth.ca);
 if(o->auth.capath[0])print_quoted_option("capath",o->auth.capath);
 if(o->auth.crl_dir[0])print_quoted_option("crl-dir",o->auth.crl_dir);
 if(o->auth.crl_file[0])print_quoted_option("crl",o->auth.crl_file);
 if(o->auth.cert[0])print_quoted_option("cert",o->auth.cert);
 if(o->auth.key[0])print_quoted_option("key",o->auth.key);
 if(o->auth.pkcs12[0])print_quoted_option("pkcs12",o->auth.pkcs12);
 if(o->auth.ca[0]||o->auth.capath[0]){
  print_quoted_option("max-tls-version",o->auth.max_tls_version);
  print_quoted_option("tls-verify-method",o->auth.tls_verify_method);
  if(o->auth.tls_verify_key_usage)puts("tls-verify-key-usage");
 }
 if(o->auth.need_peer_eap)puts("need-peer-eap");
 printf("asyncmap %08lx\n",(unsigned long)o->receive_accm);print_source("asyncmap",P_ACCM);
 fputs("escape ",stdout);int first=1;
 for(unsigned i=0;i<256;i++)if(i!=0x7d&&i!=0x7e&&(o->transmit_accm[i/8]&(1u<<(i%8)))){printf("%s%x",first?"":",",i);first=0;}
 putchar('\n');print_source("escape",P_ESCAPE);
 printf("mtu %u\n",o->mtu);print_source("mtu",P_MTU);
 printf("mru %u\n",o->mru);print_source("mru",P_MRU);
 printf("lcp-echo-interval %u\n",o->echo_interval);print_source("lcp-echo-interval",P_ECHOI);
 printf("lcp-echo-failure %u\n",o->echo_failure);print_source("lcp-echo-failure",P_ECHOF);
 puts(o->persist?"persist":"nopersist");print_source("persist",P_PERSIST);
 printf("holdoff %u\n",o->holdoff);print_source("holdoff",P_HOLDOFF);
 printf("maxfail %u\n",o->maxfail);print_source("maxfail",P_MAXFAIL);
 printf("maxconnect %u\nidle %u\n",o->maxconnect,o->idle);
#define PRINT_FLAG(field,option) if(o->field)puts(option)
 PRINT_FLAG(echo_adaptive,"lcp-echo-adaptive");PRINT_FLAG(passive,"passive");PRINT_FLAG(silent,"silent");
 PRINT_FLAG(noaccomp,"noaccomp");PRINT_FLAG(nopcomp,"nopcomp");PRINT_FLAG(nomagic,"nomagic");
 PRINT_FLAG(asyncmap_disabled,"default-asyncmap");PRINT_FLAG(default_mru,"default-mru");PRINT_FLAG(receive_all,"receive-all");
 PRINT_FLAG(ipcp_accept_local,"ipcp-accept-local");PRINT_FLAG(ipcp_accept_remote,"ipcp-accept-remote");
 PRINT_FLAG(ipcp_no_address,"ipcp-no-address");PRINT_FLAG(ipcp_no_addresses,"ipcp-no-addresses");PRINT_FLAG(usepeerdns,"usepeerdns");
 PRINT_FLAG(ipv6_accept_local,"ipv6cp-accept-local");PRINT_FLAG(ipv6_accept_remote,"ipv6cp-accept-remote");
 PRINT_FLAG(ipv6_use_ipaddr,"ipv6cp-use-ipaddr");PRINT_FLAG(ipv6_no_send,"ipv6cp-nosend");
#undef PRINT_FLAG
#define PRINT_UINT(option,field) printf(option " %u\n",o->field)
 PRINT_UINT("lcp-restart",lcp_timeout);PRINT_UINT("lcp-max-configure",lcp_max_configure);PRINT_UINT("lcp-max-terminate",lcp_max_terminate);PRINT_UINT("lcp-max-failure",lcp_max_failure);
 PRINT_UINT("ipcp-restart",ipcp_timeout);PRINT_UINT("ipcp-max-configure",ipcp_max_configure);PRINT_UINT("ipcp-max-terminate",ipcp_max_terminate);PRINT_UINT("ipcp-max-failure",ipcp_max_failure);
 PRINT_UINT("ipv6cp-restart",ipv6cp_timeout);PRINT_UINT("ipv6cp-max-configure",ipv6cp_max_configure);PRINT_UINT("ipv6cp-max-terminate",ipv6cp_max_terminate);PRINT_UINT("ipv6cp-max-failure",ipv6cp_max_failure);
#undef PRINT_UINT
 if(o->rtt_file[0])print_quoted_option("lcp-rtt-file",o->rtt_file);
 for(unsigned i=0;i<2;i++){
  if(o->dns[i]){char ip[16];options_format_ip(o->dns[i],ip);printf("ms-dns %s\n",ip);}
  if(o->wins[i]){char ip[16];options_format_ip(o->wins[i],ip);printf("ms-wins %s\n",ip);}
 }
 if(o->ipv6_enabled)printf("ipv6 ::%x:%x:%x:%x,::%x:%x:%x:%x\n",
  (o->ipv6_local_id[0]<<8)|o->ipv6_local_id[1],(o->ipv6_local_id[2]<<8)|o->ipv6_local_id[3],(o->ipv6_local_id[4]<<8)|o->ipv6_local_id[5],(o->ipv6_local_id[6]<<8)|o->ipv6_local_id[7],
  (o->ipv6_peer_id[0]<<8)|o->ipv6_peer_id[1],(o->ipv6_peer_id[2]<<8)|o->ipv6_peer_id[3],(o->ipv6_peer_id[4]<<8)|o->ipv6_peer_id[5],(o->ipv6_peer_id[6]<<8)|o->ipv6_peer_id[7]);
 if(o->nodetach)puts("nodetach");
 for(int i=0;i<o->debug;i++)puts("debug");
 print_source("debug",P_DEBUG);print_source("nodetach",P_NODETACH);
}
void options_help(void) {
 puts("pppd.exe Windows x64 0.4.0 - PPP IPv4/IPv6 / Wintun\nCode protocolaire pppd 2.5.5; integration Windows native\n"
 "Usage: pppd.exe [--config-dir C:/chemin/protege] COM10 115200 10.253.77.1:10.253.77.2 [options]\n"
 "       pppd.exe [--config-dir C:/chemin/protege] call microburst-a [nodetach debug]\n"
 "       pppd.exe [--config-dir C:/chemin/protege] --stop microburst-a\n"
 "       pppd.exe --help | -h | show-options | --version | -v\n"
 "Les commandes d'information sont autonomes et fonctionnent sans elevation, DLL, COM ou configuration.\n"
 "Liaison, dryrun et --stop exigent elevation. DLL: wintun.dll x64 dans le dossier de pppd.exe.\n"
 "Defauts: 115200, 8N1, XON/XOFF, MTU/MRU1500, ACCM000a0000, escape11,13,\n"
 "local/noauth/lock/noipv6/nodefaultroute, Echo0/0, persist holdoff3 maxfail0.\n"
 "Compression: VJ TCP/IPv4, BSD-Compress et Deflate PPP; chiffrement MPPE40/128.\n"
 "Authentification: auth/noauth, require-/refuse-pap|chap|mschap|mschap-v2|eap;\n"
 "user/password/name/remotename, pap-secrets/chap-secrets explicites; aucun PAM/compte Unix.\n"
 "Les delais PAP/CHAP/EAP et LCP/IPCP/IPv6CP sont configurables, voir catalogue.\n"
#ifdef PPP_WITH_EAPTLS
 "EAP-TLS disponible: ca/capath, cert/key ou pkcs12, remotename; verification de certificat active.\n"
#endif
#ifdef PPP_WITH_PEAP
 "PEAP client disponible avec CA, remotename et user/password.\n"
 "Limites PEAP upstream: retransmissions et emission de reponses fragmentees non implementees.\n"
#endif
#if !defined(PPP_WITH_EAPTLS) && !defined(PPP_WITH_PEAP)
 "Ce build n inclut pas TLS/PEAP: leurs options sont refusees explicitement.\n"
#endif
 "callback <numero>: client CBCP, demande le rappel par le pair puis termine avec code14.\n"
 "Defauts compression: CCP actif, VJ16 slots/CID, BSD15 et Deflate15, MPPE desactive.\n"
 "bsdcomp r[,a]: 0 ou9..15; deflate r[,a]: 0 ou8..15 (8 devient9).\n"
 "require-mppe[-40|-128] impose MPPE; mppe-stateful autorise le mode avec etat.\n"
 "MPPE exclut les autres compressions CCP; noccp/novj permettent leur desactivation.\n"
 "Aucun composeur modem Windows. Multilink, Predictor/MPPC et ECP restent refuses.\n"
 "La vitesse et le flux sont configurables: baud1..4294967295, nocrtscts, xonxoff, crtscts;\n"
 "stop-bits1|2, parity none|odd|even|mark|space. Le pilote doit accepter le format demande.\n"
 "PPP binaire requiert 8 bits de donnees; data-bits8 est une extension Windows explicite.\n"
 "COM1..65535 obligatoire. IPv4: local:pair; un cote vide ou 0.0.0.0 demande sa negociation.\n"
 "IPv6: +ipv6 ou ipv6 ::1,::2; noip permet IPv6 seul; noipv6 le desactive.\n"
 "MTU/MRU128..16384, au moins1280 avec IPv6. ACCM32 bits et escape00..ff sauf5e.\n"
 "passive/silent, noaccomp/nopcomp/nomagic, lcp-echo-interval/failure/adaptive et lcp-rtt-file disponibles.\n"
 "persist/nopersist, holdoff, maxfail, maxconnect et idle sont configurables.\n"
 "ifname ASCII1..15 (defaut ppp<PID>), linkname ASCII1..63 (defaut ifname).\n"
 "Mode autonome par defaut: aucune racine ni configuration a preparer; seuls pppd.exe et wintun.dll sont requis.\n"
 "Aucun fichier options n'est charge implicitement sans --config-dir.\n"
 "--config-dir choisit une racine explicite protegee: options facultatif, puis CLI de gauche a droite.\n"
 "Sans --config-dir, les fichiers call/file demandes explicitement sont cherches dans le dossier de l'executable.\n"
 "call <nom> = racine/peers/<nom>; file relatif a racine; /etc/ppp/ est un alias de racine.\n"
 "Les fichiers optionnels restent proteges: ni UNC ni reparse point ni sortie de leur racine.\n"
 "UTF-8 strict, BOM admis; inclusions16, total1MiB, mot1023 octets; cycles refuses.\n"
 "Aucun .ppprc/options.<tty>/secret/plugin/script Unix implicite. Aucun mapping /dev vers COM.\n"
 "dryrun valide/imprime sans DLL, COM ou carte; dump imprime puis poursuit.\n"
 "Une carte Wintun par instance; IPv4/route pair /32 et IPv6 lien-local.\n"
 "defaultroute ajoute une route IPv4 possedee; defaultroute-metric choisit sa metrique.\n"
 "usepeerdns applique les DNS negocies a l interface; ms-dns/ms-wins offrent des adresses au pair.\n"
 "usepeerwins, proxyarp, route IPv6 par defaut, plugins et scripts restent refuses.\n"
 "SUPPORTED signifie implemente; LIMITED indique une limite documentee; UNSUPPORTED est refuse.\n"
 "La qualification materielle et les empreintes du binaire sont documentees dans le rapport de validation.\n"
 "Test IP radio isole sur le meme hote: non supporte. Qualifier sur deux systemes distincts.\n"
 "Sorties: 0 succes, 1 interne/controle/nettoyage, 2 CLI/config, 3 privilege, 4 plateforme/reseau,\n"
 "5 arret demande du proprietaire, 6 conflit, 7 port, 10 negociation sans reprise, 14 rappel CBCP demande.\n"
 "Catalogue complet (309 occurrences upstream, plus extensions Windows):");
 for(size_t i=0;i<sizeof(catalogue)/sizeof(catalogue[0]);i++) {
  const OptionMeta *m=&catalogue[i];const char *status=effective_status(m);
  const char *detail=strcmp(status,m->status)?"Non compile dans ce build; option refusee explicitement.":m->detail;
  printf("%-12s %-32s | %s | %s",status,m->name,m->syntax,detail);
  if(*m->alias)printf(" | alias=%s",m->alias);
  printf(" | %s",m->context);
  if(*m->guard)printf(" | garde upstream=%s",m->guard);
  if(*m->source)printf(" | %s",m->source);
  putchar('\n');
 }
}
