/* Native COM/Wintun backend for pppd Windows. No firmware or global changes. */
#define WIN32_LEAN_AND_MEAN
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0602
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <setupapi.h>
#include <cfgmgr32.h>
#include <objbase.h>
#include <winver.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <limits.h>
#include <wchar.h>
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunknown-pragmas"
#endif
#include "vendor/wintun/include/wintun.h"
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif
#include "platform_win.h"
#define ERROR_CAPACITY 1024
#define SERIAL_READ_CAPACITY 4096
#define MAX_QUEUE_CAPACITY (256u*1024u)
static DWORD last_port_error;
static const char *last_port_stage="E_PORT_OPEN";
static char last_close_error[ERROR_CAPACITY];
static const GUID network_class={0x4d36e972,0xe325,0x11ce,{0xbf,0xc1,0x08,0x00,0x2b,0xe1,0x03,0x18}};
struct WinPort {
 HANDLE handle;
 OVERLAPPED read_ov,write_ov;
 int read_pending,write_pending;
 DWORD write_requested,driver_queued;
 DCB original_dcb;
 COMMTIMEOUTS original_timeouts;
 int saved_dcb,saved_timeouts;
 uint8_t read_buffer[SERIAL_READ_CAPACITY];
 size_t read_offset,read_size;
 uint8_t *queue;
 size_t queue_capacity,queue_head,queue_size;
 char error[ERROR_CAPACITY];
};
struct WinTun {
 HMODULE library;
 WINTUN_ADAPTER_HANDLE adapter;
 WINTUN_SESSION_HANDLE session;
 NET_LUID luid;
 GUID guid;
 int has_identity,has_pnp;
 wchar_t pnp_instance[MAX_DEVICE_ID_LEN];
 HANDLE read_event;
 WINTUN_CREATE_ADAPTER_FUNC *create_adapter;
 WINTUN_CLOSE_ADAPTER_FUNC *close_adapter;
 WINTUN_GET_ADAPTER_LUID_FUNC *get_luid;
 WINTUN_START_SESSION_FUNC *start_session;
 WINTUN_END_SESSION_FUNC *end_session;
 WINTUN_GET_READ_WAIT_EVENT_FUNC *get_read_event;
 WINTUN_RECEIVE_PACKET_FUNC *receive_packet;
 WINTUN_RELEASE_RECEIVE_PACKET_FUNC *release_packet;
 WINTUN_ALLOCATE_SEND_PACKET_FUNC *allocate_packet;
 WINTUN_SEND_PACKET_FUNC *send_packet;
 int has_address,has_route;
 MIB_UNICASTIPADDRESS_ROW address;
 MIB_IPFORWARD_ROW2 route;
 int has_ipv6_address,has_ipv6_route,has_default_route,has_dns;
 MIB_UNICASTIPADDRESS_ROW ipv6_address;
 MIB_IPFORWARD_ROW2 ipv6_route,default_route;
 unsigned suppressed_ipv6_count;
 MIB_UNICASTIPADDRESS_ROW suppressed_ipv6[16];
 uint64_t dropped;
 char error[ERROR_CAPACITY];
};
static int fail_message(char *buffer,size_t size,const char *format,...)
{
 va_list args;va_start(args,format);
 if(buffer&&size){vsnprintf(buffer,size,format,args);buffer[size-1]=0;}
 va_end(args);return -1;
}
static int fail_windows(char *buffer,size_t size,const char *operation,DWORD code)
{
 char detail[400]="";wchar_t detail_w[400]={0};
 FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_IGNORE_INSERTS,NULL,code,0,detail_w,400,NULL);
 WideCharToMultiByte(CP_UTF8,0,detail_w,-1,detail,sizeof(detail),NULL,NULL);
 size_t n=strlen(detail);while(n&&(detail[n-1]=='\r'||detail[n-1]=='\n'))detail[--n]=0;
 return fail_message(buffer,size,"%s: Windows error %lu (0x%08lx)%s%s",operation,(unsigned long)code,(unsigned long)code,detail[0]?": ":"",detail);
}
static void copy_error(char *dst,size_t size,const char *src)
{if(dst&&size){snprintf(dst,size,"%s",src);dst[size-1]=0;}}
static int port_fail(WinPort *p,const char *operation,DWORD code)
{last_port_error=code;return fail_windows(p->error,sizeof(p->error),operation,code);}
static int start_serial_read(WinPort *p)
{
 DWORD done=0;ResetEvent(p->read_ov.hEvent);
 if(ReadFile(p->handle,p->read_buffer,sizeof(p->read_buffer),&done,&p->read_ov)){
  p->read_size=done;p->read_offset=0;return 0;
 }
 DWORD code=GetLastError();
 if(code==ERROR_IO_PENDING){p->read_pending=1;return 0;}
 return port_fail(p,"ReadFile COM",code);
}
WinPort *win_port_open(const AppOptions *o,size_t queue_limit,char *error,size_t error_size)
{
 last_port_error=0;
 last_port_stage="E_PORT_OPEN";
 if(!o||queue_limit<4096||queue_limit>MAX_QUEUE_CAPACITY){
  last_port_error=ERROR_INVALID_PARAMETER;fail_message(error,error_size,"Invalid COM options/TX queue capacity");return NULL;
 }
 WinPort *p=calloc(1,sizeof(*p));
 if(!p){last_port_error=ERROR_NOT_ENOUGH_MEMORY;fail_message(error,error_size,"Out of memory opening COM");return NULL;}
 p->handle=INVALID_HANDLE_VALUE;p->queue_capacity=queue_limit;p->queue=malloc(queue_limit);
 if(!p->queue){port_fail(p,"Allocate COM TX queue",ERROR_NOT_ENOUGH_MEMORY);goto failed;}
 const char *name=o->device;if(!strncmp(name,"\\\\.\\",4))name+=4;
 if(_strnicmp(name,"COM",3)||!name[3]){port_fail(p,"Invalid COM name",ERROR_INVALID_PARAMETER);goto failed;}
 unsigned long number=0;
 for(size_t i=3;name[i];++i){
  if(name[i]<'0'||name[i]>'9'||number>6553){port_fail(p,"Invalid COM number",ERROR_INVALID_PARAMETER);goto failed;}
  number=number*10+(unsigned)(name[i]-'0');
 }
 if(number<1||number>65535||!o->baud||o->data_bits!=8||o->parity<0||o->parity>4||
    (o->stop_bits!=1&&o->stop_bits!=2)||o->flow<0||o->flow>2){
  port_fail(p,"Invalid binary PPP COM format",ERROR_INVALID_PARAMETER);goto failed;
 }
 wchar_t path[40];swprintf(path,40,L"\\\\.\\COM%lu",number);
 p->handle=CreateFileW(path,GENERIC_READ|GENERIC_WRITE,0,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL|FILE_FLAG_OVERLAPPED,NULL);
 if(p->handle==INVALID_HANDLE_VALUE){port_fail(p,"Open exclusive COM",GetLastError());goto failed;}
 last_port_stage="E_PORT_CONFIG";
 p->original_dcb.DCBlength=sizeof(p->original_dcb);
 if(!GetCommState(p->handle,&p->original_dcb)){port_fail(p,"GetCommState original",GetLastError());goto failed;}
 p->saved_dcb=1;
 if(!GetCommTimeouts(p->handle,&p->original_timeouts)){port_fail(p,"GetCommTimeouts original",GetLastError());goto failed;}
 p->saved_timeouts=1;
 if(!SetupComm(p->handle,32768,32768)){port_fail(p,"SetupComm queues",GetLastError());goto failed;}
 COMMPROP props;memset(&props,0,sizeof(props));props.wPacketLength=sizeof(props);
 if(!GetCommProperties(p->handle,&props)){port_fail(p,"GetCommProperties",GetLastError());goto failed;}
 DWORD rx_queue=props.dwCurrentRxQueue?props.dwCurrentRxQueue:32768;
 if(o->flow==1&&rx_queue<256){port_fail(p,"RX queue too small for XON/XOFF",ERROR_INVALID_DATA);goto failed;}
 WORD threshold=(WORD)(rx_queue>=16384?4096:rx_queue/4);
 DCB d=p->original_dcb;
 d.BaudRate=o->baud;d.ByteSize=(BYTE)o->data_bits;d.Parity=(BYTE)o->parity;
 d.StopBits=o->stop_bits==2?TWOSTOPBITS:ONESTOPBIT;d.fBinary=TRUE;d.fParity=o->parity!=NOPARITY;
 d.fOutxCtsFlow=o->flow==2;d.fOutxDsrFlow=FALSE;d.fDtrControl=DTR_CONTROL_DISABLE;d.fDsrSensitivity=FALSE;
 d.fTXContinueOnXoff=TRUE;d.fOutX=o->flow==1;d.fInX=o->flow==1;
 d.fErrorChar=FALSE;d.fNull=FALSE;d.fAbortOnError=FALSE;
 d.fRtsControl=o->flow==2?RTS_CONTROL_HANDSHAKE:RTS_CONTROL_DISABLE;
 d.XonChar=0x11;d.XoffChar=0x13;d.XonLim=threshold;d.XoffLim=threshold;
 if(!SetCommState(p->handle,&d)){port_fail(p,"SetCommState",GetLastError());goto failed;}
 DCB c;memset(&c,0,sizeof(c));c.DCBlength=sizeof(c);
 if(!GetCommState(p->handle,&c)){port_fail(p,"Read back COM configuration",GetLastError());goto failed;}
 if(c.BaudRate!=d.BaudRate||c.ByteSize!=d.ByteSize||c.Parity!=d.Parity||c.StopBits!=d.StopBits||
    c.fBinary!=d.fBinary||c.fParity!=d.fParity||c.fOutxCtsFlow!=d.fOutxCtsFlow||c.fOutxDsrFlow||
    c.fDsrSensitivity||c.fInX!=d.fInX||c.fOutX!=d.fOutX||c.fDtrControl!=d.fDtrControl||
    c.fRtsControl!=d.fRtsControl||c.fNull||c.fErrorChar||c.fAbortOnError||!c.fTXContinueOnXoff||
    (o->flow==1&&(c.XonChar!=0x11||c.XoffChar!=0x13||c.XonLim!=threshold||c.XoffLim!=threshold))){
  port_fail(p,"Driver did not retain COM configuration",ERROR_INVALID_DATA);goto failed;
 }
 COMMTIMEOUTS timeouts;memset(&timeouts,0,sizeof(timeouts));timeouts.ReadIntervalTimeout=MAXDWORD;
 timeouts.ReadTotalTimeoutMultiplier=MAXDWORD;timeouts.ReadTotalTimeoutConstant=20;
 if(!SetCommTimeouts(p->handle,&timeouts)){port_fail(p,"SetCommTimeouts",GetLastError());goto failed;}
 p->read_ov.hEvent=CreateEventW(NULL,TRUE,FALSE,NULL);p->write_ov.hEvent=CreateEventW(NULL,TRUE,FALSE,NULL);
 if(!p->read_ov.hEvent||!p->write_ov.hEvent){port_fail(p,"Create COM events",GetLastError());goto failed;}
 /* No purge, drain, artificial XON or deliberate reset pulse. */
 if(start_serial_read(p))goto failed;
 return p;
failed:
 copy_error(error,error_size,p->error);win_port_close(p);return NULL;
}
int win_port_queue(WinPort *p,const uint8_t *data,size_t size)
{
 if(!p||(!data&&size))return -1;
 if(size>p->queue_capacity-p->queue_size)return fail_message(p->error,sizeof(p->error),"COM TX queue full");
 size_t tail=(p->queue_head+p->queue_size)%p->queue_capacity,first=p->queue_capacity-tail;
 if(first>size)first=size;
 if(first)memcpy(p->queue+tail,data,first);
 if(size>first)memcpy(p->queue,data+first,size-first);
 p->queue_size+=size;return 0;
}
static int refresh_serial_status(WinPort *p)
{
 DWORD faults=0;COMSTAT status;memset(&status,0,sizeof(status));
 if(!ClearCommError(p->handle,&faults,&status))return port_fail(p,"ClearCommError",GetLastError());
 p->driver_queued=status.cbOutQue;
 if(faults){
  last_port_error=ERROR_INVALID_DATA;
  return fail_message(p->error,sizeof(p->error),"COM status reports errors 0x%08lx",(unsigned long)faults);
 }
 return 0;
}
int win_port_poll(WinPort *p)
{
 if(!p)return -1;
 if(refresh_serial_status(p))return -1;
 DWORD done=0;
 if(p->write_pending){
  if(!GetOverlappedResult(p->handle,&p->write_ov,&done,FALSE)){
   DWORD code=GetLastError();if(code==ERROR_IO_INCOMPLETE)return 0;return port_fail(p,"COM write completion",code);
  }
  p->write_pending=0;
  if(done>p->write_requested||done>p->queue_size)return port_fail(p,"Invalid COM write size",ERROR_INVALID_DATA);
  p->queue_head=(p->queue_head+done)%p->queue_capacity;p->queue_size-=done;
  /* A completed WriteFile means that the driver accepted bytes, not that the
   * UART finished sending them. Sample after completion before exposing an
   * empty transport to the frame scheduler. */
  if(refresh_serial_status(p))return -1;
 }
 if(!p->queue_size)return 0;
 size_t size=p->queue_capacity-p->queue_head;if(size>p->queue_size)size=p->queue_size;if(size>4096)size=4096;
 p->write_requested=(DWORD)size;ResetEvent(p->write_ov.hEvent);
 if(WriteFile(p->handle,p->queue+p->queue_head,(DWORD)size,&done,&p->write_ov)){
  if(done>size)return port_fail(p,"Invalid immediate COM write size",ERROR_INVALID_DATA);
  p->queue_head=(p->queue_head+done)%p->queue_capacity;p->queue_size-=done;
  return refresh_serial_status(p);
 }
 DWORD code=GetLastError();if(code==ERROR_IO_PENDING){p->write_pending=1;return 0;}
 return port_fail(p,"WriteFile COM",code);
}
int win_port_read(WinPort *p,uint8_t *data,size_t capacity)
{
 if(!p||!data||!capacity||capacity>INT_MAX)return -1;
 if(p->read_pending){
  DWORD done=0;
  if(!GetOverlappedResult(p->handle,&p->read_ov,&done,FALSE)){
   DWORD code=GetLastError();if(code==ERROR_IO_INCOMPLETE)return 0;return port_fail(p,"COM read completion",code);
  }
  p->read_pending=0;
  if(done>sizeof(p->read_buffer))return port_fail(p,"Invalid COM read size",ERROR_INVALID_DATA);
  p->read_size=done;p->read_offset=0;
 }
 if(!p->read_size){if(start_serial_read(p))return -1;if(!p->read_size)return 0;}
 size_t size=p->read_size;if(size>capacity)size=capacity;
 memcpy(data,p->read_buffer+p->read_offset,size);p->read_offset+=size;p->read_size-=size;return (int)size;
}
size_t win_port_queued(const WinPort *p)
{
 /* Pending overlapped bytes can also appear in cbOutQue. This is deliberately
  * a conservative occupancy estimate; callers rely on zero/nonzero, not a
  * wire byte counter. No second frame is admitted while either queue has data. */
 return p?p->queue_size+(size_t)p->driver_queued:0;
}
const char *win_port_error(const WinPort *p){return p?p->error:"No COM port";}
unsigned long win_port_last_error_code(void){return last_port_error;}
const char *win_port_last_error_stage(void){return last_port_stage;}
void *win_port_read_event(const WinPort *p){return p?p->read_ov.hEvent:NULL;}
void *win_port_write_event(const WinPort *p){return p?p->write_ov.hEvent:NULL;}
static void cancel_and_join(HANDLE h,OVERLAPPED *op,int *pending)
{
 if(!*pending)return;
 CancelIoEx(h,op);DWORD done=0;GetOverlappedResult(h,op,&done,TRUE);*pending=0;
}
void win_port_close(WinPort *p)
{
 if(!p)return;
 if(p->handle!=INVALID_HANDLE_VALUE){
  cancel_and_join(p->handle,&p->read_ov,&p->read_pending);cancel_and_join(p->handle,&p->write_ov,&p->write_pending);
  if(p->saved_dcb)SetCommState(p->handle,&p->original_dcb);
  if(p->saved_timeouts)SetCommTimeouts(p->handle,&p->original_timeouts);
  CloseHandle(p->handle);
 }
 if(p->read_ov.hEvent)CloseHandle(p->read_ov.hEvent);
 if(p->write_ov.hEvent)CloseHandle(p->write_ov.hEvent);
 free(p->queue);free(p);
}
static int check_library_version(WinTun *t,const wchar_t *path)
{
 DWORD unused=0,size=GetFileVersionInfoSizeW(path,&unused);
 if(!size)return fail_windows(t->error,sizeof(t->error),"Read Wintun DLL version",GetLastError());
 void *data=malloc(size);if(!data)return fail_message(t->error,sizeof(t->error),"Out of memory reading Wintun version");
 VS_FIXEDFILEINFO *info=NULL;UINT info_size=0;
 int valid=GetFileVersionInfoW(path,0,size,data)&&VerQueryValueW(data,L"\\",(void **)&info,&info_size)&&
  info_size>=sizeof(*info)&&info->dwSignature==0xfeef04bd&&HIWORD(info->dwFileVersionMS)==0&&
  LOWORD(info->dwFileVersionMS)==14&&HIWORD(info->dwFileVersionLS)==1;
 free(data);
 if(!valid)return fail_message(t->error,sizeof(t->error),"wintun.dll must be the official x64 Wintun 0.14.1 package");
 return 0;
}
/* GetModuleFileName can return a DOS path even if an earlier component has a
 * reserved Win32 name (for example this task's "con" directory). Preserve the
 * filesystem spelling by using extended paths for every DLL-related API. */
static int sibling_library_path(WinTun *t,wchar_t path[32768])
{
 wchar_t raw[32768];DWORD length=GetModuleFileNameW(NULL,raw,32768);
 if(!length||length>=32768)return fail_message(t->error,sizeof(t->error),"Cannot resolve executable directory");
 for(DWORD i=0;i<length;++i)if(raw[i]==L'/')raw[i]=L'\\';
 wchar_t *slash=wcsrchr(raw,L'\\');
 if(!slash||(size_t)(slash-raw)+12>=32768)return fail_message(t->error,sizeof(t->error),"Executable path too long");
 wcscpy(slash+1,L"wintun.dll");length=(DWORD)wcslen(raw);
 if(!wcsncmp(raw,L"\\\\?\\",4)){wcscpy(path,raw);return 0;}
 if(((raw[0]>=L'A'&&raw[0]<=L'Z')||(raw[0]>=L'a'&&raw[0]<=L'z'))&&raw[1]==L':'&&raw[2]==L'\\'){
  if(length+4>=32768)return fail_message(t->error,sizeof(t->error),"Extended executable path too long");
  wcscpy(path,L"\\\\?\\");wcscat(path,raw);return 0;
 }
 if(raw[0]==L'\\'&&raw[1]==L'\\'&&raw[2]!=L'.'){
  if(length+6>=32768)return fail_message(t->error,sizeof(t->error),"Extended UNC executable path too long");
  wcscpy(path,L"\\\\?\\UNC\\");wcscat(path,raw+2);return 0;
 }
 return fail_message(t->error,sizeof(t->error),"Executable path is not an absolute filesystem path");
}
static int open_library_image(WinTun *t,const wchar_t *path,HANDLE *file)
{
 *file=CreateFileW(path,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
 if(*file==INVALID_HANDLE_VALUE)return fail_windows(t->error,sizeof(t->error),"Open sibling Wintun image",GetLastError());
 IMAGE_DOS_HEADER dos;IMAGE_FILE_HEADER header;DWORD signature=0,done=0;WORD magic=0;
 LARGE_INTEGER size,position;
 int valid=GetFileSizeEx(*file,&size)&&size.QuadPart>=(LONGLONG)sizeof(dos)&&
  ReadFile(*file,&dos,sizeof(dos),&done,NULL)&&done==sizeof(dos)&&dos.e_magic==IMAGE_DOS_SIGNATURE&&
  dos.e_lfanew>=(LONG)sizeof(dos)&&size.QuadPart-(LONGLONG)dos.e_lfanew>=(LONGLONG)(sizeof(signature)+sizeof(header)+sizeof(magic));
 if(valid){
  position.QuadPart=dos.e_lfanew;
  valid=SetFilePointerEx(*file,position,NULL,FILE_BEGIN)&&
   ReadFile(*file,&signature,sizeof(signature),&done,NULL)&&done==sizeof(signature)&&signature==IMAGE_NT_SIGNATURE&&
   ReadFile(*file,&header,sizeof(header),&done,NULL)&&done==sizeof(header)&&
   header.Machine==IMAGE_FILE_MACHINE_AMD64&&(header.Characteristics&IMAGE_FILE_DLL)&&header.SizeOfOptionalHeader>=sizeof(magic)&&
   ReadFile(*file,&magic,sizeof(magic),&done,NULL)&&done==sizeof(magic)&&magic==IMAGE_NT_OPTIONAL_HDR64_MAGIC;
 }
 if(!valid){CloseHandle(*file);*file=INVALID_HANDLE_VALUE;return fail_message(t->error,sizeof(t->error),"wintun.dll must be a valid x64 PE DLL");}
 return 0;
}
static int load_wintun(WinTun *t)
{
 wchar_t path[32768];if(sibling_library_path(t,path))return -1;
 HANDLE source=INVALID_HANDLE_VALUE;if(open_library_image(t,path,&source))return -1;
 if(check_library_version(t,path)){CloseHandle(source);return -1;}
 t->library=LoadLibraryExW(path,NULL,LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|LOAD_LIBRARY_SEARCH_SYSTEM32);
 DWORD load_error=GetLastError();CloseHandle(source);
 if(!t->library)return fail_windows(t->error,sizeof(t->error),"Load sibling x64 wintun.dll",load_error);
#define LOAD_API(member,name) do { FARPROC fn=GetProcAddress(t->library,name); \
 if(!fn)return fail_message(t->error,sizeof(t->error),"Missing Wintun export %s",name); \
 memcpy(&t->member,&fn,sizeof(fn)); } while(0)
 LOAD_API(create_adapter,"WintunCreateAdapter");LOAD_API(close_adapter,"WintunCloseAdapter");
 LOAD_API(get_luid,"WintunGetAdapterLUID");LOAD_API(start_session,"WintunStartSession");
 LOAD_API(end_session,"WintunEndSession");LOAD_API(get_read_event,"WintunGetReadWaitEvent");
 LOAD_API(receive_packet,"WintunReceivePacket");LOAD_API(release_packet,"WintunReleaseReceivePacket");
 LOAD_API(allocate_packet,"WintunAllocateSendPacket");LOAD_API(send_packet,"WintunSendPacket");
#undef LOAD_API
 return 0;
}
int win_tun_check_library(char *error,size_t error_size)
{
 WinTun t;memset(&t,0,sizeof(t));int rc=load_wintun(&t);
 if(rc)copy_error(error,error_size,t.error);
 if(t.library)FreeLibrary(t.library);
 return rc;
}
static int capture_pnp(WinTun *t)
{
 wchar_t wanted[40];if(!StringFromGUID2(&t->guid,wanted,40))return -1;
 HDEVINFO set=SetupDiGetClassDevsW(&network_class,NULL,NULL,DIGCF_PRESENT);
 if(set==INVALID_HANDLE_VALUE)return -1;
 int found=0;
 for(DWORD i=0;;++i){
  SP_DEVINFO_DATA device;memset(&device,0,sizeof(device));device.cbSize=sizeof(device);
  if(!SetupDiEnumDeviceInfo(set,i,&device))break;
  HKEY key=SetupDiOpenDevRegKey(set,&device,DICS_FLAG_GLOBAL,0,DIREG_DRV,KEY_READ);
  if(key==INVALID_HANDLE_VALUE)continue;
  wchar_t instance[80];DWORD bytes=sizeof(instance),type=0;
  LONG rc=RegQueryValueExW(key,L"NetCfgInstanceId",NULL,&type,(BYTE *)instance,&bytes);RegCloseKey(key);
  instance[79]=0;
  if(rc!=ERROR_SUCCESS||type!=REG_SZ||_wcsicmp(instance,wanted))continue;
  if(SetupDiGetDeviceInstanceIdW(set,&device,t->pnp_instance,MAX_DEVICE_ID_LEN,NULL))found=1;
  break;
 }
 SetupDiDestroyDeviceInfoList(set);return found?0:-1;
}
WinTun *win_tun_open(const char *name,char *error,size_t error_size)
{
 WinTun *t=calloc(1,sizeof(*t));if(!t){fail_message(error,error_size,"Out of memory opening Wintun");return NULL;}
 wchar_t wide[256];
 if(!name||!name[0]||!MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,name,-1,wide,256)){
  fail_message(t->error,sizeof(t->error),"Invalid UTF-8 ip_row alias");goto failed;
 }
 NET_LUID existing;
 if(ConvertInterfaceAliasToLuid(wide,&existing)==NO_ERROR){fail_message(t->error,sizeof(t->error),"ip_row alias already exists; existing adapters are never adopted");goto failed;}
 if(load_wintun(t))goto failed;
 GUID requested;if(FAILED(CoCreateGuid(&requested))){fail_message(t->error,sizeof(t->error),"Cannot create new adapter UUID");goto failed;}
 t->adapter=t->create_adapter(wide,L"Microburst PPP",&requested);
 if(!t->adapter){fail_windows(t->error,sizeof(t->error),"Create Wintun adapter",GetLastError());goto failed;}
 t->get_luid(t->adapter,&t->luid);
 DWORD rc=ConvertInterfaceLuidToGuid(&t->luid,&t->guid);
 if(rc!=NO_ERROR){fail_windows(t->error,sizeof(t->error),"Read actual adapter GUID",rc);goto failed;}
 t->has_identity=1;
 wchar_t actual_alias[256];
 rc=ConvertInterfaceLuidToAlias(&t->luid,actual_alias,256);
 if(rc!=NO_ERROR||wcscmp(actual_alias,wide)){
  fail_windows(t->error,sizeof(t->error),"Created adapter alias differs from requested name",rc?rc:ERROR_ALREADY_EXISTS);goto failed;
 }
 if(capture_pnp(t)){fail_message(t->error,sizeof(t->error),"Cannot identify created Wintun PnP node");goto failed;}
 t->has_pnp=1;
 t->session=t->start_session(t->adapter,WINTUN_MIN_RING_CAPACITY);
 if(!t->session){fail_windows(t->error,sizeof(t->error),"Start Wintun session",GetLastError());goto failed;}
 t->read_event=t->get_read_event(t->session);
 if(!t->read_event){fail_windows(t->error,sizeof(t->error),"Get Wintun read event",GetLastError());goto failed;}
 return t;
failed:
 {char original[ERROR_CAPACITY];copy_error(original,sizeof(original),t->error);int cleanup=win_tun_close(t);
  if(cleanup)fail_message(error,error_size,"%s; rollback: %s",original,last_close_error);else copy_error(error,error_size,original);}
 return NULL;
}
int win_tun_clear_ip(WinTun *t)
{
 if(!t)return -1;
 DWORD error=NO_ERROR;
 if(t->has_dns){uint32_t empty[2]={0,0};if(win_tun_set_dns(t,empty))return -1;}
 if(t->has_default_route){DWORD rc=DeleteIpForwardEntry2(&t->default_route);if(rc==NO_ERROR||rc==ERROR_NOT_FOUND||rc==ERROR_FILE_NOT_FOUND)t->has_default_route=0;else error=rc;}
 if(t->has_route){DWORD rc=DeleteIpForwardEntry2(&t->route);if(rc==NO_ERROR||rc==ERROR_NOT_FOUND||rc==ERROR_FILE_NOT_FOUND)t->has_route=0;else error=rc;}
 if(t->has_address){DWORD rc=DeleteUnicastIpAddressEntry(&t->address);if(rc==NO_ERROR||rc==ERROR_NOT_FOUND||rc==ERROR_FILE_NOT_FOUND)t->has_address=0;else if(!error)error=rc;}
 if(error)return fail_windows(t->error,sizeof(t->error),"Remove owned IPv4 configuration",error);
 return 0;
}
int win_tun_set_ip(WinTun *t,uint32_t local,uint32_t peer,unsigned mtu)
{
 if(!t)return -1;
 if(!local||!peer||local==peer||mtu<128||mtu>16384)return fail_message(t->error,sizeof(t->error),"Invalid negotiated IPv4 address/MTU");
 if(win_tun_clear_ip(t))return -1;
 MIB_IPINTERFACE_ROW ip_row;InitializeIpInterfaceEntry(&ip_row);ip_row.InterfaceLuid=t->luid;ip_row.Family=AF_INET;
 DWORD rc=GetIpInterfaceEntry(&ip_row);
 if(rc!=NO_ERROR)return fail_windows(t->error,sizeof(t->error),"Get owned IPv4 ip_row",rc);
 ip_row.NlMtu=mtu;ip_row.UseAutomaticMetric=FALSE;ip_row.Metric=5;ip_row.ForwardingEnabled=FALSE;
 ip_row.WeakHostSend=FALSE;ip_row.WeakHostReceive=FALSE;ip_row.RouterDiscoveryBehavior=RouterDiscoveryDisabled;
 ip_row.SitePrefixLength=0;ip_row.DadTransmits=0;
 rc=SetIpInterfaceEntry(&ip_row);if(rc!=NO_ERROR)return fail_windows(t->error,sizeof(t->error),"Set owned IPv4 ip_row",rc);
 InitializeUnicastIpAddressEntry(&t->address);t->address.InterfaceLuid=t->luid;
 t->address.Address.Ipv4.sin_family=AF_INET;t->address.Address.Ipv4.sin_addr.s_addr=local;
 t->address.OnLinkPrefixLength=32;t->address.PrefixOrigin=IpPrefixOriginManual;t->address.SuffixOrigin=IpSuffixOriginManual;
 t->address.ValidLifetime=0xffffffff;t->address.PreferredLifetime=0xffffffff;t->address.SkipAsSource=FALSE;
 rc=CreateUnicastIpAddressEntry(&t->address);
 if(rc!=NO_ERROR)return fail_windows(t->error,sizeof(t->error),"Create owned IPv4 /32",rc);
 t->has_address=1;
 InitializeIpForwardEntry(&t->route);t->route.InterfaceLuid=t->luid;
 t->route.DestinationPrefix.Prefix.Ipv4.sin_family=AF_INET;t->route.DestinationPrefix.Prefix.Ipv4.sin_addr.s_addr=peer;
 t->route.DestinationPrefix.PrefixLength=32;t->route.NextHop.Ipv4.sin_family=AF_INET;
 t->route.NextHop.Ipv4.sin_addr.s_addr=0;t->route.Protocol=MIB_IPPROTO_NETMGMT;t->route.Metric=0;
 rc=CreateIpForwardEntry2(&t->route);
 if(rc!=NO_ERROR){fail_windows(t->error,sizeof(t->error),"Create peer on-link /32 route",rc);goto rollback;}
 t->has_route=1;
 MIB_IPFORWARD_ROW2 route_check=t->route;rc=GetIpForwardEntry2(&route_check);
 if(rc!=NO_ERROR||route_check.InterfaceLuid.Value!=t->luid.Value||route_check.DestinationPrefix.PrefixLength!=32||route_check.NextHop.Ipv4.sin_addr.s_addr!=0){
  fail_windows(t->error,sizeof(t->error),"Read back peer route",rc?rc:ERROR_INVALID_DATA);goto rollback;
 }
 InitializeIpInterfaceEntry(&ip_row);ip_row.InterfaceLuid=t->luid;ip_row.Family=AF_INET;rc=GetIpInterfaceEntry(&ip_row);
 if(rc!=NO_ERROR||ip_row.NlMtu!=mtu){fail_windows(t->error,sizeof(t->error),"Read back IPv4 MTU",rc?rc:ERROR_INVALID_DATA);goto rollback;}
 ULONGLONG deadline=GetTickCount64()+3000;
 for(;;){
  MIB_UNICASTIPADDRESS_ROW check=t->address;rc=GetUnicastIpAddressEntry(&check);
  if(rc==NO_ERROR&&check.OnLinkPrefixLength==32&&check.DadState==IpDadStatePreferred)break;
  if(rc==NO_ERROR&&(check.DadState==IpDadStateDuplicate||check.DadState==IpDadStateInvalid)){
   fail_message(t->error,sizeof(t->error),"Owned IPv4 address duplicate/invalid");goto rollback;
  }
  if(GetTickCount64()>=deadline){fail_windows(t->error,sizeof(t->error),"IPv4 address did not become preferred",rc?rc:ERROR_TIMEOUT);goto rollback;}
  Sleep(10);
 }
 return 0;
rollback:
 {char saved[ERROR_CAPACITY];copy_error(saved,sizeof(saved),t->error);win_tun_clear_ip(t);copy_error(t->error,sizeof(t->error),saved);}
 return -1;
}
int win_tun_read(WinTun *t,uint8_t *data,size_t capacity)
{
 if(!t||!data||!capacity||capacity>INT_MAX)return -1;
 for(unsigned count=0;count<32;++count){
  DWORD size=0;BYTE *packet=t->receive_packet(t->session,&size);
  if(!packet){DWORD code=GetLastError();if(code==ERROR_NO_MORE_ITEMS)return 0;return fail_windows(t->error,sizeof(t->error),"Receive Wintun packet",code);}
  unsigned version=size?packet[0]>>4:0;
  if((version!=4&&version!=6)||size<(version==6?40u:20u)||size>capacity||size>16384){++t->dropped;t->release_packet(t->session,packet);continue;}
  memcpy(data,packet,size);t->release_packet(t->session,packet);return (int)size;
 }
 return 0;
}
int win_tun_send(WinTun *t,const uint8_t *data,size_t size)
{
 if(!t||!data||size<20||size>16384||((data[0]>>4)!=4&&(data[0]>>4)!=6)||((data[0]>>4)==6&&size<40))return -1;
 BYTE *packet=t->allocate_packet(t->session,(DWORD)size);
 if(!packet){DWORD code=GetLastError();if(code==ERROR_BUFFER_OVERFLOW){++t->dropped;return 1;}return fail_windows(t->error,sizeof(t->error),"Allocate Wintun packet",code);}
 memcpy(packet,data,size);t->send_packet(t->session,packet);return 0;
}
const char *win_tun_error(const WinTun *t){return t?t->error:"No Wintun ip_row";}
uint64_t win_tun_luid(const WinTun *t){return t?t->luid.Value:0;}
void win_tun_guid(const WinTun *t,char out[40])
{
 if(!out)return;
 out[0]=0;if(!t||!t->has_identity)return;
 wchar_t value[40];if(StringFromGUID2(&t->guid,value,40))WideCharToMultiByte(CP_UTF8,0,value,-1,out,40,NULL,NULL);
}
void *win_tun_read_event(const WinTun *t){return t?t->read_event:NULL;}
uint64_t win_tun_dropped(const WinTun *t){return t?t->dropped:0;}
static int adapter_present(const WinTun *t)
{
 int present=0;
 if(t->has_pnp){
  DEVINST node;CONFIGRET rc=CM_Locate_DevNodeW(&node,(DEVINSTID_W)t->pnp_instance,CM_LOCATE_DEVNODE_NORMAL);
  if(rc==CR_SUCCESS)present=1;
  else if(rc!=CR_NO_SUCH_DEVNODE)return -1;
 }
 if(t->luid.Value){
  MIB_IF_ROW2 row;memset(&row,0,sizeof(row));row.InterfaceLuid=t->luid;DWORD rc=GetIfEntry2(&row);
  if(rc==NO_ERROR)present=1;
  else if(rc!=ERROR_FILE_NOT_FOUND&&rc!=ERROR_NOT_FOUND)return -1;
 }
 return present;
}
int win_tun_close(WinTun *t)
{
 if(!t)return 0;
 last_close_error[0]=0;int failed=win_tun_clear_ip(t);
 if(win_tun_clear_ipv6(t))failed=-1;
 if(failed)copy_error(last_close_error,sizeof(last_close_error),t->error);
 if(t->adapter&&!t->has_pnp){
  failed=-1;copy_error(last_close_error,sizeof(last_close_error),"Created adapter PnP identity unavailable; cleanup will run, but PnP removal cannot be confirmed");
 }
 if(t->session&&t->end_session){t->end_session(t->session);t->session=NULL;}
 if(t->adapter&&t->close_adapter){t->close_adapter(t->adapter);t->adapter=NULL;}
 ULONGLONG deadline=GetTickCount64()+3000;
 while(adapter_present(t)){
  if(GetTickCount64()>=deadline){
   char guid[40];win_tun_guid(t,guid);fail_message(last_close_error,sizeof(last_close_error),"Removal not confirmed for GUID %s, LUID %llu",guid,(unsigned long long)t->luid.Value);failed=-1;break;
  }
  Sleep(10);
 }
 if(t->library)FreeLibrary(t->library);
 free(t);return failed?-1:0;
}
const char *win_tun_close_error(void){return last_close_error;}
#include "platform_network.inc"
