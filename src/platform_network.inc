/* Windows IP Helper integration. Protocol negotiation remains upstream pppd.
 * Included by platform_win.c to keep owned adapter state private. */
typedef struct PppDnsSettings {
 ULONG Version; ULONG64 Flags; PWSTR Domain,NameServer,SearchList;
 ULONG RegistrationEnabled,RegisterAdapterName,EnableLLMNR,QueryAdapterName;
 PWSTR ProfileNameServer;
} PppDnsSettings;
typedef DWORD (WINAPI *PppSetDnsSettings)(GUID,const PppDnsSettings *);
int win_tun_set_dns(WinTun *t,const uint32_t servers[2])
{
 if(!t||!servers)return -1;
 if(!t->has_dns&&!servers[0]&&!servers[1])return 0;
 HMODULE library=GetModuleHandleW(L"iphlpapi.dll");
 FARPROC proc=library?GetProcAddress(library,"SetInterfaceDnsSettings"):NULL;
 PppSetDnsSettings set_dns=NULL;
 _Static_assert(sizeof(set_dns)==sizeof(proc),"Windows function pointer size");
 memcpy(&set_dns,&proc,sizeof(set_dns));
 if(!set_dns)return fail_windows(t->error,sizeof(t->error),"SetInterfaceDnsSettings requires Windows 10 build 19041 or later",ERROR_NOT_SUPPORTED);
 wchar_t names[96]={0};size_t used=0;
 for(unsigned i=0;i<2;i++)if(servers[i]){
  const uint8_t *p=(const uint8_t *)&servers[i];
  int count=swprintf(names+used,96-used,L"%ls%u.%u.%u.%u",used?L",":L"",p[0],p[1],p[2],p[3]);
  if(count<0)return fail_message(t->error,sizeof(t->error),"DNS list formatting failed");
  used+=(size_t)count;
 }
 PppDnsSettings settings={0};settings.Version=1;settings.Flags=2;settings.NameServer=names;
 DWORD rc=set_dns(t->guid,&settings);
 if(rc)return fail_windows(t->error,sizeof(t->error),"Set owned adapter DNS",rc);
 t->has_dns=used!=0;return 0;
}
int win_tun_set_default_route(WinTun *t,unsigned metric)
{
 if(!t||!t->has_address)return -1;
 if(t->has_default_route)return 0;
 InitializeIpForwardEntry(&t->default_route);t->default_route.InterfaceLuid=t->luid;
 t->default_route.DestinationPrefix.Prefix.Ipv4.sin_family=AF_INET;
 t->default_route.DestinationPrefix.PrefixLength=0;
 t->default_route.NextHop.Ipv4.sin_family=AF_INET;
 t->default_route.Protocol=MIB_IPPROTO_NETMGMT;t->default_route.Metric=metric;
 DWORD rc=CreateIpForwardEntry2(&t->default_route);
 if(rc)return fail_windows(t->error,sizeof(t->error),"Create owned IPv4 default route",rc);
 t->has_default_route=1;return 0;
}
int win_tun_clear_ipv6(WinTun *t)
{
 if(!t)return -1;
 DWORD error=NO_ERROR;
 if(t->has_ipv6_route){DWORD rc=DeleteIpForwardEntry2(&t->ipv6_route);if(rc==NO_ERROR||rc==ERROR_NOT_FOUND||rc==ERROR_FILE_NOT_FOUND)t->has_ipv6_route=0;else error=rc;}
 if(t->has_ipv6_address){DWORD rc=DeleteUnicastIpAddressEntry(&t->ipv6_address);if(rc==NO_ERROR||rc==ERROR_NOT_FOUND||rc==ERROR_FILE_NOT_FOUND)t->has_ipv6_address=0;else if(!error)error=rc;}
 for(unsigned i=0;i<t->suppressed_ipv6_count;i++){
  DWORD rc=SetUnicastIpAddressEntry(&t->suppressed_ipv6[i]);
  if(rc!=NO_ERROR&&rc!=ERROR_NOT_FOUND&&rc!=ERROR_FILE_NOT_FOUND&&!error)error=rc;
 }
 if(!error)t->suppressed_ipv6_count=0;
 if(error)return fail_windows(t->error,sizeof(t->error),"Remove owned IPv6 configuration",error);
 return 0;
}
int win_tun_set_ipv6(WinTun *t,const uint8_t local[8],const uint8_t peer[8],unsigned mtu)
{
 const uint8_t zero[8]={0};
 if(!t||!local||!peer||!memcmp(local,zero,8)||!memcmp(peer,zero,8)||!memcmp(local,peer,8)||mtu<1280||mtu>16384)
  return t?fail_message(t->error,sizeof(t->error),"Invalid negotiated IPv6 identifier/MTU"):-1;
 if(win_tun_clear_ipv6(t))return -1;
 MIB_IPINTERFACE_ROW row;InitializeIpInterfaceEntry(&row);row.Family=AF_INET6;row.InterfaceLuid=t->luid;
 DWORD rc=GetIpInterfaceEntry(&row);
 if(rc)return fail_windows(t->error,sizeof(t->error),"Get owned IPv6 interface",rc);
 row.NlMtu=mtu;row.UseAutomaticMetric=FALSE;row.Metric=5;row.ForwardingEnabled=FALSE;
 row.RouterDiscoveryBehavior=RouterDiscoveryDisabled;row.DadTransmits=0;
 row.WeakHostSend=FALSE;row.WeakHostReceive=FALSE;
 rc=SetIpInterfaceEntry(&row);
 if(rc)return fail_windows(t->error,sizeof(t->error),"Set owned IPv6 interface",rc);
 InitializeUnicastIpAddressEntry(&t->ipv6_address);t->ipv6_address.InterfaceLuid=t->luid;
 t->ipv6_address.Address.Ipv6.sin6_family=AF_INET6;
 uint8_t *address=(uint8_t *)&t->ipv6_address.Address.Ipv6.sin6_addr;
 address[0]=0xfe;address[1]=0x80;memcpy(address+8,local,8);
 t->ipv6_address.OnLinkPrefixLength=64;t->ipv6_address.PrefixOrigin=IpPrefixOriginManual;
 t->ipv6_address.SuffixOrigin=IpSuffixOriginManual;t->ipv6_address.ValidLifetime=0xffffffff;
 t->ipv6_address.PreferredLifetime=0xffffffff;t->ipv6_address.SkipAsSource=FALSE;
 rc=CreateUnicastIpAddressEntry(&t->ipv6_address);
 if(rc)return fail_windows(t->error,sizeof(t->error),"Create owned IPv6 link-local address",rc);
 t->has_ipv6_address=1;
 InitializeIpForwardEntry(&t->ipv6_route);t->ipv6_route.InterfaceLuid=t->luid;
 t->ipv6_route.DestinationPrefix.Prefix.Ipv6.sin6_family=AF_INET6;
 address=(uint8_t *)&t->ipv6_route.DestinationPrefix.Prefix.Ipv6.sin6_addr;
 address[0]=0xfe;address[1]=0x80;memcpy(address+8,peer,8);
 t->ipv6_route.DestinationPrefix.PrefixLength=128;t->ipv6_route.NextHop.Ipv6.sin6_family=AF_INET6;
 t->ipv6_route.Protocol=MIB_IPPROTO_NETMGMT;t->ipv6_route.Metric=0;
 rc=CreateIpForwardEntry2(&t->ipv6_route);
 if(rc){char saved[ERROR_CAPACITY];fail_windows(saved,sizeof(saved),"Create owned IPv6 peer route",rc);win_tun_clear_ipv6(t);copy_error(t->error,sizeof(t->error),saved);return -1;}
 t->has_ipv6_route=1;
 /* Linux PPP installs a /128 peer route. An automatically generated Windows
  * link-local source is not the IPv6CP peer and has no return route there.
  * Retain automatic addresses, but exclude them from source selection only
  * on this newly created adapter. Restore each original flag on clear. */
 PMIB_UNICASTIPADDRESS_TABLE table=NULL;
 rc=GetUnicastIpAddressTable(AF_INET6,&table);
 if(rc){char saved[ERROR_CAPACITY];fail_windows(saved,sizeof(saved),"Read owned IPv6 addresses for source selection",rc);win_tun_clear_ipv6(t);copy_error(t->error,sizeof(t->error),saved);return -1;}
 for(ULONG i=0;i<table->NumEntries;i++){
  MIB_UNICASTIPADDRESS_ROW address_row=table->Table[i];
  const uint8_t *bytes=(const uint8_t *)&address_row.Address.Ipv6.sin6_addr;
  if(address_row.InterfaceLuid.Value!=t->luid.Value||bytes[0]!=0xfe||(bytes[1]&0xc0)!=0x80||address_row.SkipAsSource||!memcmp(bytes+8,local,8))continue;
  if(t->suppressed_ipv6_count>=16){rc=ERROR_BUFFER_OVERFLOW;break;}
  MIB_UNICASTIPADDRESS_ROW skipped=address_row;skipped.SkipAsSource=TRUE;
  rc=SetUnicastIpAddressEntry(&skipped);if(rc)break;
  t->suppressed_ipv6[t->suppressed_ipv6_count++]=address_row;
 }
 FreeMibTable(table);
 if(rc){char saved[ERROR_CAPACITY];fail_windows(saved,sizeof(saved),"Select negotiated IPv6CP source address",rc);win_tun_clear_ipv6(t);copy_error(t->error,sizeof(t->error),saved);return -1;}
 return 0;
}
