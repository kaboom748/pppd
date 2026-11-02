#ifndef PPPD_WINDOWS_OPTIONS_H
#define PPPD_WINDOWS_OPTIONS_H
#include <stddef.h>
#include <stdint.h>
#include "auth_port.h"
#include "data_options.h"
typedef struct AppOptions {
 PppDataOptions data;
 char device[32]; unsigned baud, data_bits, stop_bits; int parity, flow;
 uint32_t local_ip_be, peer_ip_be; uint16_t mtu,mru;
 uint32_t receive_accm; uint8_t transmit_accm[32];
 unsigned echo_interval,echo_failure,holdoff,maxfail;
 int echo_adaptive,passive,silent,noaccomp,nopcomp,nomagic,asyncmap_disabled;
 unsigned lcp_timeout,lcp_max_configure,lcp_max_terminate,lcp_max_failure,lcp_loopback_failure;
 unsigned ipcp_timeout,ipcp_max_configure,ipcp_max_terminate,ipcp_max_failure;
 int ipcp_accept_local,ipcp_accept_remote,usepeerdns,usepeerwins;
 uint32_t dns[2],wins[2];
 int ipv4_disabled,ipv6_enabled,ipv6_accept_local,ipv6_accept_remote;
 uint8_t ipv6_local_id[8],ipv6_peer_id[8];
 unsigned ipv6cp_timeout,ipv6cp_max_configure,ipv6cp_max_terminate,ipv6cp_max_failure;
 unsigned maxconnect;
 unsigned idle;
 int default_mru,receive_all,ipcp_no_address,ipcp_no_addresses,ipv6_use_ipaddr,ipv6_no_send;
 int default_route;
 unsigned default_route_metric;
 char rtt_file[2048];
 PppAuthConfig auth;
 int debug,dump,persist,dry_run,nodetach,help,version,config_explicit;
 char ifname[64],linkname[64],config_dir[2048],stop_name[64];
} AppOptions;
void options_defaults(AppOptions *o);
int options_parse(AppOptions *o,int argc,const char *const *argv,char *error,size_t error_size);
void options_help(void);
void options_print(const AppOptions *o);
void options_format_ip(uint32_t ip,char out[16]);
const char *options_error_code(void);
#endif
