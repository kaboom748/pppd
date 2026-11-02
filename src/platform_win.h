/* Native Windows COM and Wintun backend; confined to one owner event loop. */
#ifndef PPPD_PLATFORM_WIN_H
#define PPPD_PLATFORM_WIN_H
#include <stddef.h>
#include <stdint.h>
#include "options.h"
typedef struct WinPort WinPort;
typedef struct WinTun WinTun;
WinPort *win_port_open(const AppOptions *,size_t queue_limit,char *,size_t);
int win_port_queue(WinPort *,const uint8_t *,size_t);
int win_port_poll(WinPort *);
int win_port_read(WinPort *,uint8_t *,size_t);
/* Conservative application + driver TX occupancy from the latest poll.
 * Pending bytes can overlap both counts. Zero is the frame-scheduling gate;
 * this value is not a transmitted-byte counter. No blocking driver drain. */
size_t win_port_queued(const WinPort *);
const char *win_port_error(const WinPort *);
unsigned long win_port_last_error_code(void);
const char *win_port_last_error_stage(void);
void *win_port_read_event(const WinPort *);
void *win_port_write_event(const WinPort *);
void win_port_close(WinPort *);
/* Check sibling DLL and exports without creating an adapter. */
int win_tun_check_library(char *,size_t);
WinTun *win_tun_open(const char *name,char *,size_t);
int win_tun_set_ip(WinTun *,uint32_t local_be,uint32_t peer_be,unsigned mtu);
int win_tun_clear_ip(WinTun *);
int win_tun_set_ipv6(WinTun *,const uint8_t local_id[8],const uint8_t peer_id[8],unsigned mtu);
int win_tun_clear_ipv6(WinTun *);
int win_tun_set_dns(WinTun *,const uint32_t servers[2]);
int win_tun_set_default_route(WinTun *,unsigned metric);
int win_tun_read(WinTun *,uint8_t *,size_t);
/* 0 sent, 1 dropped because bounded ring is full, -1 fatal API error. */
int win_tun_send(WinTun *,const uint8_t *,size_t);
const char *win_tun_error(const WinTun *);
uint64_t win_tun_luid(const WinTun *);
void win_tun_guid(const WinTun *,char out[40]);
void *win_tun_read_event(const WinTun *);
uint64_t win_tun_dropped(const WinTun *);
/* Frees object. 0 only when interface and owned PnP node are absent. */
int win_tun_close(WinTun *);
const char *win_tun_close_error(void);
#endif
