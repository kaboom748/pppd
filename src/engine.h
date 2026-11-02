#ifndef MICROBURST_PPP_ENGINE_H
#define MICROBURST_PPP_ENGINE_H
#include <stddef.h>
#include <stdint.h>
#include "auth_port.h"
#include "data_options.h"
#define PPP_ENGINE_MAX_MRU 16384u
#define PPP_ENGINE_MAX_WIRE (2u * (PPP_ENGINE_MAX_MRU + 6u) + 2u)
typedef struct PppCounters {
    uint64_t tx_frames,rx_frames,tx_ipv4,rx_ipv4;
    uint64_t rx_fcs_errors,rx_invalid,rx_oversize,tx_dropped,rx_dropped;
    uint64_t tx_ipv6,rx_ipv6;
} PppCounters;
void ppp_engine_get_counters(PppCounters *out);

/* One PPP link per process. All functions and callbacks run on ONE event-loop
 * thread; callbacks must not re-enter the engine. No IP stack is embedded here:
 * Windows (Wintun), or a test harness, owns all IP packets. CCP/VJ/MPPE run in this process; no multilink.
 * local_ip_be and peer_ip_be are network-byte-order values.
 */
typedef struct PppConfig {
    PppDataOptions data;
    uint32_t local_ip_be, peer_ip_be;
    uint16_t mtu, mru;
    uint32_t receive_accm;
    uint8_t transmit_accm[32];
    unsigned echo_interval, echo_failure;
    int debug;
    int echo_adaptive,passive,silent,noaccomp,nopcomp,nomagic,asyncmap_disabled;
    unsigned lcp_timeout,lcp_max_configure,lcp_max_terminate,lcp_max_failure,lcp_loopback_failure;
    unsigned ipcp_timeout,ipcp_max_configure,ipcp_max_terminate,ipcp_max_failure;
    int ipcp_accept_local,ipcp_accept_remote,usepeerdns,usepeerwins;
    uint32_t dns[2],wins[2];
    int ipv4_disabled,ipv6_enabled,ipv6_accept_local,ipv6_accept_remote;
    uint8_t ipv6_local_id[8],ipv6_peer_id[8];
    unsigned ipv6cp_timeout,ipv6cp_max_configure,ipv6cp_max_terminate,ipv6cp_max_failure;
    unsigned maxconnect;
    char rtt_file[2048];
    int default_mru,receive_all,ipcp_no_address,ipcp_no_addresses,ipv6_use_ipaddr,ipv6_no_send;
    unsigned idle;
    PppAuthConfig auth;
} PppConfig;

typedef struct PppOps {
    void *ctx;
    /* Return 0 only if ALL bytes were copied/enqueued; no partial acceptance. */
    int (*write_serial)(void *ctx, const uint8_t *bytes, size_t length);
    /* Valid PPP IPv4 payload; callback must copy before returning. */
    int (*receive_ip)(void *ctx, const uint8_t *bytes, size_t length);
    /* up=1 after IPCP succeeds; up=0 when the session reaches its dead phase.
     * mtu is the negotiated transmit limit, never larger than config.mtu.
     * On up=0, addresses are the last negotiated values (or configured values).
     */
    void (*status)(void *ctx, int up, uint32_t local_ip_be,
                   uint32_t peer_ip_be, uint16_t mtu);
    void (*log)(void *ctx, const char *message);
    /* IPv6 link-local identifiers; callback configures the host interface. */
    void (*status_ipv6)(void *ctx,int up,const uint8_t local_id[8],
                        const uint8_t peer_id[8],uint16_t mtu);
    void (*network_parameters)(void *ctx,const uint32_t dns[2],const uint32_t wins[2]);
} PppOps;

int ppp_engine_init(const PppConfig *config, const PppOps *ops);
int ppp_engine_start(void);
void ppp_engine_serial_input(const uint8_t *bytes, size_t length);
/* Returns 0 if encoded successfully; nonzero for down/invalid/oversize/output error. */
int ppp_engine_send_ipv4(const uint8_t *bytes, size_t length);
int ppp_engine_send_ip(const uint8_t *bytes,size_t length);
/* Monotonic wrapping millisecond clock. First call establishes the time base.
 * Call regularly (e.g. every 10ms), including while no serial data arrives. */
void ppp_engine_poll(uint32_t now_ms);
void ppp_engine_close(void);
/* Prefer calling after is_dead(). Cancels all remaining callbacks and clears
 * the link state. The caller owns the shutdown grace period and serial I/O.
 * Never invoke from a callback. */
void ppp_engine_destroy(void);
int ppp_engine_is_up(void);
int ppp_engine_is_dead(void);
int ppp_engine_last_error(void);

#endif
