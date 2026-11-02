/* Native host declarations for the retained upstream LCP/IPCP/IPv6CP code. */
#ifndef PPP_CORE_EXTRA_H
#define PPP_CORE_EXTRA_H
#include <time.h>
#include "eui64.h"
#ifndef PPP_IPV6CP
#define PPP_IPV6CP 0x8057
#endif
#ifndef PHASE_AUTHENTICATE
#define PHASE_AUTHENTICATE 5
#endif
#define PPP_CORE_MAX_MRU 16384
struct pppd_stats { unsigned int pkts_in,pkts_out; };
int get_ppp_stats(int,struct pppd_stats *);
int ppp_core_monotonic(struct timespec *);
void ppp_core_network_parameters(const uint32_t *,const uint32_t *);
int ppp_core_sif6addr(int,eui64_t,eui64_t);
int ppp_core_cif6addr(int);
extern int demand;
#endif
