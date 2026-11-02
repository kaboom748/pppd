/*
 * ipcp.c - PPP IP Control Protocol.
 *
 * Copyright (c) 1984-2000 Carnegie Mellon University. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any legal
 *    details, please contact
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */


/* Windows adaptation: negotiation callbacks retained; Unix option/scripts/IP hooks replaced. */

#include "pppd-private.h"
#include "core_extra.h"
#include "fsm.h"
#include "ipcp.h"
#define CILEN_VOID 2
#define CILEN_COMPRESS 4
#define CILEN_VJ 6
#define CILEN_ADDR 6
#define CILEN_ADDRS 10
#define CODENAME(x) ((x)==CONFACK?"ACK":(x)==CONFNAK?"NAK":"REJ")
#define MAX_STATES 16
fsm ipcp_fsm[NUM_PPP];
ipcp_options ipcp_wantoptions[NUM_PPP],ipcp_gotoptions[NUM_PPP],ipcp_allowoptions[NUM_PPP],ipcp_hisoptions[NUM_PPP];
bool noremoteip=0;
bool usepeerdns=0,usepeerwins=0;
static bool ask_for_local=1;
static int ipcp_is_open=0;
void (*ip_choose_hook)(uint32_t*)=NULL;
static void ipcp_close(int unit,char *reason);
static void ipcp_up(fsm *f){

    ipcp_options *ho = &ipcp_hisoptions[f->unit];
    ipcp_options *go = &ipcp_gotoptions[f->unit];
    ipcp_options *wo = &ipcp_wantoptions[f->unit];

    IPCPDEBUG(("ipcp: up"));

    /*
     * We must have a non-zero IP address for both ends of the link.
     */

    if (wo->hisaddr && !wo->accept_remote && !noremoteip &&
	(!(ho->neg_addr || ho->old_addrs) || ho->hisaddr != wo->hisaddr)) {
	error("Peer refused to agree to his IP address");
	ipcp_close(f->unit, "Refused his IP address");
	return;
    }
    if (!ho->neg_addr && !ho->old_addrs)
	ho->hisaddr = wo->hisaddr;

    if (!(go->neg_addr || go->old_addrs) && (wo->neg_addr || wo->old_addrs)
	&& wo->ouraddr != 0) {
	error("Peer refused to agree to our IP address");
	ipcp_close(f->unit, "Refused our IP address");
	return;
    }
    if (go->ouraddr == 0) {
	error("Could not determine local IP address");
	ipcp_close(f->unit, "Could not determine local IP address");
	return;
    }
    if (ho->hisaddr == 0 && !noremoteip) {
	ho->hisaddr = htonl(0x0a404040);
	warn("Could not determine remote IP address: defaulting to %I",
	     ho->hisaddr);
    }

    if(ho->hisaddr && !auth_ip_addr(f->unit,ho->hisaddr)){
        ipcp_close(f->unit,"Unauthorized remote IP address");return;
    }
    if(!sifaddr(f->unit,go->ouraddr,ho->hisaddr,0xffffffffu)){
        ipcp_close(f->unit,"Interface configuration failed");return;
    }
    if(!go->req_dns1)go->dnsaddr[0]=0;
    if(!go->req_dns2)go->dnsaddr[1]=0;
    ppp_core_network_parameters(go->dnsaddr,go->winsaddr);
    np_up(f->unit,PPP_IP);
}
static void ipcp_down(fsm *f){np_down(f->unit,PPP_IP);cifaddr(f->unit,0,0);}
static void
ipcp_init(int unit);
static void
ipcp_open(int unit);
static void
ipcp_close(int unit, char *reason);
static void
ipcp_lowerup(int unit);
static void
ipcp_lowerdown(int unit);
static void
ipcp_input(int unit, u_char *p, int len);
static void
ipcp_protrej(int unit);
static void
ipcp_resetci(fsm *f);
static int
ipcp_cilen(fsm *f);
static void
ipcp_addci(fsm *f, u_char *ucp, int *lenp);
static int
ipcp_ackci(fsm *f, u_char *p, int len);
static int
ipcp_nakci(fsm *f, u_char *p, int len, int treat_as_reject);
static int
ipcp_rejci(fsm *f, u_char *p, int len);
static int
ipcp_reqci(fsm *f, u_char *inp,	int *len, int reject_if_disagree);
static void
ipcp_finished(fsm *f);

static fsm_callbacks ipcp_callbacks={ipcp_resetci,ipcp_cilen,ipcp_addci,ipcp_ackci,ipcp_nakci,ipcp_rejci,ipcp_reqci,ipcp_up,ipcp_down,NULL,ipcp_finished,NULL,NULL,NULL,"IPCP"};
struct protent ipcp_protent={PPP_IPCP,ipcp_init,ipcp_input,ipcp_protrej,ipcp_lowerup,ipcp_lowerdown,ipcp_open,ipcp_close,NULL,NULL,1,"IPCP","IP",NULL,NULL,NULL,NULL};
static void
ipcp_init(int unit)
{
    fsm *f = &ipcp_fsm[unit];
    ipcp_options *wo = &ipcp_wantoptions[unit];
    ipcp_options *ao = &ipcp_allowoptions[unit];

    f->unit = unit;
    f->protocol = PPP_IPCP;
    f->callbacks = &ipcp_callbacks;
    fsm_init(&ipcp_fsm[unit]);
    ipcp_is_open = 0;

    /*
     * Some 3G modems use repeated IPCP NAKs as a way of stalling
     * until they can contact a server on the network, so we increase
     * the default number of NAKs we accept before we start treating
     * them as rejects.
     */
    f->maxnakloops = DEFMAXNAKLOOPS;

    memset(wo, 0, sizeof(*wo));
    memset(ao, 0, sizeof(*ao));

    wo->neg_addr = wo->old_addrs = 1;
    wo->neg_vj = 0;
    wo->vj_protocol = IPCP_VJ_COMP;
    wo->maxslotindex = MAX_STATES - 1; /* really max index */
    wo->cflag = 1;


    /* max slots and slot-id compression are currently hardwired in */
    /* ppp_if.c to 16 and 1, this needs to be changed (among other */
    /* things) gmc */

    ao->neg_addr = ao->old_addrs = 1;
    ao->neg_vj = 0;
    ao->maxslotindex = MAX_STATES - 1;
    ao->cflag = 1;

    /*
     * XXX These control whether the user may use the proxyarp
     * and defaultroute options.
     */
    ao->proxy_arp = 0;
    ao->default_route = 0;
}

static void
ipcp_open(int unit)
{
    fsm_open(&ipcp_fsm[unit]);
    ipcp_is_open = 1;
}

static void
ipcp_close(int unit, char *reason)
{
    fsm_close(&ipcp_fsm[unit], reason);
}

static void
ipcp_lowerup(int unit)
{
    fsm_lowerup(&ipcp_fsm[unit]);
}

static void
ipcp_lowerdown(int unit)
{
    fsm_lowerdown(&ipcp_fsm[unit]);
}

static void
ipcp_input(int unit, u_char *p, int len)
{
    fsm_input(&ipcp_fsm[unit], p, len);
}

static void
ipcp_protrej(int unit)
{
    fsm_lowerdown(&ipcp_fsm[unit]);
}

static void
ipcp_resetci(fsm *f)
{
    ipcp_options *wo = &ipcp_wantoptions[f->unit];
    ipcp_options *go = &ipcp_gotoptions[f->unit];
    ipcp_options *ao = &ipcp_allowoptions[f->unit];

    wo->req_addr = ((wo->neg_addr || wo->old_addrs) &&
	(ao->neg_addr || ao->old_addrs)) ||
	(wo->hisaddr && !wo->accept_remote);
    if (wo->ouraddr == 0)
	wo->accept_local = 1;
    if (wo->hisaddr == 0)
	wo->accept_remote = 1;
    wo->req_dns1 = usepeerdns;	/* Request DNS addresses from the peer */
    wo->req_dns2 = usepeerdns;
    wo->req_wins1 = usepeerwins; /* Request WINS addresses from the peer */
    wo->req_wins2 = usepeerwins;
    *go = *wo;
    if (!ask_for_local)
	go->ouraddr = 0;
    if (ip_choose_hook) {
	ip_choose_hook(&wo->hisaddr);
	if (wo->hisaddr) {
	    wo->accept_remote = 0;
	}
    }
    BZERO(&ipcp_hisoptions[f->unit], sizeof(ipcp_options));
}

static int
ipcp_cilen(fsm *f)
{
    ipcp_options *go = &ipcp_gotoptions[f->unit];
    ipcp_options *wo = &ipcp_wantoptions[f->unit];
    ipcp_options *ho = &ipcp_hisoptions[f->unit];

#define LENCIADDRS(neg)		(neg ? CILEN_ADDRS : 0)
#define LENCIVJ(neg, old)	(neg ? (old? CILEN_COMPRESS : CILEN_VJ) : 0)
#define LENCIADDR(neg)		(neg ? CILEN_ADDR : 0)
#define LENCIDNS(neg)		LENCIADDR(neg)
#define LENCIWINS(neg)		LENCIADDR(neg)

    /*
     * First see if we want to change our options to the old
     * forms because we have received old forms from the peer.
     */
    if (go->neg_addr && go->old_addrs && !ho->neg_addr && ho->old_addrs)
	go->neg_addr = 0;
    if (wo->neg_vj && !go->neg_vj && !go->old_vj) {
	/* try an older style of VJ negotiation */
	/* use the old style only if the peer did */
	if (ho->neg_vj && ho->old_vj) {
	    go->neg_vj = 1;
	    go->old_vj = 1;
	    go->vj_protocol = ho->vj_protocol;
	}
    }

    return (LENCIADDRS(!go->neg_addr && go->old_addrs) +
	    LENCIVJ(go->neg_vj, go->old_vj) +
	    LENCIADDR(go->neg_addr) +
	    LENCIDNS(go->req_dns1) +
	    LENCIDNS(go->req_dns2) +
	    LENCIWINS(go->req_wins1) +
	    LENCIWINS(go->req_wins2)) ;
}

static void
ipcp_addci(fsm *f, u_char *ucp, int *lenp)
{
    ipcp_options *go = &ipcp_gotoptions[f->unit];
    int len = *lenp;

#define ADDCIADDRS(opt, neg, val1, val2) \
    if (neg) { \
	if (len >= CILEN_ADDRS) { \
	    u_int32_t l; \
	    PUTCHAR(opt, ucp); \
	    PUTCHAR(CILEN_ADDRS, ucp); \
	    l = ntohl(val1); \
	    PUTLONG(l, ucp); \
	    l = ntohl(val2); \
	    PUTLONG(l, ucp); \
	    len -= CILEN_ADDRS; \
	} else \
	    go->old_addrs = 0; \
    }

#define ADDCIVJ(opt, neg, val, old, maxslotindex, cflag) \
    if (neg) { \
	int vjlen = old? CILEN_COMPRESS : CILEN_VJ; \
	if (len >= vjlen) { \
	    PUTCHAR(opt, ucp); \
	    PUTCHAR(vjlen, ucp); \
	    PUTSHORT(val, ucp); \
	    if (!old) { \
		PUTCHAR(maxslotindex, ucp); \
		PUTCHAR(cflag, ucp); \
	    } \
	    len -= vjlen; \
	} else \
	    neg = 0; \
    }

#define ADDCIADDR(opt, neg, val) \
    if (neg) { \
	if (len >= CILEN_ADDR) { \
	    u_int32_t l; \
	    PUTCHAR(opt, ucp); \
	    PUTCHAR(CILEN_ADDR, ucp); \
	    l = ntohl(val); \
	    PUTLONG(l, ucp); \
	    len -= CILEN_ADDR; \
	} else \
	    neg = 0; \
    }

#define ADDCIDNS(opt, neg, addr) \
    if (neg) { \
	if (len >= CILEN_ADDR) { \
	    u_int32_t l; \
	    PUTCHAR(opt, ucp); \
	    PUTCHAR(CILEN_ADDR, ucp); \
	    l = ntohl(addr); \
	    PUTLONG(l, ucp); \
	    len -= CILEN_ADDR; \
	} else \
	    neg = 0; \
    }

#define ADDCIWINS(opt, neg, addr) \
    if (neg) { \
	if (len >= CILEN_ADDR) { \
	    u_int32_t l; \
	    PUTCHAR(opt, ucp); \
	    PUTCHAR(CILEN_ADDR, ucp); \
	    l = ntohl(addr); \
	    PUTLONG(l, ucp); \
	    len -= CILEN_ADDR; \
	} else \
	    neg = 0; \
    }

    ADDCIADDRS(CI_ADDRS, !go->neg_addr && go->old_addrs, go->ouraddr,
	       go->hisaddr);

    ADDCIVJ(CI_COMPRESSTYPE, go->neg_vj, go->vj_protocol, go->old_vj,
	    go->maxslotindex, go->cflag);

    ADDCIADDR(CI_ADDR, go->neg_addr, go->ouraddr);

    ADDCIDNS(CI_MS_DNS1, go->req_dns1, go->dnsaddr[0]);

    ADDCIDNS(CI_MS_DNS2, go->req_dns2, go->dnsaddr[1]);

    ADDCIWINS(CI_MS_WINS1, go->req_wins1, go->winsaddr[0]);

    ADDCIWINS(CI_MS_WINS2, go->req_wins2, go->winsaddr[1]);

    *lenp -= len;
}

static int
ipcp_ackci(fsm *f, u_char *p, int len)
{
    ipcp_options *go = &ipcp_gotoptions[f->unit];
    u_short cilen, citype, cishort;
    u_int32_t cilong;
    u_char cimaxslotindex, cicflag;

    /*
     * CIs must be in exactly the same order that we sent...
     * Check packet length and CI length at each step.
     * If we find any deviations, then this packet is bad.
     */

#define ACKCIADDRS(opt, neg, val1, val2) \
    if (neg) { \
	u_int32_t l; \
	if ((len -= CILEN_ADDRS) < 0) \
	    goto bad; \
	GETCHAR(citype, p); \
	GETCHAR(cilen, p); \
	if (cilen != CILEN_ADDRS || \
	    citype != opt) \
	    goto bad; \
	GETLONG(l, p); \
	cilong = htonl(l); \
	if (val1 != cilong) \
	    goto bad; \
	GETLONG(l, p); \
	cilong = htonl(l); \
	if (val2 != cilong) \
	    goto bad; \
    }

#define ACKCIVJ(opt, neg, val, old, maxslotindex, cflag) \
    if (neg) { \
	int vjlen = old? CILEN_COMPRESS : CILEN_VJ; \
	if ((len -= vjlen) < 0) \
	    goto bad; \
	GETCHAR(citype, p); \
	GETCHAR(cilen, p); \
	if (cilen != vjlen || \
	    citype != opt)  \
	    goto bad; \
	GETSHORT(cishort, p); \
	if (cishort != val) \
	    goto bad; \
	if (!old) { \
	    GETCHAR(cimaxslotindex, p); \
	    if (cimaxslotindex != maxslotindex) \
		goto bad; \
	    GETCHAR(cicflag, p); \
	    if (cicflag != cflag) \
		goto bad; \
	} \
    }

#define ACKCIADDR(opt, neg, val) \
    if (neg) { \
	u_int32_t l; \
	if ((len -= CILEN_ADDR) < 0) \
	    goto bad; \
	GETCHAR(citype, p); \
	GETCHAR(cilen, p); \
	if (cilen != CILEN_ADDR || \
	    citype != opt) \
	    goto bad; \
	GETLONG(l, p); \
	cilong = htonl(l); \
	if (val != cilong) \
	    goto bad; \
    }

#define ACKCIDNS(opt, neg, addr) \
    if (neg) { \
	u_int32_t l; \
	if ((len -= CILEN_ADDR) < 0) \
	    goto bad; \
	GETCHAR(citype, p); \
	GETCHAR(cilen, p); \
	if (cilen != CILEN_ADDR || citype != opt) \
	    goto bad; \
	GETLONG(l, p); \
	cilong = htonl(l); \
	if (addr != cilong) \
	    goto bad; \
    }

#define ACKCIWINS(opt, neg, addr) \
    if (neg) { \
	u_int32_t l; \
	if ((len -= CILEN_ADDR) < 0) \
	    goto bad; \
	GETCHAR(citype, p); \
	GETCHAR(cilen, p); \
	if (cilen != CILEN_ADDR || citype != opt) \
	    goto bad; \
	GETLONG(l, p); \
	cilong = htonl(l); \
	if (addr != cilong) \
	    goto bad; \
    }

    ACKCIADDRS(CI_ADDRS, !go->neg_addr && go->old_addrs, go->ouraddr,
	       go->hisaddr);

    ACKCIVJ(CI_COMPRESSTYPE, go->neg_vj, go->vj_protocol, go->old_vj,
	    go->maxslotindex, go->cflag);

    ACKCIADDR(CI_ADDR, go->neg_addr, go->ouraddr);

    ACKCIDNS(CI_MS_DNS1, go->req_dns1, go->dnsaddr[0]);

    ACKCIDNS(CI_MS_DNS2, go->req_dns2, go->dnsaddr[1]);

    ACKCIWINS(CI_MS_WINS1, go->req_wins1, go->winsaddr[0]);

    ACKCIWINS(CI_MS_WINS2, go->req_wins2, go->winsaddr[1]);

    /*
     * If there are any remaining CIs, then this packet is bad.
     */
    if (len != 0)
	goto bad;
    return (1);

bad:
    IPCPDEBUG(("ipcp_ackci: received bad Ack!"));
    return (0);
}

static int
ipcp_nakci(fsm *f, u_char *p, int len, int treat_as_reject)
{
    ipcp_options *wo = &ipcp_wantoptions[f->unit];
    ipcp_options *go = &ipcp_gotoptions[f->unit];
    u_char cimaxslotindex, cicflag;
    u_char citype, cilen, *next;
    u_short cishort;
    u_int32_t ciaddr1, ciaddr2, l, cidnsaddr, ciwinsaddr;
    ipcp_options no;		/* options we've seen Naks for */
    ipcp_options try;		/* options to request next time */

    BZERO(&no, sizeof(no));
    try = *go;

    /*
     * Any Nak'd CIs must be in exactly the same order that we sent.
     * Check packet length and CI length at each step.
     * If we find any deviations, then this packet is bad.
     */
#define NAKCIADDRS(opt, neg, code) \
    if ((neg) && \
	(cilen = p[1]) == CILEN_ADDRS && \
	len >= cilen && \
	p[0] == opt) { \
	len -= cilen; \
	INCPTR(2, p); \
	GETLONG(l, p); \
	ciaddr1 = htonl(l); \
	GETLONG(l, p); \
	ciaddr2 = htonl(l); \
	no.old_addrs = 1; \
	code \
    }

#define NAKCIVJ(opt, neg, code) \
    if (go->neg && \
	((cilen = p[1]) == CILEN_COMPRESS || cilen == CILEN_VJ) && \
	len >= cilen && \
	p[0] == opt) { \
	len -= cilen; \
	INCPTR(2, p); \
	GETSHORT(cishort, p); \
	no.neg = 1; \
        code \
    }

#define NAKCIADDR(opt, neg, code) \
    if (go->neg && \
	(cilen = p[1]) == CILEN_ADDR && \
	len >= cilen && \
	p[0] == opt) { \
	len -= cilen; \
	INCPTR(2, p); \
	GETLONG(l, p); \
	ciaddr1 = htonl(l); \
	no.neg = 1; \
	code \
    }

#define NAKCIDNS(opt, neg, code) \
    if (go->neg && \
	((cilen = p[1]) == CILEN_ADDR) && \
	len >= cilen && \
	p[0] == opt) { \
	len -= cilen; \
	INCPTR(2, p); \
	GETLONG(l, p); \
	cidnsaddr = htonl(l); \
	no.neg = 1; \
	code \
    }

#define NAKCIWINS(opt, neg, code) \
    if (go->neg && \
	((cilen = p[1]) == CILEN_ADDR) && \
	len >= cilen && \
	p[0] == opt) { \
	len -= cilen; \
	INCPTR(2, p); \
	GETLONG(l, p); \
	ciwinsaddr = htonl(l); \
	no.neg = 1; \
	code \
    }

    /*
     * Accept the peer's idea of {our,his} address, if different
     * from our idea, only if the accept_{local,remote} flag is set.
     */
    NAKCIADDRS(CI_ADDRS, !go->neg_addr && go->old_addrs,
	       if (treat_as_reject) {
		   try.old_addrs = 0;
	       } else {
		   if (go->accept_local && ciaddr1) {
		       /* take his idea of our address */
		       try.ouraddr = ciaddr1;
		   }
		   if (go->accept_remote && ciaddr2) {
		       /* take his idea of his address */
		       try.hisaddr = ciaddr2;
		   }
	       }
	);

    /*
     * Accept the peer's value of maxslotindex provided that it
     * is less than what we asked for.  Turn off slot-ID compression
     * if the peer wants.  Send old-style compress-type option if
     * the peer wants.
     */
    NAKCIVJ(CI_COMPRESSTYPE, neg_vj,
	    if (treat_as_reject) {
		try.neg_vj = 0;
	    } else if (cilen == CILEN_VJ) {
		GETCHAR(cimaxslotindex, p);
		GETCHAR(cicflag, p);
		if (cishort == IPCP_VJ_COMP) {
		    try.old_vj = 0;
		    if (cimaxslotindex < go->maxslotindex)
			try.maxslotindex = cimaxslotindex;
		    if (!cicflag)
			try.cflag = 0;
		} else {
		    try.neg_vj = 0;
		}
	    } else {
		if (cishort == IPCP_VJ_COMP || cishort == IPCP_VJ_COMP_OLD) {
		    try.old_vj = 1;
		    try.vj_protocol = cishort;
		} else {
		    try.neg_vj = 0;
		}
	    }
	    );

    NAKCIADDR(CI_ADDR, neg_addr,
	      if (treat_as_reject) {
		  try.neg_addr = 0;
		  try.old_addrs = 0;
	      } else if (go->accept_local && ciaddr1) {
		  /* take his idea of our address */
		  try.ouraddr = ciaddr1;
	      }
	      );

    NAKCIDNS(CI_MS_DNS1, req_dns1,
	     if (treat_as_reject) {
		 try.req_dns1 = 0;
	     } else {
		 try.dnsaddr[0] = cidnsaddr;
	     }
	     );

    NAKCIDNS(CI_MS_DNS2, req_dns2,
	     if (treat_as_reject) {
		 try.req_dns2 = 0;
	     } else {
		 try.dnsaddr[1] = cidnsaddr;
	     }
	     );

    NAKCIWINS(CI_MS_WINS1, req_wins1,
	     if (treat_as_reject) {
		 try.req_wins1 = 0;
	     } else {
		 try.winsaddr[0] = ciwinsaddr;
	     }
	     );

    NAKCIWINS(CI_MS_WINS2, req_wins2,
	     if (treat_as_reject) {
		 try.req_wins2 = 0;
	     } else {
		 try.winsaddr[1] = ciwinsaddr;
	     }
	     );

    /*
     * There may be remaining CIs, if the peer is requesting negotiation
     * on an option that we didn't include in our request packet.
     * If they want to negotiate about IP addresses, we comply.
     * If they want us to ask for compression, we refuse.
     * If they want us to ask for ms-dns, we do that, since some
     * peers get huffy if we don't.
     */
    while (len >= CILEN_VOID) {
	GETCHAR(citype, p);
	GETCHAR(cilen, p);
	if ( cilen < CILEN_VOID || (len -= cilen) < 0 )
	    goto bad;
	next = p + cilen - 2;

	switch (citype) {
	case CI_COMPRESSTYPE:
	    if (go->neg_vj || no.neg_vj ||
		(cilen != CILEN_VJ && cilen != CILEN_COMPRESS))
		goto bad;
	    no.neg_vj = 1;
	    break;
	case CI_ADDRS:
	    if ((!go->neg_addr && go->old_addrs) || no.old_addrs
		|| cilen != CILEN_ADDRS)
		goto bad;
	    try.neg_addr = 0;
	    GETLONG(l, p);
	    ciaddr1 = htonl(l);
	    if (ciaddr1 && go->accept_local)
		try.ouraddr = wo->old_addrs ? ciaddr1 : 0;
	    GETLONG(l, p);
	    ciaddr2 = htonl(l);
	    if (ciaddr2 && go->accept_remote)
		try.hisaddr = ciaddr2;
	    no.old_addrs = 1;
	    break;
	case CI_ADDR:
	    if (go->neg_addr || no.neg_addr || cilen != CILEN_ADDR)
		goto bad;
	    try.old_addrs = 0;
	    GETLONG(l, p);
	    ciaddr1 = htonl(l);
	    if (ciaddr1 && go->accept_local)
		try.ouraddr = ciaddr1;
	    if (try.ouraddr != 0 && wo->neg_addr)
		try.neg_addr = 1;
	    no.neg_addr = 1;
	    break;
	case CI_MS_DNS1:
	    if (go->req_dns1 || no.req_dns1 || cilen != CILEN_ADDR)
		goto bad;
	    GETLONG(l, p);
	    try.dnsaddr[0] = htonl(l);
	    try.req_dns1 = 1;
	    no.req_dns1 = 1;
	    break;
	case CI_MS_DNS2:
	    if (go->req_dns2 || no.req_dns2 || cilen != CILEN_ADDR)
		goto bad;
	    GETLONG(l, p);
	    try.dnsaddr[1] = htonl(l);
	    try.req_dns2 = 1;
	    no.req_dns2 = 1;
	    break;
	case CI_MS_WINS1:
	    if (go->req_wins1 || no.req_wins1 || cilen != CILEN_ADDR)
		goto bad;
	    GETLONG(l, p);
	    try.winsaddr[0] = htonl(l);
	    try.req_wins1 = 1;
	    no.req_wins1 = 1;
	    break;
	case CI_MS_WINS2:
	    if (go->req_wins2 || no.req_wins2 || cilen != CILEN_ADDR)
		goto bad;
	    GETLONG(l, p);
	    try.winsaddr[1] = htonl(l);
	    try.req_wins2 = 1;
	    no.req_wins2 = 1;
	    break;
	}
	p = next;
    }

    /*
     * OK, the Nak is good.  Now we can update state.
     * If there are any remaining options, we ignore them.
     */
    if (f->state != OPENED)
	*go = try;

    return 1;

bad:
    IPCPDEBUG(("ipcp_nakci: received bad Nak!"));
    return 0;
}

static int
ipcp_rejci(fsm *f, u_char *p, int len)
{
    ipcp_options *go = &ipcp_gotoptions[f->unit];
    u_char cimaxslotindex, ciflag, cilen;
    u_short cishort;
    u_int32_t cilong;
    ipcp_options try;		/* options to request next time */

    try = *go;
    /*
     * Any Rejected CIs must be in exactly the same order that we sent.
     * Check packet length and CI length at each step.
     * If we find any deviations, then this packet is bad.
     */
#define REJCIADDRS(opt, neg, val1, val2) \
    if ((neg) && \
	(cilen = p[1]) == CILEN_ADDRS && \
	len >= cilen && \
	p[0] == opt) { \
	u_int32_t l; \
	len -= cilen; \
	INCPTR(2, p); \
	GETLONG(l, p); \
	cilong = htonl(l); \
	/* Check rejected value. */ \
	if (cilong != val1) \
	    goto bad; \
	GETLONG(l, p); \
	cilong = htonl(l); \
	/* Check rejected value. */ \
	if (cilong != val2) \
	    goto bad; \
	try.old_addrs = 0; \
    }

#define REJCIVJ(opt, neg, val, old, maxslot, cflag) \
    if (go->neg && \
	p[1] == (old? CILEN_COMPRESS : CILEN_VJ) && \
	len >= p[1] && \
	p[0] == opt) { \
	len -= p[1]; \
	INCPTR(2, p); \
	GETSHORT(cishort, p); \
	/* Check rejected value. */  \
	if (cishort != val) \
	    goto bad; \
	if (!old) { \
	   GETCHAR(cimaxslotindex, p); \
	   if (cimaxslotindex != maxslot) \
	     goto bad; \
	   GETCHAR(ciflag, p); \
	   if (ciflag != cflag) \
	     goto bad; \
        } \
	try.neg = 0; \
     }

#define REJCIADDR(opt, neg, val) \
    if (go->neg && \
	(cilen = p[1]) == CILEN_ADDR && \
	len >= cilen && \
	p[0] == opt) { \
	u_int32_t l; \
	len -= cilen; \
	INCPTR(2, p); \
	GETLONG(l, p); \
	cilong = htonl(l); \
	/* Check rejected value. */ \
	if (cilong != val) \
	    goto bad; \
	try.neg = 0; \
    }

#define REJCIDNS(opt, neg, dnsaddr) \
    if (go->neg && \
	((cilen = p[1]) == CILEN_ADDR) && \
	len >= cilen && \
	p[0] == opt) { \
	u_int32_t l; \
	len -= cilen; \
	INCPTR(2, p); \
	GETLONG(l, p); \
	cilong = htonl(l); \
	/* Check rejected value. */ \
	if (cilong != dnsaddr) \
	    goto bad; \
	try.neg = 0; \
    }

#define REJCIWINS(opt, neg, addr) \
    if (go->neg && \
	((cilen = p[1]) == CILEN_ADDR) && \
	len >= cilen && \
	p[0] == opt) { \
	u_int32_t l; \
	len -= cilen; \
	INCPTR(2, p); \
	GETLONG(l, p); \
	cilong = htonl(l); \
	/* Check rejected value. */ \
	if (cilong != addr) \
	    goto bad; \
	try.neg = 0; \
    }

    REJCIADDRS(CI_ADDRS, !go->neg_addr && go->old_addrs,
	       go->ouraddr, go->hisaddr);

    REJCIVJ(CI_COMPRESSTYPE, neg_vj, go->vj_protocol, go->old_vj,
	    go->maxslotindex, go->cflag);

    REJCIADDR(CI_ADDR, neg_addr, go->ouraddr);

    REJCIDNS(CI_MS_DNS1, req_dns1, go->dnsaddr[0]);

    REJCIDNS(CI_MS_DNS2, req_dns2, go->dnsaddr[1]);

    REJCIWINS(CI_MS_WINS1, req_wins1, go->winsaddr[0]);

    REJCIWINS(CI_MS_WINS2, req_wins2, go->winsaddr[1]);

    /*
     * If there are any remaining CIs, then this packet is bad.
     */
    if (len != 0)
	goto bad;
    /*
     * Now we can update state.
     */
    if (f->state != OPENED)
	*go = try;
    return 1;

bad:
    IPCPDEBUG(("ipcp_rejci: received bad Reject!"));
    return 0;
}

static int
ipcp_reqci(fsm *f, u_char *inp,	int *len, int reject_if_disagree)
{
    ipcp_options *wo = &ipcp_wantoptions[f->unit];
    ipcp_options *ho = &ipcp_hisoptions[f->unit];
    ipcp_options *ao = &ipcp_allowoptions[f->unit];
    u_char *cip, *next;		/* Pointer to current and next CIs */
    u_int32_t cilen, citype;	/* Parsed len, type */
    u_short cishort;		/* Parsed short value */
    u_int32_t tl, ciaddr1, ciaddr2;/* Parsed address values */
    int rc = CONFACK;		/* Final packet return code */
    int orc;			/* Individual option return code */
    u_char *p;			/* Pointer to next char to parse */
    u_char *ucp = inp;		/* Pointer to current output char */
    u_int32_t l = *len;		/* Length left */
    u_char maxslotindex, cflag;
    int d;
    int dup, warned = 0;
    int seendns[2], seenwins[2];

    /*
     * Reset all his options.
     */
    BZERO(ho, sizeof(*ho));
    seendns[0] = seendns[1] = 0;
    seenwins[0] = seenwins[1] = 0;

    /*
     * Process all his options.
     */
    next = inp;
    while (l) {
	orc = CONFACK;			/* Assume success */
	dup = 0;
	cip = p = next;			/* Remember begining of CI */
	if (l < 2 ||			/* Not enough data for CI header or */
	    p[1] < 2 ||			/*  CI length too small or */
	    p[1] > l) {			/*  CI length too big? */
	    IPCPDEBUG(("ipcp_reqci: bad CI length!"));
	    orc = CONFREJ;		/* Reject bad CI */
	    cilen = l;			/* Reject till end of packet */
	    l = 0;			/* Don't loop again */
	    goto endswitch;
	}
	GETCHAR(citype, p);		/* Parse CI type */
	GETCHAR(cilen, p);		/* Parse CI length */
	l -= cilen;			/* Adjust remaining length */
	next += cilen;			/* Step to next CI */

	switch (citype) {		/* Check CI type */
	case CI_ADDRS:
	    if (ho->old_addrs) {
		dup = 1;
		break;
	    }
	    ho->old_addrs = 1;
	    if (!ao->old_addrs || ho->neg_addr ||
		cilen != CILEN_ADDRS) {	/* Check CI length */
		orc = CONFREJ;		/* Reject CI */
		break;
	    }

	    /*
	     * If he has no address, or if we both have his address but
	     * disagree about it, then NAK it with our idea.
	     * In particular, if we don't know his address, but he does,
	     * then accept it.
	     */
	    GETLONG(tl, p);		/* Parse source address (his) */
	    ciaddr1 = htonl(tl);
	    if (ciaddr1 != wo->hisaddr
		&& (ciaddr1 == 0 || !wo->accept_remote)) {
		orc = CONFNAK;
		if (!reject_if_disagree) {
		    DECPTR(sizeof(u_int32_t), p);
		    tl = ntohl(wo->hisaddr);
		    PUTLONG(tl, p);
		}
	    } else if (ciaddr1 == 0 && wo->hisaddr == 0) {
		/*
		 * If neither we nor he knows his address, reject the option.
		 */
		orc = CONFREJ;
		wo->req_addr = 0;	/* don't NAK with 0.0.0.0 later */
		break;
	    }

	    /*
	     * If he doesn't know our address, or if we both have our address
	     * but disagree about it, then NAK it with our idea.
	     */
	    GETLONG(tl, p);		/* Parse desination address (ours) */
	    ciaddr2 = htonl(tl);
	    if (ciaddr2 != wo->ouraddr) {
		if (ciaddr2 == 0 || !wo->accept_local) {
		    orc = CONFNAK;
		    if (!reject_if_disagree && wo->old_addrs) {
			DECPTR(sizeof(u_int32_t), p);
			tl = ntohl(wo->ouraddr);
			PUTLONG(tl, p);
		    }
		} else {
		    wo->ouraddr = ciaddr2;	/* accept peer's idea */
		}
	    }

	    ho->hisaddr = ciaddr1;
	    ho->ouraddr = ciaddr2;
	    break;

	case CI_ADDR:
	    if (ho->neg_addr) {
		dup = 1;
		break;
	    }
	    ho->neg_addr = 1;
	    if (!ao->neg_addr || ho->old_addrs ||
		cilen != CILEN_ADDR) {	/* Check CI length */
		orc = CONFREJ;		/* Reject CI */
		break;
	    }

	    /*
	     * If he has no address, or if we both have his address but
	     * disagree about it, then NAK it with our idea.
	     * In particular, if we don't know his address, but he does,
	     * then accept it.
	     */
	    GETLONG(tl, p);	/* Parse source address (his) */
	    ciaddr1 = htonl(tl);
	    if (ciaddr1 != wo->hisaddr
		&& (ciaddr1 == 0 || !wo->accept_remote)) {
		orc = CONFNAK;
		if (!reject_if_disagree) {
		    DECPTR(sizeof(u_int32_t), p);
		    tl = ntohl(wo->hisaddr);
		    PUTLONG(tl, p);
		}
	    } else if (ciaddr1 == 0 && wo->hisaddr == 0) {
		/*
		 * Don't ACK an address of 0.0.0.0 - reject it instead.
		 */
		orc = CONFREJ;
		wo->req_addr = 0;	/* don't NAK with 0.0.0.0 later */
		break;
	    }

	    ho->hisaddr = ciaddr1;
	    break;

	case CI_MS_DNS1:
	case CI_MS_DNS2:
	    /* Microsoft primary or secondary DNS request */
	    d = citype == CI_MS_DNS2;
	    if (seendns[d]) {
		dup = 1;
		break;
	    }
	    seendns[d] = 1;

	    /* If we do not have a DNS address then we cannot send it */
	    if (ao->dnsaddr[d] == 0 ||
		cilen != CILEN_ADDR) {	/* Check CI length */
		orc = CONFREJ;		/* Reject CI */
		break;
	    }
	    GETLONG(tl, p);
	    if (htonl(tl) != ao->dnsaddr[d]) {
                DECPTR(sizeof(u_int32_t), p);
		tl = ntohl(ao->dnsaddr[d]);
		PUTLONG(tl, p);
		orc = CONFNAK;
            }
            break;

	case CI_MS_WINS1:
	case CI_MS_WINS2:
	    /* Microsoft primary or secondary WINS request */
	    d = citype == CI_MS_WINS2;
	    if (seenwins[d]) {
		dup = 1;
		break;
	    }
	    seenwins[d] = 1;

	    /* If we do not have a WINS address then we cannot send it */
	    if (ao->winsaddr[d] == 0 ||
		cilen != CILEN_ADDR) {	/* Check CI length */
		orc = CONFREJ;		/* Reject CI */
		break;
	    }
	    GETLONG(tl, p);
	    if (htonl(tl) != ao->winsaddr[d]) {
                DECPTR(sizeof(u_int32_t), p);
		tl = ntohl(ao->winsaddr[d]);
		PUTLONG(tl, p);
		orc = CONFNAK;
            }
            break;

	case CI_COMPRESSTYPE:
	    if (ho->neg_vj) {
		dup = 1;
		break;
	    }
	    ho->neg_vj = 1;
	    if (!ao->neg_vj ||
		(cilen != CILEN_VJ && cilen != CILEN_COMPRESS)) {
		orc = CONFREJ;
		break;
	    }
	    GETSHORT(cishort, p);

	    if (!(cishort == IPCP_VJ_COMP ||
		  (cishort == IPCP_VJ_COMP_OLD && cilen == CILEN_COMPRESS))) {
		orc = CONFREJ;
		break;
	    }

	    ho->vj_protocol = cishort;
	    if (cilen == CILEN_VJ) {
		GETCHAR(maxslotindex, p);
		if (maxslotindex > ao->maxslotindex) {
		    orc = CONFNAK;
		    if (!reject_if_disagree){
			DECPTR(1, p);
			PUTCHAR(ao->maxslotindex, p);
		    }
		}
		GETCHAR(cflag, p);
		if (cflag && !ao->cflag) {
		    orc = CONFNAK;
		    if (!reject_if_disagree){
			DECPTR(1, p);
			PUTCHAR(wo->cflag, p);
		    }
		}
		ho->maxslotindex = maxslotindex;
		ho->cflag = cflag;
	    } else {
		ho->old_vj = 1;
		ho->maxslotindex = MAX_STATES - 1;
		ho->cflag = 1;
	    }
	    break;

	default:
	    orc = CONFREJ;
	    break;
	}
	if (dup) {
	    if (!warned) {
		warn("IPCP: ignoring duplicate configuration option(s)");
		warned = 1;
	    }
	    continue;
	}
endswitch:
	if (orc == CONFACK &&		/* Good CI */
	    rc != CONFACK)		/*  but prior CI wasnt? */
	    continue;			/* Don't send this one */

	if (orc == CONFNAK) {		/* Nak this CI? */
	    if (reject_if_disagree)	/* Getting fed up with sending NAKs? */
		orc = CONFREJ;		/* Get tough if so */
	    else {
		if (rc == CONFREJ)	/* Rejecting prior CI? */
		    continue;		/* Don't send this one */
		if (rc == CONFACK) {	/* Ack'd all prior CIs? */
		    rc = CONFNAK;	/* Not anymore... */
		    ucp = inp;		/* Backup */
		}
	    }
	}

	if (orc == CONFREJ &&		/* Reject this CI */
	    rc != CONFREJ) {		/*  but no prior ones? */
	    rc = CONFREJ;
	    ucp = inp;			/* Backup */
	}

	/* Need to move CI? */
	if (ucp != cip)
	    BCOPY(cip, ucp, cilen);	/* Move it */

	/* Update output pointer */
	INCPTR(cilen, ucp);
    }

    /*
     * If we aren't rejecting this packet, and we want to negotiate
     * their address, and they didn't send their address, then we
     * send a NAK with a CI_ADDR option appended.  We check that the
     * input buffer is long enough that we can append the extra
     * option safely.
     */
    if (rc != CONFREJ && !ho->neg_addr && !ho->old_addrs &&
	wo->req_addr && !reject_if_disagree &&
	((wo->hisaddr && !wo->accept_remote) || !noremoteip) &&
	(rc == CONFACK || ucp + CILEN_ADDR <= inp + PPP_MRU - HEADERLEN)) {
	if (rc == CONFACK) {
	    rc = CONFNAK;
	    ucp = inp;			/* reset pointer */
	    wo->req_addr = 0;		/* don't ask again */
	}
	PUTCHAR(CI_ADDR, ucp);
	PUTCHAR(CILEN_ADDR, ucp);
	tl = ntohl(wo->hisaddr);
	PUTLONG(tl, ucp);
    }

    *len = ucp - inp;			/* Compute output length */
    IPCPDEBUG(("ipcp: returning Configure-%s", CODENAME(rc)));
    return (rc);			/* Return final code */
}

static void
ipcp_finished(fsm *f)
{
	if (ipcp_is_open) {
		ipcp_is_open = 0;
		np_finished(f->unit, PPP_IP);
	}
}
