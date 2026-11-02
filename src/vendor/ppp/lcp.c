/*
 * lcp.c - PPP Link Control Protocol.
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


/* Upstream negotiation and Echo/RTT algorithms; native host boundary below. */
#include "pppd-private.h"
#include "core_extra.h"
#include "fsm.h"
#include "lcp.h"
#include "chap.h"
#define DELAYED_UP 0x100
#define CILEN_VOID 2
#define CILEN_CHAR 3
#define CILEN_SHORT 4
#define CILEN_CHAP 5
#define CILEN_LONG 6
#define CILEN_LQR 8
#define CILEN_CBCP 3
#define CODENAME(x) ((x)==CONFACK?"ACK":(x)==CONFNAK?"NAK":"REJ")
#define LCP_RTT_MAGIC 0x19450425
#define LCP_RTT_HEADER_LENGTH 4
#define LCP_RTT_FILE_SIZE 8192
#define LCP_RTT_ELEMENTS ((LCP_RTT_FILE_SIZE/sizeof(u_int32_t)-LCP_RTT_HEADER_LENGTH)/2)
fsm lcp_fsm[NUM_PPP];
lcp_options lcp_wantoptions[NUM_PPP],lcp_gotoptions[NUM_PPP],lcp_allowoptions[NUM_PPP],lcp_hisoptions[NUM_PPP];
int lcp_echo_interval=0,lcp_echo_fails=0,lcp_loopbackfail=DEFLOOPBACKFAIL;
bool lcp_echo_adaptive=0,lax_recv=0,noendpoint=1,multilink=0;
char *lcp_rtt_file=NULL;
static u_char nak_buffer[PPP_CORE_MAX_MRU];
static int lcp_echos_pending,lcp_echo_number,lcp_echo_timer_running,lcp_rtt_file_fd;
static uint32_t lcp_rtt_storage[LCP_RTT_FILE_SIZE/4],*lcp_rtt_buffer;
static FILE *lcp_rtt_stream;
/* Only the Unix mmap/file operations are replaced; on-disk format unchanged. */
static int ppp_core_rtt_flush(void) {
    if (!lcp_rtt_stream || fseek(lcp_rtt_stream,0,SEEK_SET) ||
        fwrite(lcp_rtt_buffer,1,LCP_RTT_FILE_SIZE,lcp_rtt_stream)!=LCP_RTT_FILE_SIZE ||
        fflush(lcp_rtt_stream)) return -1;
    return 0;
}
static void lcp_rtt_open_file(void) {
    if (!lcp_rtt_file || !*lcp_rtt_file) return;
#ifdef _WIN32
    wchar_t path[4096];
    if(!MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,lcp_rtt_file,-1,path,4096)) {
        error("Invalid UTF-8 RTT filename");return;
    }
    lcp_rtt_stream=_wfopen(path,L"r+b");
    if(!lcp_rtt_stream)lcp_rtt_stream=_wfopen(path,L"w+b");
#else
    lcp_rtt_stream=fopen(lcp_rtt_file,"r+b");
    if(!lcp_rtt_stream)lcp_rtt_stream=fopen(lcp_rtt_file,"w+b");
#endif
    if(!lcp_rtt_stream){error("Cannot open RTT file");return;}
    memset(lcp_rtt_storage,0,sizeof(lcp_rtt_storage));
    (void)fread(lcp_rtt_storage,1,sizeof(lcp_rtt_storage),lcp_rtt_stream);
    lcp_rtt_buffer=lcp_rtt_storage;
    if(lcp_rtt_buffer[0]!=htonl(LCP_RTT_MAGIC)){
        memset(lcp_rtt_buffer,0,LCP_RTT_FILE_SIZE);lcp_rtt_buffer[0]=htonl(LCP_RTT_MAGIC);
    }
    lcp_rtt_buffer[3]=htonl(lcp_echo_interval);lcp_rtt_buffer[1]=htonl(1);
    lcp_rtt_file_fd=1;
    if(ppp_core_rtt_flush()<0)error("Cannot initialize RTT file");
}
static void lcp_rtt_close_file(void) {
    if(!lcp_rtt_file_fd)return;
    lcp_rtt_buffer[1]=0;
    if(ppp_core_rtt_flush()<0)error("Cannot flush RTT file");
    fclose(lcp_rtt_stream);lcp_rtt_stream=NULL;lcp_rtt_buffer=NULL;lcp_rtt_file_fd=0;
}
static void
lcp_init(int unit);
void
lcp_open(int unit);
void
lcp_close(int unit, char *reason);
void
lcp_lowerup(int unit);
void
lcp_lowerdown(int unit);
static void
lcp_delayed_up(void *arg);
static void
lcp_input(int unit, u_char *p, int len);
static int
lcp_extcode(fsm *f, int code, int id, u_char *inp, int len);
static void
lcp_rprotrej(fsm *f, u_char *inp, int len);
static void
lcp_protrej(int unit);
void
lcp_sprotrej(int unit, u_char *p, int len);
static void
lcp_resetci(fsm *f);
static int
lcp_cilen(fsm *f);
static void
lcp_addci(fsm *f, u_char *ucp, int *lenp);
static int
lcp_ackci(fsm *f, u_char *p, int len);
static int
lcp_nakci(fsm *f, u_char *p, int len, int treat_as_reject);
static int
lcp_rejci(fsm *f, u_char *p, int len);
static int
lcp_reqci(fsm *f, u_char *inp, int *lenp, int reject_if_disagree);
static void
lcp_up(fsm *f);
static void
lcp_down(fsm *f);
static void
lcp_starting(fsm *f);
static void
lcp_finished(fsm *f);
static
void LcpLinkFailure (fsm *f);
static void
LcpEchoCheck (fsm *f);
static void
LcpEchoTimeout (void *arg);
static void
lcp_rtt_update_buffer (unsigned long rtt);
static void
lcp_received_echo_reply (fsm *f, int id, u_char *inp, int len);
static void
LcpSendEchoRequest (fsm *f);
static void
lcp_echo_lowerup (int unit);
static void
lcp_echo_lowerdown (int unit);

static fsm_callbacks lcp_callbacks={lcp_resetci,lcp_cilen,lcp_addci,lcp_ackci,lcp_nakci,lcp_rejci,lcp_reqci,lcp_up,lcp_down,lcp_starting,lcp_finished,NULL,NULL,lcp_extcode,"LCP"};
struct protent lcp_protent={PPP_LCP,lcp_init,lcp_input,lcp_protrej,lcp_lowerup,lcp_lowerdown,lcp_open,lcp_close,NULL,NULL,1,"LCP",NULL,NULL,NULL,NULL,NULL};
static void
lcp_init(int unit)
{
    fsm *f = &lcp_fsm[unit];
    lcp_options *wo = &lcp_wantoptions[unit];
    lcp_options *ao = &lcp_allowoptions[unit];

    f->unit = unit;
    f->protocol = PPP_LCP;
    f->callbacks = &lcp_callbacks;

    fsm_init(f);

    BZERO(wo, sizeof(*wo));
    wo->neg_mru = 1;
    wo->mru = DEFMRU;
    wo->neg_asyncmap = 1;
    wo->neg_magicnumber = 1;
    wo->neg_pcompression = 1;
    wo->neg_accompression = 1;

    BZERO(ao, sizeof(*ao));
    ao->neg_mru = 1;
    ao->mru = MAXMRU;
    ao->neg_asyncmap = 1;
    ao->neg_chap = 1;
    ao->chap_mdtype = chap_mdtype_all;
    ao->neg_upap = 1;
    ao->neg_eap = 1;
    ao->neg_magicnumber = 1;
    ao->neg_pcompression = 1;
    ao->neg_accompression = 1;
    ao->neg_endpoint = 0;
}

void
lcp_open(int unit)
{
    fsm *f = &lcp_fsm[unit];
    lcp_options *wo = &lcp_wantoptions[unit];

    f->flags &= ~(OPT_PASSIVE | OPT_SILENT);
    if (wo->passive)
	f->flags |= OPT_PASSIVE;
    if (wo->silent)
	f->flags |= OPT_SILENT;
    fsm_open(f);
}

void
lcp_close(int unit, char *reason)
{
    fsm *f = &lcp_fsm[unit];
    int oldstate;

    if (!in_phase(PHASE_DEAD) && !in_phase(PHASE_MASTER))
	new_phase(PHASE_TERMINATE);

    if (f->flags & DELAYED_UP) {
	UNTIMEOUT(lcp_delayed_up, f);
	f->state = STOPPED;
    }
    oldstate = f->state;

    fsm_close(f, reason);
    if (oldstate == STOPPED && f->flags & (OPT_PASSIVE|OPT_SILENT|DELAYED_UP)) {
	/*
	 * This action is not strictly according to the FSM in RFC1548,
	 * but it does mean that the program terminates if you do a
	 * lcp_close() when a connection hasn't been established
	 * because we are in passive/silent mode or because we have
	 * delayed the fsm_lowerup() call and it hasn't happened yet.
	 */
	f->flags &= ~DELAYED_UP;
	lcp_finished(f);
    }
}

void
lcp_lowerup(int unit)
{
    lcp_options *wo = &lcp_wantoptions[unit];
    fsm *f = &lcp_fsm[unit];

    /*
     * Don't use A/C or protocol compression on transmission,
     * but accept A/C and protocol compressed packets
     * if we are going to ask for A/C and protocol compression.
     */
    if (ppp_send_config(unit, PPP_MRU, 0xffffffff, 0, 0) < 0
	|| ppp_recv_config(unit, PPP_MRU, (lax_recv? 0: 0xffffffff),
			   wo->neg_pcompression, wo->neg_accompression) < 0)
	    return;
    peer_mru[unit] = PPP_MRU;

    if (listen_time != 0) {
	f->flags |= DELAYED_UP;
	ppp_timeout(lcp_delayed_up, f, 0, listen_time * 1000);
    } else
	fsm_lowerup(f);
}

void
lcp_lowerdown(int unit)
{
    fsm *f = &lcp_fsm[unit];

    if (f->flags & DELAYED_UP) {
	f->flags &= ~DELAYED_UP;
	UNTIMEOUT(lcp_delayed_up, f);
    } else
	fsm_lowerdown(&lcp_fsm[unit]);
}

static void
lcp_delayed_up(void *arg)
{
    fsm *f = arg;

    if (f->flags & DELAYED_UP) {
	f->flags &= ~DELAYED_UP;
	fsm_lowerup(f);
    }
}

static void
lcp_input(int unit, u_char *p, int len)
{
    fsm *f = &lcp_fsm[unit];

    if (f->flags & DELAYED_UP) {
	f->flags &= ~DELAYED_UP;
	UNTIMEOUT(lcp_delayed_up, f);
	fsm_lowerup(f);
    }
    fsm_input(f, p, len);
}

static int
lcp_extcode(fsm *f, int code, int id, u_char *inp, int len)
{
    u_char *magp;

    switch( code ){
    case PROTREJ:
	lcp_rprotrej(f, inp, len);
	break;
    
    case ECHOREQ:
        if (len < 4) return 1; /* reject malformed short Echo before PUTLONG */
	if (f->state != OPENED)
	    break;
	magp = inp;
	PUTLONG(lcp_gotoptions[f->unit].magicnumber, magp);
	fsm_sdata(f, ECHOREP, id, inp, len);
	break;
    
    case ECHOREP:
	lcp_received_echo_reply(f, id, inp, len);
	break;

    case DISCREQ:
    case IDENTIF:
    case TIMEREM:
	break;

    default:
	return 0;
    }
    return 1;
}

static void
lcp_rprotrej(fsm *f, u_char *inp, int len)
{
    int i;
    struct protent *protp;
    u_short prot;
    const char *pname;

    if (len < 2) {
	LCPDEBUG(("lcp_rprotrej: Rcvd short Protocol-Reject packet!"));
	return;
    }

    GETSHORT(prot, inp);

    /*
     * Protocol-Reject packets received in any state other than the LCP
     * OPENED state SHOULD be silently discarded.
     */
    if( f->state != OPENED ){
	LCPDEBUG(("Protocol-Reject discarded: LCP in state %d", f->state));
	return;
    }

    pname = protocol_name(prot);

    /*
     * Upcall the proper Protocol-Reject routine.
     */
    for (i = 0; (protp = protocols[i]) != NULL; ++i)
	if (protp->protocol == prot && protp->enabled_flag) {
	    if (pname == NULL)
		dbglog("Protocol-Reject for 0x%x received", prot);
	    else
		dbglog("Protocol-Reject for '%s' (0x%x) received", pname,
		       prot);
	    (*protp->protrej)(f->unit);
	    return;
	}

    if (pname == NULL)
	warn("Protocol-Reject for unsupported protocol 0x%x", prot);
    else
	warn("Protocol-Reject for unsupported protocol '%s' (0x%x)", pname,
	     prot);
}

static void
lcp_protrej(int unit)
{
    /*
     * Can't reject LCP!
     */
    error("Received Protocol-Reject for LCP!");
    fsm_protreject(&lcp_fsm[unit]);
}

void
lcp_sprotrej(int unit, u_char *p, int len)
{
    /*
     * Send back the protocol and the information field of the
     * rejected packet.  We only get here if LCP is in the OPENED state.
     */
    p += 2;
    len -= 2;

    fsm_sdata(&lcp_fsm[unit], PROTREJ, ++lcp_fsm[unit].id,
	      p, len);
}

static void
lcp_resetci(fsm *f)
{
    lcp_options *wo = &lcp_wantoptions[f->unit];
    lcp_options *go = &lcp_gotoptions[f->unit];
    lcp_options *ao = &lcp_allowoptions[f->unit];

    wo->magicnumber = magic();
    wo->numloops = 0;
    *go = *wo;
    if (!multilink) {
	go->neg_mrru = 0;
	go->neg_ssnhf = 0;
	go->neg_endpoint = 0;
    }
    if (noendpoint)
	ao->neg_endpoint = 0;
    peer_mru[f->unit] = PPP_MRU;
    auth_reset(f->unit);
}

static int
lcp_cilen(fsm *f)
{
    lcp_options *go = &lcp_gotoptions[f->unit];

#define LENCIVOID(neg)	((neg) ? CILEN_VOID : 0)
#define LENCICHAP(neg)	((neg) ? CILEN_CHAP : 0)
#define LENCISHORT(neg)	((neg) ? CILEN_SHORT : 0)
#define LENCILONG(neg)	((neg) ? CILEN_LONG : 0)
#define LENCILQR(neg)	((neg) ? CILEN_LQR: 0)
#define LENCICBCP(neg)	((neg) ? CILEN_CBCP: 0)
    /*
     * NB: we only ask for one of CHAP, UPAP, or EAP, even if we will
     * accept more than one.  We prefer EAP first, then CHAP, then
     * PAP.
     */
    return (LENCISHORT(go->neg_mru && go->mru != DEFMRU) +
	    LENCILONG(go->neg_asyncmap && go->asyncmap != 0xFFFFFFFF) +
	    LENCISHORT(go->neg_eap) +
	    LENCICHAP(!go->neg_eap && go->neg_chap) +
	    LENCISHORT(!go->neg_eap && !go->neg_chap && go->neg_upap) +
	    LENCILQR(go->neg_lqr) +
	    LENCICBCP(go->neg_cbcp) +
	    LENCILONG(go->neg_magicnumber) +
	    LENCIVOID(go->neg_pcompression) +
	    LENCIVOID(go->neg_accompression) +
	    LENCISHORT(go->neg_mrru) +
	    LENCIVOID(go->neg_ssnhf) +
	    (go->neg_endpoint? CILEN_CHAR + go->endpoint.length: 0));
}

static void
lcp_addci(fsm *f, u_char *ucp, int *lenp)
{
    lcp_options *go = &lcp_gotoptions[f->unit];
    u_char *start_ucp = ucp;

#define ADDCIVOID(opt, neg) \
    if (neg) { \
	PUTCHAR(opt, ucp); \
	PUTCHAR(CILEN_VOID, ucp); \
    }
#define ADDCISHORT(opt, neg, val) \
    if (neg) { \
	PUTCHAR(opt, ucp); \
	PUTCHAR(CILEN_SHORT, ucp); \
	PUTSHORT(val, ucp); \
    }
#define ADDCICHAP(opt, neg, val) \
    if (neg) { \
	PUTCHAR((opt), ucp); \
	PUTCHAR(CILEN_CHAP, ucp); \
	PUTSHORT(PPP_CHAP, ucp); \
	PUTCHAR((CHAP_DIGEST(val)), ucp); \
    }
#define ADDCILONG(opt, neg, val) \
    if (neg) { \
	PUTCHAR(opt, ucp); \
	PUTCHAR(CILEN_LONG, ucp); \
	PUTLONG(val, ucp); \
    }
#define ADDCILQR(opt, neg, val) \
    if (neg) { \
	PUTCHAR(opt, ucp); \
	PUTCHAR(CILEN_LQR, ucp); \
	PUTSHORT(PPP_LQR, ucp); \
	PUTLONG(val, ucp); \
    }
#define ADDCICHAR(opt, neg, val) \
    if (neg) { \
	PUTCHAR(opt, ucp); \
	PUTCHAR(CILEN_CHAR, ucp); \
	PUTCHAR(val, ucp); \
    }
#define ADDCIENDP(opt, neg, class, val, len) \
    if (neg) { \
	int i; \
	PUTCHAR(opt, ucp); \
	PUTCHAR(CILEN_CHAR + len, ucp); \
	PUTCHAR(class, ucp); \
	for (i = 0; i < len; ++i) \
	    PUTCHAR(val[i], ucp); \
    }

    ADDCISHORT(CI_MRU, go->neg_mru && go->mru != DEFMRU, go->mru);
    ADDCILONG(CI_ASYNCMAP, go->neg_asyncmap && go->asyncmap != 0xFFFFFFFF,
	      go->asyncmap);
    ADDCISHORT(CI_AUTHTYPE, go->neg_eap, PPP_EAP);
    ADDCICHAP(CI_AUTHTYPE, !go->neg_eap && go->neg_chap, go->chap_mdtype);
    ADDCISHORT(CI_AUTHTYPE, !go->neg_eap && !go->neg_chap && go->neg_upap,
	       PPP_PAP);
    ADDCILQR(CI_QUALITY, go->neg_lqr, go->lqr_period);
    ADDCICHAR(CI_CALLBACK, go->neg_cbcp, CBCP_OPT);
    ADDCILONG(CI_MAGICNUMBER, go->neg_magicnumber, go->magicnumber);
    ADDCIVOID(CI_PCOMPRESSION, go->neg_pcompression);
    ADDCIVOID(CI_ACCOMPRESSION, go->neg_accompression);
    ADDCISHORT(CI_MRRU, go->neg_mrru, go->mrru);
    ADDCIVOID(CI_SSNHF, go->neg_ssnhf);
    ADDCIENDP(CI_EPDISC, go->neg_endpoint, go->endpoint.class,
	      go->endpoint.value, go->endpoint.length);

    if (ucp - start_ucp != *lenp) {
	/* this should never happen, because peer_mtu should be 1500 */
	error("Bug in lcp_addci: wrong length");
    }
}

static int
lcp_ackci(fsm *f, u_char *p, int len)
{
    lcp_options *go = &lcp_gotoptions[f->unit];
    u_char cilen, citype, cichar;
    u_short cishort;
    u_int32_t cilong;

    /*
     * CIs must be in exactly the same order that we sent.
     * Check packet length and CI length at each step.
     * If we find any deviations, then this packet is bad.
     */
#define ACKCIVOID(opt, neg) \
    if (neg) { \
	if ((len -= CILEN_VOID) < 0) \
	    goto bad; \
	GETCHAR(citype, p); \
	GETCHAR(cilen, p); \
	if (cilen != CILEN_VOID || \
	    citype != opt) \
	    goto bad; \
    }
#define ACKCISHORT(opt, neg, val) \
    if (neg) { \
	if ((len -= CILEN_SHORT) < 0) \
	    goto bad; \
	GETCHAR(citype, p); \
	GETCHAR(cilen, p); \
	if (cilen != CILEN_SHORT || \
	    citype != opt) \
	    goto bad; \
	GETSHORT(cishort, p); \
	if (cishort != val) \
	    goto bad; \
    }
#define ACKCICHAR(opt, neg, val) \
    if (neg) { \
	if ((len -= CILEN_CHAR) < 0) \
	    goto bad; \
	GETCHAR(citype, p); \
	GETCHAR(cilen, p); \
	if (cilen != CILEN_CHAR || \
	    citype != opt) \
	    goto bad; \
	GETCHAR(cichar, p); \
	if (cichar != val) \
	    goto bad; \
    }
#define ACKCICHAP(opt, neg, val) \
    if (neg) { \
	if ((len -= CILEN_CHAP) < 0) \
	    goto bad; \
	GETCHAR(citype, p); \
	GETCHAR(cilen, p); \
	if (cilen != CILEN_CHAP || \
	    citype != (opt)) \
	    goto bad; \
	GETSHORT(cishort, p); \
	if (cishort != PPP_CHAP) \
	    goto bad; \
	GETCHAR(cichar, p); \
	if (cichar != (CHAP_DIGEST(val))) \
	  goto bad; \
    }
#define ACKCILONG(opt, neg, val) \
    if (neg) { \
	if ((len -= CILEN_LONG) < 0) \
	    goto bad; \
	GETCHAR(citype, p); \
	GETCHAR(cilen, p); \
	if (cilen != CILEN_LONG || \
	    citype != opt) \
	    goto bad; \
	GETLONG(cilong, p); \
	if (cilong != val) \
	    goto bad; \
    }
#define ACKCILQR(opt, neg, val) \
    if (neg) { \
	if ((len -= CILEN_LQR) < 0) \
	    goto bad; \
	GETCHAR(citype, p); \
	GETCHAR(cilen, p); \
	if (cilen != CILEN_LQR || \
	    citype != opt) \
	    goto bad; \
	GETSHORT(cishort, p); \
	if (cishort != PPP_LQR) \
	    goto bad; \
	GETLONG(cilong, p); \
	if (cilong != val) \
	  goto bad; \
    }
#define ACKCIENDP(opt, neg, class, val, vlen) \
    if (neg) { \
	int i; \
	if ((len -= CILEN_CHAR + vlen) < 0) \
	    goto bad; \
	GETCHAR(citype, p); \
	GETCHAR(cilen, p); \
	if (cilen != CILEN_CHAR + vlen || \
	    citype != opt) \
	    goto bad; \
	GETCHAR(cichar, p); \
	if (cichar != class) \
	    goto bad; \
	for (i = 0; i < vlen; ++i) { \
	    GETCHAR(cichar, p); \
	    if (cichar != val[i]) \
		goto bad; \
	} \
    }

    ACKCISHORT(CI_MRU, go->neg_mru && go->mru != DEFMRU, go->mru);
    ACKCILONG(CI_ASYNCMAP, go->neg_asyncmap && go->asyncmap != 0xFFFFFFFF,
	      go->asyncmap);
    ACKCISHORT(CI_AUTHTYPE, go->neg_eap, PPP_EAP);
    ACKCICHAP(CI_AUTHTYPE, !go->neg_eap && go->neg_chap, go->chap_mdtype);
    ACKCISHORT(CI_AUTHTYPE, !go->neg_eap && !go->neg_chap && go->neg_upap,
	       PPP_PAP);
    ACKCILQR(CI_QUALITY, go->neg_lqr, go->lqr_period);
    ACKCICHAR(CI_CALLBACK, go->neg_cbcp, CBCP_OPT);
    ACKCILONG(CI_MAGICNUMBER, go->neg_magicnumber, go->magicnumber);
    ACKCIVOID(CI_PCOMPRESSION, go->neg_pcompression);
    ACKCIVOID(CI_ACCOMPRESSION, go->neg_accompression);
    ACKCISHORT(CI_MRRU, go->neg_mrru, go->mrru);
    ACKCIVOID(CI_SSNHF, go->neg_ssnhf);
    ACKCIENDP(CI_EPDISC, go->neg_endpoint, go->endpoint.class,
	      go->endpoint.value, go->endpoint.length);

    /*
     * If there are any remaining CIs, then this packet is bad.
     */
    if (len != 0)
	goto bad;
    return (1);
bad:
    LCPDEBUG(("lcp_acki: received bad Ack!"));
    return (0);
}

static int
lcp_nakci(fsm *f, u_char *p, int len, int treat_as_reject)
{
    lcp_options *go = &lcp_gotoptions[f->unit];
    lcp_options *wo = &lcp_wantoptions[f->unit];
    u_char citype, cichar, *next;
    u_short cishort;
    u_int32_t cilong;
    lcp_options no;		/* options we've seen Naks for */
    lcp_options try;		/* options to request next time */
    int looped_back = 0;
    int cilen;

    BZERO(&no, sizeof(no));
    try = *go;

    /*
     * Any Nak'd CIs must be in exactly the same order that we sent.
     * Check packet length and CI length at each step.
     * If we find any deviations, then this packet is bad.
     */
#define NAKCIVOID(opt, neg) \
    if (go->neg && \
	len >= CILEN_VOID && \
	p[1] == CILEN_VOID && \
	p[0] == opt) { \
	len -= CILEN_VOID; \
	INCPTR(CILEN_VOID, p); \
	no.neg = 1; \
	try.neg = 0; \
    }
#define NAKCICHAP(opt, neg, code) \
    if (go->neg && \
	len >= CILEN_CHAP && \
	p[1] == CILEN_CHAP && \
	p[0] == opt) { \
	len -= CILEN_CHAP; \
	INCPTR(2, p); \
	GETSHORT(cishort, p); \
	GETCHAR(cichar, p); \
	no.neg = 1; \
	code \
    }
#define NAKCICHAR(opt, neg, code) \
    if (go->neg && \
	len >= CILEN_CHAR && \
	p[1] == CILEN_CHAR && \
	p[0] == opt) { \
	len -= CILEN_CHAR; \
	INCPTR(2, p); \
	GETCHAR(cichar, p); \
	no.neg = 1; \
	code \
    }
#define NAKCISHORT(opt, neg, code) \
    if (go->neg && \
	len >= CILEN_SHORT && \
	p[1] == CILEN_SHORT && \
	p[0] == opt) { \
	len -= CILEN_SHORT; \
	INCPTR(2, p); \
	GETSHORT(cishort, p); \
	no.neg = 1; \
	code \
    }
#define NAKCILONG(opt, neg, code) \
    if (go->neg && \
	len >= CILEN_LONG && \
	p[1] == CILEN_LONG && \
	p[0] == opt) { \
	len -= CILEN_LONG; \
	INCPTR(2, p); \
	GETLONG(cilong, p); \
	no.neg = 1; \
	code \
    }
#define NAKCILQR(opt, neg, code) \
    if (go->neg && \
	len >= CILEN_LQR && \
	p[1] == CILEN_LQR && \
	p[0] == opt) { \
	len -= CILEN_LQR; \
	INCPTR(2, p); \
	GETSHORT(cishort, p); \
	GETLONG(cilong, p); \
	no.neg = 1; \
	code \
    }
#define NAKCIENDP(opt, neg) \
    if (go->neg && \
	len >= CILEN_CHAR && \
	p[0] == opt && \
	p[1] >= CILEN_CHAR && \
	p[1] <= len) { \
	len -= p[1]; \
	INCPTR(p[1], p); \
	no.neg = 1; \
	try.neg = 0; \
    }

    /*
     * NOTE!  There must be no assignments to individual fields of *go in
     * the code below.  Any such assignment is a BUG!
     */
    /*
     * We don't care if they want to send us smaller packets than
     * we want.  Therefore, accept any MRU less than what we asked for,
     * but then ignore the new value when setting the MRU in the kernel.
     * If they send us a bigger MRU than what we asked, accept it, up to
     * the limit of the default MRU we'd get if we didn't negotiate.
     */
    if (go->neg_mru && go->mru != DEFMRU) {
	NAKCISHORT(CI_MRU, neg_mru,
		   if (cishort <= wo->mru || cishort <= DEFMRU)
		       try.mru = cishort;
		   );
    }

    /*
     * Add any characters they want to our (receive-side) asyncmap.
     */
    if (go->neg_asyncmap && go->asyncmap != 0xFFFFFFFF) {
	NAKCILONG(CI_ASYNCMAP, neg_asyncmap,
		  try.asyncmap = go->asyncmap | cilong;
		  );
    }

    /*
     * If they've nak'd our authentication-protocol, check whether
     * they are proposing a different protocol, or a different
     * hash algorithm for CHAP.
     */
    if ((go->neg_chap || go->neg_upap || go->neg_eap)
	&& len >= CILEN_SHORT
	&& p[0] == CI_AUTHTYPE && p[1] >= CILEN_SHORT && p[1] <= len) {
	cilen = p[1];
	len -= cilen;
	no.neg_chap = go->neg_chap;
	no.neg_upap = go->neg_upap;
	no.neg_eap = go->neg_eap;
	INCPTR(2, p);
	GETSHORT(cishort, p);
	if (cishort == PPP_PAP && cilen == CILEN_SHORT) {
	    /* If we were asking for EAP, then we need to stop that. */
	    if (go->neg_eap)
		try.neg_eap = 0;

	    /* If we were asking for CHAP, then we need to stop that. */
	    else if (go->neg_chap)
		try.neg_chap = 0;
	    /*
	     * If we weren't asking for CHAP or EAP, then we were asking for
	     * PAP, in which case this Nak is bad.
	     */
	    else
		goto bad;

	} else if (cishort == PPP_CHAP && cilen == CILEN_CHAP) {
	    GETCHAR(cichar, p);
	    /* Stop asking for EAP, if we were. */
	    if (go->neg_eap) {
		try.neg_eap = 0;
		/* Try to set up to use their suggestion, if possible */
		if (CHAP_CANDIGEST(go->chap_mdtype, cichar))
		    try.chap_mdtype = CHAP_MDTYPE_D(cichar);
	    } else if (go->neg_chap) {
		/*
		 * We were asking for our preferred algorithm, they must
		 * want something different.
		 */
		if (cichar != CHAP_DIGEST(go->chap_mdtype)) {
		    if (CHAP_CANDIGEST(go->chap_mdtype, cichar)) {
			/* Use their suggestion if we support it ... */
			try.chap_mdtype = CHAP_MDTYPE_D(cichar);
		    } else {
			/* ... otherwise, try our next-preferred algorithm. */
			try.chap_mdtype &= ~(CHAP_MDTYPE(try.chap_mdtype));
			if (try.chap_mdtype == MDTYPE_NONE) /* out of algos */
			    try.neg_chap = 0;
		    }
		} else {
		    /*
		     * Whoops, they Nak'd our algorithm of choice
		     * but then suggested it back to us.
		     */
		    goto bad;
		}
	    } else {
		/*
		 * Stop asking for PAP if we were asking for it.
		 */
		try.neg_upap = 0;
	    }

	} else {

	    /*
	     * If we were asking for EAP, and they're Conf-Naking EAP,
	     * well, that's just strange.  Nobody should do that.
	     */
	    if (cishort == PPP_EAP && cilen == CILEN_SHORT && go->neg_eap)
		dbglog("Unexpected Conf-Nak for EAP");

	    /*
	     * We don't recognize what they're suggesting.
	     * Stop asking for what we were asking for.
	     */
	    if (go->neg_eap)
		try.neg_eap = 0;
	    else if (go->neg_chap)
		try.neg_chap = 0;
	    else
		try.neg_upap = 0;
	    p += cilen - CILEN_SHORT;
	}
    }

    /*
     * If they can't cope with our link quality protocol, we'll have
     * to stop asking for LQR.  We haven't got any other protocol.
     * If they Nak the reporting period, take their value XXX ?
     */
    NAKCILQR(CI_QUALITY, neg_lqr,
	     if (cishort != PPP_LQR)
		 try.neg_lqr = 0;
	     else
		 try.lqr_period = cilong;
	     );

    /*
     * Only implementing CBCP...not the rest of the callback options
     */
    NAKCICHAR(CI_CALLBACK, neg_cbcp,
              try.neg_cbcp = 0;
              );

    /*
     * Check for a looped-back line.
     */
    NAKCILONG(CI_MAGICNUMBER, neg_magicnumber,
	      try.magicnumber = magic();
	      looped_back = 1;
	      );

    /*
     * Peer shouldn't send Nak for protocol compression or
     * address/control compression requests; they should send
     * a Reject instead.  If they send a Nak, treat it as a Reject.
     */
    NAKCIVOID(CI_PCOMPRESSION, neg_pcompression);
    NAKCIVOID(CI_ACCOMPRESSION, neg_accompression);

    /*
     * Nak for MRRU option - accept their value if it is smaller
     * than the one we want.
     */
    if (go->neg_mrru) {
	NAKCISHORT(CI_MRRU, neg_mrru,
		   if (treat_as_reject)
		       try.neg_mrru = 0;
		   else if (cishort <= wo->mrru)
		       try.mrru = cishort;
		   );
    }

    /*
     * Nak for short sequence numbers shouldn't be sent, treat it
     * like a reject.
     */
    NAKCIVOID(CI_SSNHF, neg_ssnhf);

    /*
     * Nak of the endpoint discriminator option is not permitted,
     * treat it like a reject.
     */
    NAKCIENDP(CI_EPDISC, neg_endpoint);

    /*
     * There may be remaining CIs, if the peer is requesting negotiation
     * on an option that we didn't include in our request packet.
     * If we see an option that we requested, or one we've already seen
     * in this packet, then this packet is bad.
     * If we wanted to respond by starting to negotiate on the requested
     * option(s), we could, but we don't, because except for the
     * authentication type and quality protocol, if we are not negotiating
     * an option, it is because we were told not to.
     * For the authentication type, the Nak from the peer means
     * `let me authenticate myself with you' which is a bit pointless.
     * For the quality protocol, the Nak means `ask me to send you quality
     * reports', but if we didn't ask for them, we don't want them.
     * An option we don't recognize represents the peer asking to
     * negotiate some option we don't support, so ignore it.
     */
    while (len >= CILEN_VOID) {
	GETCHAR(citype, p);
	GETCHAR(cilen, p);
	if (cilen < CILEN_VOID || (len -= cilen) < 0)
	    goto bad;
	next = p + cilen - 2;

	switch (citype) {
	case CI_MRU:
	    if ((go->neg_mru && go->mru != DEFMRU)
		|| no.neg_mru || cilen != CILEN_SHORT)
		goto bad;
	    GETSHORT(cishort, p);
	    if (cishort < DEFMRU) {
		try.neg_mru = 1;
		try.mru = cishort;
	    }
	    break;
	case CI_ASYNCMAP:
	    if ((go->neg_asyncmap && go->asyncmap != 0xFFFFFFFF)
		|| no.neg_asyncmap || cilen != CILEN_LONG)
		goto bad;
	    break;
	case CI_AUTHTYPE:
	    if (go->neg_chap || no.neg_chap || go->neg_upap || no.neg_upap ||
		go->neg_eap || no.neg_eap)
		goto bad;
	    break;
	case CI_MAGICNUMBER:
	    if (go->neg_magicnumber || no.neg_magicnumber ||
		cilen != CILEN_LONG)
		goto bad;
	    break;
	case CI_PCOMPRESSION:
	    if (go->neg_pcompression || no.neg_pcompression
		|| cilen != CILEN_VOID)
		goto bad;
	    break;
	case CI_ACCOMPRESSION:
	    if (go->neg_accompression || no.neg_accompression
		|| cilen != CILEN_VOID)
		goto bad;
	    break;
	case CI_QUALITY:
	    if (go->neg_lqr || no.neg_lqr || cilen != CILEN_LQR)
		goto bad;
	    break;
	case CI_MRRU:
	    if (go->neg_mrru || no.neg_mrru || cilen != CILEN_SHORT)
		goto bad;
	    break;
	case CI_SSNHF:
	    if (go->neg_ssnhf || no.neg_ssnhf || cilen != CILEN_VOID)
		goto bad;
	    try.neg_ssnhf = 1;
	    break;
	case CI_EPDISC:
	    if (go->neg_endpoint || no.neg_endpoint || cilen < CILEN_CHAR)
		goto bad;
	    break;
	}
	p = next;
    }

    /*
     * OK, the Nak is good.  Now we can update state.
     * If there are any options left we ignore them.
     */
    if (f->state != OPENED) {
	if (looped_back) {
	    if (++try.numloops >= lcp_loopbackfail) {
		notice("Serial line is looped back.");
		ppp_set_status(EXIT_LOOPBACK);
		lcp_close(f->unit, "Loopback detected");
	    }
	} else
	    try.numloops = 0;
	*go = try;
    }

    return 1;

bad:
    LCPDEBUG(("lcp_nakci: received bad Nak!"));
    return 0;
}

static int
lcp_rejci(fsm *f, u_char *p, int len)
{
    lcp_options *go = &lcp_gotoptions[f->unit];
    u_char cichar;
    u_short cishort;
    u_int32_t cilong;
    lcp_options try;		/* options to request next time */

    try = *go;

    /*
     * Any Rejected CIs must be in exactly the same order that we sent.
     * Check packet length and CI length at each step.
     * If we find any deviations, then this packet is bad.
     */
#define REJCIVOID(opt, neg) \
    if (go->neg && \
	len >= CILEN_VOID && \
	p[1] == CILEN_VOID && \
	p[0] == opt) { \
	len -= CILEN_VOID; \
	INCPTR(CILEN_VOID, p); \
	try.neg = 0; \
    }
#define REJCISHORT(opt, neg, val) \
    if (go->neg && \
	len >= CILEN_SHORT && \
	p[1] == CILEN_SHORT && \
	p[0] == opt) { \
	len -= CILEN_SHORT; \
	INCPTR(2, p); \
	GETSHORT(cishort, p); \
	/* Check rejected value. */ \
	if (cishort != val) \
	    goto bad; \
	try.neg = 0; \
    }
#define REJCICHAP(opt, neg, val) \
    if (go->neg && \
	len >= CILEN_CHAP && \
	p[1] == CILEN_CHAP && \
	p[0] == opt) { \
	len -= CILEN_CHAP; \
	INCPTR(2, p); \
	GETSHORT(cishort, p); \
	GETCHAR(cichar, p); \
	/* Check rejected value. */ \
	if ((cishort != PPP_CHAP) || (cichar != (CHAP_DIGEST(val)))) \
	    goto bad; \
	try.neg = 0; \
	try.neg_eap = try.neg_upap = 0; \
    }
#define REJCILONG(opt, neg, val) \
    if (go->neg && \
	len >= CILEN_LONG && \
	p[1] == CILEN_LONG && \
	p[0] == opt) { \
	len -= CILEN_LONG; \
	INCPTR(2, p); \
	GETLONG(cilong, p); \
	/* Check rejected value. */ \
	if (cilong != val) \
	    goto bad; \
	try.neg = 0; \
    }
#define REJCILQR(opt, neg, val) \
    if (go->neg && \
	len >= CILEN_LQR && \
	p[1] == CILEN_LQR && \
	p[0] == opt) { \
	len -= CILEN_LQR; \
	INCPTR(2, p); \
	GETSHORT(cishort, p); \
	GETLONG(cilong, p); \
	/* Check rejected value. */ \
	if (cishort != PPP_LQR || cilong != val) \
	    goto bad; \
	try.neg = 0; \
    }
#define REJCICBCP(opt, neg, val) \
    if (go->neg && \
	len >= CILEN_CBCP && \
	p[1] == CILEN_CBCP && \
	p[0] == opt) { \
	len -= CILEN_CBCP; \
	INCPTR(2, p); \
	GETCHAR(cichar, p); \
	/* Check rejected value. */ \
	if (cichar != val) \
	    goto bad; \
	try.neg = 0; \
    }
#define REJCIENDP(opt, neg, class, val, vlen) \
    if (go->neg && \
	len >= CILEN_CHAR + vlen && \
	p[0] == opt && \
	p[1] == CILEN_CHAR + vlen) { \
	int i; \
	len -= CILEN_CHAR + vlen; \
	INCPTR(2, p); \
	GETCHAR(cichar, p); \
	if (cichar != class) \
	    goto bad; \
	for (i = 0; i < vlen; ++i) { \
	    GETCHAR(cichar, p); \
	    if (cichar != val[i]) \
		goto bad; \
	} \
	try.neg = 0; \
    }

    REJCISHORT(CI_MRU, neg_mru, go->mru);
    REJCILONG(CI_ASYNCMAP, neg_asyncmap, go->asyncmap);
    REJCISHORT(CI_AUTHTYPE, neg_eap, PPP_EAP);
    if (!go->neg_eap) {
	REJCICHAP(CI_AUTHTYPE, neg_chap, go->chap_mdtype);
	if (!go->neg_chap) {
	    REJCISHORT(CI_AUTHTYPE, neg_upap, PPP_PAP);
	}
    }
    REJCILQR(CI_QUALITY, neg_lqr, go->lqr_period);
    REJCICBCP(CI_CALLBACK, neg_cbcp, CBCP_OPT);
    REJCILONG(CI_MAGICNUMBER, neg_magicnumber, go->magicnumber);
    REJCIVOID(CI_PCOMPRESSION, neg_pcompression);
    REJCIVOID(CI_ACCOMPRESSION, neg_accompression);
    REJCISHORT(CI_MRRU, neg_mrru, go->mrru);
    REJCIVOID(CI_SSNHF, neg_ssnhf);
    REJCIENDP(CI_EPDISC, neg_endpoint, go->endpoint.class,
	      go->endpoint.value, go->endpoint.length);

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
    LCPDEBUG(("lcp_rejci: received bad Reject!"));
    return 0;
}

static int
lcp_reqci(fsm *f, u_char *inp, int *lenp, int reject_if_disagree)
{
    lcp_options *go = &lcp_gotoptions[f->unit];
    lcp_options *ho = &lcp_hisoptions[f->unit];
    lcp_options *ao = &lcp_allowoptions[f->unit];
    u_char *cip, *next;		/* Pointer to current and next CIs */
    int cilen, citype, cichar;	/* Parsed len, type, char value */
    u_short cishort;		/* Parsed short value */
    u_int32_t cilong;		/* Parse long value */
    int rc = CONFACK;		/* Final packet return code */
    int orc;			/* Individual option return code */
    u_char *p;			/* Pointer to next char to parse */
    u_char *rejp;		/* Pointer to next char in reject frame */
    u_char *nakp;		/* Pointer to next char in Nak frame */
    int l = *lenp;		/* Length left */
    bool warned, seenci[CI_LCP_LAST+1];

    /*
     * Reset all his options.
     */
    BZERO(ho, sizeof(*ho));
    BZERO(seenci, sizeof(seenci));

    /*
     * Process all his options.
     */
    next = inp;
    nakp = nak_buffer;
    rejp = inp;
    while (l) {
	orc = CONFACK;			/* Assume success */
	cip = p = next;			/* Remember begining of CI */
	if (l < 2 ||			/* Not enough data for CI header or */
	    p[1] < 2 ||			/*  CI length too small or */
	    p[1] > l) {			/*  CI length too big? */
	    LCPDEBUG(("lcp_reqci: bad CI length!"));
	    orc = CONFREJ;		/* Reject bad CI */
	    cilen = l;			/* Reject till end of packet */
	    l = 0;			/* Don't loop again */
	    citype = 0;
	    goto endswitch;
	}
	GETCHAR(citype, p);		/* Parse CI type */
	GETCHAR(cilen, p);		/* Parse CI length */
	l -= cilen;			/* Adjust remaining length */
	next += cilen;			/* Step to next CI */

	if (rc == CONFREJ)
	    nakp = nak_buffer;

	if (citype <= CI_LCP_LAST) {
	    if (seenci[citype]) {
		if (!warned) {
		    warn("LCP: ignoring duplicate configuration option(s)");
		    warned = 1;
		}
		continue;
	    }
	    seenci[citype] = 1;
	}

	switch (citype) {		/* Check CI type */
	case CI_MRU:
	    if (!ao->neg_mru ||		/* Allow option? */
		cilen != CILEN_SHORT) {	/* Check CI length */
		orc = CONFREJ;		/* Reject CI */
		break;
	    }
	    GETSHORT(cishort, p);	/* Parse MRU */

	    /*
	     * He must be able to receive at least our minimum.
	     * No need to check a maximum.  If he sends a large number,
	     * we'll just ignore it.
	     */
	    if (cishort < MINMRU) {
		orc = CONFNAK;		/* Nak CI */
		PUTCHAR(CI_MRU, nakp);
		PUTCHAR(CILEN_SHORT, nakp);
		PUTSHORT(MINMRU, nakp);	/* Give him a hint */
		break;
	    }
	    ho->neg_mru = 1;		/* Remember he sent MRU */
	    ho->mru = cishort;		/* And remember value */
	    break;

	case CI_ASYNCMAP:
	    if (!ao->neg_asyncmap ||
		cilen != CILEN_LONG) {
		orc = CONFREJ;
		break;
	    }
	    GETLONG(cilong, p);

	    /*
	     * Asyncmap must have set at least the bits
	     * which are set in lcp_allowoptions[unit].asyncmap.
	     */
	    if ((ao->asyncmap & ~cilong) != 0) {
		orc = CONFNAK;
		PUTCHAR(CI_ASYNCMAP, nakp);
		PUTCHAR(CILEN_LONG, nakp);
		PUTLONG(ao->asyncmap | cilong, nakp);
		break;
	    }
	    ho->neg_asyncmap = 1;
	    ho->asyncmap = cilong;
	    break;

	case CI_AUTHTYPE:
	    if (cilen < CILEN_SHORT ||
		!(ao->neg_upap || ao->neg_chap || ao->neg_eap)) {
		/*
		 * Reject the option if we're not willing to authenticate.
		 */
		dbglog("No auth is possible");
		orc = CONFREJ;
		break;
	    }
	    GETSHORT(cishort, p);

	    /*
	     * Authtype must be PAP, CHAP, or EAP.
	     *
	     * Note: if more than one of ao->neg_upap, ao->neg_chap, and
	     * ao->neg_eap are set, and the peer sends a Configure-Request
	     * with two or more authenticate-protocol requests, then we will
	     * simply ignore the second and following requests, because
	     * RFC1661 says "An implementation MUST NOT include multiple
	     * Authentication-Protocol Configuration Options in its
	     * Configure-Request packets".
             */

	    if (cishort == PPP_PAP) {
		if (!ao->neg_upap) {	/* we don't want to do PAP */
		    orc = CONFNAK;	/* NAK it and suggest CHAP or EAP */
		    PUTCHAR(CI_AUTHTYPE, nakp);
		    if (ao->neg_eap) {
			PUTCHAR(CILEN_SHORT, nakp);
			PUTSHORT(PPP_EAP, nakp);
		    } else {
			PUTCHAR(CILEN_CHAP, nakp);
			PUTSHORT(PPP_CHAP, nakp);
			PUTCHAR(CHAP_DIGEST(ao->chap_mdtype), nakp);
		    }
		    break;
		}
		ho->neg_upap = 1;
		break;
	    }
	    if (cishort == PPP_CHAP) {
		if (!ao->neg_chap) {	/* we don't want to do CHAP */
		    orc = CONFNAK;	/* NAK it and suggest EAP or PAP */
		    PUTCHAR(CI_AUTHTYPE, nakp);
		    PUTCHAR(CILEN_SHORT, nakp);
		    if (ao->neg_eap) {
			PUTSHORT(PPP_EAP, nakp);
		    } else {
			PUTSHORT(PPP_PAP, nakp);
		    }
		    break;
		}
		GETCHAR(cichar, p);	/* get digest type */
		if (!(CHAP_CANDIGEST(ao->chap_mdtype, cichar))) {
		    /*
		     * We can't/won't do the requested type,
		     * suggest something else.
		     */
		    orc = CONFNAK;
		    PUTCHAR(CI_AUTHTYPE, nakp);
		    PUTCHAR(CILEN_CHAP, nakp);
		    PUTSHORT(PPP_CHAP, nakp);
		    PUTCHAR(CHAP_DIGEST(ao->chap_mdtype), nakp);
		    break;
		}
		ho->chap_mdtype = CHAP_MDTYPE_D(cichar); /* save md type */
		ho->neg_chap = 1;
		break;
	    }
	    if (cishort == PPP_EAP) {
		if (!ao->neg_eap) {	/* we don't want to do EAP */
		    orc = CONFNAK;	/* NAK it and suggest CHAP or PAP */
		    PUTCHAR(CI_AUTHTYPE, nakp);
		    if (ao->neg_chap) {
			PUTCHAR(CILEN_CHAP, nakp);
			PUTSHORT(PPP_CHAP, nakp);
			PUTCHAR(CHAP_DIGEST(ao->chap_mdtype), nakp);
		    } else {
			PUTCHAR(CILEN_SHORT, nakp);
			PUTSHORT(PPP_PAP, nakp);
		    }
		    break;
		}
		ho->neg_eap = 1;
		break;
	    }

	    /*
	     * We don't recognize the protocol they're asking for.
	     * Nak it with something we're willing to do.
	     * (At this point we know ao->neg_upap || ao->neg_chap ||
	     * ao->neg_eap.)
	     */
	    orc = CONFNAK;
	    PUTCHAR(CI_AUTHTYPE, nakp);
	    if (ao->neg_eap) {
		PUTCHAR(CILEN_SHORT, nakp);
		PUTSHORT(PPP_EAP, nakp);
	    } else if (ao->neg_chap) {
		PUTCHAR(CILEN_CHAP, nakp);
		PUTSHORT(PPP_CHAP, nakp);
		PUTCHAR(CHAP_DIGEST(ao->chap_mdtype), nakp);
	    } else {
		PUTCHAR(CILEN_SHORT, nakp);
		PUTSHORT(PPP_PAP, nakp);
	    }
	    break;

	case CI_QUALITY:
	    if (!ao->neg_lqr ||
		cilen != CILEN_LQR) {
		orc = CONFREJ;
		break;
	    }

	    GETSHORT(cishort, p);
	    GETLONG(cilong, p);

	    /*
	     * Check the protocol and the reporting period.
	     * XXX When should we Nak this, and what with?
	     */
	    if (cishort != PPP_LQR) {
		orc = CONFNAK;
		PUTCHAR(CI_QUALITY, nakp);
		PUTCHAR(CILEN_LQR, nakp);
		PUTSHORT(PPP_LQR, nakp);
		PUTLONG(ao->lqr_period, nakp);
		break;
	    }
	    break;

	case CI_MAGICNUMBER:
	    if (!(ao->neg_magicnumber || go->neg_magicnumber) ||
		cilen != CILEN_LONG) {
		orc = CONFREJ;
		break;
	    }
	    GETLONG(cilong, p);

	    /*
	     * He must have a different magic number.
	     */
	    if (go->neg_magicnumber &&
		cilong == go->magicnumber) {
		cilong = magic();	/* Don't put magic() inside macro! */
		orc = CONFNAK;
		PUTCHAR(CI_MAGICNUMBER, nakp);
		PUTCHAR(CILEN_LONG, nakp);
		PUTLONG(cilong, nakp);
		break;
	    }
	    ho->neg_magicnumber = 1;
	    ho->magicnumber = cilong;
	    break;


	case CI_PCOMPRESSION:
	    if (!ao->neg_pcompression ||
		cilen != CILEN_VOID) {
		orc = CONFREJ;
		break;
	    }
	    ho->neg_pcompression = 1;
	    break;

	case CI_ACCOMPRESSION:
	    if (!ao->neg_accompression ||
		cilen != CILEN_VOID) {
		orc = CONFREJ;
		break;
	    }
	    ho->neg_accompression = 1;
	    break;

	case CI_MRRU:
	    if (!ao->neg_mrru || !multilink ||
		cilen != CILEN_SHORT) {
		orc = CONFREJ;
		break;
	    }

	    GETSHORT(cishort, p);
	    /* possibly should insist on a minimum/maximum MRRU here */
	    ho->neg_mrru = 1;
	    ho->mrru = cishort;
	    break;

	case CI_SSNHF:
	    if (!ao->neg_ssnhf || !multilink ||
		cilen != CILEN_VOID) {
		orc = CONFREJ;
		break;
	    }
	    ho->neg_ssnhf = 1;
	    break;

	case CI_EPDISC:
	    if (!ao->neg_endpoint ||
		cilen < CILEN_CHAR ||
		cilen > CILEN_CHAR + MAX_ENDP_LEN) {
		orc = CONFREJ;
		break;
	    }
	    GETCHAR(cichar, p);
	    cilen -= CILEN_CHAR;
	    ho->neg_endpoint = 1;
	    ho->endpoint.class = cichar;
	    ho->endpoint.length = cilen;
	    BCOPY(p, ho->endpoint.value, cilen);
	    INCPTR(cilen, p);
	    break;

	default:
	    LCPDEBUG(("lcp_reqci: rcvd unknown option %d", citype));
	    orc = CONFREJ;
	    break;
	}

endswitch:
	if (orc == CONFACK &&		/* Good CI */
	    rc != CONFACK)		/*  but prior CI wasnt? */
	    continue;			/* Don't send this one */

	if (orc == CONFNAK) {		/* Nak this CI? */
	    /* If we get too many NAK'd CIs, reject instead. */
	    /* Shouldn't be able to happen */
	    if (nakp - nak_buffer > PPP_MRU - 8)
		orc = CONFREJ;
	    else if (reject_if_disagree	/* Getting fed up with sending NAKs? */
		&& citype != CI_MAGICNUMBER) {
		orc = CONFREJ;		/* Get tough if so */
	    } else {
		if (rc == CONFREJ)	/* Rejecting prior CI? */
		    continue;		/* Don't send this one */
		rc = CONFNAK;
	    }
	}
	if (orc == CONFREJ) {		/* Reject this CI */
	    rc = CONFREJ;
	    if (cip != rejp)		/* Need to move rejected CI? */
		BCOPY(cip, rejp, cilen); /* Move it */
	    INCPTR(cilen, rejp);	/* Update output pointer */
	}
    }

    /*
     * If we wanted to send additional NAKs (for unsent CIs), the
     * code would go here.  The extra NAKs would go at *nakp.
     * At present there are no cases where we want to ask the
     * peer to negotiate an option.
     */

    switch (rc) {
    case CONFACK:
	*lenp = next - inp;
	break;
    case CONFNAK:
	/*
	 * Copy the Nak'd options from the nak_buffer to the caller's buffer.
	 */
	*lenp = nakp - nak_buffer;
	BCOPY(nak_buffer, inp, *lenp);
	break;
    case CONFREJ:
	*lenp = rejp - inp;
	break;
    }

    LCPDEBUG(("lcp_reqci: returning CONF%s.", CODENAME(rc)));
    return (rc);			/* Return final code */
}

static void
lcp_up(fsm *f)
{
    lcp_options *wo = &lcp_wantoptions[f->unit];
    lcp_options *ho = &lcp_hisoptions[f->unit];
    lcp_options *go = &lcp_gotoptions[f->unit];
    lcp_options *ao = &lcp_allowoptions[f->unit];
    int mtu, mru;

    if (!go->neg_magicnumber)
	go->magicnumber = 0;
    if (!ho->neg_magicnumber)
	ho->magicnumber = 0;

    /*
     * Set our MTU to the smaller of the MTU we wanted and
     * the MRU our peer wanted.  If we negotiated an MRU,
     * set our MRU to the larger of value we wanted and
     * the value we got in the negotiation.
     * Note on the MTU: the link MTU can be the MRU the peer wanted,
     * the interface MTU is set to the lowest of that, the
     * MTU we want to use, and our link MRU.
     */
    mtu = ho->neg_mru? ho->mru: PPP_MRU;
    mru = go->neg_mru? MAX(wo->mru, go->mru): PPP_MRU;
#ifdef PPP_WITH_MULTILINK
    if (!(multilink && go->neg_mrru && ho->neg_mrru))
#endif /* PPP_WITH_MULTILINK */
	ppp_set_mtu(f->unit, MIN(MIN(mtu, mru), ao->mru));
    ppp_send_config(f->unit, mtu,
		    (ho->neg_asyncmap? ho->asyncmap: 0xffffffff),
		    ho->neg_pcompression, ho->neg_accompression);
    ppp_recv_config(f->unit, mru,
		    (lax_recv? 0: go->neg_asyncmap? go->asyncmap: 0xffffffff),
		    go->neg_pcompression, go->neg_accompression);

    /*
     * Make it explicit that peer_mru[] is between MINMRU and PPP_MRU.
     * We wouldn't have accepted a proposed MRU from the peer that is
     * less than MINMRU, but we might have accepted one greater than PPP_MRU.
     */
    if (ho->neg_mru && ho->mru < PPP_MRU)
	peer_mru[f->unit] = MAX(ho->mru, MINMRU);

    lcp_echo_lowerup(f->unit);  /* Enable echo messages */

    link_established(f->unit);
}

static void
lcp_down(fsm *f)
{
    lcp_options *go = &lcp_gotoptions[f->unit];

    lcp_echo_lowerdown(f->unit);

    link_down(f->unit);

    ppp_send_config(f->unit, PPP_MRU, 0xffffffff, 0, 0);
    ppp_recv_config(f->unit, PPP_MRU,
		    (go->neg_asyncmap? go->asyncmap: 0xffffffff),
		    go->neg_pcompression, go->neg_accompression);
    peer_mru[f->unit] = PPP_MRU;
}

static void
lcp_starting(fsm *f)
{
    link_required(f->unit);
}

static void
lcp_finished(fsm *f)
{
    link_terminated(f->unit);
}

static
void LcpLinkFailure (fsm *f)
{
    if (f->state == OPENED) {
	info("No response to %d echo-requests", lcp_echos_pending);
        notice("Serial link appears to be disconnected.");
	ppp_set_status(EXIT_PEER_DEAD);
	lcp_close(f->unit, "Peer not responding");
    }
}

static void
LcpEchoCheck (fsm *f)
{
    LcpSendEchoRequest (f);
    if (f->state != OPENED)
	return;

    /*
     * Start the timer for the next interval.
     */
    if (lcp_echo_timer_running)
	warn("assertion lcp_echo_timer_running==0 failed");
    TIMEOUT (LcpEchoTimeout, f, lcp_echo_interval);
    lcp_echo_timer_running = 1;
}

static void
LcpEchoTimeout (void *arg)
{
    if (lcp_echo_timer_running != 0) {
        lcp_echo_timer_running = 0;
        LcpEchoCheck ((fsm *) arg);
    }
}

static void
lcp_rtt_update_buffer (unsigned long rtt)
{
    volatile u_int32_t *const ring_header = lcp_rtt_buffer;
    volatile u_int32_t *const ring_buffer = lcp_rtt_buffer
	+ LCP_RTT_HEADER_LENGTH;
    unsigned int next_entry, lost;

    /* choose the next entry where the data will be stored */
    next_entry = ntohl(ring_header[2]);
    if (next_entry >= (LCP_RTT_ELEMENTS - 1) * 2)
	next_entry = 0;				/* go back to the beginning */
    else
	next_entry += 2;			/* use the next one */

    /* update the data element */
    /* storing the timestamp in an *unsigned* long allows dates up to 2106 */
    ring_buffer[next_entry] = htonl((u_int32_t) time(NULL));
    lost = lcp_echos_pending - 1;
    if (lost > 0xFF)
	lost = 0xFF;		/* truncate the lost packets count to 256 */
    if (rtt > 0xFFFFFF)
	rtt = 0xFFFFFF;		/* truncate the RTT to 16777216 */
    /* use bits 24-31 for the lost packets count and bits 0-23 for the RTT */
    ring_buffer[next_entry + 1] = htonl((u_int32_t) ((lost << 24) + rtt));

    /* update the pointer to the (just updated) most current data element */
    ring_header[2] = htonl(next_entry);

    /* In theory, CPUs implementing a weakly-consistent memory model do not
     * guarantee that these three memory store operations to the buffer will
     * be seen in the same order by the reader process.
     * This means that a process reading the file could see the index
     * having been updated before the element that the index points to had
     * been written.
     * But in practice we expect that the read(2) system call used by
     * consumers processes is atomic with respect to the following msync(2)
     * call, so we ignore the issue.
     */

    if (ppp_core_rtt_flush() < 0)
	error("msync() for %s failed: %m", lcp_rtt_file);
}

static void
lcp_received_echo_reply (fsm *f, int id, u_char *inp, int len)
{
    u_int32_t magic;

    /* Check the magic number - don't count replies from ourselves. */
    if (len < 4) {
	dbglog("lcp: received short Echo-Reply, length %d", len);
	return;
    }
    GETLONG(magic, inp);
    if (lcp_gotoptions[f->unit].neg_magicnumber
	&& magic == lcp_gotoptions[f->unit].magicnumber) {
	warn("appear to have received our own echo-reply!");
	return;
    }

    if (lcp_rtt_file_fd && len >= 16) {
	long lcp_rtt_magic;

	/*
	 * If the magic word is found at the beginning of the data section
	 * of the frame then read the timestamp which follows and subtract
	 * it from the current time to compute the round trip time.
	 */
	GETLONG(lcp_rtt_magic, inp);
	if (lcp_rtt_magic == LCP_RTT_MAGIC) {
	    struct timespec ts;
	    unsigned long req_sec, req_nsec, rtt;

	    ppp_core_monotonic(&ts);
	    GETLONG(req_sec, inp);
	    GETLONG(req_nsec, inp);
	    /* compute the RTT in microseconds */
	    rtt = (ts.tv_sec - req_sec) * 1000000
		+ (ts.tv_nsec / 1000 - req_nsec / 1000);
	    /* log the RTT */
	    lcp_rtt_update_buffer(rtt);
	}
    }

    /* Reset the number of outstanding echo frames */
    lcp_echos_pending = 0;
}

static void
LcpSendEchoRequest (fsm *f)
{
    u_int32_t lcp_magic;
    u_char pkt[16], *pktp;

    /*
     * Detect the failure of the peer at this point.
     */
    if (lcp_echo_fails != 0) {
        if (lcp_echos_pending >= lcp_echo_fails) {
            LcpLinkFailure(f);
	    lcp_echos_pending = 0;
	}
    }

    /*
     * If adaptive echos have been enabled, only send the echo request if
     * no traffic was received since the last one.
     */
    if (lcp_echo_adaptive) {
	static unsigned int last_pkts_in = 0;
	struct pppd_stats cur_stats;

	if (get_ppp_stats(f->unit, &cur_stats) && cur_stats.pkts_in != last_pkts_in) {
	    last_pkts_in = cur_stats.pkts_in;
	    /* receipt of traffic indicates the link is working... */
	    lcp_echos_pending = 0;
	    return;
	}
    }

    /*
     * Make and send the echo request frame.
     */
    if (f->state == OPENED) {
        lcp_magic = lcp_gotoptions[f->unit].magicnumber;
	pktp = pkt;
	PUTLONG(lcp_magic, pktp);

	/* Put a timestamp in the data section of the frame */
	if (lcp_rtt_file_fd) {
	    struct timespec ts;

	    PUTLONG(LCP_RTT_MAGIC, pktp);
	    ppp_core_monotonic(&ts);
	    PUTLONG((u_int32_t)ts.tv_sec, pktp);
	    PUTLONG((u_int32_t)ts.tv_nsec, pktp);
	}

        fsm_sdata(f, ECHOREQ, lcp_echo_number++ & 0xFF, pkt, pktp - pkt);
	++lcp_echos_pending;
    }
}

static void
lcp_echo_lowerup (int unit)
{
    fsm *f = &lcp_fsm[unit];

    /* Clear the parameters for generating echo frames */
    lcp_echos_pending      = 0;
    lcp_echo_number        = 0;
    lcp_echo_timer_running = 0;

    /* Open the file where the LCP RTT data will be logged */
    lcp_rtt_open_file();
  
    /* If a timeout interval is specified then start the timer */
    if (lcp_echo_interval != 0)
        LcpEchoCheck (f);
}

static void
lcp_echo_lowerdown (int unit)
{
    fsm *f = &lcp_fsm[unit];

    if (lcp_echo_timer_running != 0) {
        UNTIMEOUT (LcpEchoTimeout, f);
        lcp_echo_timer_running = 0;
    }

    /* Close the file containing the LCP RTT data */
    lcp_rtt_close_file();
}
