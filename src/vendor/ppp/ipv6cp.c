/*
 * ipv6cp.c - PPP IPV6 Control Protocol.
 *
 * Copyright (c) 1999 Tommi Komulainen.  All rights reserved.
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
 * 3. The name(s) of the authors of this software must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission.
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Tommi Komulainen
 *     <Tommi.Komulainen@iki.fi>".
 *
 * THE AUTHORS OF THIS SOFTWARE DISCLAIM ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
 * SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 */

/*  Original version, based on RFC2023 :

    Copyright (c) 1995, 1996, 1997 Francis.Dupont@inria.fr, INRIA Rocquencourt,
    Alain.Durand@imag.fr, IMAG,
    Jean-Luc.Richier@imag.fr, IMAG-LSR.

    Copyright (c) 1998, 1999 Francis.Dupont@inria.fr, GIE DYADE,
    Alain.Durand@imag.fr, IMAG,
    Jean-Luc.Richier@imag.fr, IMAG-LSR.

    Ce travail a été fait au sein du GIE DYADE (Groupement d'Intérêt
    Économique ayant pour membres BULL S.A. et l'INRIA).

    Ce logiciel informatique est disponible aux conditions
    usuelles dans la recherche, c'est-à-dire qu'il peut
    être utilisé, copié, modifié, distribué à l'unique
    condition que ce texte soit conservé afin que
    l'origine de ce logiciel soit reconnue.

    Le nom de l'Institut National de Recherche en Informatique
    et en Automatique (INRIA), de l'IMAG, ou d'une personne morale
    ou physique ayant participé à l'élaboration de ce logiciel ne peut
    être utilisé sans son accord préalable explicite.

    Ce logiciel est fourni tel quel sans aucune garantie,
    support ou responsabilité d'aucune sorte.
    Ce logiciel est dérivé de sources d'origine
    "University of California at Berkeley" et
    "Digital Equipment Corporation" couvertes par des copyrights.

    L'Institut d'Informatique et de Mathématiques Appliquées de Grenoble (IMAG)
    est une fédération d'unités mixtes de recherche du CNRS, de l'Institut National
    Polytechnique de Grenoble et de l'Université Joseph Fourier regroupant
    sept laboratoires dont le laboratoire Logiciels, Systèmes, Réseaux (LSR).

    This work has been done in the context of GIE DYADE (joint R & D venture
    between BULL S.A. and INRIA).

    This software is available with usual "research" terms
    with the aim of retain credits of the software. 
    Permission to use, copy, modify and distribute this software for any
    purpose and without fee is hereby granted, provided that the above
    copyright notice and this permission notice appear in all copies,
    and the name of INRIA, IMAG, or any contributor not be used in advertising
    or publicity pertaining to this material without the prior explicit
    permission. The software is provided "as is" without any
    warranties, support or liabilities of any kind.
    This software is derived from source code from
    "University of California at Berkeley" and
    "Digital Equipment Corporation" protected by copyrights.

    Grenoble's Institute of Computer Science and Applied Mathematics (IMAG)
    is a federation of seven research units funded by the CNRS, National
    Polytechnic Institute of Grenoble and University Joseph Fourier.
    The research unit in Software, Systems, Networks (LSR) is member of IMAG.
*/

/*
 * Derived from :
 *
 *
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

/*
 * TODO: 
 *
 * Proxy Neighbour Discovery.
 *
 * Better defines for selecting the ordering of
 *   interface up / set address. (currently checks for __linux__,
 *   since SVR4 && (SNI || __USLC__) didn't work properly)
 */


/* Original IPv6CP negotiation, with native IP host callbacks. */
#include "pppd-private.h"
#include "core_extra.h"
#include "fsm.h"
#include "ipv6cp.h"
#define CILEN_VOID 2
#define CILEN_COMPRESS 4
#define CILEN_IFACEID 10
#define CODENAME(x) ((x)==CONFACK?"ACK":(x)==CONFNAK?"NAK":"REJ")
#ifndef IPV6CPDEBUG
#define IPV6CPDEBUG(x) do{if(debug)dbglog x;}while(0)
#endif
ipv6cp_options ipv6cp_wantoptions[NUM_PPP],ipv6cp_gotoptions[NUM_PPP],ipv6cp_allowoptions[NUM_PPP],ipv6cp_hisoptions[NUM_PPP];
fsm ipv6cp_fsm[NUM_PPP];
int no_ifaceid_neg=0;
static int ipv6cp_noremote=0;
static void ipv6cp_up(fsm *f);
static void ipv6cp_down(fsm *f);
static void
ipv6cp_init(int unit);
static void
ipv6cp_open(int unit);
static void
ipv6cp_close(int unit, char *reason);
static void
ipv6cp_lowerup(int unit);
static void
ipv6cp_lowerdown(int unit);
static void
ipv6cp_input(int unit, u_char *p, int len);
static void
ipv6cp_protrej(int unit);
static void
ipv6cp_resetci(fsm *f);
static int
ipv6cp_cilen(fsm *f);
static void
ipv6cp_addci(fsm *f, u_char *ucp, int *lenp);
static int
ipv6cp_ackci(fsm *f, u_char *p, int len);
static int
ipv6cp_nakci(fsm *f, u_char *p, int len, int treat_as_reject);
static int
ipv6cp_rejci(fsm *f, u_char *p, int len);
static int
ipv6cp_reqci(fsm *f, u_char *inp, int *len, int reject_if_disagree);
static void
ipv6cp_finished(fsm *f);
char *
llv6_ntoa(eui64_t ifaceid);

static fsm_callbacks ipv6cp_callbacks={ipv6cp_resetci,ipv6cp_cilen,ipv6cp_addci,ipv6cp_ackci,ipv6cp_nakci,ipv6cp_rejci,ipv6cp_reqci,ipv6cp_up,ipv6cp_down,NULL,ipv6cp_finished,NULL,NULL,NULL,"IPV6CP"};
struct protent ipv6cp_protent={PPP_IPV6CP,ipv6cp_init,ipv6cp_input,ipv6cp_protrej,ipv6cp_lowerup,ipv6cp_lowerdown,ipv6cp_open,ipv6cp_close,NULL,NULL,0,"IPV6CP","IPv6",NULL,NULL,NULL,NULL};

static void ipv6cp_up(fsm *f){

    ipv6cp_options *ho = &ipv6cp_hisoptions[f->unit];
    ipv6cp_options *go = &ipv6cp_gotoptions[f->unit];
    ipv6cp_options *wo = &ipv6cp_wantoptions[f->unit];

    IPV6CPDEBUG(("ipv6cp: up"));

    /*
     * We must have a non-zero LL address for both ends of the link.
     */

    if (!eui64_iszero(wo->hisid) && !wo->accept_remote && (!ho->neg_ifaceid || !eui64_equals(ho->hisid, wo->hisid))) {
	error("Peer refused to agree to his interface identifier");
	ipv6cp_close(f->unit, "Refused his interface identifier");
	return;
    }
    if (!ho->neg_ifaceid)
	ho->hisid = wo->hisid;

    if(!no_ifaceid_neg) {
	if (eui64_iszero(ho->hisid) && !ipv6cp_noremote) {
	    error("Could not determine remote LL address");
	    ipv6cp_close(f->unit, "Could not determine remote LL address");
	    return;
	}
	if (eui64_iszero(go->ourid)) {
	    error("Could not determine local LL address");
	    ipv6cp_close(f->unit, "Could not determine local LL address");
	    return;
	}
	if (eui64_equals(go->ourid, ho->hisid)) {
	    error("local and remote LL addresses are equal");
	    ipv6cp_close(f->unit, "local and remote LL addresses are equal");
	    return;
	}
    }

    if(!ppp_core_sif6addr(f->unit,go->ourid,ho->hisid)){
        ipv6cp_close(f->unit,"Interface configuration failed");return;
    }
    np_up(f->unit,PPP_IPV6);
}
static void ipv6cp_down(fsm *f){np_down(f->unit,PPP_IPV6);ppp_core_cif6addr(f->unit);}
static void
ipv6cp_init(int unit)
{
    fsm *f = &ipv6cp_fsm[unit];
    ipv6cp_options *wo = &ipv6cp_wantoptions[unit];
    ipv6cp_options *ao = &ipv6cp_allowoptions[unit];

    f->unit = unit;
    f->protocol = PPP_IPV6CP;
    f->callbacks = &ipv6cp_callbacks;
    fsm_init(&ipv6cp_fsm[unit]);

    memset(wo, 0, sizeof(*wo));
    memset(ao, 0, sizeof(*ao));

    wo->accept_local = 0;
    wo->accept_remote = 0;
    wo->neg_ifaceid = 1;
    ao->neg_ifaceid = 1;

#ifdef IPV6CP_COMP
    wo->neg_vj = 1;
    ao->neg_vj = 1;
    wo->vj_protocol = IPV6CP_COMP;
#endif

    /*
     * XXX This controls whether the user may use the defaultroute option.
     */
    ao->default_route = 1;
}

static void
ipv6cp_open(int unit)
{
    fsm_open(&ipv6cp_fsm[unit]);
}

static void
ipv6cp_close(int unit, char *reason)
{
    fsm_close(&ipv6cp_fsm[unit], reason);
}

static void
ipv6cp_lowerup(int unit)
{
    fsm_lowerup(&ipv6cp_fsm[unit]);
}

static void
ipv6cp_lowerdown(int unit)
{
    fsm_lowerdown(&ipv6cp_fsm[unit]);
}

static void
ipv6cp_input(int unit, u_char *p, int len)
{
    fsm_input(&ipv6cp_fsm[unit], p, len);
}

static void
ipv6cp_protrej(int unit)
{
    fsm_lowerdown(&ipv6cp_fsm[unit]);
}

static void
ipv6cp_resetci(fsm *f)
{
    ipv6cp_options *wo = &ipv6cp_wantoptions[f->unit];
    ipv6cp_options *go = &ipv6cp_gotoptions[f->unit];

    wo->req_ifaceid = wo->neg_ifaceid && ipv6cp_allowoptions[f->unit].neg_ifaceid;
    
    if (!wo->opt_local) {
	wo->accept_local = 1;
	if (!demand)
	    eui64_magic_nz(wo->ourid);
    }
    if (!wo->opt_remote)
	wo->accept_remote = 1;
    
    *go = *wo;
    eui64_zero(go->hisid);	/* last proposed interface identifier */
}

static int
ipv6cp_cilen(fsm *f)
{
    ipv6cp_options *go = &ipv6cp_gotoptions[f->unit];

#define LENCIVJ(neg)		(neg ? CILEN_COMPRESS : 0)
#define LENCIIFACEID(neg)	(neg ? CILEN_IFACEID : 0)

    return (LENCIIFACEID(go->neg_ifaceid) +
	    LENCIVJ(go->neg_vj));
}

static void
ipv6cp_addci(fsm *f, u_char *ucp, int *lenp)
{
    ipv6cp_options *go = &ipv6cp_gotoptions[f->unit];
    int len = *lenp;

#define ADDCIVJ(opt, neg, val) \
    if (neg) { \
	int vjlen = CILEN_COMPRESS; \
	if (len >= vjlen) { \
	    PUTCHAR(opt, ucp); \
	    PUTCHAR(vjlen, ucp); \
	    PUTSHORT(val, ucp); \
	    len -= vjlen; \
	} else \
	    neg = 0; \
    }

#define ADDCIIFACEID(opt, neg, val1) \
    if (neg) { \
	int idlen = CILEN_IFACEID; \
	if (len >= idlen) { \
	    PUTCHAR(opt, ucp); \
	    PUTCHAR(idlen, ucp); \
	    eui64_put(val1, ucp); \
	    len -= idlen; \
	} else \
	    neg = 0; \
    }

    ADDCIIFACEID(CI_IFACEID, go->neg_ifaceid, go->ourid);

    ADDCIVJ(CI_COMPRESSTYPE, go->neg_vj, go->vj_protocol);

    *lenp -= len;
}

static int
ipv6cp_ackci(fsm *f, u_char *p, int len)
{
    ipv6cp_options *go = &ipv6cp_gotoptions[f->unit];
    u_short cilen, citype, cishort;
    eui64_t ifaceid;

    /*
     * CIs must be in exactly the same order that we sent...
     * Check packet length and CI length at each step.
     * If we find any deviations, then this packet is bad.
     */

#define ACKCIVJ(opt, neg, val) \
    if (neg) { \
	int vjlen = CILEN_COMPRESS; \
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
    }

#define ACKCIIFACEID(opt, neg, val1) \
    if (neg) { \
	int idlen = CILEN_IFACEID; \
	if ((len -= idlen) < 0) \
	    goto bad; \
	GETCHAR(citype, p); \
	GETCHAR(cilen, p); \
	if (cilen != idlen || \
	    citype != opt) \
	    goto bad; \
	eui64_get(ifaceid, p); \
	if (! eui64_equals(val1, ifaceid)) \
	    goto bad; \
    }

    ACKCIIFACEID(CI_IFACEID, go->neg_ifaceid, go->ourid);

    ACKCIVJ(CI_COMPRESSTYPE, go->neg_vj, go->vj_protocol);

    /*
     * If there are any remaining CIs, then this packet is bad.
     */
    if (len != 0)
	goto bad;
    return (1);

bad:
    IPV6CPDEBUG(("ipv6cp_ackci: received bad Ack!"));
    return (0);
}

static int
ipv6cp_nakci(fsm *f, u_char *p, int len, int treat_as_reject)
{
    ipv6cp_options *wo = &ipv6cp_wantoptions[f->unit];
    ipv6cp_options *go = &ipv6cp_gotoptions[f->unit];
    u_char citype, cilen, *next;
    u_short cishort;
    eui64_t ifaceid;
    ipv6cp_options no;		/* options we've seen Naks for */
    ipv6cp_options try;		/* options to request next time */

    BZERO(&no, sizeof(no));
    try = *go;

    /*
     * Any Nak'd CIs must be in exactly the same order that we sent.
     * Check packet length and CI length at each step.
     * If we find any deviations, then this packet is bad.
     */
#define NAKCIIFACEID(opt, neg, code) \
    if (go->neg && \
	len >= (cilen = CILEN_IFACEID) && \
	p[1] == cilen && \
	p[0] == opt) { \
	len -= cilen; \
	INCPTR(2, p); \
	eui64_get(ifaceid, p); \
	no.neg = 1; \
	code \
    }

#define NAKCIVJ(opt, neg, code) \
    if (go->neg && \
	((cilen = p[1]) == CILEN_COMPRESS) && \
	len >= cilen && \
	p[0] == opt) { \
	len -= cilen; \
	INCPTR(2, p); \
	GETSHORT(cishort, p); \
	no.neg = 1; \
        code \
    }

    /*
     * Accept the peer's idea of {our,his} interface identifier, if different
     * from our idea, only if the accept_{local,remote} flag is set.
     */
    NAKCIIFACEID(CI_IFACEID, neg_ifaceid,
		 if (treat_as_reject) {
		     try.neg_ifaceid = 0;
		 } else if (go->accept_local && !eui64_iszero(ifaceid) && !eui64_equals(ifaceid, go->hisid)) {
		     try.ourid = ifaceid;
		 } else if (eui64_iszero(ifaceid) && !go->opt_local && wo->neg_ifaceid) {
		     while (eui64_iszero(ifaceid) || 
			    eui64_equals(ifaceid, go->hisid)) /* bad luck */
			 eui64_magic(ifaceid);
		     try.ourid = ifaceid;
		     IPV6CPDEBUG(("local LL address %s", llv6_ntoa(ifaceid)));
		 }
		 );

#ifdef IPV6CP_COMP
    NAKCIVJ(CI_COMPRESSTYPE, neg_vj,
	    {
		if (cishort == IPV6CP_COMP && !treat_as_reject) {
		    try.vj_protocol = cishort;
		} else {
		    try.neg_vj = 0;
		}
	    }
	    );
#else
    NAKCIVJ(CI_COMPRESSTYPE, neg_vj,
	    {
		try.neg_vj = 0;
	    }
	    );
#endif

    /*
     * There may be remaining CIs, if the peer is requesting negotiation
     * on an option that we didn't include in our request packet.
     * If they want to negotiate about interface identifier, we comply.
     * If they want us to ask for compression, we refuse.
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
		(cilen != CILEN_COMPRESS))
		goto bad;
	    no.neg_vj = 1;
	    break;
	case CI_IFACEID:
	    if (go->neg_ifaceid || no.neg_ifaceid || cilen != CILEN_IFACEID)
		goto bad;
	    try.neg_ifaceid = 1;
	    eui64_get(ifaceid, p);
	    if (go->accept_local && !eui64_iszero(ifaceid) && !eui64_equals(ifaceid, go->hisid)) {
		try.ourid = ifaceid;
	    } else if (eui64_iszero(ifaceid) && !go->opt_local && wo->neg_ifaceid) {
		while (eui64_iszero(ifaceid) || 
		       eui64_equals(ifaceid, go->hisid)) /* bad luck */
		    eui64_magic(ifaceid);
		try.ourid = ifaceid;
	    } else {
		try.neg_ifaceid = 0;
	    }
	    no.neg_ifaceid = 1;
	    break;
	}
	p = next;
    }

    /* If there is still anything left, this packet is bad. */
    if (len != 0)
	goto bad;

    /*
     * OK, the Nak is good.  Now we can update state.
     */
    if (f->state != OPENED)
	*go = try;

    return 1;

bad:
    IPV6CPDEBUG(("ipv6cp_nakci: received bad Nak!"));
    return 0;
}

static int
ipv6cp_rejci(fsm *f, u_char *p, int len)
{
    ipv6cp_options *go = &ipv6cp_gotoptions[f->unit];
    u_char cilen;
    u_short cishort;
    eui64_t ifaceid;
    ipv6cp_options try;		/* options to request next time */

    try = *go;
    /*
     * Any Rejected CIs must be in exactly the same order that we sent.
     * Check packet length and CI length at each step.
     * If we find any deviations, then this packet is bad.
     */
#define REJCIIFACEID(opt, neg, val1) \
    if (go->neg && \
	len >= (cilen = CILEN_IFACEID) && \
	p[1] == cilen && \
	p[0] == opt) { \
	len -= cilen; \
	INCPTR(2, p); \
	eui64_get(ifaceid, p); \
	/* Check rejected value. */ \
	if (! eui64_equals(ifaceid, val1)) \
	    goto bad; \
	try.neg = 0; \
    }

#define REJCIVJ(opt, neg, val) \
    if (go->neg && \
	p[1] == CILEN_COMPRESS && \
	len >= p[1] && \
	p[0] == opt) { \
	len -= p[1]; \
	INCPTR(2, p); \
	GETSHORT(cishort, p); \
	/* Check rejected value. */  \
	if (cishort != val) \
	    goto bad; \
	try.neg = 0; \
     }

    REJCIIFACEID(CI_IFACEID, neg_ifaceid, go->ourid);

    REJCIVJ(CI_COMPRESSTYPE, neg_vj, go->vj_protocol);

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
    IPV6CPDEBUG(("ipv6cp_rejci: received bad Reject!"));
    return 0;
}

static int
ipv6cp_reqci(fsm *f, u_char *inp, int *len, int reject_if_disagree)
{
    ipv6cp_options *wo = &ipv6cp_wantoptions[f->unit];
    ipv6cp_options *ho = &ipv6cp_hisoptions[f->unit];
    ipv6cp_options *ao = &ipv6cp_allowoptions[f->unit];
    ipv6cp_options *go = &ipv6cp_gotoptions[f->unit];
    u_char *cip, *next;		/* Pointer to current and next CIs */
    u_short cilen, citype;	/* Parsed len, type */
    u_short cishort;		/* Parsed short value */
    eui64_t ifaceid;		/* Parsed interface identifier */
    int rc = CONFACK;		/* Final packet return code */
    int orc;			/* Individual option return code */
    u_char *p;			/* Pointer to next char to parse */
    u_char *ucp = inp;		/* Pointer to current output char */
    int l = *len;		/* Length left */
    bool warned = 0, seenci[CI_COMPRESSTYPE+1];

    /*
     * Reset all his options.
     */
    BZERO(ho, sizeof(*ho));
    BZERO(seenci, sizeof(seenci));
    
    /*
     * Process all his options.
     */
    next = inp;
    while (l) {
	orc = CONFACK;			/* Assume success */
	cip = p = next;			/* Remember begining of CI */
	if (l < 2 ||			/* Not enough data for CI header or */
	    p[1] < 2 ||			/*  CI length too small or */
	    p[1] > l) {			/*  CI length too big? */
	    IPV6CPDEBUG(("ipv6cp_reqci: bad CI length!"));
	    orc = CONFREJ;		/* Reject bad CI */
	    cilen = l;			/* Reject till end of packet */
	    l = 0;			/* Don't loop again */
	    goto endswitch;
	}
	GETCHAR(citype, p);		/* Parse CI type */
	GETCHAR(cilen, p);		/* Parse CI length */
	l -= cilen;			/* Adjust remaining length */
	next += cilen;			/* Step to next CI */

	if (citype <= CI_COMPRESSTYPE) {
	    if (seenci[citype]) {
		if (!warned) {
		    warn("IPV6CP: ignoring duplicate configuration option(s)");
		    warned = 1;
		}
		continue;
	    }
	    seenci[citype] = 1;
	}

	switch (citype) {		/* Check CI type */
	case CI_IFACEID:
	    IPV6CPDEBUG(("ipv6cp: received interface identifier "));

	    if (!ao->neg_ifaceid ||
		cilen != CILEN_IFACEID) {	/* Check CI length */
		orc = CONFREJ;		/* Reject CI */
		break;
	    }

	    /*
	     * If he has no interface identifier, or if we both have same 
	     * identifier then NAK it with new idea.
	     * In particular, if we don't know his identifier, but he does,
	     * then accept it.
	     */
	    eui64_get(ifaceid, p);
	    IPV6CPDEBUG(("(%s)", llv6_ntoa(ifaceid)));
	    if (eui64_iszero(ifaceid) && eui64_iszero(go->ourid)) {
		orc = CONFREJ;		/* Reject CI */
		break;
	    }
	    if (!eui64_iszero(wo->hisid) && !wo->accept_remote &&
		!eui64_equals(ifaceid, wo->hisid)) {
		    
		orc = CONFNAK;
		ifaceid = wo->hisid;
		go->hisid = ifaceid;
		DECPTR(sizeof(ifaceid), p);
		eui64_put(ifaceid, p);
	    } else
	    if (eui64_iszero(ifaceid) || eui64_equals(ifaceid, go->ourid)) {
		orc = CONFNAK;
		if (eui64_iszero(go->hisid))	/* first time, try option */
		    ifaceid = wo->hisid;
		if (eui64_equals(ifaceid, go->ourid)) /* bad luck */
		    eui64_zero(ifaceid);
		if (eui64_iszero(ifaceid)) {
		    if (wo->opt_remote)
			ifaceid = wo->hisid;
		    else {
			while (eui64_iszero(ifaceid) ||
			       eui64_equals(ifaceid, go->ourid)) /* bad luck */
			    eui64_magic(ifaceid);
		    }
		}
		go->hisid = ifaceid;
		DECPTR(sizeof(ifaceid), p);
		eui64_put(ifaceid, p);
	    }

	    ho->neg_ifaceid = 1;
	    ho->hisid = ifaceid;
	    break;

	case CI_COMPRESSTYPE:
	    IPV6CPDEBUG(("ipv6cp: received COMPRESSTYPE "));
	    if (!ao->neg_vj ||
		(cilen != CILEN_COMPRESS)) {
		orc = CONFREJ;
		break;
	    }
	    GETSHORT(cishort, p);
	    IPV6CPDEBUG(("(%d)", cishort));

#ifdef IPV6CP_COMP
	    if (!(cishort == IPV6CP_COMP)) {
		orc = CONFREJ;
		break;
	    }

	    ho->neg_vj = 1;
	    ho->vj_protocol = cishort;
	    break;
#else
	    orc = CONFREJ;
	    break;
#endif

	default:
	    orc = CONFREJ;
	    break;
	}

endswitch:
	IPV6CPDEBUG((" (%s)\n", CODENAME(orc)));

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
     * their identifier and they didn't send their identifier, then we
     * send a NAK with a CI_IFACEID option appended.  We assume the
     * input buffer is long enough that we can append the extra
     * option safely.
     */
    if (rc != CONFREJ && !ho->neg_ifaceid &&
	wo->req_ifaceid && !reject_if_disagree) {
	if (rc == CONFACK) {
	    rc = CONFNAK;
	    ucp = inp;				/* reset pointer */
	    wo->req_ifaceid = 0;		/* don't ask again */
	}
	PUTCHAR(CI_IFACEID, ucp);
	PUTCHAR(CILEN_IFACEID, ucp);
	eui64_put(wo->hisid, ucp);
    }

    *len = ucp - inp;			/* Compute output length */
    IPV6CPDEBUG(("ipv6cp: returning Configure-%s", CODENAME(rc)));
    return (rc);			/* Return final code */
}

static void
ipv6cp_finished(fsm *f)
{
    np_finished(f->unit, PPP_IPV6);
}

char *
llv6_ntoa(eui64_t ifaceid)
{
    static char b[64];

    sprintf(b, "fe80::%s", eui64_ntoa(ifaceid));
    return b;
}
