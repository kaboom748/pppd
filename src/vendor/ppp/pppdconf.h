/* Native Windows host for pppd 2.5.5 userspace protocols. */
#ifndef PPPD_WINDOWS_CONF_H
#define PPPD_WINDOWS_CONF_H
#define PPP_WITH_AUTH 1
#define PPP_WITH_CHAPMS 1
#define PPP_WITH_MPPE_KEYS 1
#define PPP_WITH_MPPE 1
#define PPP_WITH_CBCP 1
/* PPP_WITH_EAPTLS / PPP_WITH_PEAP require the static TLS build. */
#endif
