/* Host integration for the original pppd 2.5.5 authentication protocols. */
#ifndef PPP_AUTH_PORT_H
#define PPP_AUTH_PORT_H
#include <stdint.h>
#define PPP_AUTH_PAP 1u
#define PPP_AUTH_CHAP_MD5 2u
#define PPP_AUTH_MSCHAP 4u
#define PPP_AUTH_MSCHAPV2 8u
#define PPP_AUTH_EAP 16u
#define PPP_AUTH_ALL 31u
/* This structure is copied across processes: it must contain no pointers. */
typedef struct PppAuthConfig {
    uint32_t require_mask, refuse_mask;
    uint32_t peer_ip_be; /* Filled by the engine; certificate peer address policy. */
    char user[256], password[256], name[256], remotename[256];
    char pap_secrets[2048], chap_secrets[2048];
    char ca[2048], cert[2048], key[2048], key_password[256];
    char capath[2048], crl_dir[2048], crl_file[2048], pkcs12[2048];
    char max_tls_version[8], tls_verify_method[32], callback[256];
    int tls_verify_key_usage, need_peer_eap;
    int timeout, max_transmits, rechallenge;
    int pap_restart, pap_timeout, pap_max_authreq;
    int chap_restart, chap_timeout, chap_max_challenge, chap_interval;
    int eap_restart, eap_timeout, eap_max_sreq, eap_max_rreq, eap_interval;
    int chapms_strip_domain;
} PppAuthConfig;
int ppp_auth_configure(const PppAuthConfig *config);
void ppp_auth_init(void);
void ppp_auth_start(int unit);
void ppp_auth_lowerdown(int unit);
int ppp_auth_dispatch(unsigned short protocol, const unsigned char *payload, int length);
/* Implemented by the engine. Called only once authentication is complete. */
void ppp_engine_network_start(int unit);
#endif
