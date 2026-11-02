#ifndef PPP_CCP_HOST_H
#define PPP_CCP_HOST_H
extern bool require_mppe,refuse_mppe_stateful;
extern int auth_done[];
int ccp_test(int,unsigned char*,int,int);
void ccp_flags_set(int,int,int);
int ccp_fatal_error(int);
int ppp_get_mtu(int);
void continue_networks(int);
#endif
