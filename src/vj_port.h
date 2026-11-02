#ifndef PPP_VJ_PORT_H
#define PPP_VJ_PORT_H
#include <stddef.h>
#include <stdint.h>
typedef struct PppVj PppVj;
/* Slot counts: 0 disables the direction, otherwise 1..255. Caller normally
 * passes the negotiated IPCP maxslotindex+1 in each direction. */
PppVj *ppp_vj_create(unsigned receive_slots,unsigned transmit_slots,int compress_cid);
void ppp_vj_destroy(PppVj *vj);
/* Input/output are PPP information fields, excluding ff03/protocol. Encoding
 * returns PPP_IP(0x21), PPP_VJC_COMP(0x2d), or PPP_VJC_UNCOMP(0x2f).
 * Returns output length, or -1 for invalid state/input/output capacity. */
int ppp_vj_encode(PppVj *,const uint8_t *input,size_t length,uint8_t *output,size_t capacity,uint16_t *protocol);
int ppp_vj_decode(PppVj *,uint16_t protocol,const uint8_t *input,size_t length,uint8_t *output,size_t capacity);
/* Call after discarded/damaged serial frames, as Linux does for line errors. */
void ppp_vj_toss(PppVj *);
#endif
