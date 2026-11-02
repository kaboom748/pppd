#ifndef PPP_DATA_PORT_H
#define PPP_DATA_PORT_H
#include <stddef.h>
#include <stdint.h>
#include "data_options.h"
void ppp_data_init(const PppDataOptions*,unsigned,unsigned);
void ppp_data_destroy(void);
void ppp_data_set_mru(unsigned);
void ppp_data_ccp_peek(const uint8_t*,size_t,int);
int ppp_data_send(const uint8_t*,size_t,uint8_t*,size_t);
int ppp_data_receive(const uint8_t*,size_t,uint8_t*,size_t);
int ppp_data_vj_config(unsigned,unsigned,int);
void ppp_data_loss(void);
int ppp_data_encrypted_ready(void);
int ppp_data_fault(void);
#endif
