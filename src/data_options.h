#ifndef PPP_DATA_OPTIONS_H
#define PPP_DATA_OPTIONS_H
/* Host configuration for existing IPCP/CCP algorithms. Bit widths are the
 * negotiated dictionary/window maxima; zero disables that direction. */
typedef struct PppDataOptions {
 int ccp_enabled;
 int vj_enabled,vj_cid;
 unsigned vj_slots;
 int bsd_receive_bits,bsd_allow_bits;
 int deflate_receive_bits,deflate_allow_bits,deflate_correct,deflate_draft;
 int mppe_required,mppe_allow_40,mppe_allow_128,mppe_stateful;
 unsigned ccp_timeout,ccp_max_configure,ccp_max_terminate,ccp_max_failure;
} PppDataOptions;
#endif
