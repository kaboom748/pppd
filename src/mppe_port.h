/* Linux v6.1 MPPE data codec, adapted for native userspace. */
#ifndef PPP_MPPE_PORT_H
#define PPP_MPPE_PORT_H
struct compressor;
/* Same callbacks as Linux: allocation options = six CI bytes + 16 key bytes;
 * initialization options = six CI bytes. Frames are ff 03 protocol-hi protocol-lo
 * information. TX <0 means DROP, never send a plaintext fallback. RX -1 asks
 * CCP reset; RX -2 is fatal. Plaintext rejection is the host's responsibility. */
const struct compressor *ppp_mppe_compressor(void);
#endif
