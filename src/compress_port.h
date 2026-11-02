#ifndef PPP_COMPRESSION_PORT_H
#define PPP_COMPRESSION_PORT_H
#include <stddef.h>
#include <stdint.h>
typedef struct PppCompression PppCompression;
/* Frames contain ff 03 followed by the two-byte PPP protocol and information.
 * receive selects decompressor (1) versus compressor (0). */
PppCompression *ppp_comp_create(int method,const uint8_t *option,size_t option_len,int receive,unsigned mru);
void ppp_comp_destroy(PppCompression *state);
void ppp_comp_reset(PppCompression *state);
/* Return encoded length, 0 if incompressible, or -1 for invalid input.
 * A 0 return still advances compression history: transmit the original frame. */
int ppp_comp_compress(PppCompression *state,const uint8_t *frame,size_t length,uint8_t *out,size_t capacity);
/* Return decoded length, -1 (resettable error), -2 (fatal corrupt stream). */
int ppp_comp_decompress(PppCompression *state,const uint8_t *frame,size_t length,uint8_t *out,size_t capacity);
/* Feed every uncompressed eligible received frame into receive history. */
void ppp_comp_incomp(PppCompression *state,const uint8_t *frame,size_t length);
int ppp_comp_method(const PppCompression *state);
#endif
