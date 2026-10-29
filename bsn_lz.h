/* bsn_lz.h - LZ77 + canonical Huffman decoder for BSA/BSN method 7 streams. */
#ifndef BSN_LZ_H
#define BSN_LZ_H

unsigned char *bsn_lz_decode(const unsigned char *packed, unsigned long psize,
                             unsigned long outsize, unsigned long *produced);

#endif
