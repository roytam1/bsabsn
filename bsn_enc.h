/* bsn_enc.h - LZ+Huffman encoders for BSA/BSN method 7 and method 2/3
 * streams. These produce valid streams for the decoders in bsn_lz.c and
 * bsn_m23.c and for the original archivers (bsa32, BSA160/193/195,
 * BSA200, BSA2-230), but they are not bit-identical to the original
 * encoders: method 7 uses sparse frequency-ranked tables rebuilt per
 * block and methods 2/3 use complete fixed-length tables. */
#ifndef BSN_ENC_H
#define BSN_ENC_H

/* Encode in as one method 7 (LZ77 + dynamic canonical Huffman) stream.
 * Returns a malloc'd buffer holding *psize bytes, or NULL on failure. */
unsigned char *bsn_lz_encode(const unsigned char *in, unsigned long insize,
                             unsigned long *psize);

/* Encode in as one BSA method 2, 3, 5 or 6 (LZSS + dynamic canonical
 * Huffman) stream. Method 6 shares method 3's wrapper, so 6 is
 * accepted too and produces identical bytes to method 3. Method 5
 * shares method 2's wrapper plus the length-extension symbol.
 * Returns a malloc'd buffer holding *psize bytes, or NULL on failure. */
unsigned char *bsn_m23_encode(const unsigned char *in, unsigned long insize,
                              unsigned long *psize, int method);

#endif
