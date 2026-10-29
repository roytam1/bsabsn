#ifndef BSN_M23_H
#define BSN_M23_H

/* BSA "method 2/3" decoder (BSA200 lineage: LZSS + dynamic Huffman,
 * LHA-style block tables, MSB-first bitstream, 64 KiB ring).
 *
 * packed = packed stream bytes, psize = its length; trail/tsize =
 * following archive bytes fed to the bit reader on over-read, exactly
 * like the original (which reads past the packed end into whatever
 * file bytes follow). outsize = expected unpacked size.
 *
 * Returns malloc'd output (produced bytes, check == outsize) or NULL
 * on failure. method is 2 or 3.
 */
unsigned char *bsn_m23_decode(const unsigned char *packed, unsigned long psize,
                              const unsigned char *trail, unsigned long tsize,
                              unsigned long outsize, unsigned long *produced,
                              int method);

#endif
