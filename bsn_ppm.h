/* bsn_ppm.h - PPM range decoder for BSA/BSN "method 9" streams. */
#ifndef BSN_PPM_H
#define BSN_PPM_H

unsigned char *bsn_ppm_decode(const unsigned char *packed, unsigned long psize,
                              const unsigned char *trail, unsigned long tsize,
                              unsigned long outsize, unsigned long *produced,
                              int textmode);

#endif
