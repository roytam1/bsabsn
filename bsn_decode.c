/* bsn_decode.c - CLI wrapper around bsn_lz.c / bsn_m23.c / bsn_ppm.c.
 *
 * Usage:
 *   bsn_decode packed_file unpacked_size output_file [expected_file]
 *   bsn_decode -9 packed_file packed_size unpacked_size output_file [expected_file]
 *   bsn_decode -2 packed_file packed_size unpacked_size output_file [expected_file]
 *   bsn_decode -3 packed_file packed_size unpacked_size output_file [expected_file]
 *     (for -9/-2/-3 the file may hold trailing bytes after the packed
 *     stream, e.g. archive terminator, mirroring what the original
 *     decoder sees)
 *
 * Build with MSVC6:  cl bsn_decode.c bsn_lz.c bsn_m23.c bsn_ppm.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "bsn_lz.h"
#include "bsn_m23.h"
#include "bsn_ppm.h"

int main(int argc, char **argv) {
    FILE *f;
    unsigned char *packed, *out;
    unsigned long produced = 0;
    int method = 7, ai = 1;
    unsigned long psize_file, psize_log, outsize;

    if (argc >= 2 && strcmp(argv[1], "-9") == 0) { method = 9; ai = 2; }
    if (argc >= 2 && strcmp(argv[1], "-2") == 0) { method = 2; ai = 2; }
    if (argc >= 2 && strcmp(argv[1], "-3") == 0) { method = 3; ai = 2; }
    if (method != 7) {
        if (argc - ai < 4) {
            fprintf(stderr, "Usage: %s -%d packed_file packed_size unpacked_size output_file [expected_file]\n", argv[0], method);
            return 1;
        }
    } else {
        if (argc - ai < 3) {
            fprintf(stderr, "Usage: %s packed_file unpacked_size output_file [expected_file]\n", argv[0]);
            return 1;
        }
    }
    if (method != 7) {
        psize_log = strtoul(argv[ai + 1], 0, 0);
        outsize = strtoul(argv[ai + 2], 0, 0);
    } else {
        outsize = strtoul(argv[ai + 1], 0, 0);
    }

    f = fopen(argv[ai], "rb");
    if (!f) { perror("fopen"); return 1; }
    fseek(f, 0, SEEK_END);
    psize_file = (unsigned long)ftell(f);
    fseek(f, 0, SEEK_SET);
    packed = (unsigned char *)malloc(psize_file ? psize_file : 1);
    if (!packed) { fprintf(stderr, "oom\n"); fclose(f); return 1; }
    if (psize_file && fread(packed, 1, psize_file, f) != psize_file) { fprintf(stderr, "short read\n"); fclose(f); return 1; }
    fclose(f);

    if (method == 9) {
        /* trailing bytes after the packed stream act as range-coder
         * padding, exactly as the original sees them in the archive */
        unsigned long tsize = (psize_file > psize_log) ? (psize_file - psize_log) : 0;
        out = bsn_ppm_decode(packed, psize_log, packed + psize_log, tsize, outsize, &produced, 0);
    }
    else if (method == 2 || method == 3) {
        /* trailing bytes likewise feed the bit reader on over-read */
        unsigned long tsize = (psize_file > psize_log) ? (psize_file - psize_log) : 0;
        out = bsn_m23_decode(packed, psize_log, packed + psize_log, tsize, outsize, &produced, method);
    }
    else
        out = bsn_lz_decode(packed, psize_file, outsize, &produced);
    free(packed);
    if (!out) { fprintf(stderr, "decode failed\n"); return 1; }

    f = fopen(argv[ai + (method != 7 ? 3 : 2)], "wb");
    if (!f) { perror("fopen out"); free(out); return 1; }
    if (produced) fwrite(out, 1, produced, f);
    fclose(f);

    printf("decoded %lu of %lu bytes\n", produced, outsize);

    if (argc - ai >= (method != 7 ? 5 : 4)) {
        FILE *g = fopen(argv[ai + (method != 7 ? 4 : 3)], "rb");
        unsigned char *ref;
        unsigned long rsize;
        if (g) {
            fseek(g, 0, SEEK_END); rsize = (unsigned long)ftell(g); fseek(g, 0, SEEK_SET);
            ref = (unsigned char *)malloc(rsize ? rsize : 1);
            if (ref && (!rsize || fread(ref, 1, rsize, g) == rsize)) {
                if (rsize == produced && memcmp(ref, out, produced) == 0)
                    printf("MATCH (%lu bytes)\n", produced);
                else {
                    unsigned long i;
                    for (i = 0; i < rsize && i < produced; i++)
                        if (ref[i] != out[i]) break;
                    printf("MISMATCH at %lu\n", i);
                }
            }
            if (ref) free(ref);
            fclose(g);
        }
    }

    free(out);
    return 0;
}
