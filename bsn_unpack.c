/* bsn_unpack.c - container parser/extractor for BSN archives (BSA 2.3) */
/* Build with MSVC6: cl bsn_unpack.c */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "bsn_lz.h"
#include "bsn_ppm.h"

static unsigned int crc_table[256];
static int crc_table_ready = 0;

static void make_crc_table(void) {
    unsigned int c;
    int n, k;
    for (n = 0; n < 256; n++) {
        c = (unsigned int)n;
        for (k = 0; k < 8; k++) {
            if (c & 1) c = 0xEDB88320U ^ (c >> 1);
            else c = c >> 1;
        }
        crc_table[n] = c;
    }
    crc_table_ready = 1;
}

static unsigned int crc32_buf(const unsigned char *buf, size_t len) {
    unsigned int crc = 0xFFFFFFFFU;
    size_t i;
    if (!crc_table_ready) make_crc_table();
    for (i = 0; i < len; i++)
        crc = crc_table[(crc ^ buf[i]) & 0xFF] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFFU;
}

static unsigned int rd_be16(const unsigned char *p) {
    return ((unsigned int)p[0] << 8) | p[1];
}
static unsigned int rd_be32(const unsigned char *p) {
    return ((unsigned int)p[0] << 24) | ((unsigned int)p[1] << 16) |
           ((unsigned int)p[2] << 8) | p[3];
}

static void sanitize(char *s) {
    char *p;
    for (p = s; *p; p++) {
        if (*p == '/' || *p == '\\') *p = '_';
    }
}

static void make_parent_dirs(const char *path) {
    char tmp[1024];
    char *p;
    strncpy(tmp, path, sizeof(tmp)-1);
    tmp[sizeof(tmp)-1] = 0;
    for (p = tmp + 1; *p; p++) {
        if (*p == '\\' || *p == '/') {
            char saved = *p;
            *p = 0;
            _mkdir(tmp);
            *p = saved;
        }
    }
}

int main(int argc, char **argv) {
    FILE *f;
    const char *outbase;
    unsigned char ghdr[6];
    unsigned int gflags;
    char gcomment[4096];

    if (argc < 2) {
        fprintf(stderr, "Usage: %s archive.bsn [outdir]\n", argv[0]);
        return 1;
    }
    outbase = (argc >= 3) ? argv[2] : "bsn_out";
    _mkdir(outbase);

    f = fopen(argv[1], "rb");
    if (!f) { perror("fopen"); return 1; }

    /* Global header */
    if (fread(ghdr, 1, 6, f) != 6) { fprintf(stderr, "short global header\n"); return 1; }
    if (ghdr[0] != 0xFF || ghdr[1] != 'B' || ghdr[2] != 'S' || ghdr[3] != 'G') {
        fprintf(stderr, "bad global magic\n"); return 1;
    }
    gflags = rd_be16(ghdr + 4);
    printf("Global flags: 0x%04X\n", gflags);
    if (gflags & 0x0100) {
        /* NUL-terminated comment */
        size_t ci = 0;
        int c;
        while ((c = fgetc(f)) != EOF && c != 0 && ci < sizeof(gcomment)-1)
            gcomment[ci++] = (char)c;
        gcomment[ci] = 0;
        if (c == 0) { /* consumed */ }
        printf("Archive comment: %s\n", gcomment);
    }

    /* Entries */
    for (;;) {
        unsigned char magic[4];
        unsigned int L;
        unsigned char *blk;
        size_t nread;
        unsigned int csum_stored;
        unsigned int csum_calc;
        unsigned int eflags, ts, orig_size, packed_size, filecrc, extra_size = 0;
        unsigned int comment_len = 0;
        const unsigned char *p;
        const unsigned char *end;
        char filename[512];
        char outpath[1024];
        FILE *out;
        size_t data_to_read;

        if (fread(magic, 1, 4, f) != 4) {
            /* EOF expected */
            break;
        }
        if (magic[0] != 0xFF || magic[1] != 'B' || magic[2] != 'S' || magic[3] != 'A') {
            /* trailing non-entry data (e.g. archive epilogue): stop cleanly */
            {
                long cur = ftell(f);
                if (cur >= 4)
                    fprintf(stderr, "note: ignoring trailing data at file offset %ld\n", cur - 4);
            }
            break;
        }
        if (fread(&L, 1, 2, f) != 2) { fprintf(stderr, "short L\n"); return 1; }
        /* L is big-endian */
        L = rd_be16((unsigned char*)&L);
        if (L == 0 || L > 65535) { fprintf(stderr, "bad L\n"); return 1; }

        blk = (unsigned char*)malloc(L);
        if (!blk) { fprintf(stderr, "oom\n"); return 1; }
        nread = fread(blk, 1, L, f);
        if (nread != L) { fprintf(stderr, "short entry block\n"); free(blk); return 1; }

        /* checksum */
        {
            unsigned char cb[4];
            if (fread(cb, 1, 4, f) != 4) { fprintf(stderr, "short checksum\n"); free(blk); return 1; }
            csum_stored = rd_be32(cb);
        }
        csum_calc = crc32_buf(blk, L);
        if (csum_stored != csum_calc && csum_stored != ~csum_calc) {
            fprintf(stderr, "checksum mismatch (stored %08X calc %08X)\n", csum_stored, csum_calc);
            free(blk); return 1;
        }

        /* parse L-block */
        p = blk;
        end = blk + L;
        eflags = rd_be16(p); p += 2;
        /* bytes 2..3: method/format byte (0 = default); not validated */
        p += 2;
        ts = rd_be32(p); p += 4;
        /* filename */
        {
            size_t fi = 0;
            while (p < end && *p != 0 && fi < sizeof(filename)-1)
                filename[fi++] = (char)*p++;
            filename[fi] = 0;
            if (p < end && *p == 0) p++; /* skip NUL */
        }
        sanitize(filename);

        if (eflags & 0x0008) {
            if (p + 4 > end) { fprintf(stderr, "short extra\n"); free(blk); return 1; }
            extra_size = rd_be32(p); p += 4;
        }
        if (p + 4 > end) { fprintf(stderr, "short orig size\n"); free(blk); return 1; }
        orig_size = rd_be32(p); p += 4;
        if (p + 4 > end) { fprintf(stderr, "short packed size\n"); free(blk); return 1; }
        packed_size = rd_be32(p); p += 4;
        if (p + 4 > end) { fprintf(stderr, "short crc\n"); free(blk); return 1; }
        filecrc = rd_be32(p); p += 4;

        if (eflags & 0x0020) {
            if (p + 2 > end) { fprintf(stderr, "short comment len\n"); free(blk); return 1; }
            comment_len = rd_be16(p); p += 2;
            if (p + comment_len > end) { fprintf(stderr, "short comment\n"); free(blk); return 1; }
            p += comment_len;
        }

        printf("Extracting: %s  orig=%u packed=%u ts=%08X crc=%08X flags=%04X\n",
               filename, orig_size, packed_size, ts, filecrc, eflags);

        /* read packed data into memory */
        sprintf(outpath, "%s\\%s", outbase, filename);
        make_parent_dirs(outpath);

        if (packed_size == 0 && orig_size == 0) {
            /* empty stored entry */
            out = fopen(outpath, "wb");
            if (!out) { perror("fopen out"); free(blk); return 1; }
            fclose(out);
        } else if (packed_size == orig_size) {
            /* stored (uncompressed): copy through */
            out = fopen(outpath, "wb");
            if (!out) { perror("fopen out"); free(blk); return 1; }
            data_to_read = packed_size;
            {
                char buf[65536];
                size_t remaining = data_to_read;
                while (remaining > 0) {
                    size_t chunk = remaining > sizeof(buf) ? sizeof(buf) : remaining;
                    size_t r = fread(buf, 1, chunk, f);
                    if (r != chunk) { fprintf(stderr, "short data read\n"); fclose(out); free(blk); return 1; }
                    fwrite(buf, 1, r, out);
                    remaining -= r;
                }
            }
            fclose(out);
        } else {
            /* compressed: method 7 (LZ+Huffman) or method 9 (PPM) */
            unsigned char *pbuf;
            unsigned char *obuf = 0;
            unsigned long produced = 0;
            size_t r;
            unsigned int dcrc;
            pbuf = (unsigned char *)malloc(packed_size ? packed_size : 1);
            if (!pbuf) { fprintf(stderr, "oom\n"); free(blk); return 1; }
            r = fread(pbuf, 1, packed_size, f);
            if (r != packed_size) { fprintf(stderr, "short data read\n"); free(pbuf); free(blk); return 1; }
            if (eflags & 0x8000) {
                fprintf(stderr, "unsupported compression method (flags %04X) for %s\n", eflags, filename);
                free(pbuf); free(blk); return 1;
            } else if (eflags & 0x4000) {
                /* method 9 (PPM): range decoder over-reads into trailing
                 * archive bytes (like the original), so pass the file tail */
                unsigned char *tbuf = 0;
                unsigned long tsize = 0;
                long cur = ftell(f);
                printf("  method 9 (PPM) decompressing...\n");
                if (cur >= 0) {
                    long endpos;
                    fseek(f, 0, SEEK_END);
                    endpos = ftell(f);
                    fseek(f, cur, SEEK_SET);
                    if (endpos > cur) {
                        tsize = (unsigned long)(endpos - cur);
                        if (tsize > 65536) tsize = 65536;
                        tbuf = (unsigned char *)malloc(tsize ? tsize : 1);
                        if (tbuf) {
                            size_t tr = fread(tbuf, 1, tsize, f);
                            tsize = (unsigned long)tr;
                            fseek(f, cur, SEEK_SET);
                        } else {
                            tsize = 0;
                        }
                    }
                }
                obuf = bsn_ppm_decode(pbuf, packed_size, tbuf, tsize, orig_size, &produced, eflags & 1);
                if (tbuf) free(tbuf);
                /* reposition after packed data for next entry */
                fseek(f, cur, SEEK_SET);
            } else {
                obuf = bsn_lz_decode(pbuf, packed_size, orig_size, &produced);
            }
            free(pbuf);
            if (!obuf) { fprintf(stderr, "decode failed for %s\n", filename); free(blk); return 1; }
            if (produced != orig_size) {
                fprintf(stderr, "size mismatch for %s (got %lu want %u)\n", filename, produced, orig_size);
                free(obuf); free(blk); return 1;
            }
            dcrc = crc32_buf(obuf, produced);
            if (dcrc != filecrc) {
                fprintf(stderr, "data crc mismatch for %s (got %08X want %08X)\n", filename, dcrc, filecrc);
                free(obuf); free(blk); return 1;
            }
            out = fopen(outpath, "wb");
            if (!out) { perror("fopen out"); free(obuf); free(blk); return 1; }
            if (produced) fwrite(obuf, 1, produced, out);
            fclose(out);
            free(obuf);
            printf("  decoded %lu bytes, crc OK\n", produced);
        }
        free(blk);
    }

    fclose(f);
    printf("Done.\n");
    return 0;
}
