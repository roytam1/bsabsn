/* bsn_unpack.c - container parser/extractor for BSN and BSA archives (BSA 2.x)
 *
 * BSN: global magic FF 42 53 47, entry magic FF 42 53 41, big-endian
 *      fields, per-entry CRC32. Compression from entry flags: 0x4000 ->
 *      method 9 (PPM), 0x8000 -> method 10 (unsupported), else method 7
 *      (LZ77 + dynamic canonical Huffman).
 * BSA: no global header; entries are u16 header-len (0 = terminator),
 *      0xAE, method byte (0 = stored, 7 = method 7), u32le packed size,
 *      u32le orig size, u32le timestamp, 3 x u16, namelen, name, NUL,
 *      then packed data. No per-entry CRC; success = produced == orig.
 *      (The BSA writer stores 7 for every compressed method, so a PPM
 *      stream in a BSA file is tried as method 9 when method 7 fails;
 *      the originals cannot extract such files at all.)
 *
 * Commands: bsn_unpack archive[.bsn|.bsa] [outdir]  (extract, default)
 *           bsn_unpack t archive[.bsn|.bsa]          (test integrity:
 *              decode every entry and verify size/CRC, no files written)
 *           bsn_unpack l archive[.bsn|.bsa]          (list contents:
 *              names, sizes, dates and methods, no decoding)
 *
 * Build with MSVC6: cl bsn_unpack.c
 */
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

/* Incremental CRC32: crc starts at 0xFFFFFFFFU, xor the result at the end. */
static unsigned int crc32_update(unsigned int crc, const unsigned char *buf, size_t len) {
    size_t i;
    if (!crc_table_ready) make_crc_table();
    for (i = 0; i < len; i++)
        crc = crc_table[(crc ^ buf[i]) & 0xFF] ^ (crc >> 8);
    return crc;
}

/* DOS date/time (date = high word, time = low word) to readable text. */
static const char * const mon_names[12] = {
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};

static void fmt_dos_dt(unsigned long ts, char *out) {
    unsigned int date = (unsigned int)(ts >> 16);
    unsigned int time = (unsigned int)(ts & 0xFFFF);
    int day = date & 31, mon = (date >> 5) & 15, yr = (date >> 9) + 1980;
    int hh = time >> 11, mm = (time >> 5) & 63;
    if (day < 1 || day > 31 || mon < 1 || mon > 12 || hh > 23 || mm > 59)
        sprintf(out, "??-???-???? ??:??");
    else
        sprintf(out, "%02d-%s-%04d %02d:%02d",
                day, mon_names[mon - 1], yr, hh, mm);
}

static unsigned int rd_be16(const unsigned char *p) {
    return ((unsigned int)p[0] << 8) | p[1];
}
static unsigned int rd_be32(const unsigned char *p) {
    return ((unsigned int)p[0] << 24) | ((unsigned int)p[1] << 16) |
           ((unsigned int)p[2] << 8) | p[3];
}

/* little-endian readers straight from the archive file (BSA headers) */
static int rd_le16(FILE *f, unsigned int *v) {
    int a = fgetc(f), b = fgetc(f);
    if (a == EOF || b == EOF) return -1;
    *v = (unsigned int)a | ((unsigned int)b << 8);
    return 0;
}
static int rd_le32(FILE *f, unsigned long *v) {
    int a = fgetc(f), b = fgetc(f), c = fgetc(f), d = fgetc(f);
    if (a == EOF || b == EOF || c == EOF || d == EOF) return -1;
    *v = (unsigned long)a | ((unsigned long)b << 8) |
         ((unsigned long)c << 16) | ((unsigned long)d << 24);
    return 0;
}

/* Capture up to 64K of the file tail at the current position (for the PPM
 * range decoder, which over-reads past the packed end exactly like the
 * original does). File position is preserved. */
static int read_file_tail(FILE *f, unsigned char **tbuf, unsigned long *tsize) {
    long cur = ftell(f);
    long endpos;
    unsigned long n;
    unsigned char *b;
    size_t r;
    *tbuf = 0;
    *tsize = 0;
    if (cur < 0) return -1;
    fseek(f, 0, SEEK_END);
    endpos = ftell(f);
    fseek(f, cur, SEEK_SET);
    if (endpos <= cur) return 0;
    n = (unsigned long)(endpos - cur);
    if (n > 65536) n = 65536;
    b = (unsigned char *)malloc(n ? n : 1);
    if (!b) return -1;
    r = fread(b, 1, n, f);
    fseek(f, cur, SEEK_SET);
    *tbuf = b;
    *tsize = (unsigned long)r;
    return 0;
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

/* Decode BSA method 7 (LZ) with a method 9 (PPM) fallback: the BSA
 * writer stores 7 for every compressed flavor, so a PPM stream arrives
 * marked 7. LZ-first matches the original dispatch; PPM is attempted
 * only when LZ fails or the size does not match. Returns 1 with *used_ppm
 * set on a PPM success. */
static int decode_bsa_data(FILE *f, const unsigned char *pbuf,
                           unsigned long packed_size, unsigned long orig_size,
                           unsigned char **obuf, unsigned long *produced,
                           int *used_ppm) {
    unsigned char *tbuf = 0;
    unsigned long tsize = 0;
    long cur = ftell(f);
    *obuf = 0;
    *produced = 0;
    *used_ppm = 0;
    *obuf = bsn_lz_decode(pbuf, packed_size, orig_size, produced);
    if (*obuf && *produced == orig_size) return 1;
    if (*obuf) { free(*obuf); *obuf = 0; }
    if (cur < 0) return 0;
    if (read_file_tail(f, &tbuf, &tsize) != 0) return 0;
    printf("  method 7 failed, trying method 9 (PPM)...\n");
    *obuf = bsn_ppm_decode(pbuf, packed_size, tbuf, tsize, orig_size, produced, 0);
    if (tbuf) free(tbuf);
    fseek(f, cur, SEEK_SET);
    if (*obuf && *produced == orig_size) { *used_ppm = 1; return 1; }
    if (*obuf) { free(*obuf); *obuf = 0; }
    return 0;
}

static int unpack_bsa(FILE *f, const char *archive, const char *outbase, int cmd) {
    int nfiles = 0, nfailed = 0;
    unsigned long tot_orig = 0, tot_packed = 0;
    if (cmd == 2)
        printf("Listing of archive %s\n    SIZE PACKED DATE        TIME  METHOD  NAME\n-------- -------- ----------------- ------- --------------------\n",
               archive);
    for (;;) {
        int b0, b1, ae, flag, nl, c, i, used_ppm;
        unsigned long packed_size, orig_size, ts;
        unsigned int w1, w2, w3;
        long hstart, hlen_got;
        char filename[512];
        char outpath[1024];
        char dtbuf[24];
        char method[8];
        FILE *out;
        unsigned char *pbuf;
        unsigned char *obuf;
        unsigned long produced;
        size_t r;

        hstart = ftell(f);
        b0 = fgetc(f);
        if (b0 == EOF) break;           /* normal end */
        b1 = fgetc(f);
        if (b1 == EOF) { fprintf(stderr, "truncated BSA entry\n"); fclose(f); return 1; }
        if (b0 == 0 && b1 == 0) break;  /* archive terminator */
        ae = fgetc(f);
        if (ae != 0xAE) {
            fprintf(stderr, "bad BSA entry magic at offset %ld\n", hstart);
            fclose(f); return 1;
        }
        flag = fgetc(f);
        if (flag == EOF) { fprintf(stderr, "truncated BSA entry\n"); fclose(f); return 1; }
        if (rd_le32(f, &packed_size) != 0 || rd_le32(f, &orig_size) != 0 ||
            rd_le32(f, &ts) != 0) {
            fprintf(stderr, "truncated BSA sizes\n"); fclose(f); return 1;
        }
        if (rd_le16(f, &w1) != 0 || rd_le16(f, &w2) != 0 || rd_le16(f, &w3) != 0) {
            fprintf(stderr, "truncated BSA header\n"); fclose(f); return 1;
        }
        nl = fgetc(f);
        if (nl == EOF) { fprintf(stderr, "truncated BSA name\n"); fclose(f); return 1; }
        for (i = 0; i < nl; i++) {
            c = fgetc(f);
            if (c == EOF) { fprintf(stderr, "truncated BSA name\n"); fclose(f); return 1; }
            filename[i] = (char)c;
        }
        filename[nl] = 0;
        c = fgetc(f);                   /* NUL terminator */
        if (c == EOF) { fprintf(stderr, "truncated BSA entry\n"); fclose(f); return 1; }
        sanitize(filename);

        hlen_got = ftell(f) - hstart - 2;
        if (hlen_got != b0)
            fprintf(stderr, "warning: BSA header length mismatch for %s (got %ld want %d)\n",
                    filename, hlen_got, b0);

        nfiles++;
        fmt_dos_dt(ts, dtbuf);
        if (flag == 0 || packed_size == orig_size) strcpy(method, "stored");
        else if (flag == 7) strcpy(method, "m7");
        else sprintf(method, "%02X?", flag);
        if (cmd == 2) {
            /* list only: print the row and skip the packed data */
            printf("%8lu %8lu %s %-7s %s\n",
                   orig_size, packed_size, dtbuf, method, filename);
            tot_orig += orig_size; tot_packed += packed_size;
            if (fseek(f, (long)packed_size, SEEK_CUR) != 0) {
                fprintf(stderr, "short data in %s\n", filename);
                fclose(f); return 1;
            }
            continue;
        }
        if (cmd == 1)
            printf("Testing    %s ... ", filename);
        else {
            printf("Extracting: %s  orig=%lu packed=%lu ts=%08lX attr=%04X flags=%02X\n",
                   filename, orig_size, packed_size, ts, w1, flag);
            sprintf(outpath, "%s\\%s", outbase, filename);
            make_parent_dirs(outpath);
        }

        if (packed_size == 0 && orig_size == 0) {
            if (cmd == 1) printf("OK (empty)\n");
            else {
                out = fopen(outpath, "wb");
                if (!out) { perror("fopen out"); fclose(f); return 1; }
                fclose(out);
            }
            continue;
        }

        pbuf = (unsigned char *)malloc(packed_size ? packed_size : 1);
        if (!pbuf) { fprintf(stderr, "oom\n"); fclose(f); return 1; }
        r = fread(pbuf, 1, packed_size, f);
        if (r != packed_size) {
            fprintf(stderr, "short data read for %s\n", filename);
            free(pbuf); fclose(f); return 1;
        }

        if (flag == 0 || packed_size == orig_size) {
            /* stored (uncompressed): copy through */
            if (cmd == 1) printf("OK\n");
            else {
                out = fopen(outpath, "wb");
                if (!out) { perror("fopen out"); free(pbuf); fclose(f); return 1; }
                if (packed_size) fwrite(pbuf, 1, packed_size, out);
                fclose(out);
                printf("  stored %lu bytes\n", packed_size);
            }
        } else if (flag == 7) {
            obuf = 0;
            produced = 0;
            used_ppm = 0;
            if (!decode_bsa_data(f, pbuf, packed_size, orig_size, &obuf, &produced, &used_ppm)) {
                if (cmd == 1) { printf("FAILED (decode error)\n"); nfailed++; free(pbuf); continue; }
                fprintf(stderr, "decode failed for %s\n", filename);
                free(pbuf); fclose(f); return 1;
            }
            if (cmd == 1) printf("OK%s\n", used_ppm ? " (PPM)" : "");
            else {
                out = fopen(outpath, "wb");
                if (!out) { perror("fopen out"); free(obuf); free(pbuf); fclose(f); return 1; }
                if (produced) fwrite(obuf, 1, produced, out);
                fclose(out);
                printf("  decoded %lu bytes%s\n", produced, used_ppm ? " (PPM)" : "");
            }
            free(obuf);
        } else {
            fprintf(stderr, "unsupported BSA method %02X for %s\n", flag, filename);
            free(pbuf); fclose(f); return 1;
        }
        free(pbuf);
        (void)w2;
        (void)w3;
    }

    if (cmd == 2) {
        fclose(f);
        printf("-------- -------- ----------------- ------- --------------------\n");
        printf("%8lu %8lu                     total %d file(s)\n", tot_orig, tot_packed, nfiles);
        return 0;
    }
    if (cmd == 1) {
        fclose(f);
        printf("Tested %d file(s), %d failed.\n", nfiles, nfailed);
        return nfailed ? 1 : 0;
    }
    fclose(f);
    printf("Done.\n");
    return 0;
}

static int unpack_bsn(FILE *f, const char *archive, const char *outbase, int cmd) {
    unsigned char ghdr[6];
    unsigned int gflags;
    char gcomment[4096];
    int nfiles = 0, nfailed = 0;
    unsigned long tot_orig = 0, tot_packed = 0;

    /* Global header */
    if (fread(ghdr, 1, 6, f) != 6) { fprintf(stderr, "short global header\n"); return 1; }
    if (ghdr[0] != 0xFF || ghdr[1] != 'B' || ghdr[2] != 'S' || ghdr[3] != 'G') {
        fprintf(stderr, "bad global magic\n"); return 1;
    }
    gflags = rd_be16(ghdr + 4);
    if (cmd == 2)
        printf("Listing of archive %s\n", archive);
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
    if (cmd == 2)
        printf("    SIZE PACKED DATE        TIME  METHOD  NAME\n-------- -------- ----------------- ------- --------------------\n");
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
        char dtbuf[24];
        char method[8];
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

        nfiles++;
        fmt_dos_dt(ts, dtbuf);
        if (packed_size == orig_size) strcpy(method, "stored");
        else if (eflags & 0x8000) strcpy(method, "m10?");
        else if (eflags & 0x4000) strcpy(method, "m9");
        else strcpy(method, "m7");
        if (cmd == 2) {
            /* list only: print the row and skip the packed data */
            printf("%8u %8u %s %-7s %s\n",
                   orig_size, packed_size, dtbuf, method, filename);
            tot_orig += orig_size; tot_packed += packed_size;
            if (fseek(f, (long)packed_size, SEEK_CUR) != 0) {
                fprintf(stderr, "short data in %s\n", filename);
                free(blk); fclose(f); return 1;
            }
            free(blk);
            continue;
        }
        if (cmd == 1)
            printf("Testing    %s ... ", filename);
        else {
            printf("Extracting: %s  orig=%u packed=%u ts=%08X crc=%08X flags=%04X\n",
                   filename, orig_size, packed_size, ts, filecrc, eflags);
            /* read packed data into memory */
            sprintf(outpath, "%s\\%s", outbase, filename);
            make_parent_dirs(outpath);
        }

        if (packed_size == 0 && orig_size == 0) {
            /* empty stored entry */
            if (cmd == 1) printf("OK (empty)\n");
            else {
                out = fopen(outpath, "wb");
                if (!out) { perror("fopen out"); free(blk); return 1; }
                fclose(out);
            }
        } else if (packed_size == orig_size) {
            if (cmd == 1) {
                /* test only: stream through and verify the data CRC */
                unsigned int scrc = 0xFFFFFFFFU;
                size_t trem = packed_size;
                char buf[65536];
                int shortrd = 0;
                while (trem > 0) {
                    size_t chunk = trem > sizeof(buf) ? sizeof(buf) : trem;
                    size_t r2 = fread(buf, 1, chunk, f);
                    if (r2 != chunk) { shortrd = 1; break; }
                    scrc = crc32_update(scrc, (unsigned char *)buf, r2);
                    trem -= r2;
                }
                if (shortrd) { fprintf(stderr, "short data read for %s\n", filename); free(blk); fclose(f); return 1; }
                scrc ^= 0xFFFFFFFFU;
                if (scrc != filecrc) {
                    printf("FAILED (crc %08X want %08X)\n", scrc, filecrc);
                    nfailed++;
                } else printf("OK\n");
            } else {
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
            }
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
            if (!obuf) {
                if (cmd == 1) { printf("FAILED (decode error)\n"); nfailed++; free(blk); continue; }
                fprintf(stderr, "decode failed for %s\n", filename); free(blk); return 1;
            }
            if (produced != orig_size) {
                if (cmd == 1) { printf("FAILED (size %lu want %u)\n", produced, orig_size); nfailed++; free(obuf); free(blk); continue; }
                fprintf(stderr, "size mismatch for %s (got %lu want %u)\n", filename, produced, orig_size);
                free(obuf); free(blk); return 1;
            }
            dcrc = crc32_buf(obuf, produced);
            if (dcrc != filecrc) {
                if (cmd == 1) { printf("FAILED (crc %08X want %08X)\n", dcrc, filecrc); nfailed++; free(obuf); free(blk); continue; }
                fprintf(stderr, "data crc mismatch for %s (got %08X want %08X)\n", filename, dcrc, filecrc);
                free(obuf); free(blk); return 1;
            }
            if (cmd == 1) printf("OK\n");
            else {
                out = fopen(outpath, "wb");
                if (!out) { perror("fopen out"); free(obuf); free(blk); return 1; }
                if (produced) fwrite(obuf, 1, produced, out);
                fclose(out);
                printf("  decoded %lu bytes, crc OK\n", produced);
            }
            free(obuf);
        }
        free(blk);
    }

    if (cmd == 2) {
        fclose(f);
        printf("-------- -------- ----------------- ------- --------------------\n");
        printf("%8lu %8lu                     total %d file(s)\n", tot_orig, tot_packed, nfiles);
        return 0;
    }
    if (cmd == 1) {
        fclose(f);
        printf("Tested %d file(s), %d failed.\n", nfiles, nfailed);
        return nfailed ? 1 : 0;
    }
    fclose(f);
    printf("Done.\n");
    return 0;
}

int main(int argc, char **argv) {
    FILE *f;
    const char *outbase;
    const char *archive;
    unsigned char probe[4];
    int cmd = 0, ai = 1;

    if (argc >= 2 && (strcmp(argv[1], "t") == 0 || strcmp(argv[1], "l") == 0)) {
        cmd = (argv[1][0] == 't') ? 1 : 2;
        ai = 2;
    }
    if (argc - ai < 1) {
        fprintf(stderr, "Usage: %s [t|l] archive[.bsn|.bsa] [outdir]\n", argv[0]);
        fprintf(stderr, "  (no command: extract; t: test integrity; l: list contents)\n");
        return 1;
    }
    archive = argv[ai];
    outbase = (argc - ai >= 2) ? argv[ai + 1] : "bsn_out";
    if (cmd == 0) _mkdir(outbase);

    f = fopen(archive, "rb");
    if (!f) { perror("fopen"); return 1; }

    /* Container detection: BSN starts with FF 42 53 47; a BSA entry
     * starts with header-len, 00, AE. */
    if (fread(probe, 1, 4, f) != 4) { fprintf(stderr, "short file\n"); fclose(f); return 1; }
    fseek(f, 0, SEEK_SET);
    if (probe[0] == 0xFF && probe[1] == 'B' && probe[2] == 'S' && probe[3] == 'G')
        return unpack_bsn(f, archive, outbase, cmd);
    if (probe[2] == 0xAE)
        return unpack_bsa(f, archive, outbase, cmd);
    fprintf(stderr, "unknown archive format\n");
    fclose(f);
    return 1;
}
