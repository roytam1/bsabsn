/* bsn_lz.c - LZ77 + canonical Huffman decoder for BSA/BSN "method 7" streams.
 *
 * Reimplementation of the decode path in bsa32.exe:
 *   sub_413940 (LZ77 + dynamic Huffman), sub_413260 / sub_413750 / sub_413490
 *   (Huffman header + canonical table builder), sub_404DA0 (MSB-first bit
 *   reader over big-endian 16-bit words).
 *
 * Format (confirmed byte-for-byte against sample.bsn -> sample.txt):
 *   bitstream is MSB-first over bytes.
 *   block := count:16
 *            meta:  count19:5, then (count19) code lengths coded as
 *                   "3-bit value, if 7 then unary ones terminated by 0",
 *                   with a 2-bit zero-run inserted after each 3rd length.
 *            litlen: count510:9, then (count510) code lengths coded with the
 *                   meta Huffman alphabet: 0..2 are zero runs, 3.. are len-2.
 *            dist:  count17:5, then (count17) code lengths (same coding).
 *            count tokens.
 *   token := symbol (<256 literal, else length=symbol-253)
 *            if match: dist symbol d; d<=1 -> distance d+1,
 *                      else extra=d-1 bits, distance=(1<<extra)+val+1.
 */
#include <stdlib.h>
#include <string.h>
#include "bsn_lz.h"

#define MAXBITS 20

typedef struct {
    const unsigned char *data;
    unsigned long size;
    unsigned long bitpos;
} BITREADER;

static unsigned long br_getbit(BITREADER *br) {
    unsigned long byi = br->bitpos >> 3;
    unsigned int bit;
    if (byi >= br->size) { br->bitpos++; return 0; }
    bit = (br->data[byi] >> (7 - (br->bitpos & 7))) & 1;
    br->bitpos++;
    return bit;
}

static unsigned long br_read(BITREADER *br, int n) {
    unsigned long v = 0;
    int i;
    for (i = 0; i < n; i++)
        v = (v << 1) | br_getbit(br);
    return v;
}

static unsigned long br_peek(BITREADER *br, int n) {
    unsigned long p = br->bitpos;
    unsigned long v = br_read(br, n);
    br->bitpos = p;
    return v;
}

/* Canonical Huffman, MSB-first. A "const" table decodes a fixed symbol
 * consuming zero bits (original fills the fast table with a constant when
 * the code count is 0: sub_413260 / sub_413750 cnt==0 path). */
typedef struct {
    int maxlen;
    int count[MAXBITS+1];
    int first[MAXBITS+1];
    int off[MAXBITS+1];
    int nsyms;
    int sym_len[MAXBITS*520];
    int sym_val[MAXBITS*520];
    int is_const;
    int const_sym;
} HTREE;

static int htree_build(HTREE *t, const int *lens, int n) {
    int l, s, k, code, total;
    memset(t, 0, sizeof(*t));
    t->maxlen = 0;
    for (s = 0; s < n; s++) {
        l = lens[s];
        if (l < 0 || l > MAXBITS) return -1;
        if (l > t->maxlen) t->maxlen = l;
        if (l) t->count[l]++;
    }
    code = 0; total = 0;
    for (l = 1; l <= t->maxlen; l++) {
        t->first[l] = code;
        t->off[l] = total;
        code = (code + t->count[l]) << 1;
        total += t->count[l];
    }
    k = 0;
    for (l = 1; l <= t->maxlen; l++) {
        for (s = 0; s < n; s++) {
            if (lens[s] == l) {
                t->sym_len[k] = l;
                t->sym_val[k] = s;
                k++;
            }
        }
    }
    t->nsyms = k;
    t->is_const = 0;
    t->const_sym = 0;
    return k ? 0 : -1;
}

static void htree_build_const(HTREE *t, int sym) {
    memset(t, 0, sizeof(*t));
    t->is_const = 1;
    t->const_sym = sym;
}

static int htree_decode(BITREADER *br, const HTREE *t) {
    int l, code = 0, d;
    if (t->is_const) return t->const_sym;
    for (l = 1; l <= t->maxlen; l++) {
        code = (code << 1) | (int)br_getbit(br);
        d = code - t->first[l];
        if (t->count[l] && d >= 0 && d < t->count[l])
            return t->sym_val[t->off[l] + d];
    }
    return -1;
}

/* Read one "3-bit value, 7 -> unary extension" code. */
static int read_codevalue(BITREADER *br) {
    int top = (int)br_peek(br, 3);
    if (top < 7) {
        br_read(br, 3);
        return top;
    }
    {
        int extra = 0;
        br_read(br, 3);
        while (br_getbit(br)) extra++;
        return 7 + extra;
    }
}

/* sub_413260: read code lengths for the meta/distance alphabet.
 * n = alphabet size, cntbits = bits for the count, gap = zero-run cadence.
 * cnt==0 means a constant table: the special value is stored in *const_sym
 * (>=0) and no lengths are read. *const_sym is set to -1 otherwise. */
static int read_codelens(BITREADER *br, int *lens, int n, int cntbits, int gap,
                         int *const_sym) {
    int cnt = (int)br_read(br, cntbits);
    int i = 0;
    memset(lens, 0, sizeof(int) * n);
    *const_sym = -1;
    if (cnt == 0) {
        *const_sym = (int)br_read(br, cntbits);   /* special value */
        return 0;
    }
    while (i < cnt) {
        int v = read_codevalue(br);
        if (i < n) lens[i] = v;
        i++;
        if (gap && i == gap) {
            int z = (int)br_read(br, 2);
            while (z-- > 0 && i < n) { lens[i] = 0; i++; }
        }
    }
    return 0;
}

/* sub_413750: read the 510 literal/length code lengths via the meta tree.
 * cnt==0 means a constant table (special value in *const_sym). */
static int read_litlens(BITREADER *br, const HTREE *meta, int *lens, int *const_sym) {
    int cnt = (int)br_read(br, 9);
    int i = 0;
    memset(lens, 0, sizeof(int) * 510);
    *const_sym = -1;
    if (cnt == 0) {
        *const_sym = (int)br_read(br, 9);   /* special value */
        return 0;
    }
    while (i < cnt) {
        int v = htree_decode(br, meta);
        if (v < 0) return -1;
        if (v > 2) {
            if (i < 510) lens[i] = v - 2;
            i++;
            continue;
        }
        if (v == 0) {
            if (i < 510) lens[i] = 0;
            i++;
        } else if (v == 1) {
            int run = (int)br_read(br, 4) + 3;
            while (run-- > 0 && i < 510) { lens[i] = 0; i++; }
        } else {
            int run = (int)br_read(br, 9) + 20;
            while (run-- > 0 && i < 510) { lens[i] = 0; i++; }
        }
    }
    return 0;
}

/* 128 KiB sliding window, persistent across entries within one archive
 * (like the original's static window buffer, which is never cleared).
 * wpos keeps running so later entries can match earlier ones. */
#define LZ_RING_MASK 0x1FFFFUL
static unsigned char lz_ring[131072];
static unsigned long lz_wpos = 0;

unsigned char *bsn_lz_decode(const unsigned char *packed, unsigned long psize,
                             unsigned long outsize, unsigned long *produced) {
    BITREADER br;
    unsigned char *out;
    unsigned long opos = 0;
    int metalens[19], litlens[510], dlens[17];
    HTREE meta, lit, dist;
    int n, i, s;
    int meta_const, lit_const, dist_const;

    br.data = packed; br.size = psize; br.bitpos = 0;
    out = (unsigned char *)malloc(outsize ? outsize : 1);
    if (!out) return 0;

    n = (int)br_read(&br, 16);   /* first block token count */

    for (;;) {
        /* ---- block header ---- */
        read_codelens(&br, metalens, 19, 5, 3, &meta_const);
        if (meta_const >= 0) htree_build_const(&meta, meta_const);
        else if (htree_build(&meta, metalens, 19) != 0) { free(out); return 0; }
        if (read_litlens(&br, &meta, litlens, &lit_const) != 0) { free(out); return 0; }
        if (lit_const >= 0) htree_build_const(&lit, lit_const);
        else if (htree_build(&lit, litlens, 510) != 0) { free(out); return 0; }
        read_codelens(&br, dlens, 17, 5, 0, &dist_const);
        if (dist_const >= 0) htree_build_const(&dist, dist_const);
        else if (htree_build(&dist, dlens, 17) != 0) { free(out); return 0; }

        /* ---- tokens ---- */
        for (i = 0; i < n; i++) {
            if (opos >= outsize) goto done;
            s = htree_decode(&br, &lit);
            if (s < 0) { free(out); return 0; }
            if (s < 256) {
                lz_ring[lz_wpos] = (unsigned char)s;
                lz_wpos = (lz_wpos + 1) & LZ_RING_MASK;
                out[opos++] = (unsigned char)s;
            } else {
                int len = s - 253;
                int d = htree_decode(&br, &dist);
                unsigned long distance;
                int j;
                if (d < 0) { free(out); return 0; }
                if (d <= 1) distance = (unsigned long)d + 1;
                else {
                    int eb = d - 1;
                    unsigned long e = br_read(&br, eb);
                    distance = (1UL << eb) + e + 1;
                }
                for (j = 0; j < len; j++) {
                    unsigned char c;
                    if (opos >= outsize) goto done;
                    c = lz_ring[(lz_wpos - distance) & LZ_RING_MASK];
                    lz_ring[lz_wpos] = c;
                    lz_wpos = (lz_wpos + 1) & LZ_RING_MASK;
                    out[opos++] = c;
                }
            }
        }
        if (opos >= outsize) break;
        n = (int)br_read(&br, 16);
        if (n == 0 && (br.bitpos >> 3) >= psize) break;
    }
done:
    *produced = opos;
    return out;
}
