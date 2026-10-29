/* bsn_m23.c - LZSS + dynamic Huffman decoder for BSA "method 2/3" streams.
 *
 * Reimplementation of the BSA200 decode path:
 *   sub_208C4 (main loop), seg004:052E (block header), sub_1F6E7
 *   (pre-table RLE), sub_1F7F6 (lit/len table), sub_1F946 (distance),
 *   wrappers seg018:031F (method 2) / seg018:038F (method 3),
 *   sub_20808 (length extension), sub_20A91 (canonical table builder),
 *   sub_20631 (MSB-first bit reader).
 *
 * Format per block: u16 token count; 19 code lengths (5-bit count, with a
 * 2-bit zero-run inserted after every 3rd length); 510 literal/length
 * code lengths coded with the 19-symbol alphabet (0/1/2 are zero runs of
 * 1, 3+extra4, 0x14+extra9; else len-2); 14 distance code lengths
 * (4-bit count, no zero gap); then tokens. Token < 0x100 is a literal,
 * else length = symbol-0xFD. Distance base from the distance code:
 * 0 -> 0, else (1<<(c-1))|extra(c-1) bits; method 2 adds 0x2000 for
 * symbols >= 0x180 (symbol -= 0x80); method 3 has three tiers
 * (0x140/0x180/0x1C0 -> +0x2000/0x4000/0x6000, symbol -= 0x40/0x80/0xC0)
 * and extends length when the symbol is 0x13D. Method 5 uses the method 2
 * wrapper plus the length extension when the symbol is 0x17D; method 6
 * uses the method 3 wrapper. Distance = base+1, 64 KiB ring. Termination
 * is output-driven (orig byte count).
 */
#include <stdlib.h>
#include <string.h>
#include "bsn_m23.h"

#define M23_MAXBITS 16
#define M23_MAXSYM 510

typedef struct {
    const unsigned char *data;
    unsigned long size;
    unsigned long bitpos;
    int eof;                /* sticky: set once input is over-read */
} BR;

static int br_getbit(BR *br) {
    unsigned long byi = br->bitpos >> 3;
    int bit;
    if (byi >= br->size) { br->eof = 1; br->bitpos++; return 1; }
    bit = (br->data[byi] >> (7 - (br->bitpos & 7))) & 1;
    br->bitpos++;
    return bit;
}

static unsigned long br_read(BR *br, int n) {
    unsigned long v = 0;
    int i;
    for (i = 0; i < n; i++)
        v = (v << 1) | (unsigned long)br_getbit(br);
    return v;
}

/* Canonical Huffman, MSB-first, bit-by-bit decode (equivalent to the
 * original's 8-bit peek table plus subtree walk). A "const" table
 * decodes a fixed symbol consuming zero bits (count==0 path). */
typedef struct {
    int maxlen;
    int count[M23_MAXBITS+1];
    int first[M23_MAXBITS+1];
    int off[M23_MAXBITS+1];
    int nsyms;
    int is_const;
    int const_sym;
    int sym_len[M23_MAXSYM];
    int sym_val[M23_MAXSYM];
} MHT;

static void mht_build_const(MHT *t, int sym) {
    memset(t, 0, sizeof(*t));
    t->is_const = 1;
    t->const_sym = sym;
}

static int mht_build(MHT *t, const int *lens, int n) {
    int l, s, k, code, total;
    long kraft = 0;
    memset(t, 0, sizeof(*t));
    t->maxlen = 0;
    for (s = 0; s < n; s++) {
        l = lens[s];
        if (l < 0 || l > M23_MAXBITS) return -1;
        if (l) t->count[l]++;
        if (l > t->maxlen) t->maxlen = l;
    }
    /* Kraft sum over the 16-bit code space must be exact */
    for (l = 1; l <= t->maxlen; l++)
        kraft += (long)t->count[l] << (16 - l);
    if (kraft != 65536L) return -1;
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
    return 0;
}

static int mht_decode(BR *br, const MHT *t) {
    int l, code = 0, d;
    if (t->is_const) return t->const_sym;
    for (l = 1; l <= t->maxlen; l++) {
        code = (code << 1) | br_getbit(br);
        if (br->eof) return -1;
        d = code - t->first[l];
        if (t->count[l] && d >= 0 && d < t->count[l])
            return t->sym_val[t->off[l] + d];
    }
    return -1;
}

/* Read one "3-bit value, 7 -> extended by following 1-bits" code. */
static int read_codevalue(BR *br) {
    int top = (int)br_read(br, 3);
    if (top < 7 || br->eof) return top;
    {
        int extra = 0;
        while (br_getbit(br)) extra++;
        return 7 + extra;
    }
}

typedef struct {
    BR br;
    MHT pre, lit, dist;
    int prelens[64];
    int litlens[M23_MAXSYM + 2];
    int distlens[64];
    int blkcount;
    int method;
} M23;

/* sub_1F6E7(special, kbit, count): read a pre/distance alphabet
 * into lens/table. special = gap cadence (3) or -1 for none. */
static int read_pre(M23 *m, int *lens, MHT *t, int count, int kbit, int special) {
    int n, i, c, v, mval;
    n = (int)br_read(&m->br, kbit);
    if (m->br.eof) return -1;
    memset(lens, 0, sizeof(int) * count);
    if (n == 0) {
        mval = (int)br_read(&m->br, kbit);
        if (m->br.eof) return -1;
        mht_build_const(t, mval);
        return 0;
    }
    i = 0;
    while (i < n) {
        c = read_codevalue(&m->br);
        if (m->br.eof) return -1;
        if (i < count) lens[i] = c;
        i++;
        if (i == special) {
            v = (int)br_read(&m->br, 2);
            if (m->br.eof) return -1;
            while (v-- > 0) { if (i < count) lens[i] = 0; i++; }
        }
    }
    while (i < count) { lens[i] = 0; i++; }
    if (mht_build(t, lens, count) != 0) return -1;
    return 0;
}

/* sub_1F7F6: read the 510 literal/length code lengths via the pre tree. */
static int read_lit(M23 *m) {
    int n, i, c, v, mval;
    n = (int)br_read(&m->br, 9);
    if (m->br.eof) return -1;
    if (n == 0) {
        mval = (int)br_read(&m->br, 9);
        if (m->br.eof) return -1;
        memset(m->litlens, 0, sizeof(m->litlens));
        mht_build_const(&m->lit, mval);
        return 0;
    }
    memset(m->litlens, 0, sizeof(m->litlens));
    i = 0;
    while (i < n) {
        c = mht_decode(&m->br, &m->pre);
        if (c < 0) return -1;
        if (c > 2) {
            if (i < 510) m->litlens[i] = c - 2;
            i++;
            continue;
        }
        if (c == 0) v = 1;
        else if (c == 1) v = 3 + (int)br_read(&m->br, 4);
        else v = 0x14 + (int)br_read(&m->br, 9);
        if (m->br.eof) return -1;
        while (v-- > 0) { if (i < 510) m->litlens[i] = 0; i++; }
    }
    while (i < 510) { m->litlens[i] = 0; i++; }
    if (mht_build(&m->lit, m->litlens, 510) != 0) return -1;
    return 0;
}

/* seg004:052E block header shared by methods 2/3/5/6. */
static int read_header(M23 *m) {
    m->blkcount = (int)br_read(&m->br, 16);
    if (m->br.eof) return -1;
    if (read_pre(m, m->prelens, &m->pre, 19, 5, 3) != 0) return -1;
    if (read_lit(m) != 0) return -1;
    if (read_pre(m, m->distlens, &m->dist, 14, 4, -1) != 0) return -1;
    return 0;
}

/* sub_20808: length extension (methods 3/5/6): new header on block end,
 * then one more literal/length symbol. */
static int decode_ext(M23 *m) {
    if (--m->blkcount == 0) {
        if (read_header(m) != 0) return -1;
    }
    return mht_decode(&m->br, &m->lit);
}

/* sub_1F946 + method wrapper (seg018:031F for 2, seg018:038F for 3/6,
 * seg018:02F1 for 5). *sym is the length symbol, adjusted in place.
 * Returns distance base, or -1 on failure. */
static int decode_dist(M23 *m, int *sym) {
    int c, base, e, x;
    c = mht_decode(&m->br, &m->dist);
    if (c < 0) return -1;
    if (c == 0) base = 0;
    else {
        e = (int)br_read(&m->br, c - 1);
        if (m->br.eof) return -1;
        base = (1 << (c - 1)) | e;
    }
    if (m->method == 2) {
        if (*sym >= 0x180) { base += 0x2000; *sym -= 0x80; }
    } else if (m->method == 5) {
        if (*sym >= 0x180) { base += 0x2000; *sym -= 0x80; }
        if (*sym == 0x17D) {
            x = decode_ext(m);
            if (x < 0) return -1;
            *sym += x;
        }
    } else {
        /* methods 3 and 6 (wrappers seg018:038F and seg018:033A) */
        if (*sym >= 0x1C0) { base += 0x6000; *sym -= 0xC0; }
        else if (*sym >= 0x180) { base += 0x4000; *sym -= 0x80; }
        else if (*sym >= 0x140) { base += 0x2000; *sym -= 0x40; }
        if (*sym == 0x13D) {
            x = decode_ext(m);
            if (x < 0) return -1;
            *sym += x;
        }
    }
    return base;
}

unsigned char *bsn_m23_decode(const unsigned char *packed, unsigned long psize,
                              const unsigned char *trail, unsigned long tsize,
                              unsigned long outsize, unsigned long *produced,
                              int method) {
    M23 m;
    unsigned char *inbuf, *ring, *out;
    unsigned long opos = 0;
    unsigned long rhi;      /* remaining-high + 1 (word_27E3C) */
    unsigned int rlo;       /* remaining-low (bp) */
    unsigned int wpos = 0;  /* ring position (di) */
    int s, sym, len, base;

    *produced = 0;
    if (method != 2 && method != 3 && method != 5 && method != 6) return 0;

    out = (unsigned char *)malloc(outsize ? outsize : 1);
    if (!out) return 0;
    ring = (unsigned char *)malloc(65536);
    if (!ring) { free(out); return 0; }
    memset(ring, 0, 65536);

    /* input = packed stream + trailing archive bytes, like the original
     * sees them (its bit reader runs past the packed end into file data) */
    inbuf = (unsigned char *)malloc((psize + tsize) ? (psize + tsize) : 1);
    if (!inbuf) { free(out); free(ring); return 0; }
    if (psize) memcpy(inbuf, packed, psize);
    if (tsize) memcpy(inbuf + psize, trail, tsize);

    memset(&m, 0, sizeof(m));
    m.br.data = inbuf;
    m.br.size = psize + tsize;
    m.br.bitpos = 0;
    m.br.eof = 0;
    m.method = method;
    m.blkcount = 1;

    if (outsize == 0) { free(inbuf); free(ring); return out; }

    rhi = (outsize >> 16) + 1;
    rlo = (unsigned int)(outsize & 0xFFFF);

    /* no prime read needed: the original primes a zeroed bit buffer,
     * which loads (not discards) the first 16 bits; the block count
     * read below consumes exactly those bits. */

    /* loop-top entry decrement (loc_2092E first pass) */
    if (rlo == 0) { rlo = 0xFFFF; if (--rhi == 0) goto done; }
    else rlo--;

    for (;;) {
        if (--m.blkcount == 0) {
            if (read_header(&m) != 0) goto done;
        }
        if (m.br.eof) goto done;
        s = mht_decode(&m.br, &m.lit);
        if (s < 0) goto done;
        if (s < 0x100) {
            ring[wpos] = (unsigned char)s;
            out[opos++] = (unsigned char)s;
            wpos = (wpos + 1) & 0xFFFF;
            /* exactly one countdown step per literal; on a ring wrap
             * this substitutes for the step skipped by the wrap branch */
            if (rlo == 0) { rlo = 0xFFFF; if (--rhi == 0) goto done; }
            else rlo--;
        } else {
            unsigned int src, mx;
            int k;
            sym = s;
            base = decode_dist(&m, &sym);
            if (base < 0) goto done;
            len = sym - 0xFD;   /* distance is base+1 */
            if (len < 3 || opos + (unsigned long)len > outsize) goto done;
            /* source starts (base+1) bytes back: si = di-1-base */
            src = (unsigned int)((wpos - 1 - base) & 0xFFFF);
            /* fast path iff neither source nor dest range wraps 64K */
            mx = src > wpos ? src : wpos;
            if (((unsigned long)mx + (unsigned long)len) & 0x10000UL) {
                for (k = 0; k < len; k++) {
                    unsigned char b = ring[src];
                    ring[wpos] = b;
                    out[opos++] = b;
                    src = (src + 1) & 0xFFFF;
                    wpos = (wpos + 1) & 0xFFFF;
                }
            } else {
                for (k = 0; k < len; k++) {
                    unsigned char b = ring[(src + k) & 0xFFFF];
                    ring[(wpos + k) & 0xFFFF] = b;
                    out[opos++] = b;
                }
                wpos = (wpos + (unsigned int)len) & 0xFFFF;
            }
            /* 32-bit remaining -= len; done iff exactly zero */
            {
                unsigned long r = ((rhi << 16) | rlo) - (unsigned long)len;
                rhi = r >> 16;
                rlo = (unsigned int)(r & 0xFFFF);
                if (r == 0) goto done;
            }
        }
        if (opos >= outsize) goto done;
    }

done:
    *produced = opos;
    free(inbuf);
    free(ring);
    return out;
}
