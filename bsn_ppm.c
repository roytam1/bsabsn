/* bsn_ppm.c - PPM range decoder for BSA/BSN "method 9" streams.
 *
 * Reimplementation of the decode path in bsa32.exe:
 *   sub_404A90 (case 9) -> sub_406920 -> sub_405160 (main decode loop)
 *   sub_4054C0 (context setup) + sub_4057B0 (context search)
 *   sub_405D60 (range-decode one symbol or escape)
 *   sub_405840 (model update after a literal)
 *   sub_405A30 (allocate a new context node, LRU)
 *   sub_4060D0 (range-decoder rescaling) + sub_404710/sub_404DA0 (bit input)
 *   sub_406500 (model init, LABEL_9 path) + sub_40A9F0 (output flush)
 *
 * Notes (all verified against bsa32.exe.lst):
 * - The trie init loops write every 4th int with stride 8/16, leaving
 *   zero gaps; this is replicated bit-exactly (both sides need the same).
 * - The range coder keeps (lo,hi,val) 16-bit plus a 32-bit code buffer
 *   refilled 16 bits at a time, big-endian, 0xFF past end (file EOF).
 * - Hash function: h = b0; h = b1^4*h; ... (< 65536 always, no masking).
 * - Exclusion flags live in ONE 258-byte array (the "4 arrays" in the
 *   decompilation overlap by construction: 661[v] == 660[v+1]).
 *
 * Build with MSVC6:  cl bsn_ppm.c
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "bsn_ppm.h"

static int ppm_trace_n = 0;

#define PPM_NCTX   11264
#define PPM_NPOOL  22528
#define PPM_NHASH  65536

/* ---- model state (mirrors the original BSS layout) ---- */
static int     hHead[PPM_NHASH];     /* 4C2C70: hash bucket heads */
static int     hNext[PPM_NCTX];      /* 502C70: hash chain links */
static int     nFreq[PPM_NPOOL];     /* 483870: node frequencies */
static int     nChild[PPM_NPOOL];    /* 49F070: first child / free link */
static unsigned char nSym[PPM_NPOOL];   /* 499870: node symbol */
static unsigned char nOrd[PPM_NPOOL];   /* 50DC70: node order */
static unsigned char nCtx[PPM_NCTX * 5];/* 4B5070: context bytes */
static int     mtfP[PPM_NCTX];       /* 46D870: LRU prev */
static int     mtfN[PPM_NCTX];       /* 478870: LRU next */
static unsigned char xFlag[258];     /* 46D660: exclusion flags */
static unsigned char xList[260];     /* 46D768: excluded symbols */
static int     xCount;               /* 46D65C */
static unsigned char hist[8];        /* 510874..: history bytes */
static int     oh[6];                /* 5108A8: order hashes */
static int     oC4;                  /* 5108C4 */
static int     ctxN[10];             /* 46D610 base: nodes per level */
static int     ctxF[9];              /* 46D638: level flags */
static int     lvlT[8];              /* 46D5F0: level totals */
static int     escAcc;               /* 510870 */
static int     lvlIdx;               /* 510894 */
static int     freeHead;             /* 51089C */
static int     clockHand;            /* 510898 */
static int     maxOrd;               /* 46D762 */
static int     ord5cnt;              /* 46D86C */
static int     mtfHead, mtfTail;     /* 5108A0, 5108A4 */

/* ---- range coder state ---- */
static unsigned int  rc_code;        /* 46D5E0 */
static int           rc_bits;        /* 46D5E4 */
static unsigned short rc_lo, rc_hi, rc_val;  /* 510880, 51087C, 51088C */

/* ---- input ---- */
static const unsigned char *in_base;
static unsigned long in_size, in_pos;
static const unsigned char *in_trail;
static unsigned long in_tsize, in_tpos;

static int in_byte(void) {
    if (in_pos < in_size) return in_base[in_pos++];
    if (in_tpos < in_tsize) {
        int c = in_trail[in_tpos++];
#ifdef PPM_TRACE
        fprintf(stderr, "    trailbyte %02x\n", c);
#endif
        return c;
    }
    return -1;
}

static unsigned in_word(void) {
    int b0 = in_byte();
    if (b0 < 0) return 0xFFFFFFFFu;
    {
        int b1 = in_byte();
        return ((unsigned)b0 << 8) | (unsigned)(b1 & 0xFFFF);
    }
}

/* ---- output ---- */
static unsigned char *o_base;
static unsigned long  o_cap, o_len;
static int o_text;
static int o_fail;

static void o_put(unsigned char c) {
    if (o_len >= o_cap) { o_fail = 1; return; }
    o_base[o_len++] = c;
}

static unsigned char stageB[1024];
static int stageP;

static void o_flush(const unsigned char *src, int n) {
    int i;
    if (o_text) {
        for (i = 0; i < n; i++) {
            if (src[i] == 10) o_put(13);
            o_put(src[i]);
        }
    } else {
        int i2;
        for (i2 = 0; i2 < n; i2++) o_put(src[i2]);
    }
}

/* ---- bit input (sub_404710 / sub_404DA0) ---- */
static void rc_init(void) {
    rc_code = 0;
    rc_bits = 0;
}

static void rc_refill(int n) {
    unsigned w;
    int k;
    rc_code <<= n;
    rc_bits -= n;
    if (rc_bits >= 0) return;
    k = -rc_bits;
    if (in_pos + 2 <= in_size) {
        w = ((unsigned)in_base[in_pos] << 8) | in_base[in_pos + 1];
        in_pos += 2;
    } else {
        w = in_word();
    }
#ifdef PPM_TRACE
    if (ppm_trace_n < 6) fprintf(stderr, "    refill n=%d w=%04x pos=%lu tpos=%lu\n", n, w & 0xFFFF, in_pos, in_tpos);
#endif
    rc_code |= w << k;
    rc_bits += 16;
}

/* range-decoder rescale (sub_4060D0). Return value unused. */
static void rc_decode(unsigned a1, unsigned a2, unsigned total) {
    unsigned range = (unsigned)rc_hi - (unsigned)rc_lo + 1u;
    unsigned hi = (unsigned)(unsigned short)((unsigned)(rc_lo - 1) + a2 * range / total);
    unsigned lo = (unsigned)rc_lo + (unsigned)(unsigned short)(a1 * range / total);
    unsigned val = rc_val;
#ifdef PPM_TRACE
    if (ppm_trace_n < 14) fprintf(stderr, "  rc(%u,%u,%u) lo=%04x hi=%04x val=%04x\n",
        a1, a2, total, rc_lo, rc_hi, rc_val);
    ppm_trace_n++;
#endif
    for (;;) {
        if (((hi ^ lo) & 0x8000u) == 0) goto norm;
        if ((lo & 0x4000u) == 0 || (hi & 0x4000u) != 0) break;
        lo &= 0x3FFFu;
        val ^= 0x4000u;
        hi |= 0x4000u;
norm:
        {
            unsigned carry = rc_code >> 31;
#ifdef PPM_TRACE
            if (ppm_trace_n < 4) fprintf(stderr, "    it hi=%08x lo=%08x carry=%u\n", hi, lo, carry);
#endif
            hi = 2u * hi + 1u;
            lo *= 2u;
            val = (unsigned short)(2u * val);
            rc_val = (unsigned short)val;
            rc_code *= 2u;
            --rc_bits;
            if (rc_bits < 0) {
                unsigned w;
                int k = -rc_bits;
                if (in_pos + 2 <= in_size) {
                    w = ((unsigned)in_base[in_pos] << 8) | in_base[in_pos + 1];
                    in_pos += 2;
                } else {
                    w = in_word();
                }
                rc_code |= w << k;
                rc_bits += 16;
                val = rc_val;
            }
            val = (unsigned short)(val + carry);
            rc_val = (unsigned short)val;
        }
    }
    rc_hi = (unsigned short)hi;
    rc_lo = (unsigned short)lo;
}

/* ---- model init (sub_406500, LABEL_9 path: always full init) ----
 *
 * NOTE on layout: the original builds these tables with SSE stores to
 * overlapping views (xmmword_46D870/46D880, 478870/478880, 49F070/49F080...).
 * The net effect is DENSE tables (no gaps): consecutive MTF ramps and a
 * consecutive free chain. (Treating the views as separate arrays leaves
 * zero gaps, breaks the LRU victim order and desynchronises the model.)
 */
static void ppm_init(void) {
    int v2, k;
    /* hash buckets/chains */
    for (v2 = 0; v2 < PPM_NHASH; v2++) hHead[v2] = -1;
    for (v2 = 0; v2 < PPM_NCTX; v2++) hNext[v2] = -1;
    /* trie nodes: dense ramp init (overlapping SSE stores combined) */
    for (v2 = 0; v2 < PPM_NCTX; v2 += 8) {
        int n;
        if (v2 + 8 > PPM_NCTX) n = PPM_NCTX - v2; else n = 8;
        memset(&nOrd[v2], 0xFF, (size_t)n);
        for (k = 0; k < 8 && v2 + k < PPM_NCTX; k++) {
            mtfN[v2 + k] = v2 + 1 + k;
            mtfP[v2 + k] = v2 - 1 + k;
            nChild[v2 + k] = -1;
        }
    }
    /* free chain [NCTX, NPOOL): consecutive, last links to -1 */
    for (v2 = PPM_NCTX; v2 < PPM_NPOOL; v2++)
        nChild[v2] = v2 + 1;
    nChild[PPM_NPOOL - 1] = -1;
    freeHead = PPM_NCTX;
    clockHand = 0;
    mtfHead = PPM_NCTX - 1;
    mtfTail = 0;
    memset(hist, 0, sizeof(hist));
    memset(xFlag, 0, sizeof(xFlag));
    xCount = 0;
    maxOrd = 5;
    ord5cnt = PPM_NCTX >> 2;
    escAcc = 0;
    oh[0] = 0;
}

/* context search (sub_4057B0) */
static int ctx_find(void) {
    int v0 = oC4 - 1;
    while (v0 >= 0) {
        int v1 = hHead[oh[v0]];
        if (v1 != -1) {
            for (;;) {
                if ((int)nOrd[v1] != v0) goto nxt;
                if (v0 == 0) { oC4 = 0; return v1; }
                {
                    int k;
                    for (k = 0; k < v0; k++)
                        if (hist[k] != nCtx[5 * v1 + k]) break;
                    if (k == v0) { oC4 = v0; return v1; }
                }
nxt:
                v1 = hNext[v1];
                if (v1 == -1) break;
            }
        }
        v0--;
    }
    return -1;
}

/* context setup (sub_4054C0) */
static int ctx_setup(void) {
    int v0;
    oh[1] = hist[0];
    lvlIdx = 0;
    oh[2] = hist[1] ^ (4 * oh[1]);
    oh[3] = hist[2] ^ (4 * oh[2]);
    oh[4] = hist[3] ^ (4 * oh[3]);
    oh[5] = hist[4] ^ (4 * oh[4]);
    for (v0 = xCount - 1; v0 >= 0; v0--) xFlag[xList[v0]] = 0;
    xCount = 0;
    oC4 = 6;
    return ctx_find();
}

/* range-decode one symbol in a context (sub_405D60). 256 = escape. */
static int ppm_decode_sym(int a1) {
    int v2 = 0, v29 = 0, v3 = 0, v4 = 0;
    int v31 = a1, v5 = a1;
    int v7, v27;
    unsigned tot, total30;
    if (a1 != -1) {
        do {
            unsigned f;
            ++v2;
            f = (unsigned)nFreq[v5];
            if (xFlag[nSym[v5]]) v29 += (int)f;
            else { v3 += (int)f; if (f < 4) ++v4; }
            v5 = nChild[v5];
        } while (v5 != -1);
        a1 = v31;
    }
    v7 = a1;
    if (v3 <= 0x1000) v7 = -1;
    tot = (unsigned)v29 + (unsigned)v3;
    lvlT[lvlIdx] = (int)tot;
    v27 = v7;
    if (tot == 1) {
        v4 = (int)tot;
    } else if (v2 > 1) {
        if (v2 == 256) {
            v4 = 1;
        } else if (2 * v2 >= (int)tot) {
            v4 = (int)((unsigned)(2 * v2) * (unsigned)v4 / tot);
            if ((int)tot == v2) v4 += v2 >> 2;
            if (!v4) v4 = 1;
        } else if (!v4) {
            v4 = 1;
        }
    } else if (!v4) {
        v4 = 1;
    }
    if ((unsigned)escAcc < 4u) {
        /* unscaled branch */
        unsigned thr;
        unsigned short t16;
        int v9, v13, v14;
        total30 = (unsigned)v4 + (unsigned)v3;
        thr = (unsigned)(((total30 * ((unsigned)rc_val - (unsigned)rc_lo + 1u)) - 1u)
                        / ((unsigned)rc_hi - (unsigned)rc_lo + 1u));
        t16 = (unsigned short)thr;
        v9 = v31;
        v13 = 0;
        if (v31 != -1) {
            for (;;) {
                if (!xFlag[nSym[v9]]) {
                    if ((unsigned)(v13 + nFreq[v9]) > (unsigned)t16) break;
                    v13 += nFreq[v9];
                }
                v9 = nChild[v9];
                if (v9 == -1) break;
            }
        }
        v14 = nFreq[v9];
        if (v9 == -1 || !v14) goto escape;
        rc_decode((unsigned)v13, (unsigned)(v13 + v14), total30);
        {
            int v16 = lvlIdx;
            int v17 = escAcc + 1;
            ctxN[v16 + 1] = v9;
            ctxF[v16] = v31;
            lvlIdx = v16 + 1;
            {
                int v24 = v27, v25;
                escAcc = v17;
                while (v24 != -1) {
                    v25 = nFreq[v24];
                    if (v25 > 1) nFreq[v24] = v25 >> 1;
                    v24 = nChild[v24];
                }
                return (int)nSym[v9];
            }
        }
    } else {
        /* scaled branch */
        int v28;
        unsigned thr;
        unsigned short t16;
        int v9, v12, v13, v14;
        v28 = (v3 > 6) ? 1 : 2;
        total30 = (unsigned)v4 + ((unsigned)v3 << v28);
        thr = (unsigned)(((total30 * ((unsigned)rc_val - (unsigned)rc_lo + 1u)) - 1u)
                        / ((unsigned)rc_hi - (unsigned)rc_lo + 1u));
        t16 = (unsigned short)thr;
        v9 = v31;
        v12 = 0;
        if (v31 != -1) {
            for (;;) {
                if (!xFlag[nSym[v9]]) {
                    if ((((unsigned)(v12 + nFreq[v9])) << v28) > (unsigned)t16) break;
                    v12 += nFreq[v9];
                }
                v9 = nChild[v9];
                if (v9 == -1) break;
            }
        }
        v13 = v12 << v28;
        v14 = (int)((unsigned)nFreq[v9] << v28);
        if (v9 == -1 || !v14) goto escape;
        rc_decode((unsigned)v13, (unsigned)(v13 + v14), total30);
        {
            int v16 = lvlIdx;
            int v17 = escAcc + 1;
            ctxN[v16 + 1] = v9;
            ctxF[v16] = v31;
            lvlIdx = v16 + 1;
            {
                int v24 = v27, v25;
                escAcc = v17;
                while (v24 != -1) {
                    v25 = nFreq[v24];
                    if (v25 > 1) nFreq[v24] = v25 >> 1;
                    v24 = nChild[v24];
                }
                return (int)nSym[v9];
            }
        }
    }
escape:
    {
        int v20 = v31, v21, v22, v23 = lvlIdx;
        unsigned e2 = total30 - (unsigned)v4;
        rc_decode(e2, total30, total30);
        v21 = xCount;
        for (;;) {
            v22 = (int)nSym[v20];
            if (!xFlag[v22]) {
                xList[v21++] = (unsigned char)v22;
                xFlag[v22] = 1;
            }
            if (nChild[v20] == -1) break;
            v20 = nChild[v20];
        }
        xCount = v21;
        ctxN[v23 + 1] = v20;
        ctxF[v23] = ~v31;
        lvlIdx = v23 + 1;
        escAcc = 0;
        {
            int v24 = v27, v25;
            while (v24 != -1) {
                v25 = nFreq[v24];
                if (v25 > 1) nFreq[v24] = v25 >> 1;
                v24 = nChild[v24];
            }
            return 256;
        }
    }
}
/* model update after a literal (sub_405840) */
static void model_update(int lit) {
    int v1 = lvlIdx;
    if (v1) {
        int v2 = freeHead, v3 = clockHand, v21 = v2;
        do {
            int v4 = ctxN[v1--];
            int v20 = v4;
            lvlIdx = v1;
            if (ctxF[v1] < 0) {
                if (v2 == -1) {
                    /* free list empty: clock sweep + rescale */
                    for (;;) {
                        int v5 = 0, v6, v7;
                        do {
                            ++v3;
                            if (v3 == PPM_NCTX) v3 = 0;
                            v6 = nChild[v3];
                        } while (v6 == -1);
                        for (;;) {
                            v7 = ctxF[v5];
                            if (v7 < 0) v7 = ~v7;
                            if (v7 == v3) break;
                            if (++v5 > v1) goto rescale;
                        }
                    }
rescale:
                    {
                        int v8, v9 = 0, v10 = v3, v11, v12, v13, v14, v15, i, v6;
                        clockHand = v3;
                        v8 = nFreq[v3];
                        v6 = nChild[v3];
                        while (v6 != -1) {
                            int f9 = nFreq[v6];
                            v6 = nChild[v6];
                            if (v8 > f9) f9 = v8;
                            v8 = f9;
                        }
                        v9 = v8;
                        v10 = v3;
                        if (v3 != -1) {
                            v11 = v9 + 1;
                            do {
                                int v19 = v10;
                                if (nChild[v3] == -1) break;
                                v12 = v10;
                                v13 = nFreq[v10];
                                if (v13 >= v11) {
                                    v10 = nChild[v10];
                                    nFreq[v12] = (int)((unsigned)v13 / (unsigned)v11);
                                } else if (v10 == v3) {
                                    v14 = nChild[v10];
                                    nFreq[v10] = nFreq[v14];
                                    nSym[v10] = nSym[v14];
                                    nChild[v10] = nChild[v14];
                                    nChild[v14] = v21;
                                    v21 = v14;
                                } else {
                                    v15 = v3;
                                    for (i = nChild[v3]; i != v10; i = nChild[i])
                                        v15 = i;
                                    v10 = nChild[v10];
                                    nChild[v15] = v10;
                                    nChild[v12] = v21;
                                    v21 = v19;
                                }
                            } while (v10 != -1);
                            v1 = lvlIdx;
                        }
                        v4 = v20;
                        v2 = v21;
                    }
                }
                nChild[v4] = v2;
                {
                    int v17 = v2;
                    v4 = v2;
                    nFreq[v17] = 0;
                    v2 = nChild[v2];
                    nChild[v17] = -1;
                    v21 = v2;
                    freeHead = v2;
                    nSym[v4] = (unsigned char)lit;
                }
            }
            ++nFreq[v4];
        } while (v1);
    }
}

/* create a new context node, LRU slot reuse (sub_405A30) */
static void node_create(int order, int sym) {
    int v2 = mtfHead;
    int v3 = order;
    unsigned char v4 = nOrd[mtfHead];
    int v6;
    mtfHead = mtfP[mtfHead];
    {
        int v5 = mtfTail;
        mtfN[v2] = mtfTail;
        mtfTail = v2;
        mtfP[v5] = v2;
    }
    if (v4 == 0xFF) goto fill;
    if (v4 == 5) {
        if (!--ord5cnt) maxOrd = 4;
    }
    if (v4) {
        v6 = nCtx[5 * v2];
        if (v4 > 1u) {
            v6 = nCtx[5 * v2 + 1] ^ (4 * v6);
            if (v4 > 2u) {
                v6 = nCtx[5 * v2 + 2] ^ (4 * v6);
                if (v4 > 3u) {
                    v6 = nCtx[5 * v2 + 3] ^ (4 * v6);
                    if (v4 > 4u)
                        v6 = nCtx[5 * v2 + 4] ^ (4 * v6);
                }
            }
        }
    } else {
        v6 = 0;
    }
    {
        int v7 = hHead[v6];
        if (v7 == v2) {
            hHead[v6] = hNext[v2];
        } else {
            int i;
            for (i = hNext[v7]; i != v2; i = hNext[i])
                v7 = i;
            hNext[v7] = hNext[v2];
        }
    }
    {
        int v9 = nChild[v2];
        if (v9 != -1) {
            int v10 = freeHead, v11;
            do {
                v11 = nChild[v9];
                nChild[v9] = v10;
                v10 = v9;
                v9 = v11;
            } while (v11 != -1);
            freeHead = v10;
        }
    }
fill:
    nSym[v2] = (unsigned char)sym;
    nChild[v2] = -1;
    nFreq[v2] = 1;
    nOrd[v2] = (unsigned char)v3;
    nCtx[5 * v2] = hist[0];
    nCtx[5 * v2 + 1] = hist[1];
    nCtx[5 * v2 + 2] = hist[2];
    nCtx[5 * v2 + 3] = hist[3];
    nCtx[5 * v2 + 4] = hist[4];
    if (v3) {
        int v18 = hist[0], v17;
        if (v3 > 1) {
            v18 = hist[1] ^ (4 * v18);
            if (v3 > 2) {
                v18 = hist[2] ^ (4 * v18);
                if (v3 > 3) {
                    v18 = hist[3] ^ (4 * v18);
                    if (v3 > 4)
                        v18 = hist[4] ^ (4 * v18);
                }
            }
        }
        v17 = v18;
        {
            int v19 = hHead[v17];
            hHead[v17] = v2;
            hNext[v2] = v19;
        }
    } else {
        int v19 = hHead[0];
        hHead[0] = v2;
        hNext[v2] = v19;
    }
}

/* main decode loop (sub_405160) */
unsigned char *bsn_ppm_decode(const unsigned char *packed, unsigned long psize,
                              const unsigned char *trail, unsigned long tsize,
                              unsigned long outsize, unsigned long *produced,
                              int textmode) {
    unsigned char *out;
    int i;
    in_base = packed; in_size = psize; in_pos = 0;
    in_trail = trail ? trail : (const unsigned char *)"";
    in_tsize = trail ? tsize : 0; in_tpos = 0;
    (void)in_byte();  /* first stream byte: version flag, ignored */
    o_base = (unsigned char *)malloc(outsize ? outsize : 1);
    if (!o_base) return 0;
    o_cap = outsize; o_len = 0; o_text = textmode; o_fail = 0;
    stageP = 0;

    ppm_init();
    rc_init();
    rc_refill(16);
    rc_lo = 0;
    rc_hi = 0xFFFF;
    rc_val = 0;
    for (i = 0; i < 16; i++) {
        unsigned b = rc_code >> 31;
        rc_val = (unsigned short)(rc_val * 2u);
        rc_refill(1);
        rc_val = (unsigned short)(rc_val + b);
    }

    for (;;) {
        int v6 = ctx_setup();
        int v17, v18, sym;
#ifdef PPM_TRACE
        if (o_len < 8) fprintf(stderr, "sym#%lu: ctx=%d lo=%04x hi=%04x val=%04x code=%08x bits=%d\n",
            o_len, v6, rc_lo, rc_hi, rc_val, rc_code, rc_bits);
#endif
        if (v6 == -1) {
            v17 = 0;
            v18 = maxOrd + 1;
            goto order1;
        }
        v17 = (int)nOrd[v6] + 1;
        v18 = maxOrd + 1;
        for (;;) {
            sym = ppm_decode_sym(v6);
            if (sym != 256) break;
            v6 = ctx_find();
            if (v6 == -1) goto order1;
        }
        /* move to front of LRU */
        {
            int v10 = mtfTail;
            if (v6 != v10) {
                if (v6 == mtfHead) {
                    mtfHead = mtfP[v6];
                } else {
                    int v11 = mtfN[v6];
                    mtfP[v11] = mtfP[v6];
                    mtfN[mtfP[v6]] = v11;
                }
                mtfP[v10] = v6;
                mtfN[v6] = v10;
                mtfTail = v6;
            }
        }
        goto emit;
order1:
        {
            /* order -1 literal (LABEL_12): unrolled 4-wide exclusion scan */
            unsigned total = (unsigned)(0x101 - xCount);
            unsigned thr = (unsigned)(((total * ((unsigned)rc_val - (unsigned)rc_lo + 1u)) - 1u)
                                      / ((unsigned)rc_hi - (unsigned)rc_lo + 1u));
            unsigned short t16 = (unsigned short)thr;
            unsigned v8 = 0;
            int v7 = 0;
            for (;;) {
                if (!xFlag[v7]) {
                    if (v8 >= t16) break;
                    ++v8;
                }
                if (!xFlag[v7 + 1]) {
                    if (v8 >= t16) { v7 += 1; break; }
                    ++v8;
                }
                if (!xFlag[v7 + 2]) {
                    if (v8 >= t16) { v7 += 2; break; }
                    ++v8;
                }
                if (!xFlag[v7 + 3]) {
                    if (v8 >= t16) { v7 += 3; break; }
                    ++v8;
                }
                v7 += 4;
                if (v7 >= 0x100) break;
            }
            rc_decode(v8, v8 + 1, total);
            sym = v7;
        }
emit:
        if (sym == 256) break;
        model_update(sym);
        if (v18 > v17) {
            int v12 = v18, v13 = v18 - v17;
            do {
                node_create(--v12, sym);
            } while (--v13);
        }
        stageB[stageP++] = (unsigned char)sym;
#ifdef PPM_TRACE
        if (o_len < 8) fprintf(stderr, "  -> sym=%02x (o_len was %lu)\n", sym, o_len);
#endif
        if (stageP >= 1024) {
            o_flush(stageB, stageP);
            if (o_fail) { free(o_base); return 0; }
            stageP = 0;
        }
        /* history shift */
        hist[4] = hist[3]; hist[3] = hist[2]; hist[2] = hist[1];
        hist[1] = hist[0]; hist[0] = (unsigned char)sym;
    }
    if (stageP) {
        o_flush(stageB, stageP);
        if (o_fail) { free(o_base); return 0; }
        stageP = 0;
    }
    *produced = o_len;
    return o_base;
}
