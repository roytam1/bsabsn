/* bsn_enc.c - LZ+Huffman encoders for BSA/BSN method 7 and method 2/3
 * streams, producing streams for the decoders in bsn_lz.c / bsn_m23.c.
 *
 * Method 7 uses sparse frequency-ranked Huffman tables rebuilt for
 * every block (only symbols actually used get codes, lengths coded
 * with the meta tree as length+2 with zero-runs, counts truncated at
 * the last used symbol) because the older original decoders (BSA195,
 * BSA200) reject the dense fixed tables used for methods 2/3 below.
 * Code lengths are assigned by frequency rank to a complete code
 * (Kraft sum exactly 1) with lengths ceil(log2(k)) or one less,
 * rather than by a full Huffman tree: the result is within a bit of
 * optimal per symbol, keeps maximum lengths small, and stays
 * verifiable. Methods 2/3 keep complete fixed-length tables (all
 * original decoders accept them there). Output is therefore not
 * bit-identical to the original tools, but any valid stream decodes
 * byte-exactly in all of them.
 *
 * Method 7 block: u16 token count, meta lengths (19 symbols, code
 * values with the 2-bit zero-run after the 3rd length), lit/len lengths
 * (510 symbols, each coded with the meta tree as length+2), distance
 * lengths (17 symbols, plain code values), then tokens. A literal is
 * its byte value; a match is symbol 253+len (len 3..255; the original
 * encoder never emits 256) plus a distance code d (distance 1 -> d 0,
 * distance 2 -> d 1, otherwise d-1 extra bits with distance =
 * (1<<extra)+val+1; the search window is capped at 32768, like the
 * original's, even though the format could describe more). Blocks
 * hold at most 16384 tokens, the original encoder's maximum.
 *
 * Methods 2/3 block: same framing, but the lit/len alphabet is 510
 * symbols with len = symbol-0xFD, the distance alphabet is 14 symbols
 * and there is no token-length extension (matches are simply capped
 * at 127 bytes for method 2 and 63 for method 3, which also avoids
 * symbol 509 and method 3's 0x13D extension symbol; BSA16/193/195
 * misdecode method 2 matches using symbol 509). Method 2 has two
 * distance tiers (dist 1..8192 plain, 8193..16384 with the length
 * symbol shifted by 128), method 3 has four tiers (8192-byte bands,
 * the length symbol shifted by 64 per band), matching the decoders'
 * wrapper adjustments. Method 6 shares method 3's wrapper.
 *
 * The LZ tokenizer is greedy with hash chains over 3-byte sequences,
 * and the window is reset for every file (the decoders' persistent
 * ring also decodes this, since no match ever reaches before the
 * start of the current file).
 *
 * Both encoders finish the bitstream with 32 zero bits. The original
 * encoders flush an extra 00 byte this way (their streams always end
 * with a 00 byte past the byte holding the last token bit), and the
 * original method 7 bit reader misdecodes the final token of a
 * stream that ends flush at the archive end without it, while the
 * tolerant port in bsn_lz.c does not; with this encoder's short
 * codes even one trailing byte was not always enough for bsa32's
 * bit-reader lookahead, so a 4-byte margin is used. The bytes are
 * counted in the packed size; both decoders stop on the original
 * size and ignore them.
 */
#include <stdlib.h>
#include <string.h>
#include "bsn_enc.h"

/* ---------- MSB-first bit writer ---------- */

typedef struct {
    unsigned char *buf;
    unsigned long cap;
    unsigned long bitpos;
    int err;
} BW;

static void bw_bit(BW *bw, unsigned int bit) {
    unsigned long byi;
    if (bw->err) return;
    byi = bw->bitpos >> 3;
    if (byi >= bw->cap) {
        unsigned long newcap = bw->cap ? bw->cap * 2 : 8192;
        unsigned char *nb;
        while (newcap <= byi) newcap *= 2;
        nb = (unsigned char *)realloc(bw->buf, newcap);
        if (!nb) { bw->err = 1; return; }
        memset(nb + bw->cap, 0, (size_t)(newcap - bw->cap));
        bw->buf = nb;
        bw->cap = newcap;
    }
    if (bit) bw->buf[byi] |= (unsigned char)(1U << (7 - (bw->bitpos & 7)));
    bw->bitpos++;
}

static void bw_put(BW *bw, unsigned long val, int nbits) {
    int i;
    for (i = nbits - 1; i >= 0; i--)
        bw_bit(bw, (unsigned int)((val >> i) & 1UL));
}

/* ---------- canonical Huffman codes ---------- */

static void make_codes(const int *lens, int n, unsigned int *codes) {
    int i, l, maxlen = 0;
    unsigned int code = 0;
    for (i = 0; i < n; i++) {
        codes[i] = 0;
        if (lens[i] > maxlen) maxlen = lens[i];
    }
    for (l = 1; l <= maxlen; l++) {
        for (i = 0; i < n; i++)
            if (lens[i] == l) codes[i] = code++;
        code <<= 1;
    }
}

/* ---------- LZ tokenizer (greedy, hash chains) ---------- */

#define HASH_SIZE 65536
#define MAX_CHAIN 256

typedef struct {
    unsigned char is_match;
    unsigned char lit;
    unsigned short len;
    unsigned long dist;
} TOK;

static unsigned long hash3(const unsigned char *p) {
    return (((unsigned long)p[0] << 10) ^
            ((unsigned long)p[1] << 5) ^ (unsigned long)p[2]) &
           (HASH_SIZE - 1);
}

static void insert_pos(const unsigned char *in, unsigned long insize,
                       long *heads, long *prev, unsigned long pos) {
    if (pos + 2 < insize) {
        unsigned long h = hash3(in + pos);
        prev[pos] = heads[h];
        heads[h] = (long)pos;
    }
}

static unsigned long find_match(const unsigned char *in, unsigned long insize,
                                const long *heads, const long *prev,
                                unsigned long pos, unsigned long max_len,
                                unsigned long max_dist,
                                unsigned long *dist_out) {
    unsigned long max_possible = insize - pos;
    unsigned long best = 0, best_dist = 0, attempts = 0;
    long cand;
    if (max_possible > max_len) max_possible = max_len;
    if (max_possible < 3) return 0;
    cand = heads[hash3(in + pos)];
    while (cand != -1L && attempts < MAX_CHAIN) {
        unsigned long c = (unsigned long)cand;
        unsigned long len = 0;
        if (c >= pos) break;
        if (pos - c > max_dist) break;
        if (best > 0 && best < max_possible &&
            in[c + best] != in[pos + best]) {
            cand = prev[c];
            attempts++;
            continue;
        }
        while (len < max_possible && in[c + len] == in[pos + len]) len++;
        if (len > best) {
            best = len;
            best_dist = pos - c;
            if (best >= max_possible) break;
        }
        cand = prev[c];
        attempts++;
    }
    *dist_out = best_dist;
    return best;
}

static int tokenize(const unsigned char *in, unsigned long insize,
                    unsigned long max_len, unsigned long max_dist,
                    TOK **tok_out, unsigned long *ntok_out) {
    TOK *toks;
    long *heads, *prev;
    unsigned long pos = 0, ntok = 0, i;
    *tok_out = 0;
    *ntok_out = 0;
    if (insize == 0) return 0;
    toks = (TOK *)malloc(sizeof(TOK) * insize);
    heads = (long *)malloc(sizeof(long) * HASH_SIZE);
    prev = (long *)malloc(sizeof(long) * insize);
    if (!toks || !heads || !prev) {
        free(toks); free(heads); free(prev);
        return -1;
    }
    for (i = 0; i < HASH_SIZE; i++) heads[i] = -1L;
    for (i = 0; i < insize; i++) prev[i] = -1L;
    while (pos < insize) {
        unsigned long dist = 0, len = 0, j;
        if (pos + 2 < insize)
            len = find_match(in, insize, heads, prev, pos,
                             max_len, max_dist, &dist);
        if (len >= 3) {
            toks[ntok].is_match = 1;
            toks[ntok].lit = 0;
            toks[ntok].len = (unsigned short)len;
            toks[ntok].dist = dist;
            ntok++;
            for (j = 0; j < len; j++) insert_pos(in, insize, heads, prev, pos + j);
            pos += len;
        } else {
            toks[ntok].is_match = 0;
            toks[ntok].lit = in[pos];
            toks[ntok].len = 1;
            toks[ntok].dist = 0;
            ntok++;
            insert_pos(in, insize, heads, prev, pos);
            pos++;
        }
    }
    free(heads);
    free(prev);
    *tok_out = toks;
    *ntok_out = ntok;
    return 0;
}

/* ---------- block header writers ---------- */

static int floor_log2_ul(unsigned long x) {
    int e = 0;
    while ((1UL << (e + 1)) <= x) e++;
    return e;
}

/* Code-length value: 3 bits plain, 7 extends with unary 1-bits + 0. */
static void bw_codevalue(BW *bw, int v) {
    if (v < 7) {
        bw_put(bw, (unsigned long)v, 3);
    } else {
        int i;
        bw_put(bw, 7UL, 3);
        for (i = 0; i < v - 7; i++) bw_put(bw, 1UL, 1);
        bw_put(bw, 0UL, 1);
    }
}

/* Meta/pre alphabet (19 symbols): count in 5 bits, lengths as code
 * values with a 2-bit zero-run inserted after the 3rd length, exactly
 * as the decoders consume them. */
static void bw_pre_header(BW *bw, const int *lens, int n) {
    int i;
    bw_put(bw, (unsigned long)n, 5);
    for (i = 0; i < n; i++) {
        bw_codevalue(bw, lens[i]);
        if (i == 2) bw_put(bw, 0UL, 2);
    }
}

/* Distance alphabet: count in cntbits, plain code values, no gap. */
static void bw_dist_header(BW *bw, const int *lens, int n, int cntbits) {
    int i;
    bw_put(bw, (unsigned long)n, cntbits);
    for (i = 0; i < n; i++) bw_codevalue(bw, lens[i]);
}

/* Lit/len lengths (510 symbols): 9-bit count, then each length coded
 * with the meta/pre tree as (length + 2). */
static void bw_lit_header(BW *bw, const int *litlens,
                          const int *prelens, const unsigned int *precodes) {
    int i;
    bw_put(bw, 510UL, 9);
    for (i = 0; i < 510; i++) {
        int sym = litlens[i] + 2;
        bw_put(bw, (unsigned long)precodes[sym], prelens[sym]);
    }
}

/* Fixed complete code lengths for methods 2/3. Every alphabet's
 * Kraft sum is exactly 1: pre 13x(1/16)+6x(1/32), lit/len
 * 2x(1/256)+508x(1/512), distances 2x(1/8)+12x(1/16). */
static void fixed_lens(int *pre, int *lit, int *dist, int ndist) {
    int i;
    for (i = 0; i < 19; i++) pre[i] = (i < 13) ? 4 : 5;
    for (i = 0; i < 510; i++) lit[i] = (i < 2) ? 8 : 9;
    for (i = 0; i < ndist; i++)
        dist[i] = (ndist == 17) ? ((i < 15) ? 4 : 5) : ((i < 2) ? 3 : 4);
}

/* Assign complete code lengths by frequency rank: the k used
 * symbols get lengths L or L-1 where L = ceil(log2(k)), the most
 * frequent getting the shorter length, so the Kraft sum is exactly
 * 1 and the maximum length is small (<=9 for 510 symbols). A single
 * used symbol gets a dummy partner so the code stays complete. */
static void rank_lens(const unsigned long *freq, int n, int *lens) {
    int used[510];
    int k = 0, i, j, L, x;
    for (i = 0; i < n; i++) {
        lens[i] = 0;
        if (freq[i]) used[k++] = i;
    }
    if (k == 0) return;
    if (k == 1) {
        lens[used[0]] = 1;
        for (i = 0; i < n; i++)
            if (!freq[i]) { lens[i] = 1; break; }
        return;
    }
    for (i = 1; i < k; i++) {
        int v = used[i];
        j = i - 1;
        while (j >= 0 && (freq[used[j]] < freq[v] ||
               (freq[used[j]] == freq[v] && used[j] > v))) {
            used[j + 1] = used[j];
            j--;
        }
        used[j + 1] = v;
    }
    L = 0;
    while ((1 << L) < k) L++;
    x = (1 << L) - k;
    for (i = 0; i < k; i++)
        lens[used[i]] = (i < x) ? (L > 1 ? L - 1 : 1) : L;
}

static int last_nonzero(const int *lens, int n) {
    int i;
    for (i = n - 1; i >= 0; i--)
        if (lens[i]) return i;
    return -1;
}

/* Encode lit/len lengths as meta symbols (0/1/2 are zero runs of
 * 1, 3+extra4 and 20+extra9; otherwise length+2). Returns the
 * token count; rsym/rextra/rebits are filled. */
static int lit_rle(const int *litlens, int cnt, int *rsym,
                   unsigned long *rextra, int *rebits) {
    int i = 0, n = 0;
    while (i < cnt) {
        if (litlens[i] != 0) {
            rsym[n] = litlens[i] + 2;
            rextra[n] = 0;
            rebits[n] = 0;
            n++;
            i++;
            continue;
        }
        {
            int j = i, run;
            while (j < cnt && litlens[j] == 0) j++;
            run = j - i;
            if (run == 1) {
                rsym[n] = 0; rextra[n] = 0; rebits[n] = 0; n++;
            } else if (run == 2) {
                rsym[n] = 0; rextra[n] = 0; rebits[n] = 0; n++;
                rsym[n] = 0; rextra[n] = 0; rebits[n] = 0; n++;
            } else if (run <= 18) {
                rsym[n] = 1; rextra[n] = (unsigned long)(run - 3); rebits[n] = 4; n++;
            } else if (run == 19) {
                rsym[n] = 1; rextra[n] = 15; rebits[n] = 4; n++;
                rsym[n] = 0; rextra[n] = 0; rebits[n] = 0; n++;
            } else {
                rsym[n] = 2; rextra[n] = (unsigned long)(run - 20); rebits[n] = 9; n++;
            }
            i = j;
        }
    }
    return n;
}

/* Dynamic meta header: count in 5 bits, code values with the 2-bit
 * zero-run after the 3rd length (exactly as the decoders consume
 * them, including when the count is exactly 3). */
static void bw_dyn_pre_header(BW *bw, const int *metalens, int metacnt) {
    int i = 0, gap = 0;
    bw_put(bw, (unsigned long)metacnt, 5);
    if (metacnt > 3) {
        while (3 + gap < metacnt && metalens[3 + gap] == 0 && gap < 3) gap++;
    }
    while (i < metacnt) {
        bw_codevalue(bw, metalens[i]);
        i++;
        if (i == 3) {
            bw_put(bw, (unsigned long)gap, 2);
            i += gap;
        }
    }
}

#define BLOCK_TOKENS_M7 16384UL
#define BLOCK_TOKENS_M23 32768UL

unsigned char *bsn_lz_encode(const unsigned char *in, unsigned long insize,
                             unsigned long *psize) {
    TOK *toks = 0;
    unsigned long ntok = 0, tpos = 0;
    BW bw;
    memset(&bw, 0, sizeof(bw));
    *psize = 0;
    if (tokenize(in, insize, 255UL, 32768UL, &toks, &ntok) != 0) return 0;
    while (tpos < ntok) {
        unsigned long chunk = ntok - tpos, i;
        unsigned long litfreq[510], distfreq[17], metafreq[19];
        int litlens[510], distlens[17], metalens[19];
        unsigned int litcodes[510], distcodes[17], metacodes[19];
        int rsym[1024], rebits[1024];
        unsigned long rextra[1024];
        int n_rle, litcnt, metacnt, distcnt, has_dist = 0;
        if (chunk > BLOCK_TOKENS_M7) chunk = BLOCK_TOKENS_M7;
        /* frequency counts for this block */
        memset(litfreq, 0, sizeof(litfreq));
        memset(distfreq, 0, sizeof(distfreq));
        memset(metafreq, 0, sizeof(metafreq));
        for (i = 0; i < chunk; i++) {
            TOK *t = &toks[tpos + i];
            if (!t->is_match) {
                litfreq[t->lit]++;
            } else {
                int d;
                litfreq[253 + (int)t->len]++;
                if (t->dist == 1) d = 0;
                else if (t->dist == 2) d = 1;
                else d = floor_log2_ul(t->dist - 1) + 1;
                distfreq[d]++;
                has_dist = 1;
            }
        }
        /* sparse complete tables by frequency rank */
        rank_lens(litfreq, 510, litlens);
        litcnt = last_nonzero(litlens, 510) + 1;
        n_rle = lit_rle(litlens, litcnt, rsym, rextra, rebits);
        for (i = 0; i < (unsigned long)n_rle; i++) metafreq[rsym[i]]++;
        rank_lens(metafreq, 19, metalens);
        metacnt = last_nonzero(metalens, 19) + 1;
        if (has_dist) {
            rank_lens(distfreq, 17, distlens);
            distcnt = last_nonzero(distlens, 17) + 1;
        } else {
            distcnt = 0;
        }
        make_codes(litlens, 510, litcodes);
        make_codes(metalens, 19, metacodes);
        if (has_dist) make_codes(distlens, 17, distcodes);
        /* block header */
        bw_put(&bw, chunk, 16);
        bw_dyn_pre_header(&bw, metalens, metacnt);
        bw_put(&bw, (unsigned long)litcnt, 9);
        for (i = 0; i < (unsigned long)n_rle; i++) {
            bw_put(&bw, (unsigned long)metacodes[rsym[i]], metalens[rsym[i]]);
            if (rebits[i] > 0) bw_put(&bw, rextra[i], rebits[i]);
        }
        if (!has_dist) {
            bw_put(&bw, 0UL, 5);   /* const distance table */
            bw_put(&bw, 0UL, 5);
        } else {
            bw_put(&bw, (unsigned long)distcnt, 5);
            for (i = 0; i < (unsigned long)distcnt; i++)
                bw_codevalue(&bw, distlens[i]);
        }
        /* tokens */
        for (i = 0; i < chunk; i++) {
            TOK *t = &toks[tpos + i];
            if (!t->is_match) {
                bw_put(&bw, (unsigned long)litcodes[t->lit], litlens[t->lit]);
            } else {
                int sym = 253 + (int)t->len;
                int d, extra = 0;
                unsigned long val = 0;
                bw_put(&bw, (unsigned long)litcodes[sym], litlens[sym]);
                if (t->dist == 1) {
                    d = 0;
                } else if (t->dist == 2) {
                    d = 1;
                } else {
                    unsigned long x = t->dist - 1;
                    extra = floor_log2_ul(x);
                    d = extra + 1;
                    val = x - (1UL << extra);
                }
                bw_put(&bw, (unsigned long)distcodes[d], distlens[d]);
                if (extra > 0) bw_put(&bw, val, extra);
            }
        }
        tpos += chunk;
    }
    bw_put(&bw, 0UL, 32);  /* trailing flush/lookahead margin */
    free(toks);
    if (bw.err) { free(bw.buf); return 0; }
    *psize = (bw.bitpos + 7) >> 3;
    if (!bw.buf) {
        bw.buf = (unsigned char *)malloc(1);
        if (!bw.buf) return 0;
    }
    return bw.buf;
}

unsigned char *bsn_m23_encode(const unsigned char *in, unsigned long insize,
                              unsigned long *psize, int method) {
    TOK *toks = 0;
    unsigned long ntok = 0, tpos = 0;
    unsigned long max_len, max_dist;
    int prelens[19], litlens[510], distlens[14];
    unsigned int precodes[19], litcodes[510], distcodes[14];
    BW bw;
    if (method != 2 && method != 3 && method != 6) return 0;
    if (method == 2) { max_len = 127UL; max_dist = 16384UL; }
    else { max_len = 63UL; max_dist = 32768UL; }
    memset(&bw, 0, sizeof(bw));
    *psize = 0;
    if (tokenize(in, insize, max_len, max_dist, &toks, &ntok) != 0) return 0;
    fixed_lens(prelens, litlens, distlens, 14);
    make_codes(prelens, 19, precodes);
    make_codes(litlens, 510, litcodes);
    make_codes(distlens, 14, distcodes);
    while (tpos < ntok) {
        unsigned long chunk = ntok - tpos, i;
        if (chunk > BLOCK_TOKENS_M23) chunk = BLOCK_TOKENS_M23;
        bw_put(&bw, chunk, 16);
        bw_pre_header(&bw, prelens, 19);
        bw_lit_header(&bw, litlens, prelens, precodes);
        bw_dist_header(&bw, distlens, 14, 4);
        for (i = 0; i < chunk; i++) {
            TOK *t = &toks[tpos + i];
            if (!t->is_match) {
                bw_put(&bw, (unsigned long)litcodes[t->lit], litlens[t->lit]);
            } else {
                int tier, sym, c, extra = 0;
                unsigned long off, base_code, val = 0;
                if (method == 2) {
                    if (t->dist <= 8192UL) { tier = 0; off = 0UL; }
                    else { tier = 1; off = 0x2000UL; }
                    sym = 253 + (int)t->len + tier * 128;
                } else {
                    if (t->dist <= 8192UL) { tier = 0; off = 0UL; }
                    else if (t->dist <= 16384UL) { tier = 1; off = 0x2000UL; }
                    else if (t->dist <= 24576UL) { tier = 2; off = 0x4000UL; }
                    else { tier = 3; off = 0x6000UL; }
                    sym = 253 + (int)t->len + tier * 64;
                }
                base_code = (t->dist - 1) - off;
                if (base_code == 0) {
                    c = 0;
                } else {
                    extra = floor_log2_ul(base_code);
                    c = extra + 1;
                    val = base_code - (1UL << extra);
                }
                bw_put(&bw, (unsigned long)litcodes[sym], litlens[sym]);
                bw_put(&bw, (unsigned long)distcodes[c], distlens[c]);
                if (c > 0 && extra > 0) bw_put(&bw, val, extra);
            }
        }
        tpos += chunk;
    }
    bw_put(&bw, 0UL, 32);  /* trailing flush/lookahead margin */
    free(toks);
    if (bw.err) { free(bw.buf); return 0; }
    *psize = (bw.bitpos + 7) >> 3;
    if (!bw.buf) {
        bw.buf = (unsigned char *)malloc(1);
        if (!bw.buf) return 0;
    }
    return bw.buf;
}
