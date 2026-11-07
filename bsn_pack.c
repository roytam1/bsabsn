/* bsn_pack.c - archive writer for PTS BSA/BSN archives (the packer
 * counterpart of bsn_unpack.c).
 *
 * Usage:
 *   bsn_pack archive.bsa file...     create a BSA archive
 *   bsn_pack archive.bsn file...     create a BSN archive
 *   bsn_pack -0 archive.bsa file...  store files uncompressed
 *   bsn_pack -7 archive.bsa file...  compress with method 7 (default)
 *   bsn_pack -3 archive.bsa file...  compress with method 3 (BSA only)
 *   bsn_pack -2 archive.bsa file...  compress with method 2 (BSA only)
 *   bsn_pack -r archive.bsa dir...   add directories recursively
 *   bsn_pack -v ...                  list each file as it is packed
 *
 * The archive format (BSA or BSN) is chosen from the archive name
 * extension. Explicit file arguments are stored under their base
 * names; entries added with -r are stored relative to the parent of
 * the directory given, so the directory name itself is kept, with
 * '/' as the separator. BSN archives get explicit directory entries
 * (flags 0x0A00) for every directory; BSA has no directory entry
 * type, so empty directories are skipped there and subfolders are
 * represented only by the path prefixes of their files.
 *
 * Compression is done by bsn_enc.c: method 7 for BSN (and BSA), and
 * methods 2/3 for BSA. Method 9 (PPM) has no encoder and is rejected.
 * For BSA, whenever a compressed stream would not be smaller than
 * the file itself (or is empty), the file is stored uncompressed
 * instead, like the original BSA16 writer did. For BSN the original
 * writer always compresses (even when that expands a tiny file, e.g.
 * 12 -> 23 bytes in PTSDOS.BSN), and bsa32's BSN stored reader only
 * copes with the first stored entry in an archive, so BSN files are
 * likewise always compressed unless -0 is given explicitly.
 *
 * BSA entries carry no CRC: they are finished with the w1 byte-sum
 * checksum and the DOS timestamp, exactly as bsn_unpack.c verifies
 * them. BSN entries carry both the L-block CRC32 and the data
 * CRC32. Timestamps come from the files' modification times.
 *
 * Build with MSVC6:
 *   CL.EXE /nologo /O2 /Febsn_pack.exe bsn_pack.c bsn_enc.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <io.h>
#include "bsn_enc.h"

/* ---------- checksums (same as bsn_unpack.c) ---------- */

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

static unsigned int crc32_buf(const unsigned char *buf, unsigned long len) {
    unsigned int crc = 0xFFFFFFFFU;
    unsigned long i;
    if (!crc_table_ready) make_crc_table();
    for (i = 0; i < len; i++)
        crc = crc_table[(crc ^ buf[i]) & 0xFF] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFFU;
}

static unsigned int bytesum_buf(const unsigned char *buf, unsigned long len) {
    unsigned int s = 0;
    unsigned long i;
    for (i = 0; i < len; i++) s += buf[i];
    return s & 0xFFFFU;
}

/* ---------- endian helpers ---------- */

static void put_le16(unsigned char *p, unsigned int v) {
    p[0] = (unsigned char)(v & 0xFF);
    p[1] = (unsigned char)((v >> 8) & 0xFF);
}

static void put_le32(unsigned char *p, unsigned long v) {
    p[0] = (unsigned char)(v & 0xFF);
    p[1] = (unsigned char)((v >> 8) & 0xFF);
    p[2] = (unsigned char)((v >> 16) & 0xFF);
    p[3] = (unsigned char)((v >> 24) & 0xFF);
}

static void put_be16(unsigned char *p, unsigned int v) {
    p[0] = (unsigned char)((v >> 8) & 0xFF);
    p[1] = (unsigned char)(v & 0xFF);
}

static void put_be32(unsigned char *p, unsigned long v) {
    p[0] = (unsigned char)((v >> 24) & 0xFF);
    p[1] = (unsigned char)((v >> 16) & 0xFF);
    p[2] = (unsigned char)((v >> 8) & 0xFF);
    p[3] = (unsigned char)(v & 0xFF);
}

static int wr_bytes(FILE *f, const void *p, unsigned long n) {
    if (n == 0) return 0;
    return fwrite(p, 1, n, f) == n ? 0 : -1;
}

/* ---------- DOS date/time ---------- */

static unsigned long dos_timestamp(time_t t) {
    struct tm *lt = localtime(&t);
    int year, date, timev;
    if (!lt) return 0;
    year = lt->tm_year + 1900;
    if (year < 1980) {
        date = (1 << 5) | 1;
        return ((unsigned long)date << 16) | 0UL;
    }
    if (year > 2107) year = 2107;
    date = ((year - 1980) << 9) | ((lt->tm_mon + 1) << 5) | lt->tm_mday;
    timev = (lt->tm_hour << 11) | (lt->tm_min << 5) | (lt->tm_sec / 2);
    return ((unsigned long)date << 16) | (unsigned long)timev;
}

static int stat_path(const char *path, unsigned long *size,
                     unsigned long *ts, int *is_dir) {
    struct stat st;
    if (stat(path, &st) != 0) return -1;
    *is_dir = (st.st_mode & _S_IFDIR) != 0;
    *size = (unsigned long)st.st_size;
    *ts = dos_timestamp(st.st_mtime);
    return 0;
}

/* ---------- path helpers ---------- */

static char *xstrdup(const char *s) {
    size_t n = strlen(s) + 1;
    char *p = (char *)malloc(n);
    if (p) memcpy(p, s, n);
    return p;
}

static const char *base_name(const char *path) {
    const char *p = path, *last = 0;
    while (*p) {
        if (*p == '/' || *p == '\\') last = p;
        p++;
    }
    return last ? last + 1 : path;
}

/* Stored name of a directory argument: its base name, with trailing
 * separators removed ("" for "data/", "data" for "data"). */
static char *stored_root(const char *path) {
    const char *end = path + strlen(path);
    const char *start = end;
    char *out;
    size_t n;
    while (end > path && (end[-1] == '/' || end[-1] == '\\')) end--;
    while (start > path && start[-1] != '/' && start[-1] != '\\') start--;
    n = (size_t)(end - start);
    out = (char *)malloc(n + 1);
    if (!out) return 0;
    memcpy(out, start, n);
    out[n] = 0;
    return out;
}

static char *join_fs(const char *dir, const char *name) {
    size_t nd = strlen(dir), nn = strlen(name);
    int need_sep = nd > 0 && dir[nd - 1] != '/' && dir[nd - 1] != '\\';
    char *out = (char *)malloc(nd + (need_sep ? 1 : 0) + nn + 1);
    if (!out) return 0;
    memcpy(out, dir, nd);
    if (need_sep) out[nd++] = '\\';
    memcpy(out + nd, name, nn + 1);
    return out;
}

static char *join_stored(const char *dir, const char *name) {
    size_t nd = strlen(dir), nn = strlen(name);
    char *out;
    if (nd == 0) return xstrdup(name);
    out = (char *)malloc(nd + 1 + nn + 1);
    if (!out) return 0;
    memcpy(out, dir, nd);
    out[nd] = '/';
    memcpy(out + nd + 1, name, nn + 1);
    return out;
}

static int same_path(const char *a, const char *b) {
    char fa[_MAX_PATH], fb[_MAX_PATH];
    const char *pa = _fullpath(fa, a, sizeof(fa));
    const char *pb = _fullpath(fb, b, sizeof(fb));
    if (!pa || !pb) return strcmp(a, b) == 0;
    return _stricmp((char *)pa, (char *)pb) == 0;
}

/* ---------- entry list ---------- */

typedef struct {
    char *stored;   /* archive member name, '/' separated */
    char *path;     /* filesystem path to read */
    unsigned long ts;
    unsigned long size;
    int is_dir;
} ENTRY;

typedef struct {
    ENTRY *v;
    int n, cap;
} ENTRIES;

static int entries_add(ENTRIES *es, const char *stored, const char *path,
                       unsigned long ts, unsigned long size, int is_dir) {
    ENTRY *e;
    if (es->n >= es->cap) {
        int ncap = es->cap ? es->cap * 2 : 16;
        ENTRY *nv = (ENTRY *)realloc(es->v, sizeof(ENTRY) * (size_t)ncap);
        if (!nv) return -1;
        es->v = nv;
        es->cap = ncap;
    }
    e = &es->v[es->n];
    e->stored = xstrdup(stored);
    e->path = xstrdup(path);
    if (!e->stored || !e->path) return -1;
    e->ts = ts;
    e->size = size;
    e->is_dir = is_dir;
    es->n++;
    return 0;
}

static void entries_free(ENTRIES *es) {
    int i;
    for (i = 0; i < es->n; i++) {
        free(es->v[i].stored);
        free(es->v[i].path);
    }
    free(es->v);
    es->v = 0;
    es->n = es->cap = 0;
}

typedef struct {
    char *name;
    int is_dir;
} CHILD;

static int cmp_child(const void *a, const void *b) {
    return strcmp(((const CHILD *)a)->name, ((const CHILD *)b)->name);
}

/* Recursively collect the contents of fsdir (stored under storeddir).
 * Directory entries are added only when want_dirs is set (BSN);
 * BSA represents folders solely through file name prefixes. */
static int scan_dir(ENTRIES *es, const char *fsdir, const char *storeddir,
                    const char *archive_full, int want_dirs, int verbose) {
    char *pattern;
    CHILD *kids = 0;
    int nk = 0, cap = 0, i, rc = 0;
    struct _finddata_t fd;
    long h;
    size_t nd;
    pattern = (char *)malloc(strlen(fsdir) + 3);
    if (!pattern) return -1;
    nd = strlen(fsdir);
    sprintf(pattern, "%s%s*", fsdir,
            (nd > 0 && (fsdir[nd - 1] == '/' || fsdir[nd - 1] == '\\'))
                ? "" : "\\");
    h = _findfirst(pattern, &fd);
    if (h == -1L) { free(pattern); return -1; }
    for (;;) {
        if (strcmp(fd.name, ".") != 0 && strcmp(fd.name, "..") != 0) {
            if (nk >= cap) {
                int ncap = cap ? cap * 2 : 16;
                CHILD *nv = (CHILD *)realloc(kids, sizeof(CHILD) * (size_t)ncap);
                if (!nv) { rc = -1; break; }
                kids = nv;
                cap = ncap;
            }
            kids[nk].name = xstrdup(fd.name);
            if (!kids[nk].name) { rc = -1; break; }
            kids[nk].is_dir = (fd.attrib & _A_SUBDIR) != 0;
            nk++;
        }
        if (_findnext(h, &fd) != 0) break;
    }
    _findclose(h);
    free(pattern);
    if (rc != 0) {
        for (i = 0; i < nk; i++) free(kids[i].name);
        free(kids);
        return -1;
    }
    qsort(kids, (size_t)nk, sizeof(CHILD), cmp_child);
    for (i = 0; i < nk; i++) {
        char *fs = join_fs(fsdir, kids[i].name);
        char *st = join_stored(storeddir, kids[i].name);
        unsigned long size = 0, ts = 0;
        int is_dir = 0;
        if (!fs || !st) rc = -1;
        else if (archive_full && !kids[i].is_dir && same_path(fs, archive_full)) {
            if (verbose)
                printf("skipping the archive itself: %s\n", fs);
        }
        else if (stat_path(fs, &size, &ts, &is_dir) != 0) {
            fprintf(stderr, "warning: cannot stat %s, skipped\n", fs);
        }
        else if (is_dir) {
            if (want_dirs &&
                entries_add(es, st, fs, ts, 0, 1) != 0) rc = -1;
            if (rc == 0 && scan_dir(es, fs, st, archive_full, want_dirs, verbose) != 0)
                rc = -1;
        }
        else {
            if (entries_add(es, st, fs, ts, size, 0) != 0) rc = -1;
        }
        free(fs);
        free(st);
        if (rc != 0) break;
    }
    for (i = 0; i < nk; i++) free(kids[i].name);
    free(kids);
    return rc;
}

static int add_input(ENTRIES *es, const char *path, int recursive,
                     const char *archive, const char *archive_full,
                     int want_dirs, int verbose) {
    unsigned long size = 0, ts = 0;
    int is_dir = 0;
    if (stat_path(path, &size, &ts, &is_dir) != 0) {
        fprintf(stderr, "error: cannot stat '%s'\n", path);
        return -1;
    }
    if (!is_dir) {
        const char *bn = base_name(path);
        if (same_path(path, archive)) {
            fprintf(stderr, "error: archive '%s' cannot be its own input\n",
                    archive);
            return -1;
        }
        if (bn[0] == 0) {
            fprintf(stderr, "error: bad file name '%s'\n", path);
            return -1;
        }
        if (entries_add(es, bn, path, ts, size, 0) != 0) return -1;
        return 0;
    }
    if (!recursive) {
        fprintf(stderr, "error: '%s' is a directory (use -r to add it recursively)\n",
                path);
        return -1;
    }
    {
        char *root = stored_root(path);
        int rc = 0;
        if (!root) return -1;
        if (root[0] != 0 && want_dirs) {
            if (entries_add(es, root, path, ts, 0, 1) != 0) rc = -1;
        }
        if (rc == 0 &&
            scan_dir(es, path, root, archive_full, want_dirs, verbose) != 0)
            rc = -1;
        free(root);
        return rc;
    }
}

/* ---------- reading one file ---------- */

static int read_whole(const char *path, unsigned char **buf,
                      unsigned long *size) {
    FILE *f = fopen(path, "rb");
    long sz;
    if (!f) return -1;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    sz = ftell(f);
    if (sz < 0) { fclose(f); return -1; }
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return -1; }
    *buf = (unsigned char *)malloc((size_t)sz ? (size_t)sz : 1);
    if (!*buf) { fclose(f); return -1; }
    if (sz > 0 && fread(*buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(*buf);
        *buf = 0;
        fclose(f);
        return -1;
    }
    fclose(f);
    *size = (unsigned long)sz;
    return 0;
}

/* ---------- BSN writer ---------- */

static int write_bsn(FILE *f, ENTRIES *es, int method, int verbose,
                     unsigned long *tot_orig, unsigned long *tot_packed) {
    static const unsigned char gmagic[6] = {0xFF, 'B', 'S', 'G', 0x00, 0x01};
    int i, nfiles = 0;
    if (wr_bytes(f, gmagic, 6) != 0) return -1;
    for (i = 0; i < es->n; i++) {
        ENTRY *e = &es->v[i];
        unsigned char *data = 0, *pbuf = 0, *blk = 0;
        unsigned long orig = 0, packed = 0, filecrc = 0, L;
        int stored = 1;
        if (e->is_dir) {
            L = 21UL + (unsigned long)strlen(e->stored);
            blk = (unsigned char *)malloc(L ? (size_t)L : 1);
            if (!blk) return -1;
            put_be16(blk, 0x0A00);
            put_be16(blk + 2, 1);
            put_be32(blk + 4, e->ts);
            memcpy(blk + 8, e->stored, strlen(e->stored) + 1);
            put_be32(blk + 8 + strlen(e->stored) + 1, 0);
            put_be32(blk + 8 + strlen(e->stored) + 5, 0);
            put_be32(blk + 8 + strlen(e->stored) + 9, 0);
        } else {
            unsigned char magic[4];
            unsigned int crc;
            if (read_whole(e->path, &data, &orig) != 0) {
                fprintf(stderr, "error: cannot read '%s'\n", e->path);
                return -1;
            }
            packed = orig;
            if (method != 0 && orig > 0) {
                unsigned long encsize = 0;
                unsigned char *enc = bsn_lz_encode(data, orig, &encsize);
                if (enc) {
                    /* BSN: like the original writer, always emit the
                     * compressed stream, even when it is larger than
                     * the file (bsa32's BSN stored reader only copes
                     * with the first stored entry in an archive, so a
                     * stored fallback would break multi-file BSN
                     * archives in the original tool). Stored is used
                     * here only for an explicit -0 or if the encoder
                     * fails. */
                    pbuf = enc;
                    packed = encsize;
                    stored = 0;
                }
            }
            filecrc = orig ? crc32_buf(data, orig) : 0;
            L = 21UL + (unsigned long)strlen(e->stored);
            if (L > 65535UL) {
                fprintf(stderr, "error: name too long for BSN: %s\n", e->stored);
                free(data);
                free(pbuf);
                return -1;
            }
            blk = (unsigned char *)malloc((size_t)L);
            if (!blk) { free(data); free(pbuf); return -1; }
            /* BSN stored entries carry flag 0x0800 (bsa32 rejects a
             * packed_size == orig_size entry without it); directory
             * entries are 0x0A00, i.e. stored plus 0x0200. Empty
             * files keep flags 0, as the original writer emits them. */
            put_be16(blk, (stored && orig > 0) ? 0x0800 : 0);
            put_be16(blk + 2, 0);
            put_be32(blk + 4, e->ts);
            memcpy(blk + 8, e->stored, strlen(e->stored) + 1);
            put_be32(blk + 8 + strlen(e->stored) + 1, orig);
            put_be32(blk + 8 + strlen(e->stored) + 5, packed);
            put_be32(blk + 8 + strlen(e->stored) + 9, filecrc);
            crc = crc32_buf(blk, L);
            magic[0] = 0xFF; magic[1] = 'B'; magic[2] = 'S'; magic[3] = 'A';
            {
                unsigned char lh[2], ch[4];
                put_be16(lh, (unsigned int)L);
                put_be32(ch, crc);
                if (wr_bytes(f, magic, 4) != 0 ||
                    wr_bytes(f, lh, 2) != 0 ||
                    wr_bytes(f, blk, (unsigned long)L) != 0 ||
                    wr_bytes(f, ch, 4) != 0) {
                    free(blk); free(data); free(pbuf);
                    return -1;
                }
            }
            if (wr_bytes(f, stored ? data : pbuf, packed) != 0) {
                free(blk); free(data); free(pbuf);
                return -1;
            }
            free(blk);
            free(data);
            free(pbuf);
            nfiles++;
            *tot_orig += orig;
            *tot_packed += packed;
            if (verbose)
                printf("%s: %lu -> %lu (%s)\n", e->stored, orig, packed,
                       stored ? "stored" : "method 7");
            continue;
        }
        /* directory entry */
        {
            unsigned char magic[4], lh[2], ch[4];
            unsigned int crc = crc32_buf(blk, L);
            magic[0] = 0xFF; magic[1] = 'B'; magic[2] = 'S'; magic[3] = 'A';
            put_be16(lh, (unsigned int)L);
            put_be32(ch, crc);
            if (wr_bytes(f, magic, 4) != 0 ||
                wr_bytes(f, lh, 2) != 0 ||
                wr_bytes(f, blk, (unsigned long)L) != 0 ||
                wr_bytes(f, ch, 4) != 0) {
                free(blk);
                return -1;
            }
        }
        free(blk);
        if (verbose) printf("%s: (directory)\n", e->stored);
    }
    (void)nfiles;
    return 0;
}

/* ---------- BSA writer ---------- */

static int write_bsa(FILE *f, ENTRIES *es, int method, int verbose,
                     unsigned long *tot_orig, unsigned long *tot_packed) {
    int i;
    for (i = 0; i < es->n; i++) {
        ENTRY *e = &es->v[i];
        unsigned char *data = 0, *pbuf = 0, *hdr;
        unsigned long orig = 0, packed = 0, nlen;
        unsigned int w1;
        int stored = 1, bytemethod;
        if (e->is_dir) continue;    /* BSA has no directory entries */
        if (read_whole(e->path, &data, &orig) != 0) {
            fprintf(stderr, "error: cannot read '%s'\n", e->path);
            return -1;
        }
        packed = orig;
        if (method != 0 && orig > 0) {
            unsigned long encsize = 0;
            unsigned char *enc = 0;
            if (method == 7) enc = bsn_lz_encode(data, orig, &encsize);
            else enc = bsn_m23_encode(data, orig, &encsize, method);
            if (enc && encsize < orig) {
                pbuf = enc;
                packed = encsize;
                stored = 0;
            } else {
                free(enc);
            }
        }
        bytemethod = stored ? 0 : method;
        w1 = orig ? bytesum_buf(data, orig) : 0;
        nlen = (unsigned long)strlen(e->stored);
        if (nlen > 255UL) {
            fprintf(stderr, "error: name too long for BSA: %s\n", e->stored);
            free(data); free(pbuf);
            return -1;
        }
        hdr = (unsigned char *)malloc((size_t)(24UL + nlen));
        if (!hdr) { free(data); free(pbuf); return -1; }
        hdr[0] = (unsigned char)(22UL + nlen);
        hdr[1] = 0;
        hdr[2] = 0xAE;
        hdr[3] = (unsigned char)bytemethod;
        put_le32(hdr + 4, packed);
        put_le32(hdr + 8, orig);
        put_le32(hdr + 12, e->ts);
        put_le16(hdr + 16, w1);
        put_le16(hdr + 18, 0);
        put_le16(hdr + 20, 0x20);
        hdr[22] = (unsigned char)nlen;
        memcpy(hdr + 23, e->stored, (size_t)nlen);
        hdr[23 + nlen] = 0;
        if (wr_bytes(f, hdr, 24UL + nlen) != 0 ||
            wr_bytes(f, stored ? data : pbuf, packed) != 0) {
            free(hdr); free(data); free(pbuf);
            return -1;
        }
        free(hdr);
        free(data);
        free(pbuf);
        *tot_orig += orig;
        *tot_packed += packed;
        if (verbose)
            printf("%s: %lu -> %lu (%s)\n", e->stored, orig, packed,
                   stored ? "stored" : (method == 7 ? "method 7" :
                   (method == 2 ? "method 2" : "method 3")));
    }
    {
        static const unsigned char term[2] = {0, 0};
        if (wr_bytes(f, term, 2) != 0) return -1;
    }
    return 0;
}

/* ---------- main ---------- */

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [-0|-7|-2|-3] [-r] [-v] archive[.bsa|.bsn] file...\n"
        "  -0  store files uncompressed\n"
        "  -7  method 7 compression (default; the only compressed "
        "BSN method)\n"
        "  -2  method 2 compression (BSA archives only)\n"
        "  -3  method 3 compression (BSA archives only)\n"
        "  -r  add directories recursively\n"
        "  -v  list each file as it is packed\n", prog);
}

static int has_ext(const char *name, const char *ext) {
    size_t ln = strlen(name), le = strlen(ext);
    if (ln < le) return 0;
    return _stricmp(name + ln - le, ext) == 0;
}

int main(int argc, char **argv) {
    int method = 7, recursive = 0, verbose = 0, ai = 1, format = 0;
    int i, j, rc = 1;
    const char *archive;
    char archive_full[_MAX_PATH];
    ENTRIES es;
    FILE *f;
    unsigned long tot_orig = 0, tot_packed = 0;
    memset(&es, 0, sizeof(es));
    if (argc < 3) { usage(argv[0]); return 1; }
    while (ai < argc && argv[ai][0] == '-' && argv[ai][1] != 0) {
        if (strcmp(argv[ai], "-0") == 0) method = 0;
        else if (strcmp(argv[ai], "-7") == 0) method = 7;
        else if (strcmp(argv[ai], "-2") == 0) method = 2;
        else if (strcmp(argv[ai], "-3") == 0) method = 3;
        else if (strcmp(argv[ai], "-r") == 0) recursive = 1;
        else if (strcmp(argv[ai], "-v") == 0) verbose = 1;
        else if (strcmp(argv[ai], "-9") == 0) {
            fprintf(stderr, "error: method 9 (PPM) has no encoder; "
                    "only stored, method 7 and (for BSA) methods 2/3 "
                    "can be written\n");
            return 1;
        }
        else {
            fprintf(stderr, "error: unknown option '%s'\n", argv[ai]);
            usage(argv[0]);
            return 1;
        }
        ai++;
    }
    if (argc - ai < 2) { usage(argv[0]); return 1; }
    archive = argv[ai++];
    if (has_ext(archive, ".bsa")) format = 1;
    else if (has_ext(archive, ".bsn")) format = 2;
    else {
        fprintf(stderr, "error: archive name must end in .bsa or .bsn: %s\n",
                archive);
        return 1;
    }
    if (format == 2 && (method == 2 || method == 3)) {
        fprintf(stderr, "error: methods 2/3 only exist in BSA archives; "
                "use -7 or -0 for BSN\n");
        return 1;
    }
    if (!_fullpath(archive_full, archive, sizeof(archive_full)))
        strcpy(archive_full, archive);
    for (i = ai; i < argc; i++) {
        if (add_input(&es, argv[i], recursive, archive, archive_full,
                      format == 2, verbose) != 0) {
            entries_free(&es);
            return 1;
        }
    }
    if (es.n == 0) {
        fprintf(stderr, "error: nothing to pack\n");
        entries_free(&es);
        return 1;
    }
    for (i = 0; i < es.n; i++) {
        for (j = i + 1; j < es.n; j++) {
            if (_stricmp(es.v[i].stored, es.v[j].stored) == 0) {
                fprintf(stderr, "error: duplicate archive name '%s'\n",
                        es.v[i].stored);
                entries_free(&es);
                return 1;
            }
        }
    }
    f = fopen(archive, "wb");
    if (!f) {
        perror("fopen archive");
        entries_free(&es);
        return 1;
    }
    if (format == 1)
        rc = write_bsa(f, &es, method, verbose, &tot_orig, &tot_packed);
    else
        rc = write_bsn(f, &es, method, verbose, &tot_orig, &tot_packed);
    fclose(f);
    if (rc != 0) {
        fprintf(stderr, "error: failed writing archive %s\n", archive);
        entries_free(&es);
        return 1;
    }
    printf("Packed %s: %d member(s), %lu -> %lu bytes\n", archive, es.n,
           tot_orig, tot_packed);
    entries_free(&es);
    return 0;
}
