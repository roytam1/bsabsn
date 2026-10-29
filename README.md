# bsn_unpack — PTS BSA/BSN archive extractor

C reimplementation (MSVC6, C89) of the PTS BSA/BSN archive handling
from `bsa32.exe` 2.3, verified byte-for-byte against the original
DOS/Windows tools. Parses both container formats and fully
decompresses methods 0, 2, 3, 7 and 9 (plus decode paths for
methods 5/6, pending real test vectors).

## Quick start

```
bsn_unpack archive[.bsn|.bsa] [outdir]   extract (default, outdir = bsn_out)
bsn_unpack t archive[.bsn|.bsa]          test integrity, no files written
bsn_unpack l archive[.bsn|.bsa]          list contents (sizes, dates, methods)
```

Examples:

```
bsn_unpack sample0.bsa out
bsn_unpack t m3.bsa            # decode + verify, write nothing
bsn_unpack l samplep.bsn       # table with SIZE/PACKED/DATE/METHOD/NAME
```

`bsn_decode` is a CLI test wrapper for raw packed streams:

```
bsn_decode packed outsize out [expected]
bsn_decode -9 packed psize outsize out [expected]   # method 9 (PPM)
bsn_decode -2|-3|-5|-6 packed psize outsize out [expected]
```

## Build (MSVC6)

```bat
call "C:\Program Files (x86)\Microsoft Visual Studio\VC98\Bin\VCVARS32.BAT"
CL.EXE /nologo /O2 /Febsn_unpack.exe bsn_unpack.c bsn_lz.c bsn_m23.c bsn_ppm.c
CL.EXE /nologo /O2 /Febsn_decode.exe bsn_decode.c bsn_lz.c bsn_m23.c bsn_ppm.c
```

Sources: `bsn_unpack.c` (containers + CLI), `bsn_lz.c` (method 7),
`bsn_m23.c` (methods 2/3/5/6), `bsn_ppm.c` (method 9).

## Method support

| Method | BSN | BSA | Status |
|---|---|---|---|
| 0 stored | yes | yes | verified |
| 2 LZSS+Huffman 16K | — | yes | verified byte-exact (`m2.bsa`) |
| 3 LZSS+Huffman 32K | — | yes | verified byte-exact (`m3.bsa`, `Root.mnx`) |
| 5 LZSS+Huffman | — | yes | decode path wired but **unvalidated** — no packer emits flag 05, no vector exists |
| 6 LZSS+Huffman | — | yes | same code path as 3 (wrappers instruction-identical), no flag-06 vector exists |
| 7 LZ77+Huffman | yes | yes | verified byte-exact, all levels |
| 9 PPM | yes | as flag 07 | verified byte-exact (`samplep.bsn`, `230-pp.bsn`); BSA writers store PPM marked 7, so it is retried when method 7 fails (the originals cannot extract such files at all) |
| 10 | yes | — | clean "unsupported" error (no vectors) |
| 1 | — | — | rejected (BSA16-only method, no vectors, not implemented) |

BSA has no per-entry CRC. Integrity comes from: produced size ==
declared orig size for every entry, CRC32 for BSN entries, and the
`w1` byte-sum checksum (mod 2^16 of the original data) which BSA16 /
BSA200 verify after extraction — `bsn_unpack` verifies it on extract
for methods 2/3/5/6 and in `t` mode for all BSA methods.

## Test corpus (all vectors in this repo)

- `sample.bsn`, `sample0–4.bsn`, `samplep.bsn` — BSN, methods 7/9
- `sample0–4.bsa`, `samplep.bsa` — BSA, methods 7 / PPM-as-7
- `m2.bsa` — BSA method 2 (BSA16 lineage)
- `m3.bsa` + `Root.mnx` — BSA method 3 (491520 bytes, exercises the 64 KiB ring)
- `230-p.bsn`, `230-pp.bsn` — BSA2-230 output; packed streams are byte-identical to bsa32 2.3 output, only the global-flags byte differs (`0x0080` vs `0x0001`)
- `193.bsa`, `193max.bsa`, `sample-p.bsa` (= 193max), `sample-q.bsa` — BSA195 method-7 variants
- `PTSDOS.BSN` — real PTS-DOS archive: 135 entries in `ptsdos/` subfolders, incl. 4 directory entries and cross-entry LZ references
- `193.bsa`, `193max.bsa`, `sample-p.bsa` (= 193max), `sample-q.bsa` — BSA195 method-7 variants
- `sample.txt` — reference plaintext (CRLF, 18340 bytes, matching every `sample*` archive)

All of the above extract byte-identical (and `t`/`l` clean) with
`bsn_unpack`; ground truth was produced with `bsa32.exe`,
DOS `BSA.EXE`/`BSA16.EXE`/`BSA200.EXE` under `msdos.exe`.

## Tool lineage (reverse-engineered)

- `BSA16.EXE` v1.6 (1991, KamaSoft): reads 0/1/2/3, **writes 0/2/3** — files ≥ `0x5000` bytes get method 3, else method 2 (plus stored fallback).
- `BSA200.EXE` v2.00 (1995): reads 0/2/3/5/6/7/9, **writes only 0/7** (same hardcoded `0/7` selection as bsa32). `-+0..4` only retune the method-7 encoder; `-++` selects the PPM path but still marks flag 7.
- `BSA.EXE` 2.x / `bsa32.exe` 2.3: read 0/7/9(/10), write only 0/7 (PPM streams marked 7).
- `BSA2-230.EXE`: encoders bit-identical to bsa32 2.3 output; global flags `0x0080`.
- No available packer emits flags 01/05/06/09 — those dispatch cases are decode-only forward compatibility.

`BSArc 2.00` (`.bs2`) is a **different archiver family** (different
container, magic, header/checksum scheme, methods {0,1} with CRC32)
sharing only LHA-derived table-reader code — not supported here.

`sample.txt` uses CRLF line endings to match the archives; keep it
that way (the LF variant is 18000 bytes and matches nothing).

## Known quirks (faithfully handled)

- BSA writers hardcode method byte 0/7, so PPM data arrives marked 7 → retried as method 9.
- Old BSA16/BSA200 files end with a single `00` instead of `00 00`; both accepted as terminator.
- The PPM range decoder over-reads past the packed end, so trailing archive bytes are fed to the refiller exactly like the original.
- A zero Huffman code count means a constant table (DOS BSA emits these even at default level).
- BSA200's packer is broken under emulation (entry headers never written); BSA16's and BSA2-230's work.
- Entry names keep their subfolders (`ptsdos/` etc., created on extract, shown in `l`); directory entries (flag `0x0A00`, empty) create directories. Absolute paths, drive letters and `..` components are refused.
- The LZ ring persists across entries within one archive (like the original's static window buffer), so cross-entry back-references decode correctly.
