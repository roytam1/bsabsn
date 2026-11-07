# PTS BSA/BSN archives — extractor and packer

C reimplementation (MSVC6, C89) of the PTS BSA/BSN archive handling
from `bsa32.exe` 2.3, verified byte-for-byte against the original
DOS/Windows tools. Parses both container formats and fully
decompresses methods 0, 2, 3, 5, 6, 7 and 9, and writes both
container formats back with `bsn_pack` (methods 0, 2, 3, 5, 6
and 7).

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

## Packing

```
bsn_pack archive[.bsn|.bsa] file...   create an archive (format from extension)
bsn_pack -0 archive.bsa file...       store files uncompressed
bsn_pack -7 archive.bsn file...       method 7 compression (default)
bsn_pack -3 archive.bsa file...       method 3 compression (BSA only; -2/-5/-6 likewise)
bsn_pack -r archive.bsa dir...        add directories recursively
bsn_pack -v archive.bsn file...       list each file as it is packed
```

Examples:

```
bsn_pack new.bsa sample.txt FORMAT.md
bsn_pack -3 old.bsa Root.mnx
bsn_pack -r pts.bsn ptsdos
```

Explicit file arguments are stored under their base names; entries
added with `-r` are stored relative to the parent of the directory
given, so the directory name itself is kept, with `/` separators.
BSN archives get explicit directory entries (flags `0x0A00`); BSA
has no directory entry type, so its subfolders are represented only
by file name prefixes and empty directories are skipped. DOS
timestamps come from the files' modification times. BSN entries
carry the L-block CRC32 plus the data CRC32; BSA entries carry the
`w1` byte-sum checksum, exactly as `bsn_unpack` verifies them.

## Build (MSVC6)

```bat
call "C:\Program Files (x86)\Microsoft Visual Studio\VC98\Bin\VCVARS32.BAT"
CL.EXE /nologo /O2 /Febsn_unpack.exe bsn_unpack.c bsn_lz.c bsn_m23.c bsn_ppm.c
CL.EXE /nologo /O2 /Febsn_decode.exe bsn_decode.c bsn_lz.c bsn_m23.c bsn_ppm.c
CL.EXE /nologo /O2 /Febsn_pack.exe bsn_pack.c bsn_enc.c
```

Sources: `bsn_unpack.c` (containers + CLI), `bsn_lz.c` (method 7),
`bsn_m23.c` (methods 2/3/5/6), `bsn_ppm.c` (method 9),
`bsn_pack.c` (archive writer + CLI), `bsn_enc.c` (method 7 and
method 2/3 encoders).

## Packer notes

The encoders (`bsn_enc.c`) are deliberately simpler than the
originals: greedy hash-chain LZ (matches capped at 255 bytes and
32768 distance for method 7, as in the original writer, 16384
tokens per block), sparse frequency-ranked Huffman tables rebuilt
per block for method 7, and complete fixed-length tables for
methods 2/3 (matches capped at 127/63 bytes, avoiding symbol 509,
which `BSA16`/`BSA193`/`BSA195` misdecode in method 2). Output is
therefore **not bit-identical** to `bsa32`/`BSA16` output (typically
somewhat larger), but it decodes byte-exactly in every original
archiver that supports the method: `bsa32`, `BSA2-230` and `BSA200`
read method 7 in both containers, `BSA200` also reads methods 2/3,
`BSA193`/`BSA195` read methods 0/2/3/7 in BSA, and `BSA160` reads
methods 0/2/3 in BSA (verified with `t` plus byte-equal `x`
extractions, including the whole `PTSDOS.BSN` corpus repacked,
136/136 entries). Two original-tool quirks shaped the writer:
compressed streams are finished with a few zero bytes (the original
bit reader misdecodes the final token of a stream that ends flush
at the archive end), and BSN stored entries need flag `0x0800`
(directory entries are `0x0A00`). Like the original BSN writer,
`bsn_pack` always compresses BSN files (even when that expands a
tiny file) because `bsa32`'s BSN stored reader only copes with the
first stored entry in an archive; for BSA it falls back to stored
whenever compression would not be smaller, like `BSA16`. Method 9
(PPM) has no encoder and `-9` is rejected. Methods 5/6 are written
in extension-free form (capped at 127/63 bytes, so their extension
symbols never occur and the streams equal methods 2/3 byte-for-byte
apart from the method byte): emitted extensions are mishandled by
the original decoders (BSA200 CRC-fails extended matches with
distance > 1; BSA193/195 fail on symbol 509), while the
extension-free form is accepted by every original that knows the
method at all (BSA200 both Rels, BSA193/195; BSA160 predates 5/6,
bsa32/BSA2-230 accept only 0/7/9).

## Method support

| Method | BSN | BSA | Status |
|---|---|---|---|
| 0 stored | yes | yes | verified |
| 2 LZSS+Huffman 16K | — | yes | verified byte-exact (`m2.bsa`) |
| 3 LZSS+Huffman 32K | — | yes | verified byte-exact (`m3.bsa`, `Root.mnx`) |
| 5 LZSS+Huffman | — | yes | encoder emits flag 05 (extension-free form, identical stream to method 2); `t`+`x` verified in BSA200 (both Rels), BSA193/195; BSA160/bsa32/BSA2-230 reject it as unknown (predate/support only 0/7/9 or 0/2/3) |
| 6 LZSS+Huffman | — | yes | encoder emits flag 06 (identical stream to method 3); `t`+`x` verified in BSA200 (both Rels), BSA193/195; BSA160/bsa32/BSA2-230 reject it |
| 7 LZ77+Huffman | yes | yes | verified byte-exact, all levels |
| 9 PPM | yes | as flag 07 | verified byte-exact for the bsa32/BSA2-230/BSA200-Rel-0.982 variant (`sample-p.bsn`, `230-pp.bsn`); BSA200 **Rel 0.972**'s PPM variant (`samplep.bsn`, byte-identical to fresh Rel-0.972 `a -++` output) uses a different model and is incompatible with Rel 0.982+ — Rel 0.982, `bsa32` and this decoder all fail it (identical garbage output), so it is listed but not decoded. BSA writers store PPM marked 7, so it is retried when method 7 fails (the originals cannot extract such files at all) |
| 10 | yes | — | clean "unsupported" error (no vectors) |
| 1 | — | — | rejected (BSA16-only method, no vectors, not implemented) |

BSA has no per-entry CRC. Integrity comes from: produced size ==
declared orig size for every entry, CRC32 for BSN entries, and the
`w1` byte-sum checksum (mod 2^16 of the original data) which BSA16 /
BSA200 verify after extraction — `bsn_unpack` verifies it on extract
for methods 2/3/5/6 and in `t` mode for all BSA methods.

## Test corpus (all vectors in this repo)

- `sample.bsn`, `sample0–4.bsn`, `sample-p.bsn` — BSN, methods 7/9 (bsa32/BSA2-230/Rel-0.982 PPM)
- `samplep.bsn` — BSN, BSA200 Rel-0.972 PPM variant; Rel-0.972 `t` OK, but Rel-0.982/`bsa32`/`bsn_unpack` all fail identically (unsupported variant, listed only)
- `sample0–4.bsa`, `samplep.bsa` — BSA, methods 7 / PPM-as-7
- `m2.bsa` — BSA method 2 (BSA16 lineage)
- `m3.bsa` + `Root.mnx` — BSA method 3 (491520 bytes, exercises the 64 KiB ring)
- `230-p.bsn`, `230-pp.bsn` — BSA2-230 output; packed streams are byte-identical to bsa32 2.3 output, only the global-flags byte differs (`0x0080` vs `0x0001`)
- `193.bsa`, `193max.bsa`, `sample-p.bsa` (= 193max), `sample-q.bsa` — BSA195 method-7 variants
- `PTSDOS.BSN` — real PTS-DOS archive: 135 entries in `ptsdos/` subfolders, incl. 4 directory entries and cross-entry LZ references
- `193.bsa`, `193max.bsa`, `sample-p.bsa` (= 193max), `sample-q.bsa` — BSA195 method-7 variants
- `sample.txt` — reference plaintext (CRLF, 18340 bytes, matching every `sample*` archive)

All of the above except `samplep.bsn` (BSA200 Rel-0.972 PPM variant,
see above) extract byte-identical (and `t`/`l` clean) with
`bsn_unpack`; ground truth was produced with `bsa32.exe`,
DOS `BSA.EXE`/`BSA16.EXE`/`BSA200.EXE` under `msdos.exe`.

## Tool lineage (reverse-engineered)

- `BSA16.EXE` v1.6 (1991, KamaSoft): reads 0/1/2/3, **writes 0/2/3** — files ≥ `0x5000` bytes get method 3, else method 2 (plus stored fallback).
- `BSA200.EXE` v2.00 (1995): reads 0/2/3/5/6/7/9, **writes only 0/7** (same hardcoded `0/7` selection as bsa32). `-+0..4` only retune the method-7 encoder; `-++` selects the PPM path but still marks flag 7. (Rel 0.972 and Rel 0.982 both read/write method 7 identically, but their PPM models are incompatible — see above.)
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
- BSA200 Rel 0.972's BSA packer is broken under emulation (entry headers never written); BSA16's and BSA2-230's work.
- Entry names keep their subfolders (`ptsdos/` etc., created on extract, shown in `l`); directory entries (flag `0x0A00`, empty) create directories. Absolute paths, drive letters and `..` components are refused.
- The LZ ring persists across entries within one archive (like the original's static window buffer), so cross-entry back-references decode correctly.
