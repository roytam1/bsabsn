# PTS BSA/BSN archive formats

Derived from `bsa32.exe` 2.3 (`bsa32.exe.c` / `.lst`), `BSA200.lst`
and `BSA16.lst`, confirmed empirically against ground-truth
archives. All multi-byte BSA header fields are **little-endian**;
all BSN header fields are **big-endian**.

## 1. BSN container (`.bsn`)

```
offset  size  field
0       4     magic FF 42 53 47  ("FFBSG")
4       2     global flags BE (0x0100 = NUL-terminated comment follows)
[comment NUL string if flags & 0x0100]
```

Then entries until EOF:

```
offset  size  field
0       4     entry magic FF 42 53 41 ("FFBSA")
4       2     L: L-block length BE (bytes that follow, > 0)
6       L     L-block (checksummed)
6+L     4     CRC32 BE of the L-block (stored value or its bitwise
              complement are both accepted)
6+L+4   packed_size bytes of packed data
```

L-block layout:

```
offset  size  field
0       2     eflags BE
2       2     method/format byte (0 = default; not validated)
4       4     timestamp BE
8       *     filename, NUL-terminated
...     [4]   extra_size BE, present iff eflags & 0x0008
...     4     orig_size BE
...     4     packed_size BE
...     4     filecrc (CRC32 BE of original data)
...     [2+N] comment length BE + comment, present iff eflags & 0x0020
```

Method dispatch from `eflags`: `0x8000` → method 10 (not
implemented); `0x4000` → method 9 (PPM); otherwise method 7.
`eflags & 0x0800` marks a stored (raw copy) entry — writers must
set it, as `bsa32` reports a `packed_size == orig_size` entry
without it as corrupt (this unpacker accepts either). Directory
entries are `0x0A00`, i.e. stored (`0x0800`) plus directory
(`0x0200`), with `packed_size == orig_size == 0` (creates the
directory, e.g. `ptsdos/cp`); without the directory bit, a zero
size is an empty stored file. Filenames keep `/`-separated
subfolders. The original BSN writer never stores non-empty files —
it compresses even when that expands them (e.g. 12 -> 23 bytes).

Known global flags: `0x0001` (bsa32), `0x0080` (BSA2-230; only
the `0x0100` bit is acted upon).

## 2. BSA container (`.bsa`)

No global header. Entries back to back:

```
offset  size  field
0       1     hlen: header bytes following these 2 (== 22 + namelen);
              0 ends the archive (a lone 00 at EOF also ends old files)
1       1     00
2       1     magic AE
3       1     method: 0 = stored, 2/3/5/6 = LZSS+Huffman variants,
              7 = LZ77+Huffman
4       4     packed_size LE
8       4     orig_size LE
12      4     timestamp LE (DOS date = high word, DOS time = low word)
16      2     w1: byte-sum of original data, mod 2^16 (verified checksum)
18      2     w2: reserved (0)
20      2     w3: 0 (new files) or 0x20 (old files); only bit 0 is read
22      1     namelen
23      N     filename (N bytes, no code page conversion done here)
23+N    1     NUL
24+N    packed_size bytes of packed data
```

Archive terminator: `00 00` (BSA 2.x) or a single `00` at EOF
(BSA16/BSA200). There is no per-entry CRC; success is
`produced == orig_size` plus the `w1` byte-sum check (which the
originals perform after extraction).

Example (`sample0.bsa`): `20 00 AE 07 26 1B 00 00 A4 47 00 00
16 50 4C 38 ED 86 00 00 00 00 0A "sample.txt" 00` + 6950 data
bytes + `00 00` (orig = 18340, w1 = 0x86ED).

DOS date/time words: date: day = bits 0–4, month = bits 5–8,
year = bits 9–15 + 1980; time: seconds/2 = bits 0–4,
minutes = bits 5–10, hours = bits 11–15.

## 3. Method 0 — stored

Raw copy of `packed_size` (`== orig_size`) bytes.

## 4. Methods 2/3/5/6 — LZSS + dynamic Huffman (BSA200 lineage)

MSB-first bitstream. 64 KiB ring. Per block:

1. `u16` token/block count.
2. 19 code lengths (5-bit count; after the 3rd length a 2-bit value inserts that many zero lengths).
3. 510 literal/length code lengths (9-bit count), coded with the 19-symbol alphabet: values 0/1/2 are zero runs of 1, 3+extra(4 bits), 0x14+extra(9 bits); values ≥ 3 mean length `value-2`.
4. 14 distance-code lengths (4-bit count, no zero gap).
5. Tokens: value `< 0x100` is a literal; otherwise it is a length symbol, `len = symbol - 0xFD`.

Distance base from the distance code `c`: `0` → 0, else
`(1 << (c-1)) | extra(c-1 bits)`. Method wrappers adjust the
length symbol and base before that:

- method 2: `sym >= 0x180` → `base += 0x2000`, `sym -= 0x80`.
- method 3 and 6 (identical): `sym >= 0x1C0` → `base += 0x6000, sym -= 0xC0`; else `sym >= 0x180` → `base += 0x4000, sym -= 0x80`; else `sym >= 0x140` → `base += 0x2000, sym -= 0x40`; then if `sym == 0x13D`, add one more literal/length symbol (length extension, new block header if the count runs out).
- method 5: method-2 adjustment, then if `sym == 0x17D`, add one more literal/length symbol.

Final distance = base + 1; match bytes copy through the ring
(overlapping matches work). The ring persists across entries
within one archive (the original's static window buffer is never
cleared), so a later file may match text from an earlier one —
multi-file archives such as `PTSDOS.BSN` rely on this.
Termination is output-driven: a
split 16-bit countdown starts at `orig_size + 1` and each
literal costs 1, each match costs its length; the loop also
ends on table-build failure or invalid codes (partial output
then fails the size/`w1` checks).

Tables are canonical Huffman (first code 0, symbol order) with
an exact Kraft sum over the 16-bit code space; CodeGen uses an
8-bit peek table plus subtree walk, which bit-by-bit decoding
reproduces exactly. A zero code count means a constant table
(symbol = the following count-sized value, zero bits consumed).

Maximum match is 256 (method 2), 66 + extension (method 3/6);
maximum distance is 0x4000 (method 2/5), 0x8000 (method 3/6).

## 5. Method 7 — LZ77 + dynamic canonical Huffman (bsa32 lineage)

MSB-first bitstream over bytes. Block layout:

1. `u16` token count.
2. Meta alphabet (19 symbols): 5-bit count, then that many code lengths, each a 3-bit value (`7` extends by counting following 1-bits); after every 3rd length a 2-bit zero-run is inserted.
3. Literal/length alphabet (510 symbols): 9-bit count, then that many code lengths coded with the meta tree — values 0/1/2 are zero runs (1, 3+extra4, 0x14+extra9), values ≥ 3 mean length `value-2`.
4. Distance alphabet (17 symbols): 5-bit count, same length coding, no gap.
5. Tokens: value `< 256` is a literal, else `len = symbol - 253`; distance code `d <= 1` → `d+1`, else `extra = d-1` bits, `distance = (1<<extra)+val+1`. Matches may reference before the
current entry start: the 128 KiB ring persists across entries
(like the original's static window buffer), resolving to earlier
entries' bytes (zero for never-written regions).

A zero count anywhere selects a constant table (the following
count-sized value, zero bits consumed) — DOS BSA emits these
even at default level.

## 6. Method 9 — PPM order 0..5 + range coder (bsa32 lineage)

First stream byte is a version flag (ignored). Order-0..5 PPM
trie with LRU node reuse and a single 258-byte exclusion list;
binary range coder (E1/E2/E3 renormalization), MSB-first.
The decoder legitimately reads past the packed end, so the
original feeds it the following archive bytes — the unpacker
passes up to 64 KiB of file tail for this. Decoding ends at
the EOF symbol or `orig_size` bytes; CRC32 is then verified.

There are two incompatible PPM variants: the bsa32/BSA2-230/BSA200-
Rel-0.982 one (e.g. `sample-p.bsn`), which this decoder, `bsa32`
and Rel 0.982 handle, and BSA200 Rel 0.972's (`-++`, e.g.
`samplep.bsn`, byte-identical to fresh Rel-0.972 output), whose
model diverges from the newer one after a few symbols — Rel 0.982
and `bsa32 t` both CRC-fail it and this decoder fails it
identically (same garbage output), so only Rel 0.972 `t` extracts
it. A fresh Rel-0.982 `-++` archive is byte-identical to
`sample-p.bsn` except for the global-flags byte (`0x0000` vs
`0x0080`), so global flags alone do not identify the Rel-0.972
variant (both Rel builds write `0x0000`; both also reject
`0x0080` archives at the container check). Method 7 has no such
split (both Rel builds' method-7 archives pass `bsa32 t`). From
`BSA200.lst` (Rel 0.972; dispatch case 9 → `sub_21CFD` → main loop
`sub_21F44`), Rel 0.972's PPM differs from bsa32's in at least:
max order 4 (not 5), hash multipliers 3/2/1 with the order-4 hash
masked to 0x1FFF (8192-entry hash table, not 65536), context
bytes stride 4 (not 5), version-selected sizes (version 1:
NCTX 15360, NPOOL 32760), no per-decode frequency halving after a
symbol (bsa32 halves the chain), no `total <= 0x1000` forced
escape, scaled-mode switch at `total > 5` (not `> 6`), and
unscaled/scaled switch at `escAcc >= 3` (not `>= 4`). A patched
bsa32 decoder with just those parameters moved the divergence
from byte 6 to byte 11, so further decode-symbol total/escape
details still differ; a full port must translate Rel 0.972's
`sub_21546`/`sub_225D5`/`sub_21218`/`sub_21821`/`sub_221D9`
faithfully.

## 7. Checksums

- BSN: CRC32 of the L-block (stored or complemented) plus CRC32 of the decoded data vs `filecrc`.
- BSA: no CRC. BSA16/BSA200 verify `w1` (byte sum mod 2^16) after extraction; this implementation does the same on extract for methods 2/3/5/6 and in test mode for every method, plus the produced-size check everywhere.

## 8. Errata / quirks (all handled)

- Every BSA writer hardcodes the method byte to 0 or 7 (`(flags & 0x800) ? 0 : 7`); PPM streams therefore arrive marked 7. The unpacker tries method 7 first, then PPM — the originals cannot extract such files at all.
- No original packer emits flags 01/05/06/09; BSA16 additionally emits 2/3 (auto-selected: orig ≥ `0x5000` → 3, else 2). `bsn_pack` emits 05/06 in extension-free form (127/63-byte match caps, so symbols 0x17D/0x13D never occur and the streams equal methods 2/3 apart from the method byte): BSA200 (both Rels) and BSA193/195 accept them (`t` + byte-equal `x`), while BSA160 (predates 5/6) and bsa32/BSA2-230 (0/7/9 only) reject them as unknown. Emitted extensions (matches ≥128/64 bytes) are mishandled by the original decoders — BSA200 CRC-fails extended matches with distance > 1, BSA193/195 fail on symbol 509 — so they are not written; only this decoder handles them.
- Old archives terminate with a single `00` at EOF instead of `00 00`.
- BSA2-230's packed streams are byte-identical to bsa32 2.3 output; only its global-flags byte differs (`0x80` vs `0x01`).
- BSA200 Rel 0.972's BSA packer is broken under emulation (headers never written; the archive starts with zero bytes); its BSN packer works (method 7 and, with `-++`, PPM — the latter is the `samplep.bsn` variant above). BSA16's and BSA2-230's work. BSA200's `-+0..4` only retune method-7 effort; `-++` selects PPM (still flagged 7 in BSA).
- Compressed streams (methods 7 and 2/3) end with an extra `00` byte past the byte holding the last token bit; the original bit reader looks ahead past the final token and misdecodes it when a stream ends flush at the archive end, while the tolerant port in `bsn_lz.c` does not. The `bsn_pack` encoders finish with 32 zero bits for the same reason.
- BSArc 2.00 (`.bs2`) is a different archiver family (own container, magic `SB`, methods {0,1}, CRC32) sharing only LHA-derived table code — out of scope here.
