# identity-negatives: traps for function-matching engines

Original, MIT-licensed, freestanding C11 (no libc, only `stddef/stdint` headers, external linkage for every function except the
deliberate `static inline` in `inlinesplit`). One project per trap; each has 3 or 4 versions and a `suite.json` (`suite/1`) in
which every function of both versions is labelled in every pair (adjacent pairs plus one cumulative pair). Taxonomy tags follow
calibration spec 5.4. Validate with `python tools/corpus_check.py suite corpus/ours/identity-negatives/<project>`.

| project | trap | versions | what happens |
|---|---|---|---|
| `neardup` | N1 (+N5) | v1..v3 | 16 clones (10 decoders differing only in a cell offset, 6 setters differing only in a member). v2 changes ONE constant in ONE decoder (`fr_dec_ain6`, limit 1000 -> 900). v3 only swaps neighbouring clones; all clones are the same size, so each lands exactly on a sibling's old address (clang -O2). |
| `thunks` | N2 | v1..v3 | 19 jump thunks, constant-argument forwarders, argument-shuffling legacy wrappers, container-pointer adaptors, ops-table and hook indirections. v2 retargets one forwarder (`blk_read`: only the relocation target differs). v3 fixes an implementation behind unchanged thunks, retargets an adaptor member and adds a thunk. |
| `sharedhelpers` | N3 | v1..v3 | 5 helpers in `util.c`, 14 unrelated callers in 3 files. v2 adds an overflow check to `ut_parse_u32`; callers stay text-identical. v3: cosmetic rewrite of the helper (identical code), a fix in `ut_eq_nocase`, one real change in an unrelated caller. |
| `inlinesplit` | N4 | v1..v4 | v2 splits `pk_decode` (option walk extracted), v3 merges two check functions, v4 folds a single-use helper into `pk_decode` by hand. `pk_min_u32` is a `static inline` the compiler removes by itself (no symbol in the image). |
| `layoutshift` | N5 | v1..v3 | Heap allocator, no function ever changes. v2 inserts one function first (four same-sized helpers land on each other's old addresses under clang -O2); v3 reverses the definition order. |
| `lookalike` | N6 | v1..v3 | asc/desc and min/max twins with identical CFGs, three token-bucket refills differing in constants. v2 flips exactly one comparison (`lbound_desc`), v3 changes exactly one constant (`tb_refill_disk`). |
| `addremove` | N7 | v1..v3 | Checksum registry. Removed and added functions have the same loop shape (CRC-16/CCITT -> MODBUS, djb2 -> sdbm, xor8 -> lrc8, fletcher16 -> fletcher32); a removed name (`ck_crc16_ccitt`) returns in v3 with another initial value. Never renames. |
| `tables` | N11 | v1..v3 | Stack VM dominated by switches and tables. v2 adds an opcode (a new case in five functions). v3 changes one DFA table entry, signs one ALU comparison and appends a syscall table entry. |

## Design rules that make the labels checkable
- Callers that must stay `same` are kept in a different translation unit from the callee that changes (`frame_api.c`, `blk_thunks.c`,
  `util.c`/parsers, `pkt_util.c`, `syscall.c`), so the compiler cannot inline the change into them.
- Layout-neutral edits: members are only ever appended to structs; header constants used inside `same` functions never change.
- Every version compiles warning-free with `clang -std=c11 -ffreestanding -pedantic-errors -Wall -Wextra -Werror` at -O0/-O1/-O2/-O3/-Os for
  `--target=x86_64-pc-windows-msvc`, leaves no undefined symbol (no `memcpy`/`memset`/`__chkstk`), and builds with `x86_64-w64-mingw32-gcc`.
- Labels were compared with the O2 machine code (function sections, relocation-aware): `same` is byte-identical, `changed` differs.

## Known exceptions, by design
- `tables` `lex_step` (v2->v3, v1->v3): `changed`, but the code bytes are identical; only the read-only transition table differs.
- `thunks` `blk_read` (v1->v2): the bytes differ only in a relocation target. `inlinesplit` `pk_decode` v2->v3 is `cosmetic` yet compiles
  differently (the merged checks fold differently); v3->v4 compiles identically.
- `static inline pk_min_u32` is labelled `same` but has no standalone symbol.
- `neardup` and `layoutshift` address coincidences were engineered for clang -O2; another toolchain may change sizes, not labels.

## Not included yet
- N12 `bigrewrite` and the `renames` project (labels `renamed`/`moved`) are not part of this slice. Note for whoever writes them:
  `tools/corpus_check.py` flags a `moved` function whose text is byte-identical across versions, so a moved function needs a small
  in-body edit to be accepted.
