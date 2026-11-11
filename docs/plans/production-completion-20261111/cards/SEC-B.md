# Slice card SEC-B - storage-side sanitisers use the one shared hostile-character rule (WP-03, SEC-9 residual, PE-4, PE-5)

Source: `jq '.actionable_now[] | select(.id=="I1-T02")' docs/status/inventory/I1.json`; defects
`jq '.features[].defects[] | select(.id=="WP-03" or .id=="SEC-9-residual" or .id=="PE-4/PE-5")' docs/status/inventory/I1.json`.

## Goal
`src/patchtrace/hostile_text.py` defines the one rule for characters untrusted text may not carry into a stored or displayed
field (Unicode categories Cc, Cf, Cs, Zl, Zp). Five sanitisers still use their own narrower lists, so bidirectional
overrides, C1 CSI, U+2028/U+2029 and other format characters survive into stored records and one-line summaries:
- src/patchtrace/secondary/bindiff_probe.py (`sanitize`: keeps U+202E, U+2028, C1 CSI)
- src/patchtrace/secondary/runs.py (`sanitize_stderr`: keeps U+009B, U+061C)
- src/patchtrace/kbcorrelation/products.py (`clean_text`: keeps U+2028/U+2029)
- src/patchtrace/pe_overview/resources.py (`sanitize_text`: keeps 158 Cf code points)
- src/patchtrace/codetext/intraline.py (`_UNSAFE`: misses 29 code points)
Make each of them apply `hostile_text.is_hostile` (each sink keeps its own documented replacement character and the line
breaks it deliberately preserves).

## Owned files
The five files above; src/patchtrace/hostile_text.py (only to add a small shared helper if it removes duplication, e.g. a
function that replaces every hostile character except an explicit keep-set; keep `is_hostile` and `escape_text` unchanged);
tests/test_hostile_text.py (extend) and the existing test files of the five modules; the spec paragraphs that state each
sink's rule (docs/specs/pe-overview.md line ~74, docs/specs/three-tool-evidence-adapters.md line ~118, the secondary-engine
and kb specs where the sanitiser is described - amend the sentence that describes the rule, dated 2026-11-11).

## Method and traps
1. Red first: a parametrized battery in tests/test_hostile_text.py over the five entry points: for every code point in
   categories Cc, Cf, Cs, Zl, Zp (compute the set with unicodedata in the test, short ids) assert it does not survive,
   except the breaks/tabs each sink documents. Show it failing on the base.
2. Read every caller before changing a sanitiser. In particular:
   - Is a sanitiser applied to text that is later compared, hashed or used as a key (hash-on-read, dedup keys, golden
     files)? If stored kbcorrelation/1 text is re-sanitised at READ time, changing the rule could break integrity checks
     of existing stores: prove with a test that a store written before the change (use a fixture written by base code, or
     construct the rows directly) still opens and verifies. If the sanitiser only runs at import time, say so with the
     call-site evidence.
   - Goldens: run the golden/fixture tests of the five modules; a golden that legitimately contained a soft hyphen or a
     zero-width character may change - report the exact diff rather than silently regenerating.
   - intraline diffs are positional: replacing a character must not change string length or offsets unless the existing
     code already does (keep one replacement per code point).
3. Performance: these run over large texts; do not make them quadratic (precompute a translation table or use a compiled
   character class built once from the categories; measure one 1 MB input before/after and report the two timings).

## Acceptance
- Battery red before, green after: no Cc/Cf/Cs/Zl/Zp code point survives any of the five functions except documented
  breaks.
- Existing tests of secondary, kbcorrelation, pe_overview, codetext stay green (run their test files:
  `ls tests | grep -E "secondary|kbc|pe_overview|codetext|intraline|hostile"`).
- Ruff clean; specs amended; no file outside the owned list changes.
