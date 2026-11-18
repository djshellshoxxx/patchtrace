# Diff-engine adapters

`tools/research_qualification/adapters/` turns engine output into the scoring input `{case_id: [function, ...] | null}`
(`scoring.score_run`). Each adapter has `parse(source) -> list[str]`: changed functions, most changed first, ties by
name, unchanged excluded, added/removed-only after the changed ones. `source` is text/bytes content or an
`os.PathLike` (confined by `pathguard.confine`). CLI: `python -m tools.research_qualification adapters ENGINE FILE [--case ID]`.

| Engine | Input | Magnitude | Status |
|---|---|---|---|
| Ghidriff | `*.ghidriff.json` or `.md` | JSON: `1 - ratio` (then block, mnemonic ratio). Markdown: count of `+`/`-` lines in the function's diff block | JSON field names checked against ghidriff 1.0.0 source; markdown headings checked against its writer. No real run was available, so fixtures are hand-written. |
| BinDiff | `.BinDiff` SQLite, table `function` | `1 - similarity` (then lower confidence) | UNVERIFIED: no real export seen; documented schema. Only matched pairs are stored, so added/removed functions cannot be reported. |
| Rizin | Native nested `rz-diff -C -j -t functions` JSON; legacy `radiff2 -C` text or flat JSON | `1 - similarity` | Native shape has retained captures; the report-visible identity gate below is required before name ranking. Legacy text/flat JSON remains UNVERIFIED (tolerant guessed layouts). `-g` graph output unsupported. |

Notes:
- Ghidriff "modified" entries with no `code` diff type and ratio 1.0 (rename/address/call-graph only) and the markdown
  "Modified (No Code Changes)" section are treated as unchanged.
- Names are kept as reported, including C++ `A::b`, `sub_XXXX`, `FUN_XXXX`. Only x86 decoration on a plain identifier
  (`_f@8`, `@f@8`) is stripped. Nothing is invented from addresses; unnamed rows are skipped only in the legacy
  formats. Native nested Rizin records require a valid name on every non-null side.
- Empty input raises rather than returning `[]`: an empty file means the engine did not produce output (BLOCKED, use
  `null`), whereas a valid report with no changes returns `[]`.
- Hostile input: 64 MiB input cap, 1 MiB line cap, 512-char names, 500k functions; NUL/binary, invalid UTF-8, NaN,
  deep nesting, control/bidi characters and `..` path segments in names all raise `ValueError`. Input is never executed;
  BinDiff files are opened `mode=ro` with `query_only`.
- `bindiff.parse` refuses a plain `str` (ambiguous between path and content): pass a `Path` or bytes.

## Ghidriff report identity gate (2026-11-18)

The research adapter projects functions to names, which cannot represent two
distinct endpoints sharing a label. Before dropping unchanged rows, it must
inspect both reported sides and every added/deleted row. A normalized label may
occur on both sides of one pairing, but cannot identify different report records.
Known addresses are side-relative; multiple records at the same side/address,
different counterpart mappings, repeated labels after calling-convention
normalization, and changed/unchanged conflicts are refused. Exactly repeated
JSON records may contribute once only when their complete canonical JSON and
collection agree. Unrecognized or malformed supplied addresses are refused;
missing/null/blank addresses remain unknown. The report-visible guard cannot
verify omitted functions, source truth, input hashes or independent ground truth.

JSON object keys must be unique at every depth. All reported name/fullname fields
must be bounded text or null, and each present side needs a nonblank effective
label. Validate both sides, diff-type strings and every provided ranking ratio
before filtering unchanged rows. Preserve supported name-only JSON, including
legacy old-only modified rows, without claiming those rows prove native identity.
The three required function collections remain modified/added/deleted; unknown
function collections are refused rather than silently hiding identities. Count
all input records against the shared 500,000-function limit, including unchanged
and exact repeated records.

Markdown reports retain their existing ranking, but repeated normalized function
headings across modified, unchanged, added or deleted sections are ambiguous and
must be refused. An unchanged heading participates in identity validation while
remaining excluded from changed-function output. Markdown has no equivalent
verified endpoint identity and remains a textual report interpretation.
Match each diff subsection to its original reported function heading before name
normalization: a valid `_Target@8` heading and `_Target@8 Diff` block must still
emit the normalized `Target` candidate instead of losing its code changes.

Refusal raises `ValueError` before returning candidates. Existing adapters CLI
exit 2 and scorerun `BLOCKED: unparseable_report` handling apply, so malformed or
ambiguous reports cannot receive function or no-change credit. Production
normalization, case/scoring contracts, pins and frozen outcomes are unchanged.
Authored parser tests establish these mechanics only; real native qualification
and source-backed attribution remain separate.

## Native Rizin report identity gate (2026-11-18)

This gate protects the research adapter's lossy projection to function names. It checks only conflicts visible
in the report; it cannot establish source-to-binary truth when a function is omitted or mislabeled. An independent,
prospectively frozen source/binary/engine alias review remains required. No change to `expected.accept`, the case
schema/scorer, production secondary evidence or tool pins follows from this gate. Frozen results stay unchanged.

Any `original` or `modified` object key marks a JSON document as native before a legacy wrapper can select or
discard a list. A record with native type `COMPLETE`, `PARTIAL` or `UNLIKE` and neither legacy `name` nor `name2`
field also marks the document as native: removing both side keys must not turn invalid native output into an
empty legacy result. Explicitly named flat legacy records retain their tolerant type handling. Native output
must be a bare array. Every record in such a document must
have exactly `similarity`, `type`, `original`, `modified`; mixing native and legacy records or wrapping native
records in a legacy object is refused. Type is `COMPLETE`, `PARTIAL` or `UNLIKE`; similarity is a finite number
in 0..1, never a boolean. Each side is explicitly null or exactly `{addr, name, size}`: address is an unsigned
64-bit integer, size is a nonnegative integer (neither may be boolean), and name must pass the existing bounded
normalizer and remain nonblank. Both sides cannot be null. All fields and identities are checked before
unchanged rows are excluded; invalid or unnamed rows cannot disappear into an apparently empty result.

JSON object keys must be unique, including nested keys; duplicate keys are refused before overwriting a value.
This also applies to legacy JSON. Existing valid legacy flat JSON and text retain their ranking contract and
unverified status. Native input retains the existing byte/line/name bounds and adds a raw record cap of 500,000,
including unchanged and repeated rows, before identity indexing. The adapter remains stdlib-only.

For native records, each side's address and normalized name must identify one endpoint. An address cannot have
different names, sizes, counterpart, match type or similarity. All normalized labels, including the unselected
newer label and labels on unchanged records, must belong to one endpoint pair: the same label on both sides of
one pair is allowed, but reuse across pairs is ambiguous. Therefore one-to-many and many-to-one mappings,
multiple labels for one address and normalization collisions are refused. Address zero and the maximum uint64
are valid; equal numeric addresses on opposite sides are not by themselves the same endpoint.

Repeated records are allowed only when all validated fields agree: both null/endpoint values, raw names, sizes,
match type and numeric similarity. Numeric forms such as `1` and `1.0` are equivalent. Such repeats contribute
once, independent of input order. Any other repeated-address conflict is refused, including an unchanged record
followed by a differently scored record. A name shared by a renamed pair and an unrelated pair is also refused.

After validation, ordinary ranking remains unchanged: the normalized older name is used when present, otherwise
the newer name; paired similarity 1 is excluded; paired changes sort by descending `1 - similarity` then name;
valid added/removed-only names follow. Preserve literal `sym.` prefixes, C++ scopes, case and Unicode distinctions.
Do not invent aliases, strip engine namespaces, merge guessed identities or alter magnitudes to resolve conflicts.

A refusal raises `ValueError`, never `[]`. The adapters CLI returns its existing clean error exit 2; `scorerun`
records `BLOCKED: unparseable_report` and excludes it from scoring. A malformed or ambiguous report must not
receive a no-change HIT or a function HIT/MISS. A valid complete report with no changes still returns `[]`.
Production parse/ownership success and source-backed attribution remain separate prerequisites for native pilots.
Legacy unnamed-row skipping remains unverified; arbitrary legacy shapes are not covered by the native identity
proof. A verified native pilot must pass the production strict normalizer before this ranking adapter, and may
not use legacy interpretation to bypass a failed production parse.

Focused regressions: `tests/test_research_qualification_rizin_identity.py`, plus existing adapter/scoring/scorerun
suites. Use authored JSON, retained native fixture bytes and legacy fixtures; synthetic controls establish this
gate's behavior, not native accuracy or general producer qualification.
