# SPEC-33: Tier W local-only Windows calibration corpus (Winbindex pairs, public-PDB labels)

Status (2026-10-14, wave W1, synthetic and self-made validation only):
- **Built:** s2 layout and strict contracts; s3 catalogue, `resolve` and pair/manifest builder (library API, no CLI yet); s5.4 MSF reader; s6.3 relocation-masked body hash plus `.pdata` and export tables; s12 guard with its `corpus.py` hook; s13 self-made fixtures.
- **Deferred to the next wave:** s4 fetch, s5.2/5.3/5.5 exporters and the symbol-map writer, s6.1/6.2/6.4 labels and tags, s7 audit, s9 runner, s10 evaluation, s11 CLI, and the runbook.
- **Manual evidence:** one Ghidra 12.0.4 headless trial (Jython 2.7.4) force-loaded a self-made PDB with no symbol-server access. The function body sizes equalled the PDB code sizes. The trial was run by hand and is not a committed test.

Winbindex and msdl.microsoft.com were unreachable from the build sandbox (egress proxy: CONNECT 403). No Microsoft file was fetched, parsed or labelled. Refines `calibration-corpus-and-model.md` (SPEC-28/C9) sections 3.1 Tier W, 3.2-3.4, 4.2, 5.2-5.5 and 14 (C9-2, C9-10). If the two documents disagree on Tier W, this file wins for tooling and C9 wins for methodology. Never shipped: `tools/` is excluded from every package.

## 1. Decision O1 and data classes
Product-owner decision O1 = **local-only**. Every Microsoft-derived item stays on the owner's machine. That covers binaries, PDBs, symbol maps, labels, review queues, audit keys and logs, engine outputs, evaluation reports, and the Winbindex catalogue snapshots used to build them. None of it is committed, uploaded, attached to CI artifacts or published. Nothing fetched is executed: PE files are only read, and PDBs are only parsed by a stdlib reader, by Ghidra or by `llvm-pdbutil`. There is no network access except the explicit `catalogue`, `resolve` and `fetch` subcommands. Each of those needs `--consent-hosts` naming exactly the hosts it contacts (`winbindex.m417z.com`, `msdl.microsoft.com`) and uses the existing allow-listed transport (`acquisition/transport.py`). The symbols-visible engine run is the one exception, described in section 9.
Data that may be published (decision O1 still open for anything else): this spec, the runbook, the tool code, and self-made test fixtures built from repository sources (section 12).

## 2. Local layout (`PATCHTRACE_CALIB_ROOT`, default `~/.patchtrace-calibration`; refused inside the git work tree)
```
<root>/binaries/<sha256>/<file_name>                 read-only; same path as tools.calibration.corpus.binary_path
<root>/tier-w/catalogue/<file_name>.json             tier-w-catalogue/1
<root>/tier-w/manifests/<corpus_id>.json             calibration-corpus/1 (+ <corpus_id>.pairs.json tier-w-pairs/1)
<root>/tier-w/ledger/<corpus_id>.jsonl               tier-w-fetch/1 events, hash-chained (label.AnnotationLog)
<root>/tier-w/pdbs/<pdb lower>/<GUID32><AGE>/<pdb lower>   read-only, symbol-server layout
<root>/tier-w/symbols/<sha256>.<producer>.json       symbol-map/1
<root>/tier-w/labels/<corpus_id>/<pair>.truth.jsonl / .candidates.jsonl   calibration-labels/1
<root>/tier-w/labels/<corpus_id>/<pair>.detail.jsonl tier-w-label-detail/1 (names: local only)
<root>/tier-w/review/<corpus_id>/{queue.jsonl, audit-key.json, annotations.jsonl, audit-report.json}
<root>/tier-w/runs/<corpus_id>/<pair>/<h|v>/project  PatchTrace projects; matches.jsonl tier-w-matches/1; run.json
<root>/tier-w/reports/<corpus_id>.evaluation.json    tier-w-evaluation/1
<root>/tier-w/CANCEL                                 cancel switch (create the file to stop fetch/symbols/run)
```
Every JSON document written here carries `"tier": "W"`, and Tier-W pair ids start with `tw.`. These are the content markers the guard looks for (section 12). Writes go to a temporary file, then `os.replace`. Ghidra rejects project paths that have a dot-prefixed component, and Windows paths must stay under 240 characters. The `symbols` and `run` steps therefore check their working paths. They refuse with an explanatory message and suggest a short root such as `D:\ptcal`.

## 3. Catalogue and pairs
3.1 Families (default set, 14 files; G0 needs >= 6 families spanning all three classes): kernel `ntoskrnl.exe`; driver `afd.sys clfs.sys http.sys tcpip.sys ntfs.sys win32kfull.sys`; usermode-dll `ntdll.dll kernelbase.dll kernel32.dll rpcrt4.dll ucrtbase.dll msvcrt.dll ole32.dll`. Any other `validate_file_name`-valid name may be added; its class must be given explicitly (`--family name=class`).
3.2 `catalogue NAME...` downloads `<name>.json.gz` through `Transport.fetch_metadata`; `--from-file F --data-date D` reads a local copy instead. Parsing reuses `winbindex.decompress/strict_json/parse`, so the caps and the skipped-entry accounting are unchanged. Per-line KB data is extracted strictly from the same document: `windowsVersions.<line>.<KB>.updateInfo.{releaseDate, releaseVersion, heading}`. Every value is type-checked and length-bounded. Malformed values are dropped and counted. KB kind comes from the heading: `preview` if it contains "Preview", `oob` if it contains "Out-of-band", otherwise `monthly`. Only x64 builds (`machineType` 34404) are kept.
3.3 `resolve` (optional, network): for catalogue builds classified `candidates`, run `winbindex.candidate_urls` followed by `Transport.resolve` (HEAD, exactly one 302). The resolved SizeOfImage is stored as `resolved_virtual_size`. Probes are capped by `--max-probes` in total. Builds that are still unresolved stay ineligible.
3.4 Eligible build: x64, and either `virtualSize` or `resolved_virtual_size` present. A line is a Winbindex `windowsVersions` key. Its build number is the most common major of `releaseVersion`; ties go to the smaller value. A build's first date in a line is the earliest dated KB of that line (`--security-only` keeps only `monthly` KBs). Within a line, builds are ordered by (first date, version tuple, sha256).
3.5 Adjacent pairs (`adjacent-patch`, tag `stratum:monthly`): consecutive builds in a line, keeping the newest `--max-adjacent` pairs (default 4) whose newer build is dated on or after `--since`. Lines: an explicit `--lines`, or else the `--recent-lines` K (default 2) highest-build lines that have at least 2 eligible builds for that file.
3.6 Cross-feature-update pairs (`cross-version`, tag `stratum:large-rewrite`) are formed between consecutive selected lines A and B, ordered by build number. The newer build is the earliest build of B that is not in A. The older build is the latest build of A that is not in B and whose first date is on or before the newer build's first date; if none qualifies, the latest such build is used regardless of date. If either side is missing, no pair is formed.
3.7 Identical (older, newer) pairs found in several lines merge into one pair; their tags are combined. Ids are content-derived so they stay stable when the catalogue grows:
- binary: `w-<sha256[:16]>`;
- pair: `tw.<stem>.<sha256(older|newer)[:10]>`;
- lineage: `L-w-<stem>`, with `cluster_rule` `file-name`.

Lineage roles come from `lineage.assign_roles`. Recomputing lineages with body-hash overlap (C9 section 4.2) happens later, once symbol maps exist. `family_tags` holds the class, `file:<name>`, `stratum:*` and `line:<key>` (or `line:<A>-><B>`). The KB annotations of both sides go in the pairs sidecar `tier-w-pairs/1`, together with Winbindex record hashes, exclusions and the coverage check.
3.8 Manifest: the `calibration-corpus/1` document is checked with `contracts.load_manifest` before it is written. Each Tier-W binary records:
- `winbindex{timestamp, virtual_size, version, kb}`;
- `pdb{guid_age: null, name: null, used_for: labels-only}`, which `fetch` fills in;
- `toolchain` `msvc-unknown` and `redistribution` `none`.

`corpus_id` must start with `tier-w-`. If coverage misses a class or has fewer than 6 files with pairs, the command fails (exit 2) unless `--allow-incomplete` is given; the shortfall is recorded either way.

## 4. Fetch
4.1 `fetch-plan` is offline and prints every URL. `fetch --consent-hosts msdl.microsoft.com` downloads only what the plan lists. Binaries take the existing acquisition path: `quarantine.create_staging` (mode 0700, under `<root>/tier-w/staging`), then `quarantine.acquire`, which wraps `Transport.download`. That path gives one redirect to `*.blob.core.windows.net`, a size cap equal to the planned size, SHA-256 and size checks against Winbindex, and identification. Only `pe` files with machine 0x8664 are accepted, then moved to `binary_path` and made read-only. `PlannedDownload.side` is always `older`; the field is ignored outside two-file projects. The provenance (`source_url`, `redirect_host` host only, `retrieved_at`, Winbindex record hash) goes into the ledger.
4.2 PDB identity comes from the stored PE's CodeView RSDS record via `pe_overview.inspect_pe` (GUID, age, path). The PDB name is the path basename after splitting on `\` and `/`, and must match `[A-Za-z0-9._-]{1,128}` and end in `.pdb`. URL: `https://msdl.microsoft.com/download/symbols/<name>/<GUID 32 uppercase hex><age %X>/<name>`. The GUID uses Data1-3 decoded little-endian, which equals `uuid.UUID(bytes_le=...).hex.upper()`.
4.3 PDB download goes through `SymbolTransport`, a subclass of `acquisition.transport.Transport` that reuses its open, retry and read machinery. It takes the same host allow-list, consent check and single redirect to the blob host. Because no hash is known in advance, a size cap applies instead: `--pdb-cap-mib`, default 512, maximum 2048. The SHA-256 is computed while streaming. The body must start with the MSF 7.00 magic, otherwise it is deleted (`PT-ACQ-VERIFY`). A 404 means not on the server; the fallback to a compressed `.pd_` file is not attempted. After download the stdlib MSF reader (section 5.4) must find the same GUID and DBI age as the CodeView record; on a mismatch the file is deleted and the event logged `pdb-rejected`. Accepted PDBs move read-only into the symbol-server layout.
4.4 Operations:
- Throttle: every HTTP request, including retries and probes, waits at least `--min-interval` seconds (default 2) after the previous one. The transport's `Retry-After` handling (<= 60 s) is kept.
- `--max-files` bounds the downloads per run; the rest are recorded as `deferred`.
- Resume: a binary whose final file re-hashes correctly, or a PDB whose ledger SHA-256 matches, is not fetched again.
- Disk preflight: free space must be at least the missing binary bytes, plus a PDB estimate of max(4 MiB, 2 x binary size) capped at the PDB cap, plus 1 GiB of margin. The check runs again before each file.
- Cancel: Ctrl-C or the `CANCEL` file. A watcher thread sets the transport's cancel event, so partial temporary files are removed and the ledger records `cancelled`.
- Exit codes: 0 done, 1 some files failed, 2 configuration/consent/disk, 5 cancelled.

## 5. Symbol export (decision and contracts)
5.1 Options evaluated (decision: (a) is primary; (d) supplies the PDB-level facts; (b) is optional; (c) is rejected):

| Option | Gives | Cost / risk | Decision |
|---|---|---|---|
| (a) Ghidra headless / PyGhidra script `ghidra_export_symbols.py` | Names and RVAs, plus function bodies (ranges, sizes) for public-only PDBs. Ghidra's PDB reader is pure Java, handles OMAP and runs anywhere Ghidra runs, which is already needed for Ghidriff. | 20-60 s per small image and minutes for ntoskrnl. Function boundaries are Ghidra's (a `D_ghidra` dependency, recorded). It cannot by itself tell public from private, or ICF aliases from demangled duplicates. | Primary: the only option that sizes functions in Microsoft's stripped public PDBs. |
| (b) `llvm-pdbutil dump --publics/--symbols` | Publics; private `S_GPROC32` sizes. | Needs an LLVM install. Its text output is not a contract, so the parser is strict and versioned. No bodies for public-only PDBs, so sizes come from `.pdata`. | Optional adapter, also used as a parity check. |
| (c) DIA SDK (`msdia140.dll`) | Everything. | Windows-only COM from a Visual Studio install, not redistributable, needs `comtypes`/registration, untestable on Linux CI. | Rejected. |
| (d) stdlib MSF reader (`msf.py`) | GUID/age identity, stripped flag, publics, private procedures and thunks, section and OMAP mapping. | Must be hardened; it is tested against real lld PDBs and fuzzed. | Built. Used for the download identity check, for `kind`/aliases/names in every map, and as a producer (`msf`) with `.pdata` sizes. |

5.2 Ghidra modes, both driven by `jobs.run_process` with a private temporary project, a private `XDG_CONFIG_HOME`/`XDG_CACHE_HOME` (no persisted symbol-server preferences) and a timeout:
- `pyghidra` (default): the backend's configured external Python (`--python`, the one Ghidriff uses, which has PyGhidra) runs `ghidra_export_symbols.py --driver`. That calls `pyghidra.start(install_dir)` and `pyghidra.open_program(analyze=False)`, sets `PdbUniversalAnalyzer.setPdbFileOption` (force-load, so `findPdb` and symbol servers are never consulted) and `setAllowUntrustedOption(False)` in a transaction, then runs `analyzeAll` and exports.
- `headless`: `analyzeHeadless` with `-preScript ghidra_set_pdb.py <pdb> -postScript ghidra_export_symbols.py <out>`. On Windows, `.bat` launching through `cmd.exe` is refused for any argument containing `&|<>^%!"`.

The script runs under Jython 2.7 (`#@runtime Jython`, so plain `analyzeHeadless` on Ghidra 11.3+ and 12 uses Jython; older versions ignore the tag) and under CPython 3. A test therefore rejects Python-3-only syntax in it. The script reads only the stable Program API. It emits `ghidra-symbols/1`: image base, executable SHA-256 and the program's PDB options (file, GUID, age, loaded). For each non-external function it records:
- the entry RVA and the sorted body ranges, as RVAs with an exclusive end;
- the thunk flag;
- up to 16 non-DEFAULT symbol names at the entry, with source type and primary flag.

Unnamed functions are counted, not listed.
5.3 `symbol-map/1` (strict JSON, pydantic strict, `extra=forbid`, document cap 256 MiB):
```
{"contract":"symbol-map/1","tier":"W|R|test",
 "image":{"file_name","sha256","image_base","size_of_image","machine":"x64|x86|arm64|other"},
 "pdb":{"name","guid","age","sha256","stripped"} (each nullable),
 "producer":{"tool":"ghidra|llvm-pdbutil|msf","version","detail"},
 "symbols":[{"name","rva","size","size_source":"ghidra-body|pdb-proc|pdata|null","kind":"public|private|unknown",
             "aliases","thunk","ranges":[[start,end),...]}],
 "stats":{"functions","unnamed","dropped"}, "warnings":[...]}
```
Limits:
- <= 1,000,000 symbols;
- names of 1-4096 characters, no NUL;
- <= 4096 ranges per symbol and 4,000,000 in total;
- ranges sorted, non-overlapping, with `0 <= start < end <= 2^32`;
- `size` equals the summed range lengths whenever ranges exist;
- `name` unique per RVA; at most 2,000 warnings.

Name choice: the identity key is the PDB public name, which is mangled for C++ and so stays unique across overloads. Merge rule:
- PDB functions are the union of function publics and private procedures, keyed by RVA.
- At each RVA, `name` is the single public name. If that RVA has several public names (ICF), the alphabetically first is used and `aliases` is the count of the others. With no public name, the private procedure name is used.
- `kind` is `private` when a private procedure or thunk exists at that RVA, else `public`. Without a PDB index it is `unknown`.
- Size: a Ghidra body at the same RVA wins; otherwise the private procedure length, then `.pdata` (`RUNTIME_FUNCTION` end - begin, non-chained entries only); otherwise null.
- Without any PDB index, Ghidra names are used in this order: an IMPORTED name starting with `?` (mangled), then an IMPORTED primary name, then the first sorted IMPORTED name. `Ordinal_<n>`, `entry` and names starting with `.` are dropped.

5.4 MSF reader limits (`MsfError` with a code, never another exception):
- file <= 2 GiB; block size in {512, 1024, 2048, 4096, 8192, 16384, 32768};
- `num_blocks * block_size` <= the file size, rounded up to one block;
- directory blocks <= block_size/4 (same rule as LLVM); <= 65,535 streams;
- every block index < num_blocks and > 0; stream size <= 512 MiB;
- symbol record length 2..65,535 bytes, staying inside its stream; names NUL-terminated and <= 4,096 bytes;
- <= 5,000,000 records; <= 100,000 modules; cooperative cancel.

DBI flag bit 1 means "private symbols stripped". OMAP (optional debug header index 4) is applied when present: binary search over (from, to), where `to == 0` means unmapped.
5.5 `llvm-pdbutil` adapter: absolute executable; `--version` is recorded. The `dump --publics` and `dump --symbols` output is capped at 256 MiB; exceeding the cap is an error, never a truncated parse. Each line must match the LLVM 18 formats. An unknown record shape is counted as a warning and skipped. Five consecutive malformed lines, or a malformed address, fail the export. Segment:offset (decimal) maps through the PE section table. PDBs with OMAP are refused on this path.

## 6. Symbol-derived labels (C9 section 5.2)
6.1 Truth for one pair: a function is labelable when its name is unique in both images, has no ICF aliases, and has a known size on both sides. A truth correspondence (older RVA -> newer RVA, `A=same`) is formed when the names are identical and the size ratio min/max is at least `--ratio-min` (default 0.33, a preregistration parameter). Otherwise the label is excluded with a reason: `non-unique`, `alias`, `no-size`, `size-ratio`, `absent-in-newer` or `absent-in-older`. Truth records go to `<pair>.truth.jsonl` with `match_id = sym:<older rva hex>-<newer rva hex>`, `source=symbol-derived`, stratum `natural`, stage `symbols-hidden`, `p_incl=1`.
6.2 Candidate labels, for each one-to-one engine match from a `symbols-hidden` run:
- `same` when (older, newer) is a truth correspondence.
- `different` when either endpoint has a truth counterpart that is not the other endpoint.
- Otherwise unlabelled; the reason is kept in the detail file.

`no-counterpart` is never derived from symbols, because a rename or a signature change of a C++ function changes its mangled name. Those cases go to human review. Candidate records use the engine's match id and go to `<pair>.candidates.jsonl`.
6.3 `body_sha256`: SHA-256 over the body bytes, taken in range order. Bytes covered by base relocations are zeroed first: DIR64 masks 8 bytes, HIGHLOW 4, ABSOLUTE is skipped, and any other type masks 8 bytes and adds a warning. `.reloc` parsing is bounded: blocks of at least 8 bytes, at most 16 M entries. Bytes the file does not back (BSS) count as zero.
6.4 Tags, which go in the detail file. `subtype` takes the first matching tag in the order N2 > N9 > N10 > N3:
- `exported`: the RVA is in the PE export table.
- N2 thunks: the Ghidra or PDB thunk flag, `__imp_`, `__tailMerge_`, `__delayLoadHelper`, `@ILT+`, `j_`, `??_9`, `[thunk]`.
- N9 compiler-generated: security cookie/GS, `__C_specific_handler`, `__chkstk`, `_alloca_probe`, `_guard_`/`__guard_`, `_RTC_`, `__CxxFrameHandler`, deleting destructors and dynamic initializers (`??_E`, `??_G`, `??__E`, `??__F`), and EH/SEH funclets (`$filt$`, `$fin$`, `?dtor$`, `?catch$`).
- N10: `.cold`, `$cold$`, `_cold_<n>`, `.part.<n>`.
- N3: CRT string/memory functions, strsafe, `__acrt_`, `__vcrt_`, `__scrt_`, `__std_`, WPP/TraceLogging/`Mc*` ETW helpers, and the mangled scopes `@std@@`, `@wil@@`, `@WRL@Microsoft@@`, `@ATL@@`, `@Concurrency@@`.

6.5 Validity (C9 section 5.2): symbol-derived labels count only against engine runs with symbols NOT loaded. The evaluator enforces this (section 10). A Ghidriff run with `--no-symbols` still sees **export names**, so for exported functions the label and the engine use the same identity information. Every metric is therefore also reported separately for the exported and non-exported strata, and the non-exported stratum is the honest headline for symbol-derived Tier-W evidence.

## 7. Audit and error rate
7.1 The sampler, seeded with `det_uniform(seed, 'audit', pair, match_id)`, draws from the candidate labels; it uses truth labels only when no candidate labels exist, and the queue header says which. The census takes 100% of `same` labels whose relative body-size change `|new - old| / old` exceeds `--size-change` (default 0.40). The random stratum takes `--rate` (default 0.05) of the rest. The census applies to `same` only because `different` pairs are different functions by construction.
7.2 Outputs:
- `queue.jsonl` holds review items for `label.run_terminal`: pair, match id, both sides' RVA/size/body hash, a hex preview (<= 128 bytes) and the stratum. It contains no symbol label, no name and no engine output.
- `audit-key.json` holds the hidden symbol labels and p_incl.
- `review` runs `label.run_terminal` against `annotations.jsonl`, the hash-chained `AnnotationLog`.

7.3 `audit-report`: an error means the human y differs from the symbol y, where `same` = 1 and `different`/`no-counterpart` = 0. `indeterminate` answers are excluded and counted. Per stratum, the error rate is reported with a one-sided 95% Clopper-Pearson upper bound, computed by bisection on `stats.binom_cdf`. The overall estimate weights strata by population share, and its upper bound is the population-weighted sum of the stratum bounds. Output: `symbol_audit_error` (the point estimate, the key `gates.g0` reads), `symbol_audit_error_upper`, counts, and `status`:
- `insufficient` when fewer than 30 items have been reviewed;
- `weak` when the point estimate is above 0.02, in which case the source is demoted and excluded from the headline;
- `ok` otherwise.

## 8. Contracts written by Tier W (all strict, all carry `tier`)
`tier-w-catalogue/1`, `tier-w-pairs/1`, `tier-w-fetch/1` (ledger events), `ghidra-symbols/1` (transient), `symbol-map/1`, `tier-w-label-detail/1`, `tier-w-review/1` (queue header), `tier-w-audit-key/1`, `tier-w-audit-report/1`, `tier-w-matches/1`, `tier-w-run/1`, `tier-w-evaluation/1`. Persisted contracts change additively only.

## 9. Runner
For each pair and condition `symbols-hidden` (`h`) / `symbols-visible` (`v`), the runner creates a PatchTrace project from the local binaries (`ProjectService.create`). It runs Ghidriff through `patchtrace.cli._run_pair`, the same backend/apply path the desktop and `series` use, so an existing completed run is reused (resume). The `BackendConfig` comes from `--python`, `--ghidra-dir` and `--timeout`. `allow_symbol_downloads` is False for `h` (`--no-symbols`) and True for `v`. In the `v` condition, Ghidriff/Ghidra fetch the PDB from msdl.microsoft.com themselves, the same consented host. A local-only symbols-visible mode would need a backend `symbol_policy='local'` and is a follow-up for the backend owner.

Secondary engines (`--engine rz-diff`) run once per pair in the `h` project through the existing `secondary run` command and are tagged with condition `n/a`. Raw outputs stay in the project directories. Matches are extracted to `matches.jsonl`:
- Ghidriff: one-to-one `FunctionMatch` endpoints. VA - PE image base gives the RVA, and the result must lie in [0, SizeOfImage).
- Secondary: `SecondaryMatch` addresses, with the image base subtracted when `image_base_subtracted == 'no'`. Rows marked `unknown` are skipped and counted.

The engine invoker is a Protocol, so tests run without Ghidra.

## 10. Evaluation interface (shared with Tier R)
```python
class TruthLabelLike(Protocol):  pair: str; older_rva: int | None; newer_rva: int | None; answer: str; source: str; tags: tuple[str, ...]
class EngineMatchLike(Protocol): pair: str; engine: str; condition: str; older_rva: int | None; newer_rva: int | None
def evaluate(labels: Sequence[TruthLabelLike], engine_matches: Sequence[EngineMatchLike]) -> dict  # tier-w-evaluation/1
```
Per (engine, condition), each match is scored:
- `correct` when it is a `same` truth pair;
- `wrong` when an endpoint has a different truth counterpart or the pair is labelled `different`;
- otherwise `unscored`.

Reported: precision, recall over the truth pairs, F1, counts, and item-level Wilson 95% intervals (explicitly not lineage-adjusted), split overall, by tag (`exported`, `N2`, `N3`, `N9`, `N10`, `stratum:*`) and by lineage. Labels with `source == 'symbol-derived'` are ignored for any condition other than `symbols-hidden` and `n/a`. A condition left without labels reports `insufficient-labels` with the reason `circular`. `tools/calibration/tier_r/evaluate.py` had not landed at build time. `resolve_evaluator('tier-r')` imports it when it exists and the call shape matches; the local evaluator is the default. Any attribute mismatch is an integration item for builder D.

## 11. CLI (`PYTHONPATH=src python -m tools.calibration.tier_w <cmd>`)
`catalogue`, `resolve`, `pairs`, `fetch-plan`, `fetch`, `symbols`, `labels`, `audit`, `review`, `audit-report`, `run`, `evaluate`, `status`, `guard`. Every command prints one JSON summary. Exit codes:
- 0: ok;
- 1: partial failure or guard findings;
- 2: configuration, consent or input error;
- 3: BLOCKED (a tool or network is missing);
- 5: cancelled.

The only network commands are `catalogue` (without `--from-file`), `resolve` and `fetch`, and each requires `--consent-hosts`.

## 12. Repository guard (hook in `tools.calibration.corpus.guard`, logic in `tier_w/guard.py`)
`guard` fails (and so does `tests/test_calibration_tools.py::test_repository_contains_no_executable_images_outside_fixtures`, plus the Tier-W repository test) when a tracked or untracked-not-ignored file is any of the following:
1. A PDB: MSF 7.00 or 2.00 magic, or a `.pdb`/`.pd_` suffix. The only exception is a self-made fixture under `tests/fixtures/tier_w/` whose SHA-256 is listed in `tests/fixtures/tier_w/SELF_MADE.json` and whose MSF producer strings name LLVM/clang and no Microsoft compiler. (Interpretation: O1 forbids Microsoft PDBs. The integration owner asked for real self-made PDB fixtures, so any other PDB still fails.)
2. A Microsoft image: a PE (anywhere, fixtures included) that has any of:
   - "Microsoft Corporation" or "Microsoft Windows" in ASCII or UTF-16LE within the first 64 MiB;
   - a CodeView PDB name from the known Windows list (`ntkrnlmp.pdb`, `ntoskrnl.pdb`, ...);
   - a basename equal to a Tier-W family file.

   Any file whose basename is a family file name is flagged even when it is not a PE.
3. A Tier-W manifest: a JSON object with contract `calibration-corpus/1` that contains a `tier: W` binary.
4. A Tier-W derived document: a JSON object, or any of the first 50 JSONL lines, with a Tier-W contract and `tier: W`, or a `calibration-labels/1`-shaped line whose `pair` starts with `tw.`.

JSON is parsed only for files whose first non-space byte is `{` or `[` and whose size is at most 64 MiB; anything larger gets a warning finding. The hook adds 4 lines to `corpus.py`.

## 13. Tests and evidence classes
Unit and property tests use the recorded Winbindex fixture plus synthetic variants, fake openers and servers, synthetic PE files (`tests/pe_builder.py`) and an MSF builder, all labelled synthetic. The self-made DLL+PDB pairs in `tests/fixtures/tier_w/` (MIT, from `src/*.c`/`*.cpp`, rebuilt by `make_fixtures.py` with clang 18 and lld-link `/Brepro` without absolute paths) back these checks: the MSF reader, the `llvm-pdbutil` parity (skipped without `llvm-pdbutil`), the label derivation end to end, and fuzzing (mutated fixture bytes must raise only `MsfError`). The live Ghidra test (`PATCHTRACE_TIERW_GHIDRA` / `PATCHTRACE_TIERW_PYGHIDRA_PYTHON`) records `passed/failed/blocked` like the BinDiff harness and never skips silently. It is real Ghidra on self-made input, not Microsoft evidence.
Only the owner's machine can verify:
- Winbindex and msdl access and rate behaviour;
- real Microsoft PE/PDB parsing (OMAP, sizes, stripped flag) and Ghidra time per family;
- the symbol-label error rate;
- the circularity of the export stratum;
- the `pyghidra` driver on Windows.

Windows CI can run the unit suite and the Ghidra live test only where Ghidra is provisioned.

## 14. Open items
- The local `symbol_policy` (backend owner).
- `.pd_` CAB fallback.
- Body-hash lineage recomputation via `lineage.py` after symbol export.
- An HTML review front-end (terminal mode only).
- Tier R evaluator signature alignment (builder D).
- Legal review before publishing anything beyond code (O1).
