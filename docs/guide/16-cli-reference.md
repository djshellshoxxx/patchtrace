# 16. CLI reference

Every headless verb, with a working example, the exit codes, and the JSON envelope. The authoritative contract is `docs/specs/cli-umbrella.md` (SPEC-44); the flag-by-flag table generated from `argparse` is `docs/cli-reference.md` (generated 2026-10-14, before the `fabric`, `kev`, `pilot` and `rules` verbs landed; its sentence "the registry holds one verb: `panels`" is out of date, see [99](99-open-doc-questions.md)). Run any verb with `--help` for the live text. No CLI path imports Qt.

## Invocation

```bash
patchtrace <verb> ...                          # installed; or PatchTrace.exe <verb> ... (frozen)
PYTHONPATH=src python -m patchtrace <verb> ...       # from a checkout (python -m patchtrace.cli does nothing: cli.py has no __main__ guard)
patchtrace                                     # no arguments: opens the desktop
```

`PatchTrace.exe` dispatches to the CLI whenever its first argument is anything but `--self-test` or a Qt `-platform`/`-style` option, so a typo in a verb fails with exit 2 and never starts the GUI (`src/patchtrace/__main__.py`). `patchtrace --help` lists: `rank flags correlate cache acquire series secondary intelligence unified intel-tools backend` (built into `cli.py`) and `fabric kev panels pilot rules` (discovered from `src/patchtrace/cli_commands/`, one file per verb, [32](../internals/32-how-to-extend.md)). A discovered file that fails to import is listed as `unavailable (could not be loaded)` and exits 3; it never hides the other verbs.

## The `enrichment-cli/1` envelope

With `--json` stdout carries **exactly one JSON document** (sorted keys, one line) and nothing else; diagnostics go to stderr:

```json
{"command": "rank", "contract": "enrichment-cli/1", "result": {...}, "status": "complete", "warnings": []}
```

| Field | Meaning |
|---|---|
| `contract` | always `enrichment-cli/1` |
| `command` | the verb (some include the action) |
| `status` | `complete`, `partial`, `failed`, `cancelled`, `unavailable`; also seen: `stale`, `no-results` |
| `result` | verb-specific. `kev` and `rules` put their own contract name (`kev/1`, `yara-rules/1`) and a `record` inside `result`; the shape differs per verb, so read a sample of `--json` output before scripting |
| `warnings` | list of strings |

Without `--json`, warnings print to stderr as `warning: ...` and the text report goes to stdout. An unexpected exception prints one line (passed through `redact_log`) and exits 3, with `--json` too. Ctrl+C exits 5. `status` values beyond the first five are outside the closed set documented in `enrichment.md` (SPEC-44 section 8 item 4).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 2 | invalid arguments, configuration, environment or **consent** (argparse errors included) |
| 3 | runtime failure; for several verbs also a **partial** result |
| 4 | a legitimate "no result" (complete evidence, zero rows). Not a failure |
| 5 | cancelled |

Exceptions you will meet (SPEC-44 section 4, read at `fd6cdba`; confirm with `--help` and the table for a verb you automate):

- **Partial.** `rank` and `correlate` exit 0 with `status: partial`; `flags`, `series create`, `secondary run`, `unified run`, `intelligence explain`, `intel-tools run` exit 3.
- **Zero results.** `rank` exits 4; `correlate` exits 0.
- **No bundle.** `backend status` and `backend verify` exit 4; `backend selftest` and `backend diagnose` exit 2. `backend` uses **5** for a bundle that fails verification, not only for cancellation.
- `unified status` exits 0 even with no result; `unified show` exits 2 when none exists.
- `intel-tools delta` with no stored evidence exits 2 with `status: complete`.
- `cache` exits 0 always on success; `secondary binexport-check` has worker codes outside this set that the parent maps itself.

## Consent flags

Nothing touches the network without a flag naming the exact host ([17](17-privacy-and-network.md)). `acquire --consent-hosts`, `intelligence fetch --consent-hosts`, `kev fetch --consent-hosts` take the exact host list; `correlate --fetch` needs `--consent-providers` equal to `--providers`. Consent failures exit 2 before any socket opens.

## Enrichment

```bash
patchtrace rank PROJECT --json --limit 20             # attention/1 ranking; stores it unless --dry-run
patchtrace rank PROJECT --profile default --cache-dir C:\cache --refresh
patchtrace flags PROJECT --feature-id 1234567890      # WIL Feature_<uint32> transitions
patchtrace correlate PROJECT --cve CVE-2024-12345 --snapshot saved.json          # offline
patchtrace correlate PROJECT --cve CVE-2024-12345 --fetch \
    --consent-providers nvd,msrc --providers nvd,msrc --api-key-env NVD_API_KEY --save-snapshot out.json
patchtrace cache status --cache-dir C:\cache          # actions: status, verify, prune [--target-bytes N]
```

`rank`: `--run`, `--weights FILE` (integers 0 to 100 per detector), `--disable DETECTOR`, `--profile NAME|FILE` (cannot combine with `--weights`/`--disable`), `--limit` (0 = all). Base ranking is never changed by `correlate`.

## Acquisition

```bash
patchtrace acquire search afd.sys --consent-hosts winbindex.m417z.com
patchtrace acquire fetch afd.sys --older <sha256> --newer <sha256> --project NEWDIR \
    --consent-hosts winbindex.m417z.com,msdl.microsoft.com
```

`search` exits 4 when no downloadable candidate exists. `fetch` refuses equal SHA-256s and an existing project directory (exit 2).

## Series

```bash
patchtrace series create --builds b1.dll b2.dll b3.dll --labels RTM CU1 CU2 --root R --direct [--run --python PY --ghidra-dir G]
patchtrace series chains R/series.json --function NAME --json     # or --address 0x...
```

See [14](14-series.md).

## Secondary engines

```bash
patchtrace secondary import-bindiff PROJECT result.BinDiff
patchtrace secondary run PROJECT --engine rz-diff --engine bindiff --bindiff /abs/bindiff \
    --older-binexport o.BinExport --newer-binexport n.BinExport [--accept-unbound-binexport] --max-parallel 2 --timeout 1800
patchtrace secondary rzdiff PROJECT --rz-diff /usr/bin/rz-diff       # alias of run --engine rz-diff
patchtrace secondary reconcile PROJECT
patchtrace secondary binexport-check f.BinExport --artifact-sha256 <sha256> --role older
```

`--max-parallel` is 1 or 2. `--timeout` 60 to 86,400. `rz-diff` is looked up on PATH; BinDiff never is. `--no-cache` ignores stored engine runs. Partial success exits 3.

## Intelligence

```bash
patchtrace intelligence import PROJECT advisory.json --cve CVE-2024-12345     # CSAF 2.0, strict, nothing sent
patchtrace intelligence fetch PROJECT --cve CVE-2024-12345 --consent-hosts msrc.microsoft.com [--cache-dir D] [--offline]
patchtrace intelligence explain PROJECT --cve CVE-2024-12345 [--older-product PID] [--newer-product PID] --export out.md
```

`explain` never uses the network; `--export` suffix chooses `.json` or `.md`. A file name never maps to a product; use `--older-product`/`--newer-product` for your own assertion. Output restates vendor claims with explicit unknowns.

## Unified (experimental)

```bash
patchtrace unified run PROJECT [--sources ghidriff,bindiff,rz-diff,manual] [--timeout 3600] [--refresh] [--fail-on-none]
patchtrace unified show PROJECT --decision contested --change material --class constant --search AfdBind --limit 50 [--all]
patchtrace unified explain PROJECT --row <id-or-8+-digit-prefix>
patchtrace unified status PROJECT
```

Derived and ordinal; never alters the project. In this build `--no-extract` is the only mode and `--no-decompile` has no effect. `unified run` does not read the `unified/enabled` GUI setting.

## Static tool evidence

```bash
patchtrace intel-tools probe --capa /abs/capa --floss /abs/floss --diec /abs/diec
patchtrace intel-tools run PROJECT --profile basic|context|full [--engines capa,floss] [--floss-deobfuscate] [--timeout 600]
patchtrace intel-tools delta PROJECT [--engines capa] [--show-secrets]
```

Tools are never run on anything but a verified read-only scratch copy, never executed as the target. Executables come from flags or `PATCHTRACE_CAPA`, `PATCHTRACE_FLOSS`, `PATCHTRACE_DIEC` (and `_DIEC_DB`, `_DIEC_LIB`, `_CAPA_RULES`, `_CAPA_SIGS`); a build that is not the pinned release needs `--<tool>-accept-untested` and is recorded as untested. `--floss-deobfuscate` prints its consent text (it runs a CPU emulator).

## Backend bundle

```bash
patchtrace backend status [--bundle-dir D] [--work-dir W]
patchtrace backend verify --full
patchtrace backend selftest --older old.dll --newer new.dll --expect-function NAME --timeout 3600
patchtrace backend diagnose
```

All four are bundle-aware and meaningful only when `backend/` sits next to the executable ([10](10-getting-started.md)).

## Anchor fabric (read-only)

```bash
patchtrace fabric list --project P --kind function --side both --role observed --limit 100
patchtrace fabric show --project P <anchor-id-64-hex>
patchtrace fabric resolve --project P --kind function --side newer AfdBind     # found | ambiguous | unknown
patchtrace fabric stats --project P
```

`--limit` 1 to 500. A stale or unreadable batch makes the read partial (exit 3): a missing anchor is then unknown, not a negative answer. Producers publish anchors; this verb never writes.

## CISA KEV catalog

```bash
patchtrace kev status [--kev-dir D] [--max-age-days 30]
patchtrace kev plan --source cisa-github                      # prints the exact request; no network
patchtrace kev fetch --source cisa-github --consent-hosts raw.githubusercontent.com [--accept-shrink]
patchtrace kev import saved-kev.json
patchtrace kev lookup CVE-2024-12345 [--from-cve-snapshot snap.json] [--catalog f.json] [--md]
patchtrace kev diff [--from ID --to ID]
patchtrace kev prune --keep 3 --yes                           # the only deletion
```

Sources: `cisa-github` (`raw.githubusercontent.com`) and `cisa-site` (`www.cisa.gov`); `fetch` is the only network call and prints its request on stderr first. A stale catalog is `partial` and still exits 0; `--max-age-days` exceeded exits 3; no catalog exits 4. KEV is context about a CVE and never changes a ranking.

## Patch-intent leads

```bash
patchtrace pilot leads PROJECT [--cve CVE-2024-12345] [--assume-applies CVE-...] [--class fit --class review] \
    [--limit 20] [--no-unified] [--show-dismissed] [--dry-run] [--export out.md]
patchtrace pilot why PROJECT --candidate KEY [--cve CVE-...]
patchtrace pilot review PROJECT --candidate KEY --action pin|unpin|dismiss|restore|note [--text "..."]
```

Reads stored results only; nothing is sent or run. A lead is a place to look, ordered by explainable rules (integer keys, no score), and does not show that a function contains or fixes a CVE. Review events are appended and never edited. Exit 4: no completed run, no stored advisory for a named CVE, no lead.

## Detection rules

```bash
patchtrace rules probe
patchtrace rules propose PROJECT --match MATCH_ID --direction both [--confirm-material]
patchtrace rules show PROJECT [--candidate ID | --version ID]
patchtrace rules decide PROJECT --candidate ID --accept --label "AFD bind check" [--cve ID --kb ID --cwe ID --note T]
patchtrace rules test PROJECT --version ID --series DIR [--extra F] [--clean-dir D] [--expect expect.json] [--timeout 60]
patchtrace rules export PROJECT --version ID --out rule.yar [--include-names] [--with-warnings]
patchtrace rules history PROJECT [--lineage ID]
```

One candidate, one version, one project at a time. `decide --accept` stores a version and writes no file; `export` writes a *new* `.yar` and never replaces one. The YARA-X engine runs only in a hidden capped worker. `propose` needs the live pair-evidence seam (`BACKEND`); without it, it says so and changes nothing. Nothing touches the network.

## Panels

```bash
patchtrace panels list [--json]     # the manifest: id, built/not-built, area, tab group, shortcut, requires
patchtrace panels check [--json]    # lints ids, shortcuts, tab groups, tooltip prefixes, claims, imports
```

## Specified but not built

`patch`, `search`, `graph`, `strings`, `kb` (its `kb index` dispatcher exists in `kbcorrelation/cli_index.py` but no verb is registered), `build-env`, `pe-meta`, `calibration`, and the proposals `doctor`, `export`, `import`, `show`, `project` (SPEC-44 sections 7 and 9). Do not script against them.
