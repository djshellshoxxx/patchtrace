# Phase C research: headless BinDiff automation, .BinDiff import hardening, CI

Status: research note, 2026-10-14. Companion to `docs/specs/bindiff-execution.md` (SPEC-29, C4).
Method: primary sources only, about 12 fetches. No repository was cloned and no git operations were run.
Evidence labels: **[fetched]** read in this session; **[search]** only the search-result snippet was read;
**[unverified]** claim from the spec or from memory that this run could not confirm.

## 1. Findings table

| # | Source | License | What it shows | How it applies to PatchTrace |
|---|---|---|---|---|
| 1 | https://github.com/google/bindiff (README) [fetched] | Apache-2.0 | Build needs BinExport 12 as a dependency. The GUI uses the commercial yFiles library (`YFILES_DIR`, Gradle `shadowJar`, `bindiff-ui-all.jar`). The README documents no CLI flags, exit codes, output formats or install layout. | Confirms spec D1: never redistribute the GUI or yFiles. The CLI contract (U3-U5) must come from a live run or the source, not from this README. |
| 2 | https://github.com/google/bindiff/releases (tag `v8`) [fetched] | Apache-2.0 | v8 is the latest release, released 25 Sep (the year is not shown on the page). The release lists "Assets 6", but file names did not render. Release notes say a CLI option was added to output similarity scores only, without writing `.BinDiff`. | Partly answers U1: v8 has six assets. Names, URLs and hashes for the pin file still need the GitHub API or a real download. The "similarity-only" option is a possible lighter path for the probe, but its flag name is unknown. |
| 3 | https://github.com/google/bindiff/blob/main/src/main_portable.cc [fetch failed: 503; raw URL 404] | Apache-2.0 | Not read in this run. | The spec's [src] claims (flag names, exit code 1, `--version` and `--help` handling, `output_dir` checks) are **not re-verified here**. Keep them marked as source-read by the spec author until someone checks again. |
| 4 | https://github.com/google/binexport (README) [fetched] | Apache-2.0 | Supports IDA Pro (9.4 or later; 8.x discontinued), Binary Ninja and Ghidra. Ghidra headless export is `analyzeHeadless <proj> <dir> -preScript BinExport.java`, configured by `BinExport.properties` or arguments. The README does not mention an executable SHA-256 field. | Gives a concrete headless producer path for a future CI fixture (currently out of scope, D6). The spec's claim that the Ghidra exporter writes `getExecutableSHA256()` is **[unverified]**: the README is silent on it, so it needs a check in BinExport's source (U9). |
| 5 | https://github.com/joxeankoret/diaphora [fetched] | AGPL-3.0 since v2.0 (GPL-3.0 up to 1.2.4; commercial licence available) | IDA-plugin diffing with batch automation and scripting for export and diff. No headless CLI, SQLite export format or BinDiff interop is described on the page. | Reference only. AGPL is incompatible with copying code into this project's tree without a legal review. Do not vendor it. Use only as an idea source for the batch workflow. |
| 6 | https://sqlite.org/uri.html [search snippet only; direct fetch failed on DNS] | Public domain | `immutable=1` tells SQLite the file cannot change. If the file does change, results can be wrong or `SQLITE_CORRUPT` can occur. An Aug 2026 forum report says an `immutable` file is still opened read-write unless `mode=ro` is also set. | Spec §3/§7 use `mode=ro&immutable=1` on a private copy. That is right. The copy is essential, because `immutable` is unsafe if anything can still write the file. Check the SQLite version before relying on `immutable` alone. |
| 7 | https://www.sqlite.org/security.html [search snippet only] | Public domain | Defensive mode (`SQLITE_DBCONFIG_DEFENSIVE`) blocks ordinary SQL from writing the file in unsafe ways. The docs recommend `PRAGMA trusted_schema=OFF` on every connection to untrusted databases, and call these defences extra layers, not a substitute for input checks. | Spec §7.2 does not mention either setting. Add both to `import_bindiff`'s connection setup (see section 3). |
| 8 | https://www.sqlite.org/src/doc/latest/doc/trusted-schema.md [search snippet only] | Public domain | `trusted_schema` defaults to ON. With it OFF, SQL functions in triggers, views, CHECK, DEFAULT, indexes and generated columns are refused unless tagged `SQLITE_INNOCUOUS`. | Explains why the spec's plan to reject triggers, views and virtual tables is still worth doing. Rejecting them is simpler and more auditable than relying on this setting alone. |

Not researched in this run (budget reached, no primary source fetched): Windows Job Object patterns beyond the spec's own `jobs.py` review; GitHub Actions workflows that run BinDiff; third-party `bindiff` or `binexport` Python wrappers; the `.BinDiff` schema itself.

## 2. Ideas worth adopting

1. **Connection hardening as one function.** In `import_bindiff`, open with `file:<copy>?mode=ro&immutable=1` (URI flag enabled), then run `PRAGMA trusted_schema=OFF`, `PRAGMA query_only=ON`, and enable defensive mode. Python 3.12+ exposes `Connection.setconfig(sqlite3.SQLITE_DBCONFIG_DEFENSIVE, True)` **[unverified: check the 3.12 `sqlite3` docs before use]**. Run the setup on every connection.
2. **Authorizer whitelist.** `Connection.set_authorizer()` can allow only `SQLITE_SELECT`, `SQLITE_READ` on the fixed table and column names, and `SQLITE_FUNCTION` for a short list of built-ins. Deny `ATTACH`, `PRAGMA`, `CREATE`, `TRIGGER` and everything else. This is a cheap, fail-closed second layer behind the schema check. It complements the spec's `sqlite_master` rejection (§7.2) rather than replacing it.
3. **Headless BinExport in CI, later.** `analyzeHeadless ... -preScript BinExport.java` (BinExport README) is a concrete producer for committed fixtures. It fits the spec's P6 fixture step, but only after the producer decision in C3.
4. **Pinned, verified downloads.** Keep the spec's D4/D5 approach (pinned SHA-256, no `dpkg -i`, no MSI install). The release page gives the asset count, so the pin file can list exactly six candidate assets once the names are confirmed.

## 3. Warnings and pitfalls

- **Diaphora is AGPL-3.0.** Do not copy code from it into this Apache/MIT-style tree. Treat it as a design reference only.
- **yFiles.** The BinDiff GUI needs a commercial yFiles licence. The CLI path avoids it, but any packaged artefact that included the GUI jar would bring the licence question in. Keep D1 as written.
- **`immutable=1` is not a safety feature by itself.** If the file can change, results can be wrong or corrupt. Always copy first and add `mode=ro`.
- **`trusted_schema` defaults to ON.** The spec's importer currently relies only on `type='table'` checks; it needs `PRAGMA trusted_schema=OFF` as well.
- **Version gap.** The release page says v8 is the latest open-source release. The BinExport README says IDA 9.4+ is supported. Any IDA-produced `.BinExport` with an older IDA plugin is unverified (spec U9).
- **Source drift.** The spec's [src] claims could not be re-read here. Before C4 implementation, re-read `main_portable.cc` on the pinned tag, not `main`.

## 4. Answers to the spec's §12 unknowns (from this run)

| ID | Answer from this run | Status |
|---|---|---|
| U1 | v8 release has six assets; names and hashes not visible. | Partial |
| U2 | Not researched. | Open |
| U3 | Not verified: source unreadable. | Open |
| U4 | Not verified. | Open |
| U5 | Not verified. | Open |
| U6 | Not verified. | Open |
| U7 | No evidence contradicts "CLI does not need Java". The GUI needs Java and yFiles, which the README states. | Partial, supports spec |
| U8 | Not verified. | Open |
| U9 | BinExport README does not mention an executable hash field. Inconclusive. | Open, needs BinExport source |
| U10 | Not verified. | Open |
| U11 | Not verified. | Open |

## 5. Open questions

1. Can the pinned v8 `.deb` and `.msi` be listed by name through the GitHub API (needs `add_repo` with `push`, or an authenticated download)? Blocks D4/D5 and U1.
2. Re-read `src/main_portable.cc` at tag `v8` for flag names, exit codes and the stderr/stdout split (U3, U4). Blocks §2 of the spec.
3. Does `BinExport2Builder` really write `getExecutableSHA256()` (spec §3)? Check the source at the pinned BinExport tag. Blocks D11.
4. Should the importer also set `mode=ro` (not only `immutable=1`)? Yes, per the forum report; confirm the SQLite version that ships with Python 3.x on both OSes.
5. Confirm the Python-side API for defensive mode in the Python version used by CI (`setconfig`).
