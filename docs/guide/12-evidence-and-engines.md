# 12. Evidence, engines and conflicting evidence

PatchTrace treats every observation as evidence with provenance and keeps disagreement visible. This chapter explains the Engine evidence dock, how engines are run and reconciled, what each verdict means, and what to do with a `contested` row. The code behind it is in [22](../internals/22-engines-and-fusion.md).

## Rules the evidence follows

These are product invariants (`docs/plans/worker-brief.md` section 2), not options:

- Every piece of evidence names its source: engine or tool, run, artifact hash, function.
- **Conflicting evidence is kept**, never resolved by a vote or an average. Scores of different engines are never combined.
- **Unknown is not a negative vote.** An engine that did not run, failed, or has no comparable record contributes "unknown", not "against".
- Evidence derived from the same upstream data (for example two engines reading the same Ghidra database) counts once.
- Older/newer orientation is explicit everywhere.
- Advisory text, strings and code are untrusted data: bounded and escaped, never executed.
- No number is shown as vulnerability confidence. No calibrated model has passed its gates, so there is no confidence percentage anywhere ([22](../internals/22-engines-and-fusion.md), section "What is calibrated").

## The Engine evidence dock (built)

Open it from View > Engine evidence or press **Ctrl+Shift+E**. It is created eagerly at window start because it owns the engine probe and BinDiff setup. It has two tabs.

**Evidence tab.** One row per Ghidriff match with a cell per engine (Ghidriff, BinDiff, rz-diff), each in that engine's own native units (Ghidriff: raw match types; BinDiff: similarity and algorithm; rz-diff: byte similarity). Controls: **Filter** (All, Contested, Unknown, Single engine, Agree, Engine-only records), a search box, **Hide agreed**, **Show triage index**, **Copy provenance**, **Refresh**, and **Go to match in navigator** for the selected row. Banners say when results are stale (the project changed) or partial (an engine failed). Strings from tools, files and function names are shown as plain text.

**Engines tab.** Shows each engine's status and lets you run them:

| Control | Meaning |
|---|---|
| Engine checkboxes | rz-diff and BinDiff (Ghidriff is the primary and always present) |
| Parallel engines | 1 or 2 (hard cap 2 until Windows memory is measured on real pairs) |
| Timeout (s) | per engine, 60 to 86,400 |
| **Run selected engines** / **Cancel** | background run with a live elapsed timer; no confirmation dialog |
| **Probe engines** | checks which engines are usable here |
| **Import .BinDiff...** | store a genuine `.BinDiff` result for this exact pair |
| **BinDiff setup** | absolute path of the BinDiff 8 executable; `.BinExport` for the older (primary) and newer (secondary) file; **Validate .BinExport files** |

## The engines

| Engine | Role | Needs | Notes |
|---|---|---|---|
| Ghidriff | primary (baseline), always | backend ([10](10-getting-started.md)) | GPL-3.0 external process |
| rz-diff (rizin) | second opinion, byte level | `rz-diff` on PATH or `--rz-diff` | LGPL; weak evidence; raw byte similarity is dominated by address noise |
| BinDiff 8 | second opinion, structural | BinDiff executable and two `.BinExport` files | never bundled, never found via PATH |
| Unified fusion | derived ordinal view over the stored outputs | a finished Ghidriff run | experimental, see below |

`.BinExport` files are untrusted. Each is validated in a memory- and time-capped worker (size cap 256 MiB, wire pre-scan before any protobuf object is built). Export from Ghidra with **File > Export > Binary BinExport (v2) for BinDiff** (or IDA's BinExport plugin) and choose "Subtract Imagebase" the same way for both files. A file whose `executable_id` is not a SHA-256 is refused unless you tick the explicit "Accept .BinExport files without a SHA-256 executable id" override; the override is recorded in provenance. Nothing is uploaded.

Headless: `secondary run`, `secondary rzdiff`, `secondary import-bindiff`, `secondary binexport-check`, `secondary reconcile` ([16](16-cli-reference.md)). A partial success (some engines failed) exits 3 with `status: partial`.

## Verdicts: how to read a row

Reconciliation compares each secondary engine's pairing with Ghidriff's by address. The dock shows these verdict names (internal names in brackets):

| Verdict | Meaning | What to do |
|---|---|---|
| **Agree** [corroborated] | At least one secondary engine pairs the same endpoints, and none contradicts | Still verify: engines can share disassembly or compiler artifacts |
| **Contested** | An engine pairs the same function differently | Review the identities manually before interpreting a patch |
| **Single engine** | Only Ghidriff has an address-comparable match; absence elsewhere is not contradiction | Treat as unconfirmed |
| **Unknown** [insufficient] | Secondary output cannot be compared to this match | Nothing to conclude |
| **Engine-only records** | A secondary engine reports a pair that Ghidriff does not | Inspect; it is not a Ghidriff match |

A contradiction always takes priority over any number of agreeing engines. A cell that says "no record", "not comparable", "pairs elsewhere", "not run" or "failed" says exactly that; the cell never shows a made-up value.

**Triage index.** Behind **Show triage index** is a number from 55 to 83 (55 single-engine baseline, +20 for BinDiff structural corroboration, +8 for rz-diff byte corroboration, capped at 83). It is an ordinal, uncalibrated triage aid for function *matching* only. It is not a probability, not patch validity and not exploitability. It is hidden by default.

## Handling conflicting evidence

1. Filter to **Contested** and sort the rest out later.
2. Open the row's detail; each engine's native record and its limitation note are listed. An alternative-rank note ("Ghidriff matches bindiff alternative rank 2") means Ghidriff's choice equals a lower-ranked candidate of that engine; the verdict is unchanged.
3. Look at the code of both candidate pairings in the main code panes.
4. If you decide the Ghidriff pairing is wrong, use **Correct match...** with a reason ([11](11-workflow-compare.md)). The correction is recorded, the engine outputs stay as they were.
5. Never read **Agree** as "this is the vulnerable function".

## Unified comparison tab (experimental, built)

**Ctrl+Shift+U** shows the Unified tab, tabbed with Engine evidence. It displays a derived, ordinal fusion of the stored engine outputs: a pairing **decision** (matched, tentative, candidate, contested, ambiguous, older-only, newer-only, unknown) and a **change class** (unchanged, cosmetic, material, review, unknown, not-applicable). It uses labels, not numbers or probabilities. It never changes the Ghidriff result or any stored result.

- **Running it from the dock needs the `unified/enabled` setting**, which defaults to off in the alpha. This guide found no Setup control for it; see [99](99-open-doc-questions.md). The headless `unified run` does not check that flag.
- `unified run PROJECT`, then `unified show`, `unified explain --row ID`, `unified status`. A stale result is reported by `status`.
- `unchanged` and `cosmetic` rows carry a named proof (`UNCH/1`, `COS-ADDR/1`, `COS-LAYOUT/1`; `COS-PSEUDO/1` is decompiler-relative and stays visible). Their counts stay visible; do not ignore them without reading the stated proof.
- It is disabled while a Ghidriff analysis or an engine run is active.

## Other evidence sources

| Source | Built? | Where |
|---|---|---|
| Static tool evidence: capa, FLOSS, Detect It Easy | CLI built (`intel-tools probe/run/delta`); the Capabilities panel is built | [16](16-cli-reference.md) |
| CSAF advisories and CWE hypotheses | CLI built (`intelligence import/fetch/explain`) | advisory facts are vendor claims, not proof for a function |
| Patch-intent leads | CLI (`pilot`) and Leads dock built | an ordered list of places to look, not a likelihood |
| CISA KEV | CLI (`kev`) built; the Exploitation context panel is built | context about a CVE, never a ranking input |
| YARA-X rule workflow | CLI (`rules`) built; the Detection rules panel shows stored results | one candidate, one version at a time |
| KB and CVE | CLI (`kb`) built; the KB and CVE panel is built; the `patch` verb is **planned** | advisory context with stated coverage |
| Anchor fabric | CLI `fabric list/show/resolve/stats` built (read-only) | shared anchors that panels navigate by |

The only panel still **not built** in the manifest is Guide (`patchtrace panels list` shows 13 built and 1 not built, checked 2026-10-15). See [13](13-panels-and-layout.md).
