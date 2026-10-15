# 14. Series: following a function across 3 to 8 builds

A **series** follows functions across an explicit, ordered list of 3 to 8 builds of one binary (for example an RTM build and several cumulative updates). PatchTrace builds one ordinary two-artifact project per **adjacent** pair (B1 to B2, B2 to B3, ...) and assembles *chain hypotheses* from them. Contract `nway/1`, spec `docs/specs/nway.md` (SPEC-09) and `docs/specs/series-window.md` (SPEC-09b). Internals: [21](../internals/21-data-model-and-storage.md), [22](../internals/22-engines-and-fusion.md).

A chain is a **hypothesis assembled from independent pairwise results**. It is not a similarity score, and "the same function in builds 1, 2 and 3" is something you check, not something PatchTrace proves.

## Create a series (CLI, built)

The series is created headlessly; the GUI only reads it.

```bash
patchtrace series create \
  --builds rtm/afd.sys cu1/afd.sys cu2/afd.sys cu3/afd.sys \
  --labels RTM CU1 CU2 CU3 \
  --root work/afd-series \
  --direct
patchtrace series chains work/afd-series/series.json --function AfdBind --json
```

| Flag | Meaning |
|---|---|
| `--builds FILE...` | 3 to 8 files, **in your order, oldest first**. Order is never inferred from names or dates. Duplicate hashes are rejected. |
| `--labels LABEL...` | short names for the builds (max 64 characters each) |
| `--root DIR` | holds `series.json` and the pair projects |
| `--direct` | also creates a first-to-last pair project used to confirm or contradict chains |
| `--run` | actually run Ghidriff for pair projects without a completed run. Without it nothing runs; pairs without a result simply have no hops. Needs `--python` and `--ghidra-dir` |
| `--python`, `--ghidra-dir`, `--timeout` (default 3600), `--cache-dir` | backend options for `--run` |
| `--replace-corrupt` | if `series.json` is damaged, keep a `series.json.corrupt-*` copy and write a new one |

Pair projects are found by their ordered artifact hashes, never by directory name. One unreadable or foreign sibling directory does not abort the whole root. `series chains` prints chains as text or, with `--json`, one `enrichment-cli/1` document; `--function NAME` or `--address HEX` filters. Exit codes: `series create` 0 complete, 3 a pair failed (partial), 2 for bad input; `series chains` 4 when there is no chain and no stale reason ([16](16-cli-reference.md)).

You can instead run each pair yourself ([11](11-workflow-compare.md)) or import its Ghidriff JSON into the pair project, then re-run `series create` to refresh `series.json`.

## How chains are built (rules)

- A function in build k is joined across the (k-1, k) and (k, k+1) projects **within that same build**: by address when both records have one, otherwise by exact name among address-less records. Addresses are never compared across different builds.
- Edge sources, in precedence order: your manual corrections; the normalized matches (modified, added, removed, split, merged, ambiguous, unmatched); and, to cross a pair where a function did *not* change, the engine relations preserved in the run's raw Ghidriff JSON (`matches.address_matches`, after verifying the raw hash), only when 1:1 and unclaimed.
- Only **1:1 hops extend a chain**. A split, merged, ambiguous or unmatched hop ends the chain and is recorded as an **event**, so no many-to-many transitivity is ever implied.
- Chain **status**: `inferred` (the default), `confirmed` (the optional direct first-to-last pair has a 1:1 edge between the chain's endpoints), `contradicted` (the direct pair maps the start somewhere else).
- Chain **events**: `added`, `removed`, `split`, `merged`, `ambiguous`, `unmatched`, `reverted` (the code text at build k equals the text at an earlier build after a change in between).
- Match ratios stay as upstream text. Two Ghidriff correlators share the name `NameParamHash`; match types are shown verbatim and not used for scoring.
- Changing a pair project (a rematch, a new run) makes chains through it **stale**; recomputation is deterministic.
- Limits: at most 8 builds and 100,000 nodes; `series.json` is capped at 256 MiB and is strict JSON.

## Read a series in the GUI (built)

Choose **Project > Series window...** (the entry opens the Series dock and asks for a `series.json`), or show the dock from the View menu. The Series panel is a **bottom dock with one tab per opened `series.json`**; it is read-only, and closing a tab or the dock changes no project data. An earlier separate window was converted to a dock (the single-window rule; recorded in `docs/specs/non-goals.md` N-02 and the GUI plan migration M3).

Each tab loads on a worker thread (progress bar, **Cancel load**) and shows two tables:

| Table | Columns |
|---|---|
| Chains | Chain, Hops, Highest hop, Sum, Status, Events, Stale |
| Hops of the selected chain | Hop, From, To, Category, Match types, Ratio, Score, Pair state |

Controls: **Reload**, **Cancel load**, a text filter (function, address, label or chain ID; 200 characters), status filter (inferred, confirmed, contradicted), event filter, **Only stale**, **Only scored**, **Min highest hop** (0 to 100), and a sort box (Highest hop, Sum of hops, Hop count, Name, Chain ID). Buttons: **Open pair at this function** (jumps to the pair project and match, only when that pair is readable) and **Copy chain**.

**Score column.** Each hop shows the *stored* `attention/1` score of that pairing from the pair project's default-profile ranking. Nothing is recomputed. When there is no number the cell says why: `unchanged` (the function did not change in this pair, so it is not ranked), `n/a` for no stored ranking, an unreadable pair, or a stale ranking, and `not ranked` when the stored ranking has no entry for the pairing. Hover for the reason. A score is a reading order, as everywhere ([11](11-workflow-compare.md)).

**Pair state** says whether each pair project was readable (`ok`, `changed`, or an unreadable or locked state). A pair project that is open for writing in the main window is *locked*; the view reads pairs open-read-close and tolerates that. A banner appears if `series.json` is damaged and names the remedy: recreate it with `patchtrace series create`, adding `--replace-corrupt` if needed.

Error codes you may see: `PT-NWAY-INPUT`, `PT-NWAY-LIMIT`, `PT-NWAY-PAIR`, `PT-NWAY-STORAGE`, `PT-NWAY-CANCEL`.

## What `series.json` contains

Strict JSON, schema `nway/1`, written next to (not inside) the pair projects (`nway/contracts.py`):

| Field | Meaning |
|---|---|
| `series_id` | SHA-256 over the ordered build hashes; a mismatch makes the file invalid |
| `builds` | 3 to 8 entries: `ordinal` (0 to n-1 in your order), `label`, `artifact_sha256` (unique) |
| `pair_projects` | exactly one entry per adjacent pair: relative POSIX `path` (no drive, no `..`), `project_id`, `revision`, `run_id`, `notes`. The recorded revision and run are what staleness is measured against |
| `direct_project` | optional first-to-last pair (`--direct`) |
| `node_count` | number of function nodes seen |
| `chains` | each with `chain_id`, ordered `nodes` (ordinal plus address and/or name), `edges` (category, match types, upstream ratio text, `manual`, `match_id`), `hops`, `weakest_match_type`, `status`, `gaps` (ordinals with no edge), `events` |

A node needs an address or a name; a node reached only through an upstream address relation has no name. An edge joins **adjacent** builds only. A chain has at least 3 nodes, and its hop count must equal its edge count.

## Reading a result well

- Start with **confirmed** chains if you created a direct pair; they were cross-checked by a separate first-to-last comparison. An **inferred** chain is an assembly of hops and can hide a rename or a swap.
- A **contradicted** chain is not wrong data: the direct pair maps the start function somewhere else. Open both pair projects and decide.
- `reverted` events matter for patch analysis: a function whose text goes back to an earlier version after a change can mean a rollback or a different servicing branch; check the builds rather than assume.
- A `Stale` mark means a pair project changed after the series was written. Re-run `series create` (it reuses pair projects and does not re-run Ghidriff unless `--run`) before trusting the chain.
- Per-hop scores come from rankings you computed earlier in each pair project (**Rank changes** or `rank`); a pair with no stored ranking shows `n/a`, not 0.

## What is not covered

- Series creation from the GUI (there is no such control; create it with the CLI).
- Native three-build acceptance of the Series dock on the frozen executable, and a manual DPI pass, are open items (`tasks/todo.md`). The frozen smoke covers a three-build series through the CLI with imported synthetic results (check A6s); the native `--run` variant with real Ghidra is not done.
- Interpretation of a chain is yours: a hop that ranks high says "read this", not "this is a fix".

Next: [15 Files and PE overview](15-files-and-pe-overview.md).
