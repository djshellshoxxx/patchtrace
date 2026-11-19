# `patchtrace pilot`

`leads` reads the verified local CISA KEV catalogue, if available. It reports a
CVE as listed (with the date added), not in that snapshot, or unknown when no
readable catalogue is available. This context does not change function order.
The catalogue snapshot is part of the result identity; `why` and `review`
detect changes to it. An older stored result with matching inputs may be reused.

Produces ordered, explained leads for changed function pairs. A lead is a place to look. The order follows explainable rules, not likelihood. A lead does not show that a function contains or fixes any CVE. The command reads stored results and sends nothing.

```
patchtrace pilot leads ...    # compute, store and list the leads of the project
patchtrace pilot why ...      # explain one lead from the stored result
patchtrace pilot review ...   # pin, dismiss or annotate a lead (append only)
```

Useful `leads` options include `--cve`, `--class` (`fit`, `review`, `partial`, `code`, `queue`), `--limit`, `--no-unified`, `--show-dismissed` and `--export`.

`review` appends a decision. It does not delete the lead or rewrite earlier evidence. Dismissing a lead does not mean its code was validated.

Desktop equivalent: the [Leads panel](31-leads-panel.md) (`Ctrl+Shift+L`).

## Continue a retained KB/CVE investigation

After the existing `kb import-pair` or `kb attach` workflow has attached advisory
context to a project, complete its comparison before preparing leads. Eligible
retained CVRF cards can supply context for CVEs outside the project's CSAF
advisory universe. The project must retain the original field bindings and
source digests; older bundles without those bindings remain unknown.

```bash
patchtrace pilot leads PROJECT --cve CVE-2024-12345 --json
patchtrace pilot why PROJECT --candidate KEY --cve CVE-2024-12345 --json
patchtrace pilot review PROJECT --candidate KEY --cve CVE-2024-12345 --action note --text "Review rationale"
patchtrace export PROJECT --out report.json --report-version 2 --json
```

Replace `PROJECT`, the CVE and `KEY` with the project path and identifiers from
the returned leads. These commands use retained project evidence and the local
KEV catalogue. They do not fetch advisory sources or run a comparison engine.

CSAF remains authoritative for an overlapping CVE, including negative,
conflicting and withdrawn statements. Repeated vendor text does not add
independent support. CVRF-only context has unknown binary applicability and
does not identify a function as a confirmed fix. Its recorded source hashes and
field pointers describe the retained import; raw advisory bytes, upstream
freshness and authenticity are not reverified by this workflow.

Stored leads become stale when their checked project revision, pair, run,
advisory context, KEV snapshot or rule identity changes. `why` keeps the historical
explanation visible; `review` records the stale state when appending a decision.
The desktop rechecks current evidence before opening lead locations. Report/2
omits stale leads and records the reason as an unknown. Prepare leads again after
reviewing changed inputs. A newer withdrawn, malformed or ambiguous context does
not silently restore an older CVRF card.

Sources: `src/patchtrace/pilot/cli.py`, `src/patchtrace/cli_commands/pilot.py`, top-level `patchtrace --help`.
