# KB file inventories and support-page links

`patchtrace kb inventory` imports a saved KB file-list CSV, retains its original
bytes, and lets you inspect and explicitly select an eligible filename for an
existing investigation. It also inspects saved Microsoft support HTML and
previews exact requests for an optional consented fetch.

File-list metadata does not establish a binary hash, the order of a before/after
pair, or whether a file contains a CVE fix. A local import stays
`unverified-local-file`, including when you supply a Microsoft URL. Source
authenticity, product context, conflicts and unknown values remain visible.

## Commands

| Command | Purpose |
|---|---|
| `kb inventory import FILE --kb KB` | Import one saved CSV and retain its exact bytes and parsing context. |
| `kb inventory list` | List saved inventory summaries and import IDs. |
| `kb inventory show IMPORT_ID` | Verify a saved source and inspect rows, original metadata and row references. |
| `kb inventory select IMPORT_ID ENTRY_ID --investigation ID --product ID --expected-revision N` | Select one eligible row for the current investigation revision. |
| `kb inventory links HTML --page-url URL` | Inspect and retain saved HTML links without following them. |
| `kb inventory plan URL` | Preview exact ordered requests, headers, hosts, limits and plan SHA. |
| `kb inventory fetch --plan-file FILE --consent-plan SHA --consent-host HOST` | Fetch only the explicitly reviewed request plan. Repeat `--consent-host` for every planned host. |

Use `--workspace DIR` and `--json` after the subcommand. JSON output is one
`enrichment-cli/1` envelope with a `kbcorrelation/1` result. `--help` lists the
options without opening a workspace or initializing a service.

## Saved-source workflow

These commands use local files. Replace the quoted IDs and revision number with
values returned by your workspace; do not treat the example placeholders as IDs.

1. Import a saved file list with its explicit KB context:

   ```text
   patchtrace kb inventory import files.csv --kb KB5036893 --workspace kb-workspace --json
   ```

   The result includes `import_id`, source digest/authenticity, accepted and
   rejected counts, duplicate/conflict counts, truncation and parsing context.
   An optional `--asserted-source URL` records an unverified assertion separately
   from the source's identity.

2. Inspect the retained rows and their exact provenance:

   ```text
   patchtrace kb inventory show "IMPORT_ID" --name clfs --architecture amd64 --workspace kb-workspace --json
   ```

   `--name` is a case-insensitive filename substring. `--architecture` accepts
   `amd64`, `arm64`, `x86` or `unknown`. `--state` accepts `metadata-only`,
   `unknown`, `conflicted` or `descriptive-only`. `show` uses `--limit 200` by
   default, up to 500, and a zero-based `--offset`. Filters inspect retained
   rows; they do not recover records beyond a parser truncation limit.

3. Use the existing advisory workflow to obtain an investigation and product:

   ```text
   patchtrace kb index import saved-advisory.json --workspace kb-workspace
   patchtrace kb search KB5036893 --offline --workspace kb-workspace --json
   patchtrace kb products "INVESTIGATION_ID" --workspace kb-workspace --json
   ```

   Choose the exact product scope from `products`. Read the current `revision`
   from that result immediately before selection. The investigation's recorded
   document/search scope continues to apply.

4. Select one inspected row explicitly:

   ```text
   patchtrace kb inventory select "IMPORT_ID" "ENTRY_ID" --investigation "INVESTIGATION_ID" --product "SCOPE_ID" --expected-revision 3 --assert-scope --workspace kb-workspace --json
   ```

   `--assert-scope` records your explicit product mapping when the inventory has
   no matching `product_scope_id`. It does not override a known architecture,
   product, release or build conflict. Selection requires an eligible AMD64 PE
   basename with a known version and no metadata conflict. ARM64/x86 metadata
   remains inspectable; it does not expand supported analysis architectures.
   A stale revision fails without changing the recorded selection or revision.

5. Continue through saved file-index candidate selection:

   ```text
   patchtrace kb components "INVESTIGATION_ID" --workspace kb-workspace --json
   patchtrace kb index import saved-clfs.json --winbindex clfs.sys --workspace kb-workspace
   patchtrace kb pairs "INVESTIGATION_ID" --workspace kb-workspace --json
   ```

   Selected CSV names remain tier E with source row references and the analyst
   assertion visible. The existing file-index/pair workflow supplies candidate
   hashes and verifies byte identity; CSV metadata cannot supply those facts.
   If no saved file-index record can answer, `pairs` states the missing input.
   You can still use the existing `kb import-pair` workflow for two local files.

## Explicit CSV context and limits

Import and file-inventory fetch accept `--product-scope-id ID`, `--product TEXT`,
`--release TEXT`, `--build TEXT`, `--architecture`, `--delimiter` and `--locale`.
These are explicit parsing assertions, not authenticated claims. Default
architecture is `unknown`; an architecture in the source can supply the row's
value, while a contradiction remains a conflict.

Delimiters are `comma` (default), `semicolon` or `tab`. Supported encodings are
UTF-8, UTF-8 with BOM, and UTF-16 LE/BE with BOM. The parser requires English
`File name` and `File version` headers; it does not guess localized mappings.
Size locale is `en-US` by default, with `de-DE` and `invariant` available.
Dates/times retain their original text and do not establish chronology.

Default bounds include 16 MiB of CSV bytes, 100,000 scanned logical records,
5,000 retained entries and 1,000 retained diagnostics. A logical quoted record
can span multiple physical lines. Result references report both explicitly.
Rejected rows and omitted diagnostics remain counted. A partial or truncated
inventory cannot claim complete coverage, including coverage of later
architecture sections. Directory paths, formulas, reserved names and control
characters are refused as eligible filenames; safe non-PE names are descriptive
metadata only.

`list --limit N --offset N` pages summaries, with a default page size of 20 and a
maximum of 100. `list --kind support-page` lists saved HTML sources.

## Support links and optional retrieval

Inspect saved HTML with the URL of the page from which it was saved:

```text
patchtrace kb inventory links support.html --page-url "https://support.microsoft.com/help/5036893" --workspace kb-workspace --json
```

The result retains candidate links, anchor/context text and rejection reasons.
Servicing-stack, checksum and unrelated links are excluded from file-list
selection. Several plausible links remain separate candidates. Parsing does not
execute scripts, follow links or authenticate a local HTML file.

Preview an exact request and save the JSON envelope:

```text
patchtrace kb inventory plan "FILE_LIST_URL" --kind file-inventory --json > inventory-plan.json
```

Use an actual candidate URL from the inspected page in place of `FILE_LIST_URL`.
For a support page, choose `--kind support-page`. If you have reviewed a redirect
chain, repeat `--redirect-url URL` in its exact order, up to four redirects.
Previewing never performs a request. The saved full envelope can be passed
directly to `--plan-file`; a strict standalone plan JSON object is also accepted.

Read the saved preview's `plan_sha`, complete host set, URL order and limits.
Then supply the matching values explicitly:

```text
patchtrace kb inventory fetch --plan-file inventory-plan.json --consent-plan "PLAN_SHA" --consent-host go.microsoft.com --consent-host download.microsoft.com --kb KB5036893 --workspace kb-workspace --json
```

This two-host example applies only to a preview containing those two hosts.
Supply exactly your preview's host set. A CSV fetch needs `--kb` and any required
CSV parsing context. A support-page fetch needs no CSV context and does not
automatically fetch its discovered links. `--offline` refuses a fetch even when
consent is present. Monthly-CVRF and symbol-server consent do not authorize this
operation.

An unexpected redirect stops before requesting the new target. The failure
result includes `proposed_plan` and `preview`. Review the new chain and use
`plan` with its exact ordered URLs to save a new preview before consenting again.
Do not reuse the previous plan digest. Fetched source records retain original
and final URLs, actual redirect chain, acquisition time and byte digest.
`tls-allowlisted-host` describes transport provenance, not a digital signature.

## Desktop workflow

Open **KB and CVE** (`Ctrl+Shift+K`), then **File inventories…**. The inventory
dialog is available without an open comparison project.

- **Saved CSV** accepts a local file and explicit KB, product, architecture,
  delimiter and numeric-locale context. **Import saved CSV** retains its bytes.
- **Retained inventories** lists sources and verifies an explicitly chosen
  source. Filters and pages apply to retained rows. Row details expose the
  original values, source status, logical record and physical line span.
- To use a filename, supply an existing investigation ID, its exact product
  scope ID and current revision from `kb products`. Select a visible eligible
  row and press **Select this filename for the investigation**. An unmapped
  inventory also needs the explicit scope assertion. Deselecting the row,
  including with Ctrl+Space, disables selection; focus alone is insufficient.
- **Support sources** inspects saved HTML, copies an explicitly chosen accepted
  link without following it, and previews exact requests. Fetch consent starts
  unchecked, applies once, and is invalidated by input changes. A changed server
  chain needs a revised preview and fresh consent.

Operations run in workers with progress and **Cancel operation**. Closing the
dialog or changing inputs rejects late displayed results. Previous committed
imports remain available. A project change clears the selection target so a
filename cannot silently carry into another investigation. Native Windows
screen-reader and high-DPI acceptance are tracked separately from offscreen tests.

## Exit codes and recovery

| Exit | Meaning |
|---:|---|
| 0 | Operation completed. |
| 2 | Invalid arguments/context, rejected local CSV/HTML, unsupported input or missing/mismatched consent. |
| 3 | Partial retained results, runtime/storage/verification failure, or stale revision. Inspect the envelope and counts. |
| 4 | No retained matching results. This does not establish source-wide absence after truncation. |
| 5 | Cancelled. Prior committed results are preserved. |

For a stale selection, inspect the investigation again and supply its current
revision. For a damaged source, preserve it for diagnosis and restore the
original bytes; verification does not silently rewrite a prior claim. For
missing/conflicting product context, inspect the source and select or assert
only a scope supported by that context.

Implementation: `src/patchtrace/kbcorrelation/cli_inventory.py` delegates to
`inventory_service.py` and `inventory_selection.py`. The complete parser/source
contract is [PW-01](../specs/kb-file-inventory-csv.md). The existing advisory and
pair commands are described in [`patchtrace kb`](67-cli-kb.md).
