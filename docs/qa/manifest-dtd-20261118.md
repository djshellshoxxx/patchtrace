# Manifest parser-level DTD refusal — 2026-11-18

## Scope and source

This receipt covers a bounded internal-entity/doctype policy bypass in the
RT_MANIFEST reader. An authored 318-byte BOM-less UTF-16BE document preceded by
whitespace passed the decoded-text declaration screen. ElementTree recognized
the encoding from the retained NUL bytes and expanded a harmless internal entity
into `assemblyIdentity.name`. The same behavior was reproduced through the
public metadata reader over an authored PE resource. No target was executed.

| Checkpoint | Commit |
|---|---|
| Published baseline | `58fc130631f602b6e907bb054d30c21d810551d4` |
| Specification and failing tests | `a2a724056664135984248c9a75a985c432a33c50` |
| Reviewed candidate source | `e1c5006e51606caedd773bf079c20c145d290861` |

Worktree: `/workspace/scratch/c7a9e8d98848/manifest-dtd`, branch
`codex/manifest-dtd-refusal-20261118`. Production changes are confined to
`src/patchtrace/pe_overview/manifest.py`; the existing decoder, resource budgets,
warning vocabulary and manifest facts remain in place. The relevant amendment
is section 6.1 of `docs/specs/pe-version-authenticode.md`.

The original manifest source SHA-256 is
`350ec2000b35d7f7c162a05a5aa84320be7a52c664295cd3d928838ef17e7c84`.
It was byte-identical in published source and the reviewed primary-environment,
release, CVRF freshness and advisory-bounds variants listed in the retained
`original/xml-source-context.json`. The repair source SHA-256 is
`b1e83c0dbb9fb04fa9b2439433b4a2192364e684a1f9db1073b6f47b97f13aa9`.

## Repair and interface evidence

The conservative decoded-text screen remains an early refusal. A custom
`TreeBuilder.doctype` callback now rejects any doctype recognized by the
accelerated parser. The pure-Python ElementTree fallback only forwards external
SYSTEM/PUBLIC declarations to that target, so its exposed Expat parser receives
the same refusal on `StartDoctypeDeclHandler`. The refusal returns the existing
`manifest_dtd_rejected` observation without identity facts. Ordinary XML parse
failures retain their existing warning.

The primary Python interfaces were checked against the Python 3.12 documentation:

- [TreeBuilder.doctype](https://docs.python.org/3.12/library/xml.etree.elementtree.html#xml.etree.ElementTree.TreeBuilder.doctype)
- [XMLParser and its target](https://docs.python.org/3.12/library/xml.etree.elementtree.html#xml.etree.ElementTree.XMLParser)
- [Expat StartDoctypeDeclHandler](https://docs.python.org/3.12/library/pyexpat.html#xml.parsers.expat.xmlparser.StartDoctypeDeclHandler)

The installed runtime was Python 3.12.14 with Expat 2.8.3. The Python fallback
behavior was checked in the installed standard-library source and exercised in
an isolated child that disables `_elementtree`, asserts the exact imported
worktree source path, and checks that no Qt/UI modules were imported. No
dependency upgrade, parser dependency or scanner suppression was added.

## Red and green evidence

| Run | Exact boundary | Result |
|---|---|---|
| Original encoding probe | 25 bounded authored encoding cases on published source | Hidden UTF-16BE declarations accepted with space, newline and tab prefixes |
| Original external reproducer | Three hidden declarations, public PE metadata boundary, three valid controls | **4 failed, 3 passed** in 0.24 s |
| New repository tests before source edit | Hidden internal-only and empty doctypes, accepted encodings, actual metadata reader, Python fallback child | **8 failed, 11 passed** in 0.63 s |
| Focused candidate verification | New tests and existing manifest tests | **160 passed** in 3.23 s |
| Exact committed source, affected gate | Manifest, resources, version info, metadata comparison, CLI, desktop inspection and existing parser-security controls | **377 passed** in 5.97 s |
| Exact committed source, unchanged external test | Same seven original controls | **7 passed** in 0.23 s |
| Normal Ruff | `python -m ruff check src tests tools` | Passed |
| Whitespace validation | `git diff --check` | Passed |

The original probe and external test remain untouched in
`/workspace/scratch/c7a9e8d98848/qa/security-triage`. Their byte-for-byte copies,
the original failures, final logs/JUnit and source hashes are retained in the
packet below. The external green run before the source commit is retained
separately; the final evidence identifies the exact committed source.

The exact affected gate used:

```sh
env QT_QPA_PLATFORM=offscreen \
  PYTHONPATH=/workspace/scratch/c7a9e8d98848/manifest-dtd/src \
  /workspace/scratch/3a6632a6e5ff/venv/bin/python -m pytest -q \
  tests/test_pe_manifest_dtd_boundary.py tests/test_pe_manifest.py \
  tests/test_pe_resources.py tests/test_pe_version_info.py \
  tests/test_pe_meta_compare.py tests/test_pe_inspect_cli.py \
  tests/test_ui_inspection_signing.py tests/test_pe_parser_security_20261105.py \
  tests/test_pe_build_facts.py tests/test_audit116_stale_inspection_failure.py \
  --tb=short \
  --junitxml=/workspace/scratch/c7a9e8d98848/qa/manifest-dtd/affected.xml
```

The unchanged external test additionally receives the exact worktree `tests`
directory in its absolute `PYTHONPATH` for the existing authored PE builder.
`repair/affected-context.json` and `repair/external-replay-context.json` record
the complete commands, runtime, paths and hashes. The shared virtualenv's older
editable checkout was not used as the source of these runs.

## Limits and handoff

The established defect is bounded internal-entity expansion and acceptance of
a forbidden doctype. These controls do **not** establish filesystem or network
XXE, large-expansion denial of service, native Windows acceptance, real backend
accuracy or full-suite/release qualification. No external entity fetch, target
download, target execution or frozen-corpus mutation was performed. There is no
change to the existing resource/read/time budgets.

The raw scoped `S314` detector still reports the ElementTree call site. Its
unmodified JSON is retained as `repair/ruff-s314.json`; normal configured Ruff
passing does not mean the separate strict security lane has passed. This repair
adds an explicit guard and does not suppress or accept a scanner finding.

The global module index is integration-owned in the WBQ plan and was not edited
in this narrow branch. Its existing manifest row still describes the early
screen; the integration owner can update that row to reference parser-level
refusal and `tests/test_pe_manifest_dtd_boundary.py` with the reviewed repair.
Independent root review is required before integration. The remaining S310,
S603 and S608 triage is a separate read-only task.

## Retained packet

- `docs/qa/manifest-dtd-20261118/manifest.json`: exact member sizes and SHA-256 values.
- `docs/qa/manifest-dtd-20261118/evidence.zip`: **26 members, 42,813 bytes**.
- Archive SHA-256: `554b27ff7d62a9a79128933bd905e84eb52cc9e08c94db2ee0f4f812ddbf7b1c`.

Every archived member was reread and matched to the manifest after writing.
Raw working receipts remain in
`/workspace/scratch/c7a9e8d98848/qa/manifest-dtd`.
