# PatchWatch source audit and reuse integration notes — 2026-10-26

Scope: PatchWatch source-level inspection; findings are candidates, not code imports. See [roadmap](../plans/patchwatch-open-source-reuse-roadmap-20261026.md).

## Source findings
- kb/csv.rs: flexible multi-section CSV parser, architecture banners, file/version/size records; useful fixture-backed Python port. Unknown section/ambiguous columns and size parsing need strict handling.
- kb/tier1.rs: extracts 'file information' links from KB articles, excluding SSU/hash links; redirector handling must use explicit host allowlist and bounded redirects.
- kb/tier2.rs: Update Catalog Search.aspx and DownloadDialog.aspx scraping; MSU->CAB manifest fallback. Fragile markup, architecture selection, archive size/decompression/path protections need independent verification.
- sug/client.rs + analyze/ingest.rs: MSRC release/CVE ingestion and desktop KB selection; current highest-build heuristic should not collapse multiple product mappings.
- winbindex/client.rs: exact KB, version fallback and approximate pair selection; cached binary fast path returns without visible hash recheck, so PatchTrace must verify content on every use. Approximate is not verified.
- analyze/orchestrator.rs: CVE-scoped fetching/diffing/synthesis/deep-analysis state machine; transplant stages, not single-CVE uniqueness or Anthropic coupling.
- triage/anthropic.rs: native Anthropic Messages transport and JSON triage; implement behind provider interface with exact prompt preview and strict validation.
- triage/synthesis.rs: compact function-name/ratio summaries and cross-binary selection; preserve omission tracking, source identities and independent signals.
- triage/deep_analysis.rs: ranked-first then changed-code-low-similarity fallback; use stable function IDs and avoid name collisions, unbounded prompts and hallucinated snippets.
- ghidra/diff_summary.rs: separate compact DiffSummary and full DiffIndex; adapt to PatchTrace normalized verified data.
- storage/schema.rs: cves, cve_kbs, kb_enumerations, kb_files, triage, jobs, synthesis and findings; avoid (KB,filename,arch) uniqueness that can collapse versions and unique(CVE) job restriction.
- report/pocsmith_context.rs + commands/export_poc_context.rs: portable CVE context, old/new paths and ghidriff results; require explicit consent and digest manifest, no accidental redistribution.
- validate.rs: per-dependency diagnostics and in-memory end-to-end dry run; adapt to existing CLI diagnostics.

## Risks and non-copy decisions
- PatchWatch is Rust; PatchTrace is Python. Prefer behavior/fixtures ports rather than embedded Rust build dependency.
- PatchWatch Apache-2.0: preserve LICENSE, NOTICE, exact pinned SHA, modifications and attribution for copied code.
- Diaphora AGPL-3.0 and Ghidriff GPL-3.0: reference/external-process integration, no source copy under existing repository policy.
- No changes to runtime code in this planning update; no benchmarks or live native acceptance performed.

## External candidate sources
- https://github.com/ByteRay-AI/patchpair — PSFX source matching, PA30/manifest acquisition, Apache-2.0.
- https://github.com/joshterrill/post-patch-postmortem — KB-wide BinDiff workflows and SHA-pinned pairs, MIT.
- https://github.com/google/bindiff — independent matching and symbol transfer, Apache-2.0.
- https://github.com/mandiant/capa — capability classification and Ghidra integration, Apache-2.0.
- https://github.com/joxeankoret/diaphora — external matching and export formats, AGPL-3.0.
- https://github.com/clearbluejar/ghidriff — existing external comparison engine, GPL-3.0.
- https://github.com/rizinorg/rizin ; https://github.com/radareorg/radare2 — additional comparison layers.
- https://github.com/quarkslab/qbindiff — graph matching research.
- https://github.com/mandiant/flare-floss — decoded string evidence.
- https://github.com/horsicq/Detect-It-Easy — packer/compiler fingerprints.
- https://github.com/VirusTotal/yara-x — rule workflows.
- https://github.com/m417z/winbindex — existing binary metadata source.

## Follow-up audit checklist
Pin source commit, confirm license and NOTICE, read implementation and tests, map overlap with current main/PRs, write threat model, port fixtures, test offline/malformed inputs, validate on Linux/Windows, and record measurable benefit versus baseline.
