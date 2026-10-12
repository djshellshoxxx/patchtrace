# SPEC-29 — Three-tool patch investigation adapters

Status: developer-ready architecture, not code. Planned only AFTER current three-diff-engine reconciliation/calibration is complete.

## Tool selection after review
**capa** (https://github.com/mandiant/capa): choose. Behavior/capability signatures localized to functions and instructions; Ghidra/PyGhidra backend documented, versioned rule corpus and JSON. Capability added/removed does NOT prove a vulnerability fix; signatures can shift under optimizer, symbol quality and rules. Pin engine, backend and rules hash. 
**FLOSS** (https://github.com/mandiant/flare-floss): choose. Extracts static, stack, tight, decoded and language-specific strings, with JSON output and locations when available. Deduplicate and map static file offset/RVA and recovered function addresses; do not attribute decoded string to a specific function when extractor cannot provide trustworthy location.
**Detect It Easy console 'diec'** (https://github.com/horsicq/Detect-It-Easy): choose as *quality gate* ONLY; its compiler, linker, packer, protector and file-type signatures flag comparisons likely distorted by toolchain or packing. It is not positive evidence for a security mechanism. Use bounded result source/heuristic and mark unknown if weak. Research showed an upstream 2026 issue where GUI and CLI differ; test exact pinned CLI/signature DB version before accepting results.

Rejected/deferred: QBinDiff and Diaphora = additional whole matching systems, duplicating phase-3 engine work, high memory/setup; pefile/LIEF/llvm-readobj = excellent supporting PE parser for preliminary inspector but not one of the three hypothesis agents; YARA-X = valuable custom-rule layer but largely shares source rules and strings so count as *derived*, not independent evidence; TLSH/ssdeep = compiler/noise sensitive; pe-sieve = dynamic process memory not relevant to no-execution static phase; Sigcheck proprietary and signature checking belongs to existing Windows trust adapter. Tool 3 remains subject to a value gate: if DiE's quality flags do not reduce false positive work on held-out corpus, exclude from default profile despite technical integration.

## Clean module contracts
intelligence/tools/common.py: immutable ToolManifest{engine,version,cli_path,capabilities,license,rules_sha256,backend_version}; ToolRun{input_artifact_hash,config_digest,started_at,elapsed,status,error,stderr_digest,stdout_digest}; CapabilityEvidence{rule_id,namespace,scope,address_space,address,location,kind,source_run_id}; StringEvidence{value_hash,display_value,encoding,type,source_location,confidence_class,extraction_method}; EnvironmentEvidence{category,toolchain,packer,protector,detector_rule,heuristic,source,certainty}; EvidenceLink{tool_run_id,artifact_sha256,function_id,RVA,file_offset,source_fragment}. 'none found' is separate from 'tool absent/error/unsupported'.
intelligence/tools/capa.py: version/probe, supervised subprocess with JSON output, Pydantic parser, optional Ghidra backend, rule pack pinning; preserve all matching feature locations and scopes; prohibit confusing whole-file matches with function-specific matches.
intelligence/tools/floss.py: version/probe, supervised bounded JSON output and deobfuscation runtime, categorized strings; redact secrets in default reports, preserve hashed/source positions, map only verified offsets.
intelligence/tools/diec.py: version/probe, query signatures (including DB hash), strict output parsing, identify high-level compiler/packer transformations, optional low-confidence noise flag.
intelligence/tools/runner.py: user opt-in profiles (basic=capa; context=capa+FLOSS; full=capa+FLOSS+DiE quality gate); scheduler, timeout, cancellation, stdout/stderr separation, bounded outputs, per-engine sandboxed scratch, error isolation and cache key (artifact+engine+rules+backend+options).
intelligence/tools/normalize.py: convert locations into canonical module-relative RVA and compare older/newer; reject mismatched SHA, ambiguous RVA, stale output, wrong parser contract.
intelligence/tools/delta.py: calculate added/removed/unchanged capabilities and string evidence; distinguish newly detectable vs genuinely newly introduced behavior, unlocalized entries, changes caused by packing/decompiler shift.
No import from Qt; all files independently testable; no engine may modify matching, original binary or existing evidence record.

## Proposed CLI
```
PatchTrace intel-tools probe --json
PatchTrace intel-tools run PROJECT --engines capa,floss,diec --profile full --json
PatchTrace intel-tools delta PROJECT --json
```
Always verify actual upstream CLI flags for pinned versions, do not hardcode speculative flags. Sample proven forms to evaluate: capa -b ghidra target; floss -j target. Use fixed absolute executable, shell=False, private cwd, no inheritance of user shell aliases, local offline rules. Do not collect sample telemetry. Tool artifacts may be hostile, retain strict size limits and avoid rendering raw strings as HTML.

## Acceptance criteria
At least two paired Windows x64 PE fixtures for each engine with controlled changes and unchanged controls; pin CLI JSON golden fixtures and corrupted/truncated negatives; Ghidra backend fixture with matched rule locations; FLOSS recovered vs static strings; DiE stable same compiler and different-compiler pairs; missing executable, timeout, cancel, invalid address, symbol/base ambiguity, bad JSON, wrong artifact and cached/stale cases. Cross-version CLI smoke, Windows packaged path handling and airgap tests. Rank candidate functions from genuine localization only; no claims about false lead reduction until held-out benchmarks.

## Research
capa Ghidra README https://github.com/mandiant/capa/blob/master/capa/ghidra/README.md
FLOSS usage https://github.com/mandiant/flare-floss/blob/master/doc/usage.md
DiE upstream https://github.com/horsicq/Detect-It-Easy
