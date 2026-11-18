# WORKSTREAM B - Native binary analysis adapters
Adapters: (1) Ghidriff/Ghidra primary backend: src/patchtrace/backend.py, backend_cli.py, backend_progress.py,
ghidriff_launch/, runtime_discovery.py, preflight.py, backend_bundle.py, offline_bundle.py; (2) Rizin rz-diff secondary
engine, (3) BinDiff and (4) BinExport2: src/patchtrace/secondary/**; (5) Diaphora: src/patchtrace/diaphora/**; (6) intel
tools (capa, DIE/diec, FLOSS, YARA-X): tools/provision_intel_tools.py, src/patchtrace/rules, pe_overview, strings, buildenv
(external tool invocation).
Tools: tools/rzdiff/**, tools/live_backend_check.py, live_rzdiff_check.py, provision_bindiff.py, bindiff_pin.json,
backend_pin.json, intel_tools_pin.json.
Specs: secondary-engine.md, bindiff-adapter.md, bindiff-execution.md, binexport2-support.md,
binexport-producer-ghidra-host.md, ghidriff-launcher-symbols.md, ghidriff-timeout-progress.md, runtime-discovery.md,
offline-backend-installer.md, diaphora-optional-engine.md, three-tool-evidence-adapters.md, multi-engine-orchestration.md.
Handoffs: docs/handoff/rzdiff-native-red-control.md, rzdiff-producer-implementation.md, backend-bundle.md;
docs/qa/ghidriff-timeout-20261106.md; docs/audits/20261015-secondary-engines.md, 20261014-C-tool-adapters.md (TA-1..TA-12:
verify each fixed/open with file:line).

For EACH adapter fill the 14 checks: installation / dependency detection; version compatibility; native execution test (is
there REAL native evidence? which workflow and run); output parsing; result normalization; missing-executable handling;
unsupported binaries; timeout behaviour; subprocess cleanup (process-tree kill); reversed-input comparisons; consistent
function ownership; malformed outputs; adapter fallback behaviour; setup and troubleshooting docs.

Re-check the previously reported Rizin 'singleton path' and 'global parser swap' issues: read
tools/rzdiff/singleton-ownership.patch, docs/handoff/rzdiff-*.md, and
`git -C <main checkout> log --oneline -5 origin/repair/rzdiff-producer-ownership origin/qualify/native-provision-20261105`
and state precisely what is on main versus only on branches (#165, #168, #222, #224).

GitHub read: for workflows live-backend.yml, live-rizin.yml, live-bindiff.yml, live-capa.yml, live-intel-tools.yml,
backend-bundle.yml get the latest 2 runs on main (actions_list method list_workflow_runs, resource_id=<file name>, perPage 2)
and record conclusion + run id + date. A green scheduled run that SKIPS the native step is not native evidence - check job
names/steps when cheap (tools/check_live_status.py explains the status convention).

backend.py is under L2/L5: no actionable_now inside it. Candidates: adapter error handling / timeouts / cleanup in
secondary/**, diaphora/**, malformed-output handling in parsers, adapter docs.
