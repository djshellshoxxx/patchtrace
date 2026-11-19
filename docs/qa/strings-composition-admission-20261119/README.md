# Strings stored-source admission and real cache qualification

Runtime: **2f8f69c268dcc03750596114ef891ad651c59506**. Shared helper source:
**41af7c7e3f3bd5e50c49b86bc061fdef834b4daf**. The original composition recovery
and earlier artifact-identity evidence remain in
[the prior packet](../strings-composition-20261119/README.md). This later receipt
supersedes its incomplete mocked-cache qualification.

## Repair

The CLI and dock now use the shared opt-in Entry admission boundary before
constructing a stored FLOSS source. Selected run/evidence/origin ownership,
staleness, strict JSON and body bindings are checked. Refused evidence becomes
unavailable: Auto uses the current verified artifact's built-in scan, while
explicit FLOSS refuses and retains the displayed prior result. An invalid newest
selected row does not silently select an older result.

Actual cache attempts contain no newly generated raw sidecar or stdout digest.
The admitted originating evidence run now supplies the recorded raw digest,
executable, version and consent. Evidence keeps its original run identity. No raw
digest is fabricated and no shared public store behavior is changed.

The earlier stored-source artifact-refusal repair at 76734261 is retained. A
missing/replaced artifact gives the same PT-STR-INPUT refusal in CLI and dock;
owned readable input with unsupported PE layout remains usable with unknown links.

## Source-bound observations

| Stage | Result | Meaning |
| --- | --- | --- |
| New initial admission attempt | 18 failures, 1 setup error | Ten actual caller regressions, eight fixture failures using the wrong physical SQLite column, one authored FLOSS version-probe timeout. Preserve all; do not count fixture failures as product findings. |
| Corrected fixture attempt during unstable execution | Outer 120-second bound, exit 124 | No completed verdict observed; incomplete, not PASS. |
| Recovered red at 85482d9e, runtime still 76734261 | 10 failed, 9 passed in 7.32s | Actual cache loss, selected run/evidence metadata acceptance, fallback to an older run and GUI retention failures reproduced. The nine prior identity controls now use real stored rows. |
| First integrated focused selection | 75 passed in 13.40s | Working source before final docstring/import-alias cleanup; overlap with the final run below. |
| Frozen 2f8f69c2 Strings/UI/helper/help/spec selection | 889 passed in 61.12s | Exact final source, no skips or failures. |
| Ordinary Ruff / whitespace | Passed | Whole src/tests/tools ordinary configuration; no new lint suppression. |
| Independent actual caller probe | 10/10 metadata scenarios passed | Auto current-artifact fallback, explicit FLOSS refusal, no storage writes. |
| Independent actual BLOB caller probe | 2/2 passed | Typed unavailable behavior in both modes; unchanged storage. |
| Independent GUI selection | 6 passed in 4.62s | Real cache retention, owner-thread capture without a reachable live store, and prior-result preservation after metadata/artifact refusal. |

The full command of the final affected run was:

```sh
QT_QPA_PLATFORM=offscreen PYTHONPATH=src:tests timeout 180s /workspace/scratch/80dddc5347b2/patchtrace-composition-venv/bin/python -u -m pytest -q tests/test_strings*.py tests/test_ui_strings*.py tests/test_intel_tools_admission.py tests/test_help*.py tests/test_spec*.py
```

Independent unchanged cache and guard probes also passed. The cache probe uses
runner.run_tools twice, proving actual cache_hit=true/raw_sidecar=None rather than
a stand-in with impossible new raw output. Original missing/replaced-artifact
probes still refuse in both callers. The original recorded run/raw/executable/
version/consent fields match the admitted origin. The shared helper's independent
metadata and strict-JSON qualification is retained in
[its own packet](../tool-admission-20261119/README.md).

These selections overlap and must not be summed. The independently reviewed
compose SHA-256 is f7688fc4e47b5c44aad195da3b55d467b8690de661c0973d4bd3c0232f1114a1.
The source comparison was unchanged after independent review.

## Qualification boundary

All executable probes use authored fake FLOSS and synthetic PE input bytes. No
target binaries or live native FLOSS engine are executed. Offscreen Qt controls
do not qualify native Windows UI, frozen packaging or real assistive technology.
The exact combined candidate still needs its own source review and hosted gates.

The raw digest/path is recorded provenance; this slice does not verify current
raw-file bytes or strengthen normalized-sidecar I/O/resource guarantees. Current
target artifact bytes are verified separately. Public ToolStore/EnrichmentStore
implementations and persisted models are unchanged.

## Evidence

[Source proof](source-proof.json), [verbatim evidence archive](evidence.zip), and
[member/hash manifest](manifest.json). The archive retains original scripts,
before/after JSON, all completed logs/XML, fixture failures, incomplete output
and the exact source patch. Its CRC and every member digest were checked.
