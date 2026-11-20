# Registered header help and Evidence announcement recovery

## Outcome and ownership

Recovered one narrowly scoped local GUI donor onto the current combined
integration source. The default table behavior is unchanged; columns can now
request escaped help from the existing tooltip registry. Evidence state
changes now reach the existing host announcement service. No new announcement
sender, backend operation, provider request or persisted schema was added.

This worker owns only the three recovered GUI modules, their two test files,
the GUI framework specification, and this dedicated evidence/handoff. The
coordinator owns the authoritative task ledger, aggregate tests and remote
publication. The root checkout remained unchanged throughout this work.

| Identity | Commit |
|---|---|
| Combined baseline | `84798a04da9bc6a823b4b2d7802ea08a322c5367` |
| Retained local donor | `f6f4c1dce74a7e7e506d9d23219bf7b2c9e6630f` |
| Recovered donor | `b9adfa43` |
| Qualified runtime/specification/tests | `83ed3471569f01a273c429fb055a0d27ec0fe3a8` |
| Qualified complete tree before evidence-only additions | `77810c95bc838ae5f3a517bb0cd1d790b93c36b6` |

Branch: `codex/accessibility-recovery-20261120-2bad`.

## Why this is a distinct recovery

Before importing runtime changes, the donor's specification and two regression
tests were applied to the unchanged combined baseline. Both failed in 4.39
seconds: `ColumnSpec` rejected `tip_id`, and the real host Evidence panel emitted
no announcement. This independently confirms the behavior is absent even after
the coordinator's report, TaskRunner and publication repairs.

The donor contains its preceding contract amendment, the three exact source
changes, two regressions and historical QA records. The entire narrow commit
was recovered with Git provenance. Its historical records remain explicitly
about their earlier source; their pass counts do not qualify this recovery.

## Resulting behavior

- `ColumnSpec.tip_id` defaults to an empty string. A known registry ID supplies
  escaped rich help for the horizontal header tooltip; empty and unknown IDs
  retain the title/unit fallback. Display, accessible header text, cell help,
  sorting and selection keep their previous behavior. This recovers the shared
  API; it does not claim every product column already supplies a specific ID.
- A registry entry can become available after table construction. Help uses
  that entry without replacing cell help or accessible text. The fresh
  regression also checks that angle brackets and ampersands remain escaped.
- `EvidenceController` passes its shell port to `EvidencePanel`, which passes
  it to the existing matches `StateView`. Changed failures are assertive and
  other nonempty states are polite under the existing policy. Repeated state
  application and redraws stay silent; blank state text stays silent.
- Standalone panels still accept no announcer. Native assistive-technology
  output remains a separate platform acceptance gate.

The recovered specification is
[`gui-framework.md`, sections 6.6–6.7](../specs/gui-framework.md). No generated
JSON schema is affected by this GUI dataclass and optional constructor argument.

## Verification and source-provenance limit

| Check | Result |
|---|---|
| Two donor cases on unchanged combined baseline | 2 failed, expected missing behavior |
| Nine maintained affected files on recovered source | 283 passed, 0 failed, 0 skipped, 50.91 seconds |
| Source-pinned isolated import replay | 1 passed, 1.18 seconds; overlaps the 283 |
| Whole-tree Ruff (`src tests tools`, no cache) | Passed |
| Complete baseline-to-final whitespace check | Passed after lossless historical-log storage repair |

The affected selection covers table specification/model behavior, counter
ownership, Evidence host/UI behavior, shared states, announcement policy,
tooltip auditing and pure GUI import/layering. Two fresh maintained controls
cover late escaped header registration and repeated Evidence state refreshes.

The shared dependency environment has an older editable PatchTrace installation.
Normal tests imported the current worktree via explicit `PYTHONPATH`, and the
GUI core isolation checks explicitly supply the current `src`. One maintained
Evidence test uses Python `-I`, which ignores `PYTHONPATH`; its initial
subprocess therefore imported the older installed package. That observation is
retained, not counted as current-source isolation evidence.

A private lightweight environment was created for that single test. Its `.pth`
lists this worktree's `src` first and the existing dependency site-packages
second; nested editable-install `.pth` files are not processed. A `python -I`
observation confirmed this worktree's `patchtrace.__file__`, pytest 9.2.0 and
PySide6 6.12.0. The unchanged isolated-import test then passed using this
interpreter. The shared environment was not modified. The replay resolves this
one known provenance gap and is not an additional unique test or a full-suite
qualification.

The donor's raw historical pytest baseline log contained trailing whitespace.
The original complete-range whitespace check failed at three locations. The
exact bytes are retained as `baseline.log.gz` with its historical README link
updated; decompression SHA-256 remains
`2204c5550c047044882ed4a105ad6cea86203f18ab6f9e90e1571bc3d8d6cfdb`.
No assertion, acceptance budget or whitespace rule was relaxed.

## Reproduction and durable evidence

```sh
PYTHONPATH="$PWD/src" PYTHONDONTWRITEBYTECODE=1 QT_QPA_PLATFORM=offscreen \
  /workspace/scratch/b1d1356aa953/patchtrace-venv/bin/python -m pytest -q \
  -p no:cacheprovider tests/test_gui_table.py tests/test_gui_table_spec.py \
  tests/test_gui_table_counter_scope.py tests/test_evidence_host.py \
  tests/test_evidence_ui.py tests/test_gui_state_view.py \
  tests/test_gui_announce.py tests/test_tooltips.py tests/test_gui_core_isolation.py
```

Use a source-installed private environment when reproducing the `-I` test.
The [evidence archive](evidence/accessibility-recovery-20261120-2bad.zip)
contains the original baseline failure, affected and isolated-source stdout and
JUnit, environment observation, Ruff result, inherited whitespace failure,
final whitespace result, source blob/hash receipt and per-file SHA-256 manifest.
Every archived payload was checked against that manifest after writing.
Archive SHA-256:
`4e895e21261229b4e97a2bcb51d03974551f31ccce8896134f9950e07a7d6c2f`.

## Handoff

1. Independently review the recovered source, new controls and environment
   qualification boundary.
2. Integrate the donor recovery, two additional controls and evidence-only
   handoff in order; preserve the original donor and current source identities.
3. Update the coordinator-owned module index and engineering ledger. Record
   shared header-help API recovery and Evidence host-announcement integration
   separately from native screen-reader acceptance.
4. Qualify the final combined source with applicable full/hosted/native gates.
   This worker did not run a second full suite while the coordinator's frozen
   aggregate was active. Windows speech, clean-machine packaging and release
   acceptance remain unverified.

No remote branch update, pull request, main merge, release or workflow dispatch
was performed by this worker.
