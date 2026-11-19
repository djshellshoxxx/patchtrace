# Version provenance recovery — 2026-11-19

Source: historical `buildinfo.py` at `62b9a3de4d1036a6e4b9bd2618372f4042b15f7f`.
Integration parent: `c6d15e0498b37db6cd3f595bd87e4f7431886d5d`.

The absent `version --json` command reproduced exit 2 (`version-cli-baseline.log`).
The recovery uses the current lazy registry and CLI envelope, bounded held source
reads, explicit unknown Git facts, a supervised read-only Git subprocess, strict
packaged metadata, cancellation and the historical sorted source digest formula.
It leaves doctor, settings and package builders unchanged. Frozen metadata
production and native packaged execution remain separate pending work; this
consumer does not qualify a release or attest loaded bytecode.

Author gate on the working tree: **220 passed, 1 skipped in 10.08s** across
`test_buildinfo.py`, `test_version_cli.py`, `test_cli_registry.py`,
`test_doctor_cli.py` and `test_spec_registry.py`. Raw log/XML accompany this note.
The first combined gate exposed a previously omitted registry citation for the
recovered research-pilot specification; that citation is now present. Version
controls passed in that first run as well. No unrelated implementation changed.
Normal Ruff and diff checks pass. Independent review is requested at the frozen
commit containing this note; that review is not implied by this author result.

## Independent review and filter correction

At immutable `7bce4d02`, independent existing controls passed 26 tests. A separate
real Git repository with a same-size tracked-file edit demonstrated that `status`
and `describe --dirty` execute a configured clean filter (1 failed in 0.76s;
`version-independent-filter-red.log`). Those calls are removed. The observer now
queries commit and describe without worktree examination; source `dirty` is
always null with an explicit diagnostic. A source fingerprint is still available.
A configuration preflight is insufficient to bind a later config-sensitive call.

The corrected local selection passed **27 tests in 4.25s**, including the retained
real filter control. Raw log/XML accompany this note. Independent review of immutable `3be22028` passed 27 tests in 3.64 s;
its retained log/XML are `version-followup-independent.*` in the consolidation
evidence directory. No package producer or native gate
is qualified by these results.
