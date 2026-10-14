# Spec decisions taken by the integration owner (2026-10-14)

Defaults chosen so building is not blocked. Each is reversible before the corresponding PR merges; items marked **USER** need the product owner for real-world input (legal, people, budget) and keep the safe default until answered.

## SPEC-28 orchestration
- Partial success (some engines failed) exits 3 with `status: partial`. Accepted.
- Hard cap of 2 parallel engines until C8 measures Windows memory on real pairs. Accepted.
- Live rizin job needs a redistributable pair: generate a synthetic pair from repo-owned sources (compiled with clang/mingw in CI); no Microsoft binaries in git.

## Evidence panel (C6)
- D1 uncalibrated 0..83 index: hidden by default, opt-in checkbox, labelled "triage index, not a probability".
- D2 verdict names Agree / Contested / Single engine / Unknown: accepted.
- D3 Ghidriff `quality`/`match_types`: show raw values (no invented ordinal scale).
- D4 no confirm dialog before runs; show a live elapsed timer and Cancel.
- D5 evidence status in exported reports: later slice.

## BinDiff (C4)
- BinDiff is never bundled in the ZIP; explicit absolute path, discovery only pre-fills.
- `.BinExport` without a 64-hex SHA-256 `executable_id` is refused by default; an explicit "I confirm this belongs to this artifact" override is allowed and recorded in provenance (same rule as BinExport2 spec).
- `live-bindiff` workflow is not a required check; a maintainer-generated `.BinExport` pair may be committed only if built from repo-owned synthetic sources.

## Calibration (C9)
- O1 labels for Microsoft binaries stay local-only (**USER** to confirm legal position before any publication).
- O2 second annotator unknown (**USER**): until confirmed, claims are capped at ordinal bands, never a number.
- O3 GUI shows bands only until preregistered targets are met.
- O4 labelling budget/scope (**USER**): not started; tooling PRs proceed without labels.
- O5 approved: in-repo pure-Python fitter + optional `calibration-dev` extra.
- O6 clang-cl/mingw acceptable stand-ins for CI corpus builds.

## Enrichment hardening backlog
- History bound: prune beyond newest 100 rows or 512 MiB, always keeping revision-bump snapshots; docstring updated from "append-only".
- Retention: keep 8 current + 2 stale generations per profile; imported `secondary-matches` never evicted.
- Environment allowlist: ship behind a green native Windows run, with a visible `env_passthrough` setting for proxy/custom-JDK users.
- NVD pacing: consent preview states the expected duration for keyless use.
- Merged CVE snapshots (H13): use the oldest contributing `retrieved_at` (no contract change).

## BinExport2 (C3)
- Accept `protobuf` as a core pinned dependency (upb C parser required; pure-Python fallback rejected as a DoS risk); the Fable build agent must re-verify the exact pin and the Windows frozen run.
- `.BinExport` size cap lowered from 512 MiB to 256 MiB until live data exists.
- MD5-only/empty `executable_id`: reject by default, explicit confirmation override recorded.
- Golden files: first, repo-generated synthetic exports; real Ghidra-plugin exports are produced by a CI step on the native Windows runner where Ghidra is already provisioned (**USER** may supply IDA-produced samples later).
