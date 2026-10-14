"""Known-answer corpus factory (SPEC-32, docs/specs/known-answer-corpus.md). Dev-only: never shipped, never imported by
`src/`. Builds older/newer Windows x64 PE pairs whose per-function answer is exact (debug info + source diff, planted
mutations, same-source rebuilds, authored suites) and scores engines against them. Built images are never executed."""
