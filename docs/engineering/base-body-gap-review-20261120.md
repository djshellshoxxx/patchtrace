# Generation 22 — adversarial BASE metadata inspection (non-independent)

## Exact original defect and uniqueness

On draft PR332 head `1d5b647265ae66a5f241c5cc41c4972354fd0675`, `acquisition/winbindex.py::_body_facts` returns a valid tuple for `BASE` whenever its outer body is an object, **even when `windowsVersionInfo` is absent or has nonobject content**. Its result is an apparently valid undated baseline row. Thus `_entry_rows` never increments `skipped_bodies` for the unreadable source, and downstream coverage may be overstated. On `main`, retained donor `work/winbindex-publication-20261105`, generation19 and current PR332 the same original conditional was inspected; none had this repair. This is a bounded source comparison, not a completed 154-head semantic census.

## Contract-first repair

The successor branch `codex/patchtrace-base-body-gap-20261120-g22` is stacked on the exact source head above, without touching the parent. Contract-first commit `4a41c896dd16323fff5ec8a53d276f28fe0be0db`; nine authored synthetic pytest cases in `f48b5269f5cd68e5fe19c9df8f31a7749a63b8b8`; narrow production repair in `21d89fb1b1b93269df62fa1b6f872a622e9e8ac4`. The repaired branch returns `None` for absent/nonobject `windowsVersionInfo`; the existing `_entry_rows` path counts **one** rejected body, with no baseline row. A present empty object, malformed/missing date within a valid object, all ordinary KB handling, top-level SHA rejection, parser limits and separate acquisition candidate API remain unchanged.

Original isolated algorithm mirror accepted all five missing/nonobject variants; after the minimal repair those five return `None`. Three valid-object negative controls retain a baseline and preserve a valid/unknown date. `python -m pytest -q /tmp/patchtrace_g22_mirror_test.py` yielded **8 passed in 0.05 s**, but this is a manually transcribed standalone mirror, **not production-source pytest**, Qt, native or accuracy evidence.

## Adversarial considerations

- The selected fixture already contains two rejected top-level entries and one rejected KB body. The new test requires a malformed BASE to increment only the latter category (1 to 2), preserve the surviving KB row, and not create an unknown-date BASE.
- Negative cases preserve a structurally present empty `windowsVersionInfo: {}` baseline with `release_date=None` and zero additional gaps. No original release date is invented.
- A repository test invokes `save_winbindex_record` and checks the retained raw *offline record* bytes and receipt's body-loss count. This is not the missing full raw acquisition evidence retention or resolver-input membership replay.
- Unexpected call sites, malformed real Winbindex data, Windows file behavior, the Linux force-publication interval, external provenance and release gates remain separate.
- Original PR331 Linux/Windows QA failed the same four inherited source-gap fixture assertions (Linux 23,756 passed, Windows 23,644 passed); PR332 contains the already-authored assertion correction, but its own checks were not terminal at discovery.

No separate fresh worker or outside reviewer signed off; this is coordinator adversarial review only. Exact-source pytest/Ruff and native/package acceptance are unverified because this environment cannot resolve github.com for a checkout. Preserve the original red/unknown outcomes. Do not merge or release.
