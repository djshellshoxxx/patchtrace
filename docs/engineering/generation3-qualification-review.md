# Generation 3 independent qualification review

## Exact review scope

The security boundary review uses integration commit
`afa1af3c` on `codex/maximum-completion-20261119-4c8d`. It covers the
manifest parser and cache-version recovery, the held-source Strings publication
changes, and the completed WinPairs URL/HTTP exception handling. The separate
profile review uses `31052db31054590c75c6c636c2ac49cc934f0668`.

This worker did not implement those changes, alter their assertions, mutate a
remote branch, execute analyzed binaries, or qualify a release.

## Qt release availability remains an external blocker

At **2026-11-19 23:40:56 UTC**, successful direct requests to the official PyPI
JSON endpoints for [PySide6](https://pypi.org/pypi/PySide6/json),
[shiboken6](https://pypi.org/pypi/shiboken6/json),
[PySide6-Essentials](https://pypi.org/pypi/PySide6-Essentials/json), and
[PySide6-Addons](https://pypi.org/pypi/PySide6-Addons/json) each reported stable
version **6.12.0** and **zero files for 6.12.1**. The
[release receipt](evidence/qt-release-refresh-20261119.json) records HTTP status,
retrieval time, response SHA-256, dependencies and selected wheel metadata.
This refresh supersedes availability observations from earlier that day; it
does not erase their evidence.

The [official Qt 6.12 index](https://download.qt.io/official_releases/qt/6.12/)
still lists a 6.12.0 release directory and vendor source patches. A source patch
is not a published and compatibility-qualified Python wheel. No alternative
vendor distribution or custom native backport was built or accepted here.

The current [Qt WebSockets advisory](https://www.qt.io/blog/security-advisory-cve-2026-114369)
still includes 6.11.3 and 6.12.0 in its affected interval and identifies 6.12.1
as a fixed line. Therefore a downgrade to 6.11.3 is not complete remediation.
The [Qt Network advisory](https://www.qt.io/blog/security-issue-cve-2026-116337?hsLang=en)
continues to contain overlapping affected/fixed endpoints in its prose; that
ambiguity is preserved rather than silently resolved.

One formerly unclassified patch now has a retrieved primary advisory:
[CVE-2026-105925](https://www.qt.io/blog/security-advisory-cve-2026-105925),
published November 16, identifies Qt 6.12.0 as affected by excessive allocation
when `QXmlSimpleReader::parse()` processes specially crafted XML. The vendor
names 6.12.1 among fixed versions. This is an additional assessed **component
version match**, not proof that PatchTrace invokes the affected code. Its 6.8.10
affected/fixed endpoint also overlaps in the vendor text. Exact retrieval paths
and qualifications are in the
[advisory receipt](evidence/qt-advisory-refresh-20261119.json).

The prior report's seven assessed ranges remain prior evidence. This review
does not certify a complete Qt/native SBOM, prove application exploitability,
or establish unreachability through a literal-import scan. The existing
[dependency audit](../consolidation/DEPENDENCY_ADVISORY_AUDIT_20261119.md)
and native remediation gate remain applicable. No dependency pin was changed.

## Integrated security boundary review

No additional blocking defect was established in the reviewed changes.
The parser rejects doctypes through the parser boundary, including its Python
fallback; cache version 3 separates legacy keys and envelopes. Existing
independent controls already cover version 2 reuse and digest preservation,
so they were not rerun merely to increase a test count.

The Strings source and directory handles stay live through their operations,
verification reads are bounded, and cleanup does not unlink a mutable foreign
name. The explicit Linux final source-name substitution interval remains
unresolved and is not reclassified as safe. Windows replacement still requires
native acceptance. WinPairs catches the `HTTPException` family, suppresses raw
protocol details in its public error, closes acquired responses, and applies raw
URL screening before normalization. These are scoped source-review conclusions,
not proof that the repository has no security defects.

## Profile navigation review

No blocking defect was found in `31052db3`. The implementation retains profile
names before Save can rebuild the Qt list, blocks recursive list-selection
signals during its own changes, and keeps the confirmation text plain. Save
must succeed before navigation; Cancel leaves the draft untouched. Failed loads
restore the selection corresponding to the displayed editor.

Six independently authored controls passed in **0.79 seconds**:

- Destination deletion and corruption during the Save confirmation, each with
  and without renaming the edited profile: the saved source remains selected,
  editor values match it, and the unavailable-destination error remains visible.
- Failed New and Duplicate after an explicit Discard decision: the original
  stored profile remains unchanged, the current draft remains available, and
  the failure is visible.

The test asserts the actual imported module path, so a different worktree cannot
silently supply the implementation. The
[peer controls](evidence/test_profile_peer_controls.py) and
[terminal result](evidence/profile-peer-result.txt) are retained. Ruff passes for
the peer control file. These six cases add independent boundary evidence to
the implementation worker's affected suite; they are not a second aggregate run.

Reproduce against an explicitly selected source tree:

```sh
PATCHTRACE_REVIEW_SOURCE=/absolute/reviewed/tree/src \
QT_QPA_PLATFORM=offscreen python -m pytest -q \
  -o pythonpath=/absolute/reviewed/tree/src \
  docs/engineering/evidence/test_profile_peer_controls.py
```

The coordinator still owns combined-source regression, actual-final-head CI,
native packages, manual accessibility and release gates. No L1, L2 or L3 accuracy
claim follows from this review, and unverified facts remain excluded from scoring.
