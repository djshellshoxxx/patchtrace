# Accuracy program findings, 2026-11-06/07

Status snapshot written by the coordinating session. Facts here were observed in this session (GitHub REST, CI run lists, pages actually read). Anything not observed is marked unverified. Nothing here changes the L1/L2/L3 accuracy claims: no join-accuracy, Ghidra, BinDiff or Rizin accuracy run has been executed yet.

## Merged and open work

- Merged to main this session: #205, #218, #256 (research-qualification tools, path confinement), #257 (live KB/CVE probe hardening).
- Open at time of writing: #258 (record the first live KB/CVE probe result), #260 (Windows fixed-function candidates, L3, unverified), #235 (independent wave-4 integration, being merged with main; base retargeted to main).
- Closed with an explanatory comment, branches left intact (owner-approved triage, 2026-11-06): #142, #182 (content already on main); #128, #131, #152, #163, #183 (no file changes against main); #67, 69, 71, 90, 94, 100, 102, 126, 127, 132, 136, 138, 147, 148, 158, 159, 166, 177, 178, 189, 190 (superseded: files evolved on main or in integration PRs); #167, #170, #171, #186 (paid API-agent workflow changes, not pursued while credits are limited).
- Kept open: the 37 "partly-absent" PRs. The ~37 PRs in #180-#240 already contained in integration branches are to be closed once #235 lands.

## CI observations on main

- Corpus Tier R (sharded) and Native Windows Ghidriff acceptance: success on 7cf81a0.
- Live rizin rz-diff acceptance and Live unified extraction (SPEC-31 S1): success on 7ac0147.
- Live KB/CVE correlator probe (advisory): success on 652677b.
- QA and Windows standalone on 652677b was still running when last checked; earlier runs on 7ac0147, 7cf81a0 and b569bfa show `cancelled` (superseded by newer pushes, concurrency cancel), not failed.
- SonarCloud Automatic Analysis was turned off by the owner; Sonar no longer gates PRs.

## Layered accuracy model (decision record)

- L1 advisory join (KB/CVE to product to file to pair, about 60 cases), L2 pair diff on open-source (29 independent projects, at least 90% if zero misses), L3 real Windows pairs (15 pairs, at least 82% if zero errors). Claims are per layer and never blended; bounds are one-sided exact Clopper-Pearson (alpha 0.05) over distinct projects.
- Scoring supports `expected.accept` (up to 8 extra accepted function names, for multi-function fixes and renames); the best-ranked listed name counts. A wrongly accepted name would inflate a score, so likely typo spellings are deliberately not accepted.

## Windows patch write-up research (L3 candidates, PR #260)

- 14 candidate cases (4 holdouts), all `facts: unverified` because no binary pair has been hash-checked. Binary: tcpip, http, afd x2, clfs x2, ntfs, srv2, tspkg, dwmcore, mskssrv, kdcsvc, win32kfull, ntoskrnl. Two pages were unreadable (Elastic `patch-diff-to-system`, refused by the fetch tool; one patch-diffing repo page, server error); neither was worked around.
- Pre-found pages: CVE-2024-38063 sources do not name the function Microsoft changed, so it is not a case. CVE-2022-21907 lists five changed http.sys functions and the author is unsure of the fix type. CVE-2024-30088 has one tool-generated-looking page that names the function and lock fix.
- CVE-2020-0796 was removed: the page names the vulnerable function but shows no diff.
- Six cases rest on a single source; four of those come from an aggregator page set of unknown authorship (flagged LOW-TRUST in the case notes). CVE-2023-21768 build numbers disagree between sources.
- Gaps: no ksecdd.sys, NTLM, or modern win32k case yet. Further searches (textfiles, phrack, Packet Storm, phreedom, exploitreversing, RE.SE, rapid7, ZDI, GitHub, vendor blogs) were launched; results will land in separate PRs.

## In flight at time of writing

- #235 integration (merge main into the branch, retarget, fix the archive-path finding).
- Candidate searches: `research/windows-candidates-sources-20261107`, `research/windows-candidates-github-20261107`.
- Engine output adapters (Ghidriff, BinDiff, Rizin to scoring input), `feat/rq-engine-adapters-20261107`.
- Parity comparator, `feat/rq-parity-20261107`.
- L1 KB/CVE join corpus with an independent oracle, `research/l1-join-corpus-20261107`.

## Open gates (not automated)

- Timeout measurement (PT-TIMEOUT-3/4, recorded-pair Windows rerun): owner to run (update to main, set timeout 14400, rerun the pair, run `python -m tools.research_qualification stages <ghidriff.log>`, send the log and backend-execution.json).
- The multi-session swarm is not run (credits); the orchestration prompt is in `docs/plans/swarm-orchestration-prompt-20261106.md`.
- Remaining accuracy work: AV-2 L2 candidate list, AV-3 workflow to fetch/build pairs, harness Windows kill-path test, AV-5 join evaluation (several months, independent oracle), AV-6/7, verifying Winbindex has before/after files for each Windows candidate.
