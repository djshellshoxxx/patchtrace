# Independent review of the PR #235 archive-path finding

Date: 2026-11-05. Issue: `AaGuFuc-a2s4H-WIcBuh`, rule `pythonsecurity:S8707`, `tools/check_windows_package.py:149`.

## Verdict and scanner state

**No unauthorized path traversal was reproduced. The reviewed flow is an intentional, explicit local CLI archive selection; this finding is a candidate for an authorized false-positive disposition.** It is not marked disposed by this review.

The public [PR #235 issue query](https://sonarcloud.io/api/issues/search?componentKeys=djshellshoxxx_patchtrace&pullRequest=235&statuses=OPEN) returned this single OPEN MAJOR vulnerability. The public [quality-gate query](https://sonarcloud.io/api/qualitygates/project_status?projectKey=djshellshoxxx_patchtrace&pullRequest=235) reported ERROR, with `new_security_rating=3` against threshold `1`. No issue status, permission, scanner configuration, suppression or gate was modified.

Review worktree: `/tmp/pt-independent-sonar235-20261105`, branch `docs/sonar235-package-path-20261105`. The reviewed tool at source commit `93b4b9a80d31c97659269429e0b680c9218fdf70` is byte-identical to that file at observed PR #235 head `e7a1750110fac77f1df816dfb7b749dc9125912b`: SHA-256 `b0412180c470704ee7c7340bd0514251eec03d06c0e129916b2965837118b63b`.

## Actual trust boundary

`main` accepts one explicit positional archive path through `argparse`, with required expected SHA-256, source commit and package label. It passes that path directly to the read-only preflight. The scanner flow describes `parse_args` as an HTTP request source, but this tool contains no HTTP handler, server, model-generated command processing or application-controlled remote path input.

The CLI deliberately supports archives outside the checkout or current directory; the [Windows qualification runbook](../runbooks/windows-candidate-qualification.md) asks the operator to select the downloaded candidate. No allowed input directory or filesystem sandbox is promised. A parent-relative or absolute pathname is therefore not, by itself, an escape from an enforced boundary. Hash/source checks establish expected artifact integrity, **not filesystem authorization**; the justification here is the explicit local input selection and the absence of a more privileged or remote read service, rather than a claim that hashing prevents arbitrary reads.

The file is opened with `O_RDONLY` and nonblocking/binary flags where supported. Nonregular handles are rejected before buffered IO. Size, digest, ZIP directory/layout/member paths, strict inventory and source identity are checked on the opened stream. The tool never extracts or executes package members, writes the archive, requests network access or prints their raw contents. Failure output is one generic JSON document. Successful output contains bounded structural receipt fields and explicitly leaves Windows/native/manual acceptance not run. These are content validation checks, not an authorization sandbox.

Archive member traversal is a different boundary: existing `_path` and member checks reject parent segments, absolute/Windows-unsafe names, links and colliding roots. No extraction sink exists in this tool, and those controls were independently tested rather than substituted for review of the outer CLI path.

## Independent authored controls

Command: `env -u PYTEST_ADDOPTS PYTHONPATH=$PWD/src QT_QPA_PLATFORM=offscreen python -m pytest -q tests/test_windows_package_preflight.py`.

**60 passed in 1.07 s**, raw log `/tmp/pt-independent-online-sonar235-focused.log`. Existing cases cover malformed member/inventory paths, symbolic-link members, wrong expected identity, nonregular input, resource limits, malformed ZIP/metadata and byte preservation. Fixture EXE/DLL names contain authored strings; no executable was run.

An additional independent probe created an authored candidate in a sibling directory, then invoked the real `main` once with its absolute path and once with `../outside/candidate.zip`. Both returned `verified-structure` for the exact authored digest/identity. Instrumentation required every tool `os.open` to be read-only and refused create/truncate/append flags. Both ZIP extraction methods were replaced with failing sentinels. An authored archive-content marker and the selected pathname were absent from output; the complete temporary file snapshot remained byte-identical afterward. No private/secret file, downloaded candidate or target binary was used.

## Limits and required next action

The inspector has the caller's existing filesystem read privileges; this review does not claim resistance to an attacker who already controls that local account, arbitrary filesystem mutation, a future privileged/remote wrapper, or a separate agent that executes unauthorized instructions. If a future caller introduces a restricted input root or remote file selection, that new boundary requires its own contract and containment tests.

Normal authorized Sonar project review is still required to accept or reject the proposed false-positive disposition. Until an authorized reviewer acts and current-head checks pass, the observed scanner gate remains failed. No production, Windows, native or release acceptance follows from these authored Linux controls.
