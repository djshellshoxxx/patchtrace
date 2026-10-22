# PatchTrace continuation log — 2026-10-22 (Pacific)

Working branch: `codex/patchtrace-completion-20261022`.

## Baseline and repository state

- Inspected all 23 open pull requests, branch heads, repository instructions, and PR #87's dependency handoff.
- Selected `claude/instance-d-gui` (PR #64, head `fb3645350f8f38d61dc507d7751377696aa1bcc3`, updated 2026-10-21) as the most complete integration baseline. Its latest commits are newer than the earlier work in PR #100 and it contains the larger shared GUI, unified-engine, enrichment, KB/CVE, packaging, and calibration integration.
- Merged current `main` at `e093ade3e66eebf915d1c93c75cf18c033c2abb5` into the isolated continuation branch. This retains the Windows per-user installer and later fixes absent from PR #64's base. The merge commit is `b814789`.
- Ported PR #100's eight commits in dependency order: local symbol mode/PDB staging and launcher, Setup wiring, Diaphora Mode A import and CLI, Setup extraction, docs/schema registration, and Windows path test corrections. The port currently ends at `8004e4e`.

## Dependency verification and test evidence

- Initial environment lacked the optional `search` extra. Before installation, the six failures named in PR #100 reproduced: four RapidFuzz backend tests could not import `rapidfuzz`, and two search suggestion tests returned no suggestions.
- Installed the declared extras with `python -m pip install --only-binary=:all: -e '.[dev,search,rules]'`. The pinned `rapidfuzz==3.14.6`, `yara-x==1.21.0`, and `iced-x86==1.21.0` plus development requirements installed successfully.
- After installation, the two search test modules passed: **37 passed**. This confirms those six failures were caused by the missing declared optional dependency, not by the PR #100 code.
- On the combined tree, focused local-symbol, launcher, Diaphora import/CLI/schema, and mutation tests passed: **128 passed, 23 skipped**. Compiler-dependent skips are recorded as blocked because Clang is not installed in this container; they are not counted as passes.
- After the COFF parser fix, the expanded PR #100 + parser regression batch passed: **314 passed, 24 skipped in 63.91 s**. Skips are compiler-backed and Clang is absent locally.
- `python -m ruff check src tests tools` passed on the combined tree before the COFF parser fix; it will be rerun after this checkpoint.
- PR #100's latest recorded Actions at head `66e9adc50fb118c04e5e24eacd0c221ca483a130` passed Linux and Windows QA and native Windows Ghidriff acceptance. These runs validate PR #100 by itself, not the combined continuation branch.

## Current blockers and unverified claims

- PR #64's latest full QA run (GitHub Actions run `39559162804`, merge SHA `a815670a48ae05a1ca7b2e8c2850cb880d57f825`) failed Windows QA: **2 failed, 17,988 passed, 79 skipped, 6 xfailed**. Failures are `test_masked_body_rule_rejects_address_only_changes_and_records_them[string-literal-shout]` and `[callee-swap-dispatch]`; both say `DID NOT RAISE NoMutationSite`. The Linux suite and several live acceptance jobs passed at that prior head. Local execution cannot reproduce yet because this container has no Clang and skips the compiler-dependent tests.
- Root cause is now reproduced at the parser boundary using synthetic Windows COFF assembly: `_ASM_SYMBOL` did not normalize quoted MSVC `??_C@...` RIP operands, and `_masked_function_asm` only stopped at ELF `.Lfunc_end` labels. Added regression cases first; five failed against the old implementation. Implemented quoted-symbol normalization and COFF function/data boundary detection. The focused parser regressions now pass; the compiler-backed Windows tests remain pending CI.
- Local `QT_QPA_PLATFORM=offscreen python -m pytest -q` was interrupted after nearly 10 minutes at about 1% progress. `--collect-only` was also interrupted after over 2 minutes without completing discovery. No full-suite result is claimed for this branch.
- Pushing the fast-forward branch to PR #64 failed because the workspace has no GitHub push credential. The GitHub API connector read attempt returned a transport error; it cannot upload the local commit object. Current-head CI is therefore blocked until a credentialed push path is available.
- No CI has run on the combined branch. Do not merge or call this release-ready until current-head Windows/Linux QA, Ruff, frozen Windows smoke, and portable/installer lifecycle checks pass.
- PDB local mode still lacks the GHR-5 native air-gap matrix and GHR-6 fetch path. Tests use synthetic PEs/PDBs and fake Ghidriff; they do not prove the real Ghidra symbol server stays empty.
- Diaphora is at Mode A only. The result parser is tested with synthetic SQLite data; compatibility with real Diaphora 3.4.3 output remains unverified. Export-database import, patch signals, context, GUI, Mode B, and Mode C remain open under SPEC-DA-01.
- Human/device gates remain: owner-side NVDA/Narrator, high-contrast/DPI, trusted BinDiff pin, licensed IDA/Hex-Rays smoke and legal review where applicable.

## Next actions

1. Verify the Windows COFF masked-body fix on current-head Windows CI and confirm the two reported mutation cases pass with real Clang.
2. Run the complete suite and Ruff on this exact combined tree; record actual skips, blocked live checks, and resource limits.
3. Review dependency-ordered open PR work against current integration state; port only non-duplicated, passing changes.
4. Complete feasible SPEC-53 and SPEC-DA-01 slices; generate schemas and update `docs/modules.md`, `docs/qa.md`, and `tasks/todo.md` with current evidence.
5. Rerun Ruff and diff hygiene, then publish the continuation branch through a credentialed GitHub path to obtain current-head Windows/Linux Actions. Produce release artifacts only after all required Windows gates pass. Continue to keep synthetic, live-tool, and owner-only evidence distinct.
