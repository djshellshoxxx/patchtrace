# Codespaces plan for the accuracy program

Status: plan only, nothing here is built. Written for an implementer who has no chat history (ChatGPT/Codex, or a person). Read `AGENTS.md` and `docs/plans/accuracy-program-handoff-20261107.md` first, and run `tools/handoff_status.sh`.

## Why Codespaces
Claude's sandbox and some CI contexts cannot reach Winbindex, Microsoft's symbol server, or arbitrary download hosts, and ghidriff runs take hours. A Codespace is a Linux machine with open internet, a persistent disk and more cores. It is for long, interactive or network-heavy work. Scheduled and parallel batch work stays on GitHub Actions. It cannot do Windows packaging (that needs Windows).

Unverified until checked on the owner's billing page and GitHub docs: available machine sizes, core-hour quota, idle timeout, maximum retention. Do not hard-code assumptions about them; use `hostRequirements` as a request and document what you actually got.

## Scope: what runs where
| Work | Where | Why |
|------|-------|-----|
| Long ghidriff pair diffs, timeout measurement (PT-TIMEOUT-3/4) | Codespace | hours-long, needs Ghidra, owner can watch |
| Real BinDiff and rizin exports to verify the adapters | Codespace | needs the tools installed, one-off |
| L2 open-source pair builds (about 29 projects, two commits each) | Codespace | CPU heavy, needs git clones |
| Fuzz and sanitizer runs on adapters/parsers | Codespace | long, no deadline |
| Faster full test run (pytest-xdist) | Codespace | more cores |
| Pair fetch from Winbindex (PR #271), diff-and-score matrix (PR #272) | Actions | parallel, hand-dispatched |
| Monthly L1 extension, re-verification, scoreboard | Actions (scheduled) | unattended |

## Hard rules
- No Microsoft binaries in git. Keep them under an ignored directory (`data/` or `.cache/`), add it to `.gitignore`, and commit hashes and reports only.
- No secrets in the repo, logs or devcontainer files. The Codespace gets `GITHUB_TOKEN` automatically; anything else goes in Codespaces secrets.
- Pin every download (version and sha256). Do not guess pins; if you cannot verify one, make it a required input.
- Setup must be idempotent and safe to re-run. Validate before acting, stop on the first failure.
- Windows binaries are Microsoft's: owner must accept the symbol-server terms question (open gate G4 in `kb-winbindex-packages.md`) before bulk downloads.

## Tasks (do in order, one small PR each)
Each task has an acceptance check. Do not start the next until the check is shown passing.

**CS-1 devcontainer base.** Add `.devcontainer/devcontainer.json` and `.devcontainer/setup.sh`. Python matching the repo's CI version (check `.github/workflows` for it), Java 21 (verify Ghidra's required JDK for the pinned version), git, jq, `gh`. `postCreateCommand` runs `setup.sh`, which creates a venv and installs `.[dev,search,rules]` plus `pytest-xdist`. `hostRequirements` asks for 8+ cores and 16+ GB.
Acceptance: fresh Codespace, then `python -m ruff check src tests tools` and `QT_QPA_PLATFORM=offscreen python -m pytest -q -x tests/test_research_qualification_*.py` pass. Record time and machine size in `docs/qa.md`.

**CS-2 Ghidra + ghidriff.** `setup.sh` installs `ghidriff==1.0.0` (verified on PyPI) and downloads Ghidra to `~/ghidra`. Ghidra URL and sha256 come from the owner (copy from the official release page); `setup.sh` refuses to continue on a hash mismatch and skips with a clear message if unset.
Acceptance: `ghidriff --help` works; one tiny pair diff completes and writes a report.

**CS-3 rizin and BinDiff.** Install rizin (apt or official release, verify). BinDiff needs BinExport output from Ghidra or IDA: verify the exact tooling from BinDiff/BinExport docs before writing anything; if it cannot be installed unattended, document manual steps instead.
Acceptance: one real rizin JSON and one real BinDiff SQLite export, saved under `tests/fixtures/research_adapters/real/` (small files only, licence-checked), plus a test that the adapters (PR #265) parse them. Fix the adapters if they do not. This task verifies a currently UNVERIFIED claim.

**CS-4 run scripts.** Add `scripts/cs/` with: `pairs.sh` (calls the PR #271 helper for a manifest), `diff.sh` (ghidriff one pair into `data/reports/`, with `timeout` and `nohup`, logs to a file, safe to resume), `score.sh` (PR #272 `scorerun`). No new logic; thin wrappers.
Acceptance: one end-to-end pair (small file) goes fetch, diff, score, and writes a receipt with PASS/FAIL/BLOCKED.

**CS-5 timeout measurement.** Follow the PT-TIMEOUT-3/4 steps in `tasks/todo.md`: update to main, set timeout 14400, rerun the pair, run `python -m tools.research_qualification stages <ghidriff.log>`. Commit the stage timings (not binaries) to `docs/qa.md`.
Acceptance: timings recorded; decision on the right per-pair timeout written down.

**CS-6 L2 pair builds.** First write the candidate list (about 29 independent open-source projects, each with a known security fix commit, the changed function named by the advisory or commit). Then `scripts/cs/build_pair.sh` builds before/after at two commits with fixed compiler flags and records toolchain versions and hashes. Start with 3 projects to prove the loop.
Acceptance: 3 projects produce paired binaries and a manifest that passes the case validator.

**CS-7 fuzz and sanitizers.** Add a fuzz harness for each adapter parser (hostile JSON, SQLite, markdown) and run under the Python fault handler with size limits. Fix findings in separate PRs.
Acceptance: harness runs for a fixed time budget with no crash; findings listed in `docs/qa.md`.

**CS-8 docs.** `docs/research/codespaces.md`: how to open the Codespace, machine size to pick, how to stop it (cost), where outputs go, how to download artifacts. Update the handoff doc.
Acceptance: a new person can follow it start to finish.

## Owner decisions needed
1. Machine size and monthly budget for Codespaces.
2. Ghidra release URL and sha256 (CS-2).
3. Symbol-server terms (G4) before bulk Windows downloads.
4. Whether L2 builds may use only permissively licensed projects.

## Done when
CS-1 to CS-5 are merged and one real pair has gone fetch, diff and score inside a Codespace; CS-6 to CS-8 are tracked as follow-ups.
