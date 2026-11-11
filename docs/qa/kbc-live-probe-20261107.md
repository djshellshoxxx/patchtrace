# Live KB/CVE probe: first real result (2026-11-07)

Run: GitHub Actions `Live KB/CVE correlator probe (advisory)`, run 42346127399, `workflow_dispatch` on main at 652677b.
Inputs: defaults (month 2024-Aug, CVE-2024-38063). Verdict: **passed, 7 live checks** (artifact `kbc-live`).

| Check | Result | Detail |
|---|---|---|
| msrc-reachable | passed | tcp 443 open |
| plan | passed | preview made no request; plan_sha c0ed7554...5450 |
| sync | passed | 2024-Aug stored (added); sha256 730ad133...0a1d |
| verify | passed | stored documents re-hash and re-parse |
| search | passed | CVE-2024-38063 resolves to 15 KB ids |
| winbindex-reachable | passed | tcp 443 open |
| winbindex | passed | Winbindex record for afd.sys returned |

## What this establishes
- The consent flags (`--consent-hosts`, `--consent-plan`) work end to end through `kb index sync`.
- The MSRC fetch for one month stores, re-verifies and searches by CVE on a clean runner.
- The Winbindex search path reaches the live host and returns a record.

## What it does not establish (unverified)
- One month and one CVE only. No claim about other months, product coverage, or the 15 KB ids being complete or correct.
- It does not compare the KB list against an independent source (that is the L1 join evaluation, AV-5).
- Windows runner and the GUI attach flow were not exercised.
- Winbindex pair acquisition and file download (beyond a search record) were not run.

Next: AV-5 (automated join evaluation over several months with an independent oracle).
