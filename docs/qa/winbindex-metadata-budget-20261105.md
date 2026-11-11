# Winbindex metadata operation budget — 2026-11-05

Worktree `/tmp/pt-independent-metadata-budget-20261105`, branch
`repair/winbindex-metadata-budget-20261105`, based on independent integration
`58cc60f752750a4455cd22f3b547db4a5b609c79`. The defect was identified while
implementing an exact-consent metadata preview. Relevant module index/SPEC-08
were read first and the specification clarified before implementation.

Seven injected controls failed on baseline. Two 60-second Retry-After waits
allowed a third request at the 120-second deadline. Expired/cancelled headers
could become a false not-found result. Retry connections retained the ordinary
timeout after only two seconds remained. Overshooting sleeps and a deadline
exhausted before the first attempt still reached the opener. A shortened budget
did not limit otherwise successful connection timeouts.

The shared retry helper accepts an optional deadline; its default retains existing
policies. Metadata checks that deadline before attempts/sleeps and after sleeps/
headers. Connections receive the smaller remaining timeout. Delays that cannot
fit fail rather than retry early. Returned responses close on refusal. Raw bytes,
source URL/date, headers, retry caps and typed errors remain preserved. No new
schema/model/dependency or network host.

Completed, source-bound PYTHONPATH:

- Baseline new file: **7 failed in 1.22 s**;
  `/tmp/pt-independent-metadata-budget-red.log`.
- Metadata, existing acquisition transport and CVRF controls: **94 passed,
  2 deselected in 1.52 s**; `/tmp/pt-independent-metadata-budget-green.log`.
- The two excluded slow-drip loopback controls then ran explicitly: **2 passed,
  27 deselected in 2.78 s**. This local authored server is not live source evidence.
- Whole `python -m ruff check src tests tools` and `git diff --check` passed.

No actual endpoint/binary download, target execution, broad suite or Windows check.
The opener must honor its supplied timeout; guards do not interrupt arbitrary
calls or bound local parsing CPU. PR #205's owner logs/exit and native #222/#224
work are unchanged. Independent review precedes publication and use by refresh.
