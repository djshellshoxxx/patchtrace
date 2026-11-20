# Generation 33 — four historical QA links

**Decision:** All four broken relative links predate `ad891694`. Every referenced document survives in retained history and was successfully fetched from GitHub at an exact historical commit. Replace the four link destinations with the verified URLs below; no missing-document disposition is needed.

## Pre-existing status

- Baseline: `ad8916944a697985be3e472cd57f2e15f0a263bc`, tree `23ad5e5230e539df4727f5b2235f107a3f895a98`.
- Reviewed publication: `b10746302c712d4968285cc4190f6d3adf09d57c`, tree `7a6771ca39bf0b7983d06f7e6bb0280809c773c5`.
- All four link-bearing lines are identical between those commits, and all four relative targets are absent in both trees.
- `git blame` attributes these lines to restoration commit `25b2ac8000e4bb2b941ce44ccbbb25a7eff5c278` (2026-11-03T22:51:55-07:00), `Restore truncated trackers, add tracker regression test, align spec registry (#173)`. That commit is an ancestor of the baseline; the four targets are absent there too.

The later diff to `docs/qa.md` adds the generation-33 section at the top; it does not change these historical link-bearing lines. This establishes that the broken targets were not introduced by the current qualification-document update.

## Verified replacements

| Existing relative destination | Retained commit | Verified GitHub destination |
| --- | --- | --- |
| `qa/corpus-safeguards-20261101.md` | `4aa99f7bd989765000c6ebd659c9565030a48849` | [corpus-safeguards-20261101.md](https://github.com/djshellshoxxx/patchtrace/blob/4aa99f7bd989765000c6ebd659c9565030a48849/docs/qa/corpus-safeguards-20261101.md) |
| `qa/prereg-markdown-review-20261101.md` | `f27d23a80ee49573ccca54cdf036427f57eebb2a` | [prereg-markdown-review-20261101.md](https://github.com/djshellshoxxx/patchtrace/blob/f27d23a80ee49573ccca54cdf036427f57eebb2a/docs/qa/prereg-markdown-review-20261101.md) |
| `qa/corpus-output-persistence-20261101.md` | `99660cc825b366a28e50b18eacad44dbb069ca69` | [corpus-output-persistence-20261101.md](https://github.com/djshellshoxxx/patchtrace/blob/99660cc825b366a28e50b18eacad44dbb069ca69/docs/qa/corpus-output-persistence-20261101.md) |
| `qa/output-credited-replay-20261101.md` | `aff72cddc902f31a2cf44dea9c48797edabc1c30` | [output-credited-replay-20261101.md](https://github.com/djshellshoxxx/patchtrace/blob/aff72cddc902f31a2cf44dea9c48797edabc1c30/docs/qa/output-credited-replay-20261101.md) |

## Artifact identity

| Historical document | Git blob | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| `corpus-safeguards-20261101.md` | `6d1c97cecc0d3ceb66ec118ce4393a19f4738d20` | 11,706 | `9c29334e159f8abf5453562920f2bed35f38566975ba2ddb161ca4d735d51fec` |
| `prereg-markdown-review-20261101.md` | `0f2a8f1a932c83a89bd8b6823fae3f1b0a9600f1` | 5,947 | `65b9711db2a62b714d8531232c57a5e0c649b26f7646032fd880ce85bf611d64` |
| `corpus-output-persistence-20261101.md` | `ab21d0db4f51e95f3d0b7a3e1b1723d814f4cdd8` | 9,572 | `9c3e2f24c9808bd3695f158d04b275300f4c21fbf80aa08ffe105da75ddb2071` |
| `output-credited-replay-20261101.md` | `e43b890f5b976d5b6a93f3b41c5149f96cf86994` | 5,642 | `afe033c15332845c26b032c116d9f69edc68082d936ea0b266785f9b4c08a4b4` |

Verification used the GitHub file API with each explicit commit and base64 encoding. Decoded remote bytes equal `git show <commit>:<path>` exactly, and the independently computed Git blob hashes equal both the remote and local blob IDs. The recommended commits also remain reachable from retained remote-tracking refs.

The output-persistence document has a different, shorter copy in consolidation commit `039c696c`; the recommended `99660cc8` URL identifies the original published document, including its later independent-review and main-port notes. This avoids silently selecting the different consolidation blob.

Keep these links visibly historical. Their availability does not promote their source-specific tests into current qualification. This bounded check did not validate every nested historical reference or rerun any historical claim.

## Evidence and scope

- [Structured mapping and checks](generation33-historical-link-review.json)
- [Exact GitHub read receipts](generation33-historical-links-remote.json)

No repository documents or source were modified, no tests were run, and no remote mutation occurred.
