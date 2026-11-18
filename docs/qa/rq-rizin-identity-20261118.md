# Native Rizin qualification identity guard — 2026-11-18

The research ranking adapter now refuses observable native function-identity
conflicts before projecting a report to names. A changed, unrelated function
with the expected function's name can no longer borrow that expected function's
credit when both identities are present in the native report. This does not
verify source-to-binary truth, establish ranking accuracy, or adopt a patched
native tool.

## Exact source and preserved publication history

The repair starts at published inventory continuation
`3123b6d447b96e19781094f276cdd84456e5e386`, tree
`af473efaebdb070a04c37a28b40ee0686ea368eb`. Each specification change precedes its
implementation, and no published commit is amended or rewritten.

| Stage | Local source commit | REST counterpart |
|---|---|---|
| Initial identity specification | `e696c8fd0536c203d998b8dcf7a4828767b5b23d` | `c6075fe8c3017ceadb0fac46db8909e480d0985a` |
| Native identity validation and regressions | `3b22a27cd98713ac231f46f196f6114936e99fcf` | `9934e0278ab509107f905f24293a4ce403ddaf06` |
| Recognition-gap specification | `f0823d7f127ea4d8c763f95e9e61303a15ef212b` | `723156bacd0985cea3c4377cd2abe1d2f7471210` |
| Final recognition repair | `61b7cfb49a6f496eb85efd091b2820d114e7d444` | `2b4fbd50e1136a876ffba865cbad86eb6b018627` |

The final two identities have the same tree:
`b639fb11db07761195fba5c309476474cd19caba`. Only three paths differ from the base:
the existing Rizin research adapter, its existing contract document, and one new
regression module. The following QA commit adds records without changing those
qualified source bytes. Full parent and tree identities are in the
[publication mapping](rq-rizin-identity-20261118/publication-mappings.json).

## Reproduced problem and corrected behavior

The minimal authored counterexample has an unchanged function at older/newer
addresses `0x100`/`0x200` and an unrelated changed function at `0x300`/`0x400`.
Both rows use `sym.prospective_fix`. The old adapter dropped addresses and the
unchanged row, returning that name; a name-based oracle then received a HIT.
The preserved pre-repair review contains this raw input and the observed result.

The [updated contract](../research/adapters.md#native-rizin-report-identity-gate-2026-11-18)
requires strict native row/side fields, bounded unsigned addresses, valid names
and similarities, and consistent ownership of both endpoints and all normalized
labels. Validation includes unchanged rows. Conflicting aliases, one-to-many or
many-to-one mappings, contradictory repeated rows, mixed layouts and native
records hidden in legacy wrappers are refused. Exact repeated records contribute
once. Duplicate JSON keys fail before their earlier values can be overwritten.
The existing 500,000-function bound now caps raw native rows before filtering or
deduplication, including unchanged rows.

Root and independent review then found a separate recognition gap: a known
native match type with both side keys removed could enter the unnamed legacy
path and produce an empty candidate list. A second spec/red/fix cycle recognizes
that native-shaped input and requires its complete native fields. Named flat
legacy records keep their existing tolerant type handling.

Refusal raises `ValueError`; the adapters CLI returns a clean exit 2 with no
partial candidate output. The existing scoring orchestrator records
`BLOCKED: unparseable_report`, excluding the case from scoring. It does not turn
the refusal into a MISS, a function HIT, or an empty-list no-change HIT. Valid
native ranking preserves magnitude order, older-name preference, one-sided order,
literal `sym.` prefixes, case, Unicode distinctions and address-zero behavior.

## Verification, with scopes kept separate

| Check and source | Observed result |
|---|---|
| Initial implementation controls on exact published `3123b6d4` | **89 failed, 9 passed**; original red log/JUnit retained |
| Independent controls on the same base tree | **94 failed, 20 passed**, no harness errors |
| Initial four-module candidate selection at `3b22a27c` | **193 passed** |
| Implementation recognition supplement on `3b22a27c` | **5 failed, 4 passed**, 98 deselected |
| Separate independent recognition supplement on `3b22a27c` | **12 failed, 6 passed** |
| Final four-module selection at `61b7cfb4` | **202 passed, 0 failed, 0 skipped** |
| Independent final controls at `61b7cfb4` | **114 original controls plus 18 recognition controls passed** |
| Independent repeat of the final repository selection | **202 passed**; overlaps the author's selection |
| Whole-tree Ruff and full-range whitespace checks | Passed; frozen checkout clean |
| Root replay of retained authored native records at `61b7cfb4` | Six accepted, three refused for conflicting endpoint data; no engine execution or case scoring |

Do not sum overlapping test selections or treat synthetic controls as independent
accuracy samples. The exact argv, environment, source/tree identities, JUnit,
logs, original failed controls and independent review are preserved in the
[evidence archive](rq-rizin-identity-20261118/evidence.zip), with a
[payload manifest](rq-rizin-identity-20261118/manifest.json) and
[final command receipt](rq-rizin-identity-20261118/commands.json).

The root replay uses the already retained archive-tool, unchanged-rebuild and
patched-tool outputs from the [native discovery experiment](l2-rizin-discovery-patch-20261118.md).
All six shared/executable reports remain parseable. The patched shared and
executable records retain `sym.diag_changed` as the candidate. The unmodified
shared record still returns no candidate because discovery omitted the authored
exports; this guard does not repair that discovery defect.

All three authored PE reports are refused: the archive/unchanged 14-row reports
and patched 22-row report contain conflicting endpoint match data. Those are
limits on projection to a unique name ranking, not failures of the production
secondary evidence model, which retains alternative matches. The raw bytes stay
unchanged. Both root replays and the implementation preservation check leave the
first CVE pilot, oracle and prior diagnosis artifacts unchanged.

## Remaining boundaries and integration hold

Legacy text/flat JSON remains unverified. Its unnamed-row skipping is preserved;
the new guard does not certify arbitrary legacy shapes. A verified native pilot
must first pass the production strict parser and ownership checks, and must have
an independently reviewed, prospectively frozen source/binary/engine identity
mapping. Omitted or mislabeled functions cannot be corrected from report-local
consistency alone. No global namespace stripping or inferred alias is introduced.

The orchestrator regression deliberately uses the existing Ghidriff-shaped
report locator to test error propagation through engine dispatch. It does not
qualify native Rizin report discovery or an end-to-end orchestration flow. That
integration remains separate work. Production matching, the case manifest/schema,
scorer, original L2 MISS/FAIL, tool selection, L1 expectations and L3 approval
status are unchanged.

Required full Linux/Windows, Qt, native and package acceptance still belongs to
the final published head. These focused results do not satisfy the merge and
superseded-closure gates. Follow the [current continuation record](pw01-current-integration-20261118.md)
for #304 qualification, then retarget #307 to canonical main after verified
integration and re-evaluate exact-head/base gates before a SHA-guarded REST merge
with `[no release]`.
