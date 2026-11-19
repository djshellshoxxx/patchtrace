# Immutable remote action references: source-pinned qualification

Baseline `c7d3f25858cfefbacbd8ea4022b3d13e1e2aed2a`.
Spec/current regression `51160492b66d5952c1c9b3c78fd4e337b8d4d38c` precedes
workflow-only source `2d8ef3f5fa30d06a8e3c90ba69d67b9944005908`.
Final strict test tree `3b3c3d6346c644f04a2e69d9835f147652436535`, tree
`f6bd532fb0b3475b688114c058ff0f39932ade27`, is the qualified snapshot.
Subsequent cache specification work is separate and is not qualified by this packet.

## Change and proof

The complete baseline has 22 workflow files and 186 remote action uses. Exactly
178 mutable reference values in 21 files now name the commit resolved from the
same existing canonical repository/ref. All eight preexisting immutable values
remain byte-for-byte unchanged, including the dependency-security workflow.

The 11 ref responses, 11 commit responses and one annotated Codex tag response
are retained with URLs and timestamps. Codex v1 is tag object
`54e817e77767f274e7e9ceb9da755fb5c62ce25d`, which peels to commit
`306c6a196a99dcc6582530c396a19d2672d5e9ec`. Every target's tree identity is
recorded. The action-only source changes no dispatch, trigger, input, condition,
permission, secret, token, run script, matrix, artifact, timeout or publication
field. A full raw before/after proof admits only the exact reference
substitutions; all 22 parsed YAML objects match after that mapping.

Current CODEX-1 loses only its strict-xfail decorator; its assertion body is
identical to the historical original. The other three original audit bodies also
remain unchanged. Six neighboring test files formerly required mutable tags;
their expected references now require the verified exact commits. Existing
permission/order/artifact/actor allowlists remain enforced. Pages and backend
format assertions require 40 lowercase hex characters instead of version tags.

## Actual local results

| Invocation and source | Result | Interpretation |
| --- | --- | --- |
| Unchanged four original probes, c7d3f258 | 4 failed, 0.17 s | Actual pre-repair failures, no network/children attempted |
| Required action spec regression + registry/policy positives, 51160492 | 1 failed / 112 passed, 0.58 s | Spec/test-first action failure |
| Same 13-file affected policy gate, 2d8ef3f5 | 10 failed / 420 passed / 3 xfailed, 2.42 s | Obsolete exact-tag expectations; raw originals retained |
| Final same 13-file affected policy gate, 3b3c3d63 | 430 passed / 3 xfailed, 2.31 s | All active policy assertions pass |
| Unchanged original four after workflow pinning, 2d8ef3f5 | 1 passed / 3 failed, 0.18 s | CODEX-1 green; CODEX-5/6/14 remain real unresolved failures in this slice |
| Required full `ruff check src tests tools`, detached exact 3b3c3d63 | Passed | No lint exclusions or source changes |

Three current expected failures are dependency hashes (CODEX-5), corpus cache
verification (CODEX-6), and Linux full CLI smoke (CODEX-14). They are not new
passes, ignored failures, or permission to publish. The retired historical
CODEX-15 blanket license assertion remains a separately classified policy
mismatch; this change alters no license policy. Counts are per invocation and
are not summed into product coverage. Exact commands, XML, raw logs, before/after
sources and assertion equivalence accompany this receipt.

## Limits and independent review

No action, workflow dispatch, external package install, native engine, target,
frozen binary or release was executed. Canonical API reads establish the
reference/object snapshot; they do not qualify action runtime behavior. Hosted
and native gates remain pending. Root independently reread all 23 canonical API
objects and the full spec/test delta; final independent integration and release
qualification remain root-owned. All commits carry the literal `[no release]`.

Archive: `workflow-action-pins-20261118.zip`; 98 members, 273294 bytes. SHA-256 `06102fd31bbcb169981f05040dae25f6d043a9198e9e119f3b6f435041ddff76`.
