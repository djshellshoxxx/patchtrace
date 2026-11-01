# Independent external review audit — 2026-11-01

Read-only review of PR #156 head `15deb8f28e207a9679379265571d2691de52e7e2`, tree `93785aaf6dbcf7ae48c00f86c4cf473dbb180e4d`, and PR #157 head `99660cc825b366a28e50b18eacad44dbb069ca69`, tree `5636d45531a73deb522935712307588951a2e282`. Local equivalents b92c8de (wt-identity-main) and 55e15cb (wt-corpus-output-main) have identical trees. No source, GitHub comment, review state, workflow, or policy mutation.

## External evidence and completeness

GitHub connector GET review, inline-comment and issue-comment API pages used per_page=100, page1 and page2 (all page2 empty). #156:1 review,2 inline comments,5 issue comments. #157:2 reviews,5 inline comments,5 issue comments at observation; CodeRabbit added inline4435918970 corroborating mixed-key crash. Check-runs page1 totals22 and15 respectively; page2 empty for both. Many checks remain queued/in_progress; skipped release gates do not establish acceptance.

Connector supports check-runs but rejects annotations subresource with400. Approved public unauthenticated urllib GET fetched annotation pages1 and2 (page2 empty) for156 Sonar check124867141303 and157 plan check124866876277. #156 Sonar success still contains two failure-level maintainability annotations: secondary.py36 AaGXXgSzWV1cgC4sh3zN and manual.py66 AaGXXgU4WV1cgC4sh3zO, both variable tuple-length warnings. SourceRef tuple intentionally has0or1 entries; typed canonical sort-key tuples intentionally differ by tagged value type. These annotations alone establish no runtime defect. #157 Sonar0annotations; plan annotation warns actions' Node20 runtime deprecation/forcedNode24. No gate-green conclusion.

## Actionable findings

#156 Qodo4435906075 (manual.py54–55) identifies whole manual-snapshot serialization/hash inside owner-thread make_plan. Qodo4435906078 identifies refacts_stage active Budget omitted from plan_identity and bindiff_flags at compute.py272/289. Source-confirmed; coordinator assigned receipt_fix independent implementation/repro. No duplicate source edits from this reviewer.

#157 Qodo4435911462 and CodeRabbit4435918970: P2 correctness. Two changed predictions with order_key [1] and ["first"] pass report_schemas.load_engine_output and actual train.load_outputs; to_engine_pairs then rank.midranks raises TypeError ("'<' not supported between instances of 'str' and 'int'"). Schema accepts independently bounded scalar unions but fails to enforce lexicographic comparability across actual flagged keys including fallback keys. Reject incompatible documents before publication/scoring, preserving existing provider ordering and ties.

#157 Qodo4435911469: P2 integrity. Bounded post-link fault control replaces a newly published JSON with DIFFERENT VALID normalized bytes. evaluate correctly reports pair failed and output_sha256=null, but train.load_outputs(single-run-directory) adopts1 output with mutated name. Thus even choosing one run directory cannot enforce the documented successful-report-reference policy. Reader must bind adoption to successful report pair/engine/image/digest refs (or an equivalently reviewed attestation), not trust directory contents. Repeated evaluations under parent outputs directory do produce duplicate-key TrainError, but this refusal alone is reasonable ambiguous-input rejection and is not the principal defect.

#157 Qodo4435911465: proven bound-order gap, P2 resource hardening. Tiny513-character invalid name is fully serialized and UTF-8 encoded as515-byte JSON chunk before schema rejects it. output_store.py45–58 caps total only after per-scalar encoding; write145–155 validates schema after serialization. No large allocation/OOM experiment performed; actual exhaustion is inferred, not reproduced. Validate bounded fields before materializing provider-controlled scalars and retain incremental total-byte cap; preserve original canonical accepted bytes.

#157 Qodo4435911470: reproducible compatibility mismatch, P2 triage. The same synthetic EngineOutput with513-character old_name scores statusok in-memory, statusfailed with retention. Strict512-character names/200-character version existed before157; default retention newly exercises those constraints, while Ghidriff upstream_name/version producer paths remain unbounded. Decide and document producer contract without blindly widening the reader; if names are display-only, apply deliberate producer normalization and ensure metrics/ties/replay remain faithful. No native producer run or universal real-corpus frequency claim.

## Bounded verification

One synthetic-control script took0.34s, using /workspace/scratch/142cb233d750/venv/bin/python and absolute PYTHONPATH for wt-corpus-output-main root/src/tests. Imported test_tier_r_output_persistence fixtures; used actual RS loader, train.load_outputs, to_engine_pairs/rank.midranks, OutputStore and evaluate. TemporaryDirectory owned all inputs/outputs. No native/target execution, network input, corpus consumption, full suite or performance run. No fixes or thread resolutions performed.

