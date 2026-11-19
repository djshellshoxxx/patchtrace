# Independent primary-environment review

Reviewed commit: 1f9ad8635d2952e2f65d752fe4f7df3faca8f49a.
Tree: ad43ac3dbcee546c58689e996cee44512f09adb6.
Detached checkout: /workspace/scratch/c7a9e8d98848/primary-environment-review.
Baseline: published PR #307 head 58fc130631f602b6e907bb054d30c21d810551d4.

## Conclusion

No confirmed blocker in the bounded production delta after source inspection
and independent local regression checks. This is source/local-test acceptance,
not native H7 qualification or merge approval.

Inspected the specification amendment, BackendConfig default, both desktop
absent-key readers, Setup label/tooltip, unchanged environment builder and
passthrough validation, dependency/JVM probes, bundle enforcement and unified
extraction call sites. Inspected all fixture changes. Redaction tests now select
explicit unrestricted compatibility mode; the grandchild heartbeat test selects
only its named PT_TEST_BEAT variable. Their substantive assertions are unchanged.
The final Windows case normalization preserves the secret/proxy checks.

The same seventeen affected files plus eleven independently authored controls
passed **370 tests, with 3 existing native-Windows skips**, in 60.43 seconds on
Linux. Exact source, tree, command, environment and independent test hash are in
command.json. No tracked source was changed in this detached review.

## Eleven independent controls

- Exact import provenance from the detached worktree.
- An actual isolated Python child receives the authored approved marker and
  does not receive authored credentials, injection variables or unconsented
  proxy/CA values.
- Dependency probe uses the restricted default (captured invocation).
- JVM version probe uses the restricted default and selected private JDK
  (captured invocation; no Java binary is executed).
- Explicit named proxy passthrough remains narrow.
- Bundle mode defeats both full-inheritance switches and directs scratch.
- Four forbidden injection passthrough names are refused.
- Windows case-insensitive name handling, using a pure authored mapping.

## Native limits and required receipts

The three skips are existing Windows Job Object containment/cleanup and Ghidra
Windows path-length controls. No Java, Ghidra, Ghidriff or target binary was
executed by these independent controls.

The current live-backend workflow runs only on Windows. Its PatchTrace and raw
cache tools construct BackendConfig without an explicit restrict_env argument,
so a run on this candidate will exercise the new default. The workflow has no
separate authored secret/JAVA_TOOL_OPTIONS probe step or matching receipt.

The live-unified workflow performs a real primary Ghidriff comparison (L4) on
Linux and Windows, without --no-ghidriff. That provides an existing route for
some native compatibility evidence after exact-candidate execution, but does
not supply the historical Linux seeded-store/raw-cache matrix or the specified
native-job sentinel probe. The new authored child tests may supply child-env
evidence when actually run on each OS; they do not substitute for native engine
compatibility. Required native Linux/Windows receipts remain open.

Original coordinator red and intermediate failure receipts were read and left
unchanged. No remote mutation or publication operation was performed.
