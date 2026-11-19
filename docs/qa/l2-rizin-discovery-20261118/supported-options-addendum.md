# Supported-option check — separate addendum

This source-only check supplements the sealed Rizin discovery diagnosis. It does not modify that report, its ZIP, the first pilot, any oracle, or any scorer. No native analysis, candidate rerun, target acquisition, or target execution occurred in this addendum.

**Conclusion:** no verified direct initialization option was found that restores the missing symbol/entry pass while preserving `rz-diff -t functions` matching. A separately qualified upstream/native patch and newly pinned build remains the supported repair proposal for deterministic initial seeding. There is a documented conditional event hook, described below; claiming that no configuration could ever run analysis would be too strong.

## Inspected routes

All source is from Rizin commit `c3a90e9226d977f58f4e9c75f78fa6b07afe13c7`. The earlier captured native help and `rz-diff.c` were read without changing the sealed evidence.

| Route | Pinned implementation | Consequence |
| --- | --- | --- |
| `-B` | Sets `analyze_all`; the functions branch already calls `analysis_everything` unconditionally. The conditional branches also call that deeper routine directly. | Does not add the missing `analysis_all` symbol/entry pass. Help's shorthand about `aaa` does not match the complete automatic-analysis wrapper. |
| `-A` | Sets `compare_addresses`. | This is not the Rizin executable's automatic-analysis flag. |
| `-0` with `-t functions` | Evaluates a name/address, then looks up an already analyzed function in `core_diff_show`. | Selects a discovered function; does not initialize missing bodies. `-1` is rejected in this mode. |
| `-t command -0 ...` | Runs a Rizin command for each separately loaded core, then uses `rz_diff_lines_new` on the resulting text. | Can run `aa`/`aaa`, but changes the operation and output contract to a command-output line diff. It does not pre-initialize the two cores used by functions-mode matching. |
| `-t graphs` | Explicitly analyzes selected function addresses when the `-B` branch is not used. | A selected-function graph operation, not the existing whole-function match-set producer. |
| `-e cmd.open=...` or `-e cmd.load=...` | The `-e` configuration loop runs after `rz_core_file_open`, `rz_core_bin_load`, and architecture setup. | Too late to provide an initial-open/load hook for those operations. |
| `-e analysis.in`, `analysis.calls`, `analysis.hasnext`, etc. | Changes ranges, recursive-call traversal, or continuation heuristics. `cconfig.c` contains no call to `analysis_all`, `analysis_everything`, or the auto-analysis wrapper. | No explicit initial symbol-seeding contract. Heuristic coverage changes are not evidence of an equivalent initialization fix. |

The complete option parser has no functions-mode pre-command or script option. Combining multiple `-t` modes is not a supported way to preserve analysis state: the parser assigns one comparison type, and command-mode cores are freed after their text output is obtained.

## Conditional hook: real source support, no qualification

`cconfig.c` defines `cmd.fcn.new` as a command to run on function creation. `core.c` registers its handler and, at source lines 205–214, invokes `rz_core_cmd0` with that command after moving the current analysis address to the new function. Therefore a configured hook can issue analysis commands. This is a real documented configuration route, not an invented option.

It is not an established replacement for deterministic initial symbol seeding: it depends on another operation first discovering a function, and invoking `aa`/`aaa` inside it re-enters analysis. A naive persistent hook also retriggers on newly discovered functions. No pinned contract found here establishes once-only, complete, safe re-entrant initialization for arbitrary inputs. No hook recipe was executed or adopted. Testing a hook solely until the measured case improves would not qualify that contract.

The existing proposed repair remains an explicit `rz_core_analysis_all` pass before deeper functions-mode analysis, or an equivalent full wrapper preserving interruption/error handling. Building and qualifying that change is future work. The original native tool is unchanged.

## Separate naming contract

The authored executable control emits the literal name `sym.diag_changed`. The existing ranking preserves it and the scorer uses exact equality. Future engine-aware source-name comparison needs its own predeclared contract and independent tests. No labels, aliases, expected names, or measured results were patched here.

## Sources and preservation

- [Pinned `rz-diff.c`](https://github.com/rizinorg/rizin/blob/c3a90e9226d977f58f4e9c75f78fa6b07afe13c7/librz/main/rz-diff.c): help/parser, load order, command comparison, function selection, and analysis branches. SHA256 `d44bfe9d05da81ace0ce46eae8e69555c080719cebac3cb72d6686917ab1ea5b`; preserved in the sealed diagnosis.
- [Pinned `cconfig.c`](https://github.com/rizinorg/rizin/blob/c3a90e9226d977f58f4e9c75f78fa6b07afe13c7/librz/core/cconfig.c): SHA256 `91cbd802bd2e0e84a0dfdf720caba57ba49b1fdb64094e605605490742172f31`, 149,573 bytes; raw and bounded fetch receipt included here.
- [Pinned `core.c`](https://github.com/rizinorg/rizin/blob/c3a90e9226d977f58f4e9c75f78fa6b07afe13c7/librz/core/core.c): SHA256 `10e1caf0afbfe82714e2d2b84fd55ee940c99bfacebae5a49a57a6c4e996ee94`, 65,100 bytes; raw and bounded fetch receipt included here.
- Native help was copied byte-for-byte from the sealed preparation capture. All sources retain their licensing headers; the accompanying sealed diagnosis contains upstream COPYING and COPYING.LESSER.
- Original diagnosis ZIP remains SHA256 `1737440888508993969613d970787d7bdcf3db8f28d618c7c2b92fb477ff9fe3`. The first pilot remains MISS, with zero candidate reruns.
