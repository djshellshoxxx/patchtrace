# YARA-X Python bindings and permissive rule sources (research)

Status: research note, 2026-10-15, for the YRX rules plan (`docs/specs/program-e/YRX-integration-plan.md`) and SPEC-47 (`docs/specs/yara-x-rule-workflow.md`). No code. Every source below was fetched 2026-10-15 unless marked otherwise. `[U]` = not verified here. `[plan]` = measured by the YRX worker on 2026-10-14 (not re-run today).

## Versions and wheels

- Latest PyPI release is `yara-x` 1.21.0, uploaded 2026-09-29T08:16 UTC. Requires Python `>=3.9`. Accessed 2026-10-15: https://pypi.org/pypi/yara-x/1.21.0/json and https://pypi.org/pypi/yara-x/json (latest field = 1.21.0).
- 10 wheels, no sdist, all `cp38-abi3` (CPython) or `pp311` (PyPy). Windows: `yara_x-1.21.0-cp38-abi3-win_amd64.whl` (8,338,610 B). Linux: `manylinux_2_28_x86_64` (9,624,829 B) and `manylinux_2_28_aarch64`. macOS: `macosx_14_0_arm64` and `macosx_14_0_x86_64`. No musllinux wheel, so Alpine is unsupported. Same URL as above. Confirmed for 1.21.0 today.
- Release history: 1.21.0 (29 Sep), 1.20.0 (24 Aug), 1.19.0 (24 Jun), 1.18.0 (15 Jun), 1.17.0 (28 May), 1.16.0 (6 May), 1.15.0 (13 Apr), 1.14.0 (6 Mar). The GitHub page gives month and day only, so the years are inferred from the 1.21.0 PyPI date. Accessed 2026-10-15: https://github.com/VirusTotal/yara-x/releases. Cadence is roughly monthly to bi-monthly.
- Licence: BSD-3-Clause. The LICENSE file reads "Copyright (c) 2024. The YARA-X Authors. All Rights Reserved." with the usual three clauses. PyPI metadata has `license: null` and only the classifier "License :: OSI Approved :: BSD License", so the wheel metadata is thin. Accessed 2026-10-15: https://raw.githubusercontent.com/VirusTotal/yara-x/main/LICENSE.
- Rust crate notices: the plan's measurement of the wheel SBOM (303 crates, all permissive, `r-efi` tri-licensed) is `[plan]`, taken from `yara_x-1.21.0.dist-info/sboms/yara-x-py.cyclonedx.json` on 2026-10-14. It was not re-downloaded today. Per-crate licence texts are not in the wheel, which the plan already records as an open item.

## API and limits

Compiler constructor (1.21.0 tag source, `py/src/lib.rs`). Accessed 2026-10-15: https://raw.githubusercontent.com/VirusTotal/yara-x/v1.21.0/py/src/lib.rs
- `Compiler(relaxed_re_syntax=False, error_on_slow_pattern=False, includes_enabled=True, ignore_invalid_rules=False)`. The four parameters match the plan's wheel introspection.
- The upstream main-branch API doc lists only `relaxed_re_syntax` in the constructor and documents `enable_includes(bool)` as a method. Accessed 2026-10-15: https://raw.githubusercontent.com/VirusTotal/yara-x/main/site/content/docs/api/python.md. The doc is stale for the constructor, and the naming of the includes switch differs between doc and binding `[U]`.
- Compiler methods documented: `add_source(string, origin=None)`, `add_include_dir`, `define_global`, `max_warnings(n)` (since 1.16.0), `new_namespace`, `allowed_metadata(..., error=False)`, `allowed_rule_name`, `allowed_tags`, `allowed_tags_regex`, `errors()`, `warnings()`, `build()`. `build()` resets the compiler, so read `warnings()` first `[plan]`.
- `Scanner`: the tag source shows the constructor is `Scanner(rules)` and `set_timeout(seconds: u64)`. The timeout takes whole seconds only, so no sub-second timeout is possible. `max_matches_per_pattern(usize)` exists in the source but has no reference entry in the docs. `fast_scan(bool)` is documented, and fast scan was added in 1.17.0 (releases page above). Accessed 2026-10-15: the same lib.rs URL and the main-branch API doc above.
- `scan(bytes)`, `scan_file(path)`, `set_module_output`, `set_global`. `scan_file` memory-maps large files `[plan]`.
- Exceptions: `CompileError`, `ScanError`, `TimeoutError` (raised by scan methods). A Rust panic surfaces as `PanicException`, a `BaseException` subclass `[plan]`.
- Memory: the Python API has no memory limit or memory-usage option. The docs have no memory section. Memory must be capped outside the library (RLIMIT_AS or a Job Object) `[plan]`.
- GIL: `Scanner.scan` and `Scanner.scan_file` do not release the GIL (no `allow_threads`/`detach`). `Compiler`, `Scanner`, `Formatter` and `RulesIter` are `#[pyclass(unsendable)]`, and the module forces `gil_used(true)`. Verified in the 1.21.0 source today, which also confirms the plan's GIL measurement claim.
- Modules in the wheel and their availability: see the plan's Section 2 `[plan]`.

## Gotchas

- Timeouts are whole seconds and apply to the whole scan. There is no per-rule or per-pattern timeout in Python `[U]` (no such method in the doc or source).
- Performance: the upstream comparison claims YARA-X is faster, with a 200 MB regex/hex example going from over 20 s (YARA) to under 1 s (YARA-X). Accessed 2026-10-15: https://raw.githubusercontent.com/VirusTotal/yara-x/main/site/content/docs/intro/yara_vs_yara-x.md. The claims are vendor-reported and not reproduced here.
- Slow patterns: upstream warns on `slow_pattern` (E018/warning) for `{ 00 [1-10] 01 }`, and on `potentially_slow_loop` for loops bounded by `filesize`, plus `too_many_iterations`. Accessed 2026-10-15: https://raw.githubusercontent.com/VirusTotal/yara-x/main/site/content/docs/errors_and_warnings/warnings.md. The plan measured that `slow_pattern` does not fire for `{ ?? ?? ?? ?? }` or short wildcard-heavy patterns, so it is not a sufficient gate `[plan]`. Use `error_on_slow_pattern=True` plus our own literal-byte metrics.
- Panics and memory history (release notes, accessed 2026-10-15): 1.16 panic on bad reader input in the Python API; 1.17 out-of-memory in the `dex` module; 1.19 undefined behaviour deserialising untrusted rules (so never `deserialize_from` untrusted data); 1.20 panics on oversized regexes and float comparisons with `filesize`, and Teddy matching now respects timeouts. The plan's 1.12-1.13 use-after-free claim was not re-verified `[U]`.
- Python API stability: the upstream API doc is out of step with the binding (constructor parameters, `max_matches_per_pattern` undocumented). Pin the version and test the constructor surface in CI.
- Language differences from classic YARA (upstream, accessed 2026-10-15): YARA-X is not API-compatible with YARA for C, Python or Go; process scanning is not implemented (static only). Syntax and regex details are in the plan `[plan]` (escaping of `{`, base64 minimum length, `of` with boolean tuples, one modifier per kind).
- Modules: upstream says `magic` is not supported; rules that depend on an unsupported module are skipped with `ignored_rule`, which is a silent miss unless read as a warning `[U]`.

## Rule sources and licences

All accessed 2026-10-15.

| Source | Licence (primary text) | Use for us | Limits |
|---|---|---|---|
| Neo23x0/signature-base (Florian Roth) | Detection Rule License (DRL) 1.1 since 2021-08-13 (repo LICENSE, README). Earlier versions were CC BY-NC (v2.0 tag). Per-rule exceptions: "except the YARA rules that explicitly indicate a different license" (README) | Permissive for use, modification, redistribution and sale, provided we keep author identification, a link to the rule set, and a DRL notice. Matches reported from these rules must keep the author field | Check each rule's own `license` metadata before import, as some rules carry other licences. Old CC BY-NC snapshots must not be used. Sources: https://raw.githubusercontent.com/Neo23x0/signature-base/master/LICENSE, https://raw.githubusercontent.com/Neo23x0/signature-base/master/README.md |
| ReversingLabs open-source YARA (github.com/reversinglabs/reversinglabs-yara-rules) | MIT per README (read from the GitHub repo page, which shows no rule count or commit date) | Permissive; keep the copyright notice | Rule count and last-commit date not confirmed `[U]`. Source: https://github.com/reversinglabs/reversinglabs-yara-rules |
| Bartblaze/Yara-rules | MIT (copyright 2020, Bart) | Permissive; keep the copyright and permission notice | Attribution required; no version number in the licence. Source: https://raw.githubusercontent.com/bartblaze/Yara-rules/master/LICENSE |
| Malpedia signator-rules | CC BY-SA 4.0 (README: "allowing commercial usage") | Usable, but ShareAlike: derived rule files must be released under CC BY-SA 4.0 | Copyleft-like obligation on the rule files; a bundled rule file would need its own licence notice. Source: https://raw.githubusercontent.com/malpedia/signator-rules/master/README.md |
| yara-rules/rules (community) | "Our Yara ruleset is under the GNU-GPLv2 license" (README) | Only as a GPL-2.0 dependency, not bundled into a permissively licensed binary | Copyleft; the README says the mobile_malware rules were deprecated because Androguard was abandoned. Source: https://raw.githubusercontent.com/yara-rules/rules/master/README.md |
| Elastic protections-artifacts | Elastic License 2.0 (LICENSE.txt, title "Elastic License 2.0") | Do not bundle. Not open source | Forbids providing the software as a hosted or managed service, and circumventing license-key functionality. Source: https://raw.githubusercontent.com/elastic/protections-artifacts/main/LICENSE.txt |

Redistribution notes for PatchTrace (our reading, not legal advice):
- Shipping rules inside the Windows alpha is a redistribution. Use DRL, MIT rule sets only, with the notices included.
- Our generated rules (SPEC-47) are derived from the analyst's own binaries, not from these sources, so the SPEC-47 origin header applies to them, not these licences.
- Rule-set provenance (the rule's own licence metadata) must be copied into the notices file before any import.

## Corrections to our plan

- Verified and unchanged: yara-x 1.21.0 is latest and was uploaded 2026-09-29; 10 wheels with no sdist and no musllinux; BSD-3-Clause; Compiler's four constructor parameters; `scan` does not release the GIL; the four unsendable classes; `gil_used(true)`.
- Clarification to `docs/specs/program-e/YRX-integration-plan.md` Section 2: the API doc lists the includes switch as a method, not as a constructor argument. The constructor parameter `includes_enabled` is confirmed in the 1.21.0 source. Either way the spec must use the source names.
- Clarification: `set_timeout` takes whole seconds (`u64`). Any spec wording that implies sub-second timeouts must change.
- Addition: the plan has no rule-source licence section. SPEC-47 Section 2 (Traps) should add the DRL per-rule exception and the ShareAlike/GPL/ELv2 exclusions above.
- Addition: the Python API has no memory cap, so the R-08 memory limit is an external control, not a library feature. The plan already says this; the new text is that the upstream doc confirms it.
- Not re-verified: the `scan_file` memory-map and SIGBUS claim (plan cites `docs/cli/commands.md`), E035/E044/E045 limits, the `pe.offset_to_rva` absence, and the plan's iced-x86 and capstone measurements `[plan]`.

## Open questions

1. Confirm the Compiler includes-switch name against the 1.21.0 wheel's `.pyi` or `__init__` (doc says `enable_includes`, binding says `includes_enabled`) `[U]`.
2. Confirm `max_matches_per_pattern` signature and whether the 1.21.0 binding has `fast_scan` `[U]` (source shows both).
3. Get the ReversingLabs rule count, last commit, and a per-file licence check before any import `[U]`.
4. Audit the signature-base per-rule `license` metadata, and decide whether to import any rules at all (the plan currently treats rule sets as out of scope for bundling).
5. Confirm whether the Windows wheel imports cleanly on a clean Windows 10/11 machine without the MSVC runtime, and what Windows Defender does with `yara_x.pyd` (plan lists this as an owner-machine gate) `[U]`.
6. Decide the CI pin policy for a monthly yara-x release cadence (the plan pins 1.21.0 exactly; SPEC-47 R-18).
