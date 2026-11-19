# PW-02 selected-basename ASCII repair

Original reviewed candidate and packet remain unchanged at
`c5027aff98e02844e45902d76e87981962b770bb`. Follow-up spec/tests:
`8ef778545df4f1e8360c8003f57caf20125351c1`. Corrected production:
`645839646a68815ee1822ee61039af42d583903a`, tree
`292de4a3cac5cf5503b2e8dbbf8595fe79efa431`.

Independent reviewer integration_inventory found that `str.lower()` converts
U+212A into ASCII k, allowing a Unicode member basename to match `kernel.dll`.
The existing contract allowed only ASCII case normalization for PE selection.
The correction checks the original selected basename with `isascii()` before
lowercasing and the existing acquisition-name validator. It changes four source
lines/adds no new dependency, native API, schema or service. Logical Unicode
inventory names and Unicode parent components remain supported; ordinary lower,
upper and mixed-case ASCII basenames continue to select.

## Evidence

| Phase | Actual result | Classification |
| --- | --- | --- |
| Original reviewer probe at c502 | 1 failure, 2 ASCII positives | Retained in the separate original independent packet. Not rerun or overwritten by this phase. |
| `red` | collection exit 2, one import-file mismatch; no assertion results | Author and unchanged external probe initially used the same Python module basename. The raw error, initial runner and initial author test bytes are preserved. |
| `red-assertions` | 2 failures, 9 positives, 0.48 s | Renamed only the new authored file to `test_package_ascii_admission.py`; its assertions are byte-identical. Both the authored Kelvin control and unchanged external Kelvin control reproduce before the source correction. |
| `final` | 284 passes, 1.09 s | Exact source 64583964: original 273 controls, eight new authored cases and the three unchanged external cases. No skips/xfails. |

Every invocation denies sockets and subprocess/fork/exec, pins imports to the
active worktree, uses an owned system temporary directory, and records zero
attempted denied operations. Normal full Ruff and schema `--check` also pass;
their exact commands/source and raw outputs are retained. No scanner, worker,
FDI, Windows API or target is run. Windows and frozen PW-02 acceptance remain
pending; these results concern the pure selected-name boundary.

The original independent probe is retained byte-for-byte as `independent-probe.py`,
SHA-256 `a6940bb6a42a006192deeb62f9d66faf0cf57e170b26918e8e5beb78cfcdfcfd`.
The reviewer has been asked to replay their original probe and independent
controls against the exact corrected source before root integration. That
independent result is separate from the author's 284-pass run.

The first author packet remains SHA-256
`f739c4f81f7203e2d9332532c0334c796998308548b606eae164ee46acacd121`, including
the original 157 missing-API reds/110 registry positives and six subsequent
boundary failures. This follow-up does not rewrite any earlier receipt or claim.
