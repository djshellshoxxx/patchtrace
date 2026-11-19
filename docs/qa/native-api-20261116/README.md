# Pinned native API controls — 2026-11-16

These receipts qualify repository-authored Linux Rizin API controls only. No
compared binary was executed. They do not qualify CLI JSON, Windows, real target
matching, release acceptance or removal of product singleton refusal.

Rizin source: `c3a90e9226d977f58f4e9c75f78fa6b07afe13c7` (v0.9.1).
Stock similarity source SHA-256:
`a0b196dbc39e4fb3df4f850e156482ba9668838ccf5bb99a25563fd7a8c7ee5a`.
Only `librz_arch.so.0.9.1` differs between stock and corrected snapshots.
Compiler: Debian GCC 14.2.0; glibc 2.41; nine online processors. Exact build
options, dependency heads and source hashes are retained in
`evidence/provision-summary.json`.

## Preserved attempts

- `evidence/`: original setup/build logs and every first-attempt receipt. Initial
  loader exit 127 came from omitted SONAME links and remains intact. A fresh
  snapshot fixed that provisioning defect. Matrix controls then behaved as
  expected; fixed two-worker IO expectations correctly rejected this nine-worker
  host. Those failures have not been rewritten as passes.
- `worker-evidence/`: fresh controls after the source-derived portability repair.
  Its `summary.json` pins the reviewed control and validator snapshots. Every IO
  row reports the native configured worker count, independently checked against
  `os.cpu_count()`. Per-mode provenance binds loaded-library hashes before and
  after execution, not only the executable hash.

| Fresh mode | Child exit | Observed outcome | Validator |
|---|---:|---|---|
| Stock matrix | 1 | Expected singleton ownership failures | Accepted red control |
| Stock IO | 1 | Expected singleton ownership failures | Accepted red control |
| Corrected matrix | 0 | No ownership errors | Accepted green control |
| Corrected IO | 0 | No ownership/similarity errors | Accepted green control |
| Corrected wrong bytes | 1 | Exact expected similarity errors | Accepted negative control |
| Corrected wrong IO | 1 | Exact expected IO/similarity errors | Accepted negative control |

The portability repair follows pinned `librz/util/thread_pool.c` and
`librz/arch/similarity.c`: all available workers are started; each singleton
worker reads its singleton before dequeuing work. Thus singleton reads are N,2
and wrong-IO reads N+2,0, while ordinary 2:1 reads remain 2,2 and 4,0. Missing,
invalid or disagreeing worker provenance fails closed. Error counts, inventories,
expected exits and stderr constraints were not relaxed.

Both artifact manifests were independently verified before copying: 70 original
entries and 47 fresh entries. Source snapshots retain their original notices;
Rizin's GPL/LGPL license texts are included under `rizin-license/`. These are
historical receipts: recorded absolute scratch paths identify the original run,
not paths that must exist on a reader's machine. Native binaries are not bundled.
