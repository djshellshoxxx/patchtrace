# Generation 24 — isolated local advisory admission QA receipts

Date: 2026-11-20 UTC. Source code commit: `d44b658885635c8e55d6aa7872d03ccc4809ce1d`.
Current full tree at the code checkpoint: `efc4d34a587d9b24bff5a5660a6b3ab3d13ed2a0`.

1. Original bounded filesystem control, a POSIX FIFO with no writer:
   `timeout 0.4s python -c 'open(path, "rb").read(1)'` exited 124.
   This establishes a blocking Python primitive, not a complete
   repository-source test.
2. Held-descriptor primitive: `os.open(..., O_RDONLY|O_NONBLOCK)`
   returned; `stat.S_ISREG(os.fstat(fd).st_mode)` was false.
3. Five algorithm-copy controls passed locally: normal exact bytes,
   regular symlink, oversize refusal, directory refusal, FIFO refusal.
   They were run outside a PatchTrace checkout and are **not**
   source-pinned pytest, Qt, native or empirical accuracy evidence.
4. Five repository tests authored in
   `tests/test_kbc_advisory_source_admission_20261120.py`. **Unexecuted**.
5. `git ls-remote` from the container failed:
   `Could not resolve host: github.com`. `python -m ruff --version`
   reported no Ruff module. Thus full pytest/Ruff/schema/dependency
   and exact-source local tests were not accepted. Hosted CI must run
   from the published candidate.
6. PR332 predecessor had green Linux/Windows QA, Qt, native and Linux
   package with two smoke checks queued at inspection; PR333 had one
   unfinished Qt shard; PR334 had many queued checks. These do not
   qualify the new generation-24 source.

Keep the original unsplit `bffcfa99` SIGKILL, its two failure markers,
the 3,881-node diagnostic remainder, AF_UNIX EPERM and missing LLVM
toolchain limitations separate. The original ASM gate remains unchanged.
