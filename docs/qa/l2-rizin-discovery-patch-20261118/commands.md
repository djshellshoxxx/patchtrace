# Executed commands

All work was confined to `/workspace/scratch/e83fbf4505c3/l2-rizin-discovery-patch-20261118`.

```bash
/workspace/scratch/3a6632a6e5ff/venv/bin/python bounded_fetch.py https://musl.libc.org/releases/musl-1.2.4.tar.gz --host musl.libc.org --out source/musl-1.2.4.tar.gz --receipt receipts/musl-source-fetch.json --max-bytes 4194304
/workspace/scratch/3a6632a6e5ff/venv/bin/python build_musl.py
/workspace/scratch/3a6632a6e5ff/venv/bin/python build_cli.py
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/workspace/scratch/e83fbf4505c3/repair-receipt-identity/src:/workspace/scratch/e83fbf4505c3/repair-receipt-identity QT_QPA_PLATFORM=offscreen /workspace/scratch/3a6632a6e5ff/venv/bin/python run_authored_variants.py
```

The original Rizin source was copied only after its pinned SHA-256 matched. Exact complete-line replacements add the two seeding calls in the whole-functions branch; the unified patch is retained unchanged. Initial substring-match preparation refused before writing because it also matched more-indented graph-mode lines; the correction and absence of any graph-mode edit are recorded.

Safe musl extraction and SDK verification/copy are documented by `receipts/musl-safe-extraction.json` and `receipts/pinned-library-header-check.json`. The original SDK prefix was `/workspace/scratch/e83fbf4505c3/l2-tool-preparation/20261118T080830Z-rizin091/tool/rizin-0.9.1`; copied `include`, `lib` and `share` directories live under `vendor/rizin-0.9.1`. The SDK's original release archive and every used file have retained SHA-256 identities.

The build scripts record the expanded configure, make, compiler and linker command arrays without shell substitution. Native receipts record each argv and input/executable digest. Normalization runs only after raw archive/rebuild comparison passes. Original pilot analysis is never invoked.
