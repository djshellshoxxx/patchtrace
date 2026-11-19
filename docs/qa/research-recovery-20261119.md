# Research runner recovery verification — November 19, 2026

## Source and scope

The five research modules and default R1 development fixture suite were recovered from
`2fdac2ea9042985ac3c98545d38ac3461d00f4cc`, including the receipt family merged by PR #145
and its later parent-anchoring correction. This port was developed against integration
checkpoint `7dfba50f32f40b53aa056b75e0eaad7e44d4c50a`. It retains the current factory,
build-receipt, primary project, production secondary scheduler and unified APIs.
It does not restore older versions of those shared modules.

The restored consumers are the explicit `research_build` and `research_pilot` module
entry points. The pilot consumes the audit/observer helpers; both commands use the
exclusive receipt helper. `docs/specs/research-pilot.md` defines usage, ownership,
bounds, scoring, failure behavior and the remaining qualification gates.

The port adds bounded source discovery and matrix admission, bounded ordinary-file
metadata/raw reads, strict exact-digest review keys, independent copied/opened artifact
hash checks, exclusive label publication, and post-write receipt identity/byte checks.
Raw function/edge budgets are checked before production normalization. Ordinary cleanup
and optional warm-cache failures retain completed results. Every owned unified side is
offered cleanup on cancellation; standalone cancellation still propagates and does not
claim a final CLI receipt. Existing historical evidence is preserved when publication
is refused.

## Frozen focused gate

Author result: **172 passed, 14 skipped in 4.54 seconds**. The skipped cases are native
Windows sharing/reparse/device-path controls on this Linux executor. The 186 collected
cases span the six test files below. The log and JUnit receipt are adjacent files named
`research-recovery-20261119.log` and `research-recovery-20261119.xml`.

```sh
python -m pytest -q \
  tests/test_tier_r_research_audit.py \
  tests/test_tier_r_research_observers.py \
  tests/test_tier_r_research_build.py \
  tests/test_tier_r_research_pilot.py \
  tests/test_tier_r_receipt_parent_race.py \
  tests/test_tier_r_research_recovery.py
```

Scoped Ruff validation passed for the five source modules and six test files. The
controls use real bounded readers and filesystem publication, with substituted native
engine/compiler seams. They establish no live compiler, Ghidra, rz-diff, unified-native
or Windows compatibility. No target binary was executed. Source fixtures and historical
notes are development material, not accepted held-out corpus truth or engine accuracy
evidence. Independent source review identified the normalizer admission ordering and
cleanup cancellation gaps; their new controls passed in the author gate. Independent
execution evidence, when available, must be recorded separately rather than added to
this test count.

## Exact source evidence

The following SHA-256 values bind the tested source, tests, fixture and specification.
The QA document/log/XML are outside this table to avoid a self-referential digest.

| Path | SHA-256 |
|---|---|
| `tools/calibration/tier_r/research_audit.py` | `e57bf6c40e9bc6d35cf60c490e658e9011b8c38753f8b4cadffdc8ec43e750b2` |
| `tools/calibration/tier_r/research_observers.py` | `d7fec05bd00a9f7d9644ca0c1a4d76ecb19dd2546306df1bdd298a7724a6000e` |
| `tools/calibration/tier_r/research_build.py` | `dc0f664ef3b363f58f08d07e2d222e31b6852690f2e73809b93925d78c47166f` |
| `tools/calibration/tier_r/research_pilot.py` | `7648790d72bf73111dbfb9d2d7e9f9670e817ffd28cb1fdb5afdb7dcf155d017` |
| `tools/calibration/tier_r/receipts.py` | `ae997017dcacbc03417055ff0476d7553c48ffa1a4a9d95db85293d9e81f8567` |
| `tests/test_tier_r_research_audit.py` | `b1b10218457c7d4ee4ab266fa3fa381f9328e29b05d47b1598db7985b0187a2d` |
| `tests/test_tier_r_research_observers.py` | `fce8545a37a95730a776399ec0fbf62906a798919c8be350c292c186642231ac` |
| `tests/test_tier_r_research_build.py` | `24c0f7279bde66e137b236cb462444cd0ca4b97ba6e78c00304402550c0f4500` |
| `tests/test_tier_r_research_pilot.py` | `c3d26f895835d1240ebf3ba6d46b51497f64c62f4a5e9107d15588c087f6dd01` |
| `tests/test_tier_r_receipt_parent_race.py` | `eb48b5265041e08544a78a4e7d4462b2b5b567d14f84b1d3771a92f83a6d8150` |
| `tests/test_tier_r_research_recovery.py` | `887adbd0b723aae850072e27ff408ef868da5519ab33c620a5d34528e384c329` |
| `docs/specs/research-pilot.md` | `02688d2219a42fe276ae01a925613bfe50e07935baf267b042df912f2b8990a4` |
| `corpus/ours/r1-pilot/defined/README.md` | `dc7b8545bfed28e59384fdb73b2a7239aa361456aab89640c6dd140514bfafd0` |
| `corpus/ours/r1-pilot/defined/suite.json` | `4a6f4ef6ad1aa12448191d3b16d1beebbc51dea0143168b4894758f4d5a01e13` |
| `corpus/ours/r1-pilot/defined/v1/r1.c` | `5f0468899fbc95fa4026c3c74b0731a5ab412fe017bbddbed00ad7b0d97acb5f` |
| `corpus/ours/r1-pilot/defined/v2/r1.c` | `34d8d9f2a1c83c58565ed1885df192c5550e55b9ebb1716d978f8f1c51db27b7` |
