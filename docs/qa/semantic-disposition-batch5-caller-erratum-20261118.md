# Batch-five caller erratum

Root review identified a factual caller error in the original sealed batch-five ledger. At exact comparison source `55f3d0742f7d4cf32357a42b8b1cc76d85875e71`, `factory.run_mutation` calls:

```python
M.apply_case(files, operator, seed=seed, base=ref, tools=session.tools)
```

The call supplies no `extra_check`. `make_masked_body_check` is an exported optional developer API documented for `apply_case(extra_check=...)`; the exact tracked-Python reference search found only its definition/export outside tests. The authored COFF fake-producer probe calls the optional API directly. Its observed unquoted-symbol defect and passing neighbors remain valid at that boundary. It does not establish that the normal factory or CLI installs the check.

The corrected ledger sections 3, 5 and 6, machine-readable descriptions and matching generated summaries now state that boundary. No source behavior, original test bytes, result, disposition count or frozen comparison changed. The sealed commit `82d4ea017cd936b793dd8adfd50343a05df5629a` and archive SHA256 `e6b63e2b7f39b85bb18790761fe8ff8ce11f65fdc82626590bf2c67cc1f02b16` remain unchanged; this is a separately attributed correction. The immutable external packet was not regenerated.

[Exact-source proof](semantic-disposition-batch5-caller-erratum-20261118.json) records source Git blobs, SHA256, the AST-verified call arguments and complete tracked-Python reference matches. Factory SHA256: `f854363a3e70f629c43fd5da2db4cfb3f047133407f5ffc3b87faa24aba6e1c7`. Engine SHA256: `7f968cd5f64b3d5b7d9d7969744833a83b412fa75af6d57245d5a459ab443d01`. This narrow documentation check ran no compiler, target, network, native engine or pytest gate.
