"""SPEC-31 S1 ProgramIR (`program-ir/1`): ingest of the extractor's untrusted JSON Lines into a read-only sidecar.

Pure Python (stdlib + the S0a contracts): strict streaming validation (`records`), operand typing and located
address fields (`operands`), normalised keys (`features`), the BinDiff-style MD index (`mdindex`), PE tables
(`pe_tables`), the sidecar schema and digest (`schema`), the driver (`ingest`), the columnar reader (`reader`) and
content-addressed placement (`place`). Formats and deviations: docs/specs/unified-engine/03-extraction.md s12.
"""
