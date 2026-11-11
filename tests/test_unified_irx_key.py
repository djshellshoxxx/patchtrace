"""irx audit: ingest changes that alter IR content for the same extractor output move `ir_key`."""
from __future__ import annotations

from unified_extract_builder import SHA, document_set, function, header, pe_view, write_jsonl

from patchtrace.unified import extract, keys
from patchtrace.unified.extract import runner
from patchtrace.unified.ir import schema
from patchtrace.unified.ir.ingest import ExpectedSide, ingest, ingest_identity_digest, ir_key_inputs
from patchtrace.unified.ir.records import parse_header
from patchtrace.unified.limits import DEFAULT_LIMITS


def test_ir_key_input_carries_the_ingest_revision():
    assert schema.INGEST_REVISION >= 2
    assert ingest_identity_digest() != keys.ingest_limits_digest()           # the pre-audit value
    inputs = ir_key_inputs(parse_header(header(), SHA), DEFAULT_LIMITS)
    assert inputs.ingest_limits_digest == ingest_identity_digest()


def test_a_revision_bump_changes_the_key_of_the_same_extractor_output(tmp_path, monkeypatch):
    path = write_jsonl(tmp_path / 'ir.jsonl', document_set(function(0x1000, [('mov',), ('ret',)], name='f')))
    keys_seen = []
    for revision in (schema.INGEST_REVISION, schema.INGEST_REVISION + 1):
        monkeypatch.setattr(schema, 'INGEST_REVISION', revision)
        out = tmp_path / f'out{revision}'
        out.mkdir()
        keys_seen.append(ingest(path, ExpectedSide('older', SHA, pe_view(), mode='analyze'), out_dir=out)
                         .manifest.ir_key)
    assert keys_seen[0] != keys_seen[1]


def test_the_runner_predicts_the_key_the_ingest_produces():
    assert extract.INGEST_REVISION == schema.INGEST_REVISION
    assert runner.ingest_identity_digest(DEFAULT_LIMITS) == ingest_identity_digest(DEFAULT_LIMITS)
