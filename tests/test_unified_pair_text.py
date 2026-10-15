"""SPEC-31 U6: code text for unified rows that no Ghidriff match carries, read from the stored ProgramIR (`ins.txt`).
The project, the hand-assembled functions and the sidecars are the synthetic ones of the wiring tests; the real pipeline
publishes the result, so the view model, the sidecar directories and the rows are the product's own."""
from __future__ import annotations

import dataclasses

import pytest
from unified_s0_fixtures import make_project
from unified_wire_support import place_pair

from patchtrace.unified import pair_text, pipeline
from patchtrace.unified.pipeline import UnifiedOptions
from patchtrace.unified.read_model import load_unified, request_from_service


@pytest.fixture
def world(tmp_path):
    service = make_project(tmp_path / 'project')
    place_pair(service, scratch=tmp_path)
    pipeline.run_unified(service, UnifiedOptions(isolate=False))
    vm = load_unified(request_from_service(service, extraction_configured=True))
    yield service, vm
    service.close()


def row_named(vm, name):
    return next(r for r in vm.rows if name in r.function_label)


def test_the_view_model_knows_the_result_directory(world):
    _, vm = world
    assert vm.result_dir is not None and vm.result_dir.name == vm.result_id[:16]


def test_a_changed_pair_reads_both_sides_from_the_stored_disassembly(world):
    _, vm = world
    provider = pair_text.IrPairTexts()
    try:
        older, newer, label = provider(vm, row_named(vm, 'get_version'))
    finally:
        provider.close()
    assert older != newer and older.count('\n') >= 4 and newer.count('\n') >= 4
    first = older.splitlines()[0]
    assert first[:8].strip('0123456789abcdef') == '' and 'mov' in first.lower()
    assert 'ProgramIR' in label and 'decompiled code unavailable' in label and 'Ghidra' in label


def test_a_one_sided_row_shows_its_side_and_says_the_other_has_no_function(world):
    _, vm = world
    provider = pair_text.IrPairTexts()
    try:
        older, newer, _ = provider(vm, row_named(vm, 'debug_dump'))
    finally:
        provider.close()
    assert 'mov' in older.lower() and newer == pair_text.NO_FUNCTION


def test_without_a_placed_programir_the_provider_has_nothing(world, tmp_path):
    _, vm = world
    manifest = vm.manifest.model_copy(update={'ir_older': None, 'ir_newer': None})
    bare = dataclasses.replace(vm, manifest=manifest)
    provider = pair_text.IrPairTexts()
    assert provider(bare, bare.rows[0]) is None
    assert provider(dataclasses.replace(vm, result_dir=None), vm.rows[0]) is None
    provider.close()


def test_a_function_missing_from_the_ir_is_unavailable_never_invented(world, monkeypatch):
    _, vm = world
    provider = pair_text.IrPairTexts()
    try:
        monkeypatch.setattr(pair_text, 'MAX_LINES', 3)
        older, _, _ = provider(vm, row_named(vm, 'get_version'))
        assert older.splitlines()[-1].startswith('... ') and len(older.splitlines()) == 4
        monkeypatch.setattr(pair_text.IrReader, 'texts', lambda self, fid: [])
        older, _, _ = provider(vm, row_named(vm, 'get_version'))
        assert older.startswith('Disassembly text is not stored')
    finally:
        provider.close()


def test_readers_are_cached_per_ir_key_and_closed(world):
    _, vm = world
    provider = pair_text.IrPairTexts()
    provider(vm, row_named(vm, 'get_version'))
    provider(vm, row_named(vm, 'keep_same'))
    assert len(provider._readers) == 2
    provider.close()
    assert not provider._readers
