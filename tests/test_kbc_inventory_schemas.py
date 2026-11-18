"""PW-01 generated examples preserve raw-row provenance and each record's own contract.

All source bytes and future-dated receipt data are authored synthetic examples.
No network, external source compatibility or verified binary identity is exercised.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import socket
import sqlite3
from pathlib import Path

import pytest
from pydantic import ValidationError

from patchtrace.kbcorrelation import inventory_contracts, inventory_selection, inventory_store
from patchtrace.kbcorrelation.contracts import InventoryClaimRef, Record
from patchtrace.kbcorrelation.inventory_csv import parse_inventory, parse_inventory_page
from patchtrace.kbcorrelation.sources.inventory_fetch import build_plan
from patchtrace.kbcorrelation.sources.support_links import extract_links

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'docs' / 'schemas' / 'kbcorrelation'


def _generator():
    spec = importlib.util.spec_from_file_location('generate_kbc_schemas', ROOT / 'tools' / 'generate_kbc_schemas.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


GEN = _generator()
MODELS = GEN.inventory_models()


def _examples():
    return json.loads((OUT / 'inventory-examples.json').read_text(encoding='utf-8'))


def test_all_public_inventory_records_have_schemas_and_examples():
    public = {name: model for module in (inventory_contracts, inventory_store, inventory_selection)
              for name, model in vars(module).items()
              if isinstance(model, type) and issubclass(model, Record) and model.__module__ == module.__name__}
    assert MODELS == public | {'InventoryClaimRef': InventoryClaimRef}
    assert set(_examples()) == set(MODELS) == set(GEN.valid_inventory_records())
    assert not set(MODELS) & set(GEN.CONTRACTS)
    assert {name: model.model_fields['contract'].default for name, model in MODELS.items()
            if 'contract' in model.model_fields} == {
                'CsvInventory': 'kb-file-inventory/1', 'InventoryImport': 'kb-inventory-import/1',
                'SupportImport': 'kb-support-import/1', 'CsvInventoryPage': 'kb-file-inventory/2'}


@pytest.mark.parametrize('name', MODELS)
def test_inventory_examples_validate_as_labelled_and_round_trip(name):
    examples = _examples()[name]
    model = MODELS[name]
    record = model.model_validate_json(json.dumps(examples['valid']))
    assert model.model_validate_json(record.model_dump_json()) == record
    assert record == GEN.valid_inventory_records()[name]
    assert examples['invalid']
    for invalid in examples['invalid']:
        assert invalid['reason']
        with pytest.raises(ValidationError):
            model.model_validate_json(json.dumps(invalid['example']))


def test_inventory_example_replays_exact_raw_bytes_and_multiline_claim():
    records = GEN.valid_inventory_records()
    imported = records['InventoryImport']
    parsed = parse_inventory(GEN.INVENTORY_CSV, records['InventoryContext'], limits=records['InventoryLimits'])
    assert parsed == imported.parsed == records['CsvInventory']
    assert parsed.raw_sha256 == hashlib.sha256(GEN.INVENTORY_CSV).hexdigest() == imported.source.sha256
    assert parsed.raw_size == len(GEN.INVENTORY_CSV) == imported.source.size
    assert (parsed.accepted_count, parsed.rejected_count, parsed.status) == (2, 0, 'partial')
    assert records['CsvDiagnostic'].code == 'INVALID_SIZE'
    assert parsed.entries[1].size_bytes is None
    entry, claim, selection = records['InventoryEntry'], records['InventoryClaimRef'], records['InventorySelection']
    assert entry.reference.logical_record == 3
    assert (entry.reference.line_start, entry.reference.line_end) == (3, 4)
    assert entry.date_text == '2099-03-\r\n01'
    assert claim.import_id == selection.import_id == imported.import_id
    assert claim.entry_id == selection.entry_id == entry.entry_id
    assert claim.model_dump(exclude={'import_id', 'entry_id'}) == entry.reference.model_dump()
    assert selection.scope_id == parsed.context.product_scope_id
    assert entry.state == 'metadata-only'
    assert not {'sha256', 'binary_sha256', 'cve'} & set(type(entry).model_fields)


def test_inventory_page_example_keeps_an_off_page_conflict_witness_and_versioned_tsp_state():
    records = GEN.valid_inventory_records()
    page = records['CsvInventoryPage']
    replay = parse_inventory_page(GEN.INVENTORY_PAGE_CSV, page.context, records['InventoryRetention'],
                                  limits=page.limits)
    assert replay == page and page.scan_complete
    assert (page.matching_count, page.excluded_count, page.omitted_count) == (3, 1, 1)
    assert [entry.reference.logical_record for entry in page.entries] == [3, 4]
    witness = records['InventoryConflictWitness']
    assert page.conflict_witnesses == (witness,)
    assert (witness.first.logical_record, witness.second.logical_record) == (3, 5)
    assert page.entries[0].state == 'conflicted'
    assert records['InventoryPageEntry'].state == page.entries[1].state == 'metadata-only'


@pytest.mark.parametrize('name', ['InventoryImport', 'SupportImport'])
def test_local_examples_keep_unverified_local_provenance(name):
    record = GEN.valid_inventory_records()[name]
    assert record.source.origin == 'local-import'
    assert record.source.uri is None and record.retrieval is None
    assert record.source.authenticity == 'unverified-local-file'
    assert record.source.lineage == 'analyst'
    if name == 'InventoryImport':
        assert record.asserted_source.startswith('https://example.invalid/')
    else:
        assert record.source.sha256 == hashlib.sha256(GEN.SUPPORT_HTML).hexdigest()
        links = extract_links(GEN.SUPPORT_HTML, page_url=record.page_url)
        assert len(links.links) == 1 and links.links[0].accepted
        assert links.authenticity == 'unverified-local-file'


def test_synthetic_receipt_binds_exact_urls_and_does_not_promote_local_import():
    records = GEN.valid_inventory_records()
    receipt = records['RetrievalProvenance']
    plan = build_plan(receipt.original_url, kind=receipt.kind, redirects=receipt.redirect_chain[1:])
    assert receipt.plan_sha == plan.plan_sha
    assert receipt.redirect_chain == plan.urls
    assert receipt.sha256 == hashlib.sha256(GEN.INVENTORY_CSV).hexdigest()
    assert receipt.size == len(GEN.INVENTORY_CSV)
    assert receipt.retrieved_at == GEN.STAMP
    assert records['InventoryImport'].retrieval is None


def test_render_and_check_need_no_network_or_workspace(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail('schema generation must not connect or create a workspace')

    monkeypatch.setattr(socket, 'socket', forbidden)
    monkeypatch.setattr(socket, 'getaddrinfo', forbidden)
    monkeypatch.setattr(sqlite3, 'connect', forbidden)
    monkeypatch.setattr(inventory_store, 'WorkspaceStore', forbidden)
    assert GEN.render() == GEN.render()
    assert GEN.main(['--check']) == 0
