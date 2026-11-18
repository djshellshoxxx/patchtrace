"""PW-01 analyst selection, bound to raw claims and the recorded investigation scope.

No inventory metadata is a binary identity or a CVE-fix claim. The existing
file-index/pair workflow receives only explicitly selected eligible basenames.
"""
from __future__ import annotations

import json
import re
import sqlite3
import time

from pydantic import ValidationError

from .alias_catalog import CLIENT_VERSION_PATTERN
from .contracts import AnalystDecision, ComponentHint, InventoryClaimRef, Record, Sha256, domain_id
from .errors import KbcIssue
from .inventory_contracts import CsvInventoryPage
from .inventory_store import get_inventory
from .products import derive, normal_name
from .sources.cvrf import SourceError, load_json
from .store import KbcStoreError
from .workflow import Event, reduce

MAX_SELECTIONS = 5_000
MAX_SELECTION_BODY_BYTES = 8_192
SELECTION_OP = 'inventory-select'


class InventorySelection(Record):
    import_id: Sha256
    entry_id: Sha256
    scope_id: Sha256
    coverage_sha256: Sha256
    asserted_scope: bool


def _check(cancel=None, deadline=None):
    if cancel is not None and cancel.is_set():
        raise KbcStoreError('PT-KBC-CANCEL', 'inventory selection was cancelled')
    if deadline is not None and time.monotonic() > deadline:
        raise KbcStoreError('PT-KBC-LIMIT', 'inventory selection replay exceeded its time budget')


def _coverage(rev, scope_id):
    return domain_id('kbc.inventory-selection-scope', 1, {
        'lead': rev.lead.model_dump(mode='json'), 'scope_id': scope_id,
        'coverage_ids': list(rev.coverage_ids),
    })


def _decisions(ws, investigation):
    # All writers use canonical model_dump_json. Restrict allocation before JSON
    # decoding, including multibyte and NUL-containing TEXT. Non-TEXT rows
    # cannot be trusted to identify their operation and must not silently vanish.
    selections = []
    try:
        rows = ws.db.execute(
            "SELECT CASE WHEN typeof(body)='text' AND length(CAST(body AS BLOB))<=? THEN body END "
            'FROM decisions WHERE investigation_id=? '
            "AND (typeof(body)!='text' OR instr(body, ?) > 0) ORDER BY seq LIMIT ?",
            (MAX_SELECTION_BODY_BYTES, investigation, '"op":"inventory-select"', MAX_SELECTIONS + 1))
        for (body,) in rows:
            if type(body) is not str:
                raise KbcStoreError('PT-KBC-VERIFY', 'a stored inventory selection is invalid or exceeds its bounds')
            try:
                decision = AnalystDecision.model_validate_json(body)
                if decision.op != SELECTION_OP:
                    continue
                value = load_json(decision.next.encode('utf-8'))
                selected = InventorySelection.model_validate_json(json.dumps(value))
            except (ValidationError, SourceError, ValueError, RecursionError):
                raise KbcStoreError('PT-KBC-VERIFY', 'a stored inventory selection is invalid') from None
            selections.append(selected)
    except (sqlite3.Error, UnicodeError):
        raise KbcStoreError('PT-KBC-VERIFY', 'stored inventory selections could not be read safely') from None
    if len(selections) > MAX_SELECTIONS:
        raise KbcStoreError('PT-KBC-LIMIT', 'this investigation exceeds the inventory selection limit')
    return tuple(selections)


def _product_agrees(entry, scope, *, asserted):
    if entry.product is None or normal_name(entry.product) == normal_name(scope.display_name):
        return
    facts = derive(entry.product)
    # The shared derived key requires a release. An explicit client generation
    # remains known even when the CSV omits that release and therefore the key.
    actual_versions = set(re.findall(CLIENT_VERSION_PATTERN, normal_name(entry.product)))
    expected_versions = set(re.findall(CLIENT_VERSION_PATTERN, normal_name(scope.display_name)))
    if (len(actual_versions) > 1 or len(expected_versions) > 1 or
            actual_versions and expected_versions and actual_versions != expected_versions):
        raise KbcStoreError('PT-KBC-INPUT', 'the inventory Windows generation contradicts the selected product scope')
    for attr, unknown in (('family', 'unknown'), ('architecture', 'unknown'),
                          ('release', None), ('channel', None), ('edition', None), ('winbindex_key', None)):
        actual, expected = getattr(facts, attr), getattr(scope, attr)
        if actual != unknown and expected != unknown and actual != expected:
            raise KbcStoreError('PT-KBC-INPUT', 'the inventory product contradicts the selected product scope')
    if facts.conflicts or not asserted:
        raise KbcStoreError('PT-KBC-INPUT', 'the product label needs an explicit analyst scope assertion')


def _eligible(record, entry, scope, kb_builds, *, asserted):
    if isinstance(record.parsed, CsvInventoryPage) and not record.parsed.scan_complete:
        raise KbcStoreError('PT-KBC-LIMIT', 'this source page has an incomplete scan; unseen rows may contradict it')
    if record.parsed.context.kb not in kb_builds:
        raise KbcStoreError('PT-KBC-SCOPE', 'the inventory KB is outside this lead and its recorded search scope')
    claimed_scope = record.parsed.context.product_scope_id
    if claimed_scope is not None and claimed_scope != scope.scope_id:
        raise KbcStoreError('PT-KBC-INPUT', 'the inventory is bound to a different product scope')
    if claimed_scope is None and not asserted:
        raise KbcStoreError('PT-KBC-INPUT', 'confirm the analyst scope assertion for this unmapped inventory')
    if scope.architecture != 'amd64' or scope.mapping == 'conflicted':
        raise KbcStoreError('PT-KBC-UNSUPPORTED', 'selection requires an unconflicted AMD64 product scope')
    if entry.architecture != 'amd64':
        raise KbcStoreError('PT-KBC-UNSUPPORTED', 'the current analyzer requires an AMD64 inventory entry')
    if entry.basename is None or entry.state in ('conflicted', 'descriptive-only') or entry.version_components is None:
        raise KbcStoreError('PT-KBC-INPUT', 'select an eligible PE basename with a known version and no conflict')
    _product_agrees(entry, scope, asserted=asserted)
    builds = set(kb_builds[record.parsed.context.kb])
    if scope.build is not None:
        builds.add(normal_name(scope.build))
    if len(builds) > 1:
        raise KbcStoreError('PT-KBC-INPUT', 'recorded advisory builds conflict; resolve the source scope before selection')
    fixed_build = next(iter(builds), None)
    for actual, expected, label in ((entry.release, scope.release, 'release'),
                                    (entry.build, fixed_build, 'build')):
        if actual is not None and expected is not None and normal_name(actual) != normal_name(expected):
            raise KbcStoreError('PT-KBC-INPUT', f'the inventory {label} contradicts the selected product or KB')
        if actual is not None and expected is None and not asserted:
            raise KbcStoreError('PT-KBC-INPUT', f'the inventory {label} needs an explicit analyst scope assertion')


def _scope(svc, ws, rev, scope_id):
    from .cli_index import load_index

    if scope_id not in rev.scope_ids:
        raise KbcStoreError('PT-KBC-INPUT', 'that product is not listed for the recorded lead')
    index, _ = load_index(ws, svc.ports)
    scope = next((item for item in index.scopes() if item.scope_id == scope_id), None)
    if scope is None:
        raise KbcStoreError('PT-KBC-INPUT', 'repeat the search; the selected product mapping is no longer available')
    scoped = rev.model_copy(update={'selected_scope_id': scope_id})
    stored = svc._stored_scope(ws, scoped)
    if scoped.lead.kind == 'kb':
        lookup = index.lookup_kb(scoped.lead.value, scope=stored, scope_id=scope_id, now=svc._now())
    elif scoped.lead.kind == 'cve':
        lookup = index.lookup_cve(scoped.lead.value, scope=stored, scope_id=scope_id, now=svc._now())
    else:
        raise KbcStoreError('PT-KBC-INPUT', 'this investigation has no KB or CVE lead for inventory selection')
    # Keep disagreement visible. The pair lookup's optional single build is not
    # an adequate representation for deciding whether source claims conflict.
    kbs = {kb: frozenset(normal_name(edge.fixed_build) for edge in lookup.edges
                         if edge.kb == kb and edge.fixed_build)
           for kb in {edge.kb for edge in lookup.edges}}
    return scope, kbs


def _entry(record, entry_id):
    found = next((entry for entry in record.parsed.entries if entry.entry_id == entry_id), None)
    if found is None:
        raise KbcStoreError('PT-KBC-INPUT', 'that entry is not retained in this inventory; inspect its recorded limits')
    return found


def _hint(record, entry, selected):
    ref = entry.reference
    claim = InventoryClaimRef(import_id=record.import_id, entry_id=entry.entry_id, raw_sha256=ref.raw_sha256,
                              logical_record=ref.logical_record, line_start=ref.line_start, line_end=ref.line_end,
                              section_index=ref.section_index)
    reasons = [f'analyst selected CSV record {ref.logical_record}; source {record.source.authenticity}',
               'file-list metadata does not establish binary identity or a CVE fix']
    if selected.asserted_scope:
        reasons.append('product scope explicitly asserted by the analyst; source mapping remains unverified')
    return ComponentHint(hint_id=domain_id('kbc.hint', 1, {'basename': entry.basename, 'scope_id': selected.scope_id}),
                         basename=entry.basename, scope_id=selected.scope_id, tier='E',
                         reasons=tuple(sorted(reasons)), inventory_refs=(claim,))


def selected_hints(svc, ws, rev, scope_id, *, cancel=None):
    """Replay only claims bound to the current product and recorded search scope."""
    decisions = _decisions(ws, rev.investigation_id)
    key = _coverage(rev, scope_id)
    matching = [item for item in decisions if item.scope_id == scope_id and item.coverage_sha256 == key]
    if not matching:
        return ()
    scope, kbs = _scope(svc, ws, rev, scope_id)
    deadline, cached_id, record, hints = time.monotonic() + 60.0, None, None, []
    for selected in sorted(matching, key=lambda item: item.import_id):
        _check(cancel, deadline)
        if selected.import_id != cached_id:
            record = get_inventory(ws, selected.import_id, verify=True, cancel=cancel)
            cached_id = selected.import_id
        if record is None:
            raise KbcStoreError('PT-KBC-VERIFY', 'a selected inventory is missing; earlier results were preserved')
        entry = _entry(record, selected.entry_id)
        _eligible(record, entry, scope, kbs, asserted=selected.asserted_scope)
        hints.append(_hint(record, entry, selected))
    _check(cancel, deadline)
    return tuple(hints)


def select(svc, investigation, import_id, entry_id, *, product, expected_revision, assert_scope=False, cancel=None):
    from .service import Outcome

    if type(expected_revision) is not int or expected_revision < 1 or type(assert_scope) is not bool:
        raise KbcStoreError('PT-KBC-INPUT', 'selection needs an exact current revision and a boolean scope assertion')
    _check(cancel)
    with svc._open(create=False) as ws:
        rev = svc._get(ws, investigation)
        if rev.revision != expected_revision:
            raise KbcStoreError('PT-KBC-STALE', 'the investigation moved on; inspect it and select again')
        scope, kbs = _scope(svc, ws, rev, product)
        record = get_inventory(ws, import_id, verify=True, cancel=cancel)
        if record is None:
            raise KbcStoreError('PT-KBC-INPUT', 'there is no inventory with that exact import ID')
        entry = _entry(record, entry_id)
        _eligible(record, entry, scope, kbs, asserted=assert_scope)
        selected = InventorySelection(import_id=import_id, entry_id=entry_id, scope_id=product,
                                      coverage_sha256=_coverage(rev, product), asserted_scope=assert_scope)
        existing = _decisions(ws, investigation)
        new = selected not in existing
        if new or rev.selected_scope_id != product or rev.state != 'COMPONENTS_READY':
            if new and len(existing) >= MAX_SELECTIONS:
                raise KbcStoreError('PT-KBC-LIMIT', 'this investigation reached the inventory selection limit')
            # Validate both existing workflow transitions without publishing either.
            intermediate = reduce(rev, Event('product_selected', rev.revision, scope_id=product))
            if isinstance(intermediate, KbcIssue):
                raise KbcStoreError(intermediate.code, intermediate.message)
            proposed = reduce(intermediate, Event('components_ready', intermediate.revision))
            if isinstance(proposed, KbcIssue):
                raise KbcStoreError(proposed.code, proposed.message)
            proposed = proposed.model_copy(update={'revision': rev.revision + 1, 'parent': rev.revision})
            decision = AnalystDecision(op=SELECTION_OP, prior=str(rev.revision), next=selected.model_dump_json(),
                                       reason='Explicit metadata filename selection; no binary identity or CVE attribution.',
                                       created_at=svc._now())
            _check(cancel)
            try:
                ws.append_revision(proposed, expected_current=rev.revision, decisions=(decision,) if new else (),
                                   guard=lambda: _check(cancel))
            except sqlite3.Error:
                raise KbcStoreError('PT-KBC-STORAGE', 'inventory selection could not be committed') from None
            rev = proposed
        hint = _hint(record, entry, selected)
    result = {'contract': 'kbcorrelation/1', 'investigation_id': investigation, 'revision': rev.revision,
              'scope_id': product, 'state': rev.state, 'selection': selected.model_dump(mode='json'),
              'hint': hint.model_dump(mode='json')}
    return Outcome(0, 'complete', result, f'Selected {entry.basename} from CSV record {entry.reference.logical_record}. '
                   'Use kb components or kb pairs with saved Winbindex data. Binary identity and CVE attribution '
                   'remain unverified.')
