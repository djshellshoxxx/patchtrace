"""FAB-0 vocabulary, limits, errors, strict records and ports (docs/specs/program-e/FAB-integration-plan.md s4, s7).

Covers: the closed vocabularies, error and exit codes, limit invariants, plain-text safety (parity with
`sanitize_text`), strict frozen records (shape validators, lossless JSON round trip, no floats), Protocols-only
ports and the import hygiene of the package. Synthetic data only; nothing here is live evidence.
"""
from __future__ import annotations

import ast
import json
import re
import unicodedata
from pathlib import Path

import fabric_support as fs
import pytest
from pydantic import ValidationError

from patchtrace import fabric
from patchtrace.fabric import contracts, ids, limits, memory, origins, ports
from patchtrace.fabric.contracts import Anchor, PairRef, Witness
from patchtrace.fabric.limits import DEFAULT_LIMITS, FabricError, FabricLimits
from patchtrace.secondary.evidence_view import sanitize_text

PACKAGE = Path(fabric.__file__).parent
ROOT = PACKAGE.parents[2]
INVISIBLE = {'Cc', 'Cf', 'Zl', 'Zp', 'Mn', 'Mc', 'Me', 'Co', 'Cn', 'Cs'}


# --- vocabulary ---------------------------------------------------------------------------------------------------

def test_vocabularies_are_the_planned_closed_tuples():
    assert contracts.KINDS == ('function', 'string', 'import', 'capability', 'rule', 'build_fact', 'advisory_phrase',
                               'cve', 'kb', 'cwe')
    assert contracts.SIDES == ('older', 'newer', 'both', 'none')
    assert contracts.ROLES == ('observed', 'stated', 'hint')
    assert contracts.PRODUCERS == ('core', 'ue', 'cap', 'die', 'wb3', 'wbq', 'wb2', 'wb1', 'yrx', 'kb', 'kev', 'pil',
                                   'analyst')


def test_every_kind_has_roles_and_documentary_kinds_are_never_observed():
    assert set(contracts.ROLES_BY_KIND) == set(contracts.KINDS)
    for roles in contracts.ROLES_BY_KIND.values():
        assert roles and set(roles) <= set(contracts.ROLES) and len(set(roles)) == len(roles)
    for kind in ('cve', 'kb', 'cwe', 'advisory_phrase'):
        assert 'observed' not in contracts.ROLES_BY_KIND[kind]
    assert contracts.ROLES_BY_KIND['function'] == ('observed',)
    assert all('stated' not in contracts.ROLES_BY_KIND[k] for k in ('function', 'string', 'import', 'capability'))


# --- errors and limits --------------------------------------------------------------------------------------------

def test_error_codes_and_exit_codes_follow_enrichment_cli_1():
    assert set(limits.EXIT_CODES) == set(limits.ERROR_CODES)
    assert all(code.startswith('PT-FAB-') for code in limits.ERROR_CODES)
    by_exit: dict[int, set[str]] = {}
    for code, exit_code in limits.EXIT_CODES.items():
        by_exit.setdefault(exit_code, set()).add(code)
    assert by_exit == {
        2: {'PT-FAB-INPUT', 'PT-FAB-KIND', 'PT-FAB-KEY', 'PT-FAB-ORIENTATION', 'PT-FAB-ORIGIN', 'PT-FAB-UNSUPPORTED'},
        3: {'PT-FAB-LIMIT', 'PT-FAB-STALE', 'PT-FAB-STORAGE', 'PT-FAB-INTEGRITY'},
        4: {'PT-FAB-NOTFOUND'}, 5: {'PT-FAB-CANCEL'}}


def test_fabric_error_validates_code_and_reason_and_bounds_the_message():
    with pytest.raises(ValueError):
        FabricError('PT-FAB-NOPE', 'x')
    with pytest.raises(ValueError):
        FabricError('PT-FAB-KEY', 'x', reason='Bad Reason')
    err = FabricError('PT-FAB-LIMIT', 'm' * 1000, reason='anchors')
    assert len(err.message) == 400 and err.exit_code == 3 and err.code == 'PT-FAB-LIMIT'
    assert str(err).startswith('PT-FAB-LIMIT: ') and str(err).endswith('[anchors]')
    assert str(FabricError('PT-FAB-INPUT', 'plain')) == 'PT-FAB-INPUT: plain'


@pytest.mark.parametrize('bad', [0, -1, True, 1.5, '3'], ids=['zero', 'negative', 'bool', 'float', 'text'])
def test_limits_are_positive_ints_only(bad):
    with pytest.raises(ValueError):
        FabricLimits(f03_witnesses_per_anchor=bad)


@pytest.mark.parametrize('change', [{'f01_anchors_per_publish': 10, 'f02_anchors_per_project': 5},
                                    {'f09_page_rows': 600_000}], ids=['publish-over-project', 'page-over-project'])
def test_limit_orderings_are_enforced(change):
    with pytest.raises(ValueError):
        FabricLimits(**change)


def test_default_limits_are_ints_and_serialise_plainly():
    values = DEFAULT_LIMITS.as_dict()
    assert values and all(type(v) is int and v > 0 for v in values.values())
    assert list(values) == sorted(values) and all(name[0] == 'f' and name[3] == '_' for name in values)


# --- plain text ---------------------------------------------------------------------------------------------------

HOSTILE = ['a\x00b', 'a\x1bb', 'a\x7fb', 'a\x85b', 'a\ud800b', 'a\tb', 'a\nb', 'a\rb',
           *[f'a{chr(code)}b' for code in (0x200E, 0x200F, 0x2028, 0x2029, 0x202A, 0x202E, 0x2066, 0x2069)]]


@pytest.mark.parametrize('text', HOSTILE, ids=[f'h{i}' for i in range(len(HOSTILE))])
def test_plain_line_rejects_controls_bidi_separators_and_surrogates(text):
    with pytest.raises(ValueError):
        contracts.plain_line(text)


def test_plain_line_keeps_markup_and_symbols_as_plain_text():
    text = 'markup <b>stays</b> text, 100% plain é中'
    assert contracts.plain_line(text) == text


def test_clean_line_always_yields_what_plain_line_accepts():
    for code in list(range(0x2200)) + [0xD800, 0xDBFF, 0xDFFF, 0xFEFF, 0x1F600]:
        cleaned = contracts.clean_line(f'a{chr(code)}b')
        assert contracts.plain_line(cleaned) == cleaned
    assert contracts.clean_line('line\none\ttwo') == 'line one two'
    assert contracts.clean_line(None) == '' and contracts.clean_line(12345) == '12345'
    assert contracts.clean_line('x' * 200) == 'x' * 200
    capped = contracts.clean_line('x' * 1000)
    assert len(capped) == 200 and capped.endswith('...')
    assert len(contracts.clean_line('y' * 50, 10)) == 10


def test_plain_line_rejects_exactly_what_sanitize_text_removes_plus_tab_and_newline():
    for code in range(0x10000):
        if 0xD800 <= code <= 0xDFFF:
            continue
        char = chr(code)
        removed = sanitize_text(f'a{char}b') != f'a{char}b'
        try:
            contracts.plain_line(f'a{char}b')
            rejected = False
        except ValueError:
            rejected = True
        assert rejected == (removed or char in '\t\n'), hex(code)
    for text in HOSTILE:
        if '\ud800' not in text:
            assert contracts.clean_line(text) == sanitize_text(text.replace('\n', ' ').replace('\t', ' '), 200)


# --- strict records -----------------------------------------------------------------------------------------------

def _dump(model) -> dict:
    return json.loads(model.model_dump_json())


def _patch(base: dict, **change) -> str:
    return json.dumps({**base, **change})


def test_records_are_strict_frozen_and_closed():
    w = fs.wit()
    base = _dump(w)
    assert Witness.model_validate_json(json.dumps(base)) == w  # the unchanged payload is valid: only the change fails
    with pytest.raises(ValidationError):  # closed: no field outside the contract
        Witness.model_validate_json(_patch(base, extra=1))
    with pytest.raises(ValidationError):  # frozen
        w.label = 'other'
    with pytest.raises(ValidationError):  # strict: a number is not a producer, and not text either
        Witness.model_validate_json(_patch(base, producer=5))
    with pytest.raises(ValidationError):
        Witness.model_validate_json(_patch(base, label=12))
    with pytest.raises(ValidationError):  # strict: numeric text is not an RVA (lax mode would parse it)
        PairRef.model_validate({'older_sha256': fs.OLDER, 'newer_sha256': fs.NEWER, 'older_rvas': ('1',),
                                'newer_rvas': ()})
    with pytest.raises(ValidationError):  # strict: a list is not a tuple outside JSON mode
        PairRef.model_validate({'older_sha256': fs.OLDER, 'newer_sha256': fs.NEWER, 'older_rvas': [1],
                                'newer_rvas': ()})


def test_resolution_refuses_a_status_outside_the_closed_set():
    for status in contracts.RESOLVE_STATUSES:
        assert contracts.Resolution(status).status == status
    for bad in ('absent', 'missing', ''):
        with pytest.raises(ValueError):
            contracts.Resolution(bad)


WITNESS_CASES = {
    'origins-empty': {'origins': []}, 'origins-unsorted': {'origins': ['D_ghidra', 'D_bytes']},
    'origins-duplicate': {'origins': ['D_bytes', 'D_bytes']}, 'origins-bad-tag': {'origins': ['ghidra']},
    'origins-too-many': {'origins': [f'D_t{i}' for i in range(9)]},
    'facets-unsorted': {'facets': [['b', 'x'], ['a', 'y']]}, 'facets-duplicate': {'facets': [['a', 'x'], ['a', 'y']]},
    'facets-bad-name': {'facets': [['Bad', 'x']]}, 'facets-too-many': {'facets': [[f'f{i:02d}', 'x'] for i in range(17)]},
    'facets-long-value': {'facets': [['a', 'x' * 301]]}, 'label-empty': {'label': ''},
    'label-newline': {'label': 'a\nb'}, 'label-long': {'label': 'x' * 201}, 'batch-upper': {'batch': 'Run'},
    'batch-long': {'batch': 'a' * 65}, 'source-underscore': {'source': 'a_b'}, 'sha-short': {'input_sha256': 'abc'},
    'producer-unknown': {'producer': 'gui'}, 'tool-empty': {'tool': ''}, 'tool-long': {'tool': 't' * 65},
    'ref-bad-pointer': {'ref': {'kind': 'x', 'id': 'y', 'pointer': 'no-slash'}},
    'ref-control-pointer': {'ref': {'kind': 'x', 'id': 'y', 'pointer': '/a\nb'}},
    'ref-bad-kind': {'ref': {'kind': 'X_', 'id': 'y'}}, 'witness-id-short': {'witness_id': 'abc'},
}


@pytest.mark.parametrize('name', sorted(WITNESS_CASES), ids=sorted(WITNESS_CASES))
def test_witness_shape_validators_reject(name):
    base = _dump(fs.wit())
    with pytest.raises(ValidationError):
        Witness.model_validate_json(_patch(base, **WITNESS_CASES[name]))


def test_witness_accepts_a_fully_populated_record_and_round_trips():
    ref = contracts.Ref(kind='advisory-facts', id='facts-1', pointer='/vulnerabilities/0/notes/2/text',
                        sha256='c' * 64)
    w = fs.wit('kb', 'advisory-text', facets=(('phrase_kind', 'module'), ('basis', 'explicit')), tool='csaf',
               tool_version='1.2', input_sha='d' * 64, ref=ref)
    assert Witness.model_validate_json(w.model_dump_json()) == w
    assert w.facets == (('basis', 'explicit'), ('phrase_kind', 'module'))


@pytest.mark.parametrize('payload', [
    {'older_rvas': [], 'newer_rvas': []}, {'older_rvas': [2, 1], 'newer_rvas': []},
    {'older_rvas': [1, 1], 'newer_rvas': []}, {'older_rvas': [-1], 'newer_rvas': []},
    {'older_rvas': [2 ** 32], 'newer_rvas': []}, {'older_rvas': list(range(257)), 'newer_rvas': []},
    {'older_rvas': [1], 'newer_rvas': list(range(257))}, {'older_rvas': [1]},
], ids=['empty', 'unsorted', 'duplicate', 'negative', 'too-big', 'too-many-older', 'too-many-newer', 'missing-side'])
def test_pair_ref_validators_reject(payload):
    base = {'older_sha256': fs.OLDER, 'newer_sha256': fs.NEWER}
    with pytest.raises(ValidationError):
        PairRef.model_validate_json(json.dumps({**base, **payload}))


def test_pair_ref_allows_a_function_present_on_one_side_only():
    added = PairRef(older_sha256=fs.OLDER, newer_sha256=fs.NEWER, older_rvas=(), newer_rvas=(0x30,))
    assert PairRef.model_validate_json(added.model_dump_json()) == added


def _two_witnesses_in_canonical_order() -> tuple[dict, dict]:
    pair = (_dump(fs.wit('kb', 'advisory-text', batch=f'b{i}')) for i in (1, 2))
    first, second = sorted(pair, key=lambda w: w['witness_id'])
    return first, second


@pytest.mark.parametrize('case', ['empty', 'unsorted', 'duplicate', 'too-many'])
def test_anchor_witness_sequences_are_non_empty_sorted_unique_and_capped(case):
    first, second = _two_witnesses_in_canonical_order()
    witnesses = {'empty': [], 'unsorted': [second, first], 'duplicate': [first, first],
                 'too-many': [dict(first, witness_id=f'{i:064x}') for i in range(17)]}[case]
    with pytest.raises(ValidationError):
        Anchor.model_validate_json(_patch(_dump(fs.cve_anchor()), witnesses=witnesses))


def test_anchor_accepts_witnesses_in_canonical_order():
    first, second = _two_witnesses_in_canonical_order()
    loaded = Anchor.model_validate_json(_patch(_dump(fs.cve_anchor()), witnesses=[first, second]))
    assert [w.witness_id for w in loaded.witnesses] == [first['witness_id'], second['witness_id']]


@pytest.mark.parametrize('change', [
    {'kind': 'api'}, {'side': 'both-ish'}, {'role': 'claimed'}, {'key': ''}, {'key': 'k' * 201},
    {'key': 'a' + chr(0x202E) + 'b'}, {'subject': ''}, {'anchor_id': 'xyz'}],
    ids=['kind', 'side', 'role', 'key-empty', 'key-long', 'key-bidi', 'subject-empty', 'id'])
def test_anchor_shape_validators_reject(change):
    with pytest.raises(ValidationError):
        Anchor.model_validate_json(_patch(_dump(fs.cve_anchor()), **change))


def _numbers(node):
    if isinstance(node, dict):
        for value in node.values():
            yield from _numbers(value)
    elif isinstance(node, list):
        for value in node:
            yield from _numbers(value)
    elif isinstance(node, (int, float)) and not isinstance(node, bool):
        yield node


def test_anchor_json_round_trip_is_lossless_and_float_free():
    a = fs.pair_anchor(older=(0x1000, 0x1010), newer=(0x1040,), label='pair', facets=(('name', 'ParsePacket'),))
    text = a.model_dump_json()
    assert Anchor.model_validate_json(text) == a
    numbers = list(_numbers(json.loads(text)))
    assert numbers and all(type(n) is int for n in numbers)


def test_display_witness_follows_producer_order_not_hash_order():
    first = fs.wit('kb', 'advisory-text', label='from kb')
    second = fs.wit('core', 'pairing', label='from core')
    anchor = ids.make_anchor(kind='cve', key='CVE-2099-0001', side='none', role='stated', witnesses=(first, second))
    assert anchor.label == 'from core' and anchor.display.producer == 'core'
    flipped = ids.make_anchor(kind='cve', key='CVE-2099-0001', side='none', role='stated', witnesses=(second, first))
    assert flipped == anchor


# --- ports --------------------------------------------------------------------------------------------------------

PORT_NAMES = ('OriginRegistry', 'AnchorSink', 'AnchorReader')


def test_ports_module_defines_exactly_the_planned_protocols():
    defined = {n for n, v in vars(ports).items() if isinstance(v, type) and v.__module__ == ports.__name__}
    assert defined == set(PORT_NAMES)
    for name in PORT_NAMES:
        assert getattr(getattr(ports, name), '_is_protocol', False), name


def test_ports_contain_no_behaviour():
    tree = ast.parse(Path(ports.__file__).read_text(encoding='utf-8'))
    assert not [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            body = [b for b in node.body if not (isinstance(b, ast.Expr) and isinstance(b.value, ast.Constant))]
            assert not body, f'{node.name} has behaviour; ports are Protocols only'


def test_implementations_satisfy_their_ports_structurally():
    store = memory.MemoryAnchorStore()
    assert isinstance(store, ports.AnchorSink) and isinstance(store, ports.AnchorReader)
    assert isinstance(memory.NullAnchorSink(), ports.AnchorSink)
    assert isinstance(memory.NullAnchorReader(), ports.AnchorReader)
    assert isinstance(origins.DefaultOriginRegistry(), ports.OriginRegistry)
    assert not isinstance(object(), ports.AnchorSink) and not isinstance(memory.NullAnchorSink(), ports.AnchorReader)


# --- import hygiene -----------------------------------------------------------------------------------------------

FORBIDDEN = {'PySide6', 'shiboken6', 'sqlite3', 'socket', 'ssl', 'subprocess', 'urllib', 'http', 'requests', 'ctypes',
             'multiprocessing', 'asyncio', 'tempfile', 'shutil', 'os', 'pathlib', 'logging'}


def _imports(tree: ast.AST):
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield 0, alias.name
        elif isinstance(node, ast.ImportFrom):
            yield node.level, node.module or ''


ADAPTERS = {'store.py', 'pins.py'}  # the modules over the enrichment store: the only ones that may reach it and SQLite
CLI_ADAPTER = 'cli.py'  # the Qt-free dispatcher: the only module that reaches the CLI envelope, a project and paths
PANEL_LAYER = {'panel.py', 'related.py'}  # Qt-free panel declaration and view model: may use the GUI framework's pure modules
PANEL_GUI_IMPORTS = {'gui.registry', 'gui.anchors', 'gui.state', 'gui.table_spec', 'gui.text', 'tooltips', 'ui_related'}  # ui_related: the lazy controller factory


def test_package_imports_no_qt_io_or_other_feature():
    files = sorted(PACKAGE.glob('*.py'))
    assert {f.name for f in files} == {'__init__.py', 'contracts.py', 'convert.py', 'ids.py', 'limits.py',
                                       'memory.py', 'origins.py', 'ports.py', *ADAPTERS, CLI_ADAPTER, *PANEL_LAYER}
    for path in files:
        adapter = path.name in ADAPTERS
        cli_adapter = path.name == CLI_ADAPTER
        for level, module in _imports(ast.parse(path.read_text(encoding='utf-8'))):
            top = module.split('.')[0]
            if level == 0:
                allowed = {'sqlite3'} if adapter else {'pathlib'} if cli_adapter else set()
                assert (top not in FORBIDDEN or top in allowed) and top != 'patchtrace', f'{path.name} imports {module}'
            elif level == 2:  # canonical JSON and domain ids; adapters also the enrichment store and its errors
                allowed = {'enrichment.identity'}
                allowed |= {'enrichment.storage', 'enrichment.contracts'} if adapter else set()
                allowed |= {'cli', 'service', 'enrichment.storage'} if cli_adapter else set()
                allowed |= PANEL_GUI_IMPORTS if path.name in PANEL_LAYER else set()
                assert module in allowed, f'{path.name} imports ..{module}'
            else:
                assert level == 1, f'{path.name} reaches {level} levels up'


def test_every_identity_domain_in_use_is_listed():
    used: set[str] = set()
    for name in ('ids.py', 'origins.py'):
        source = (PACKAGE / name).read_text(encoding='utf-8')
        used |= set(re.findall(r"domain_id\(\s*'([a-z-]+)'", source)) | set(re.findall(r"DOMAIN = '([a-z-]+)'", source))
    assert used == set(ids.DOMAINS)


def test_no_fabric_file_hides_an_invisible_character():
    """Bidirectional controls, separators and combining marks must be built from code points, never typed: they are
    invisible in review (a Trojan Source risk) and an editor may normalise them."""
    files = [*PACKAGE.glob('*.py'), ROOT / 'tests' / 'fabric_support.py', *(ROOT / 'tests').glob('test_fabric_*.py'),
             ROOT / 'docs' / 'specs' / 'program-e' / 'FAB-integration-plan.md']
    assert len(files) >= 14
    for path in files:
        for number, line in enumerate(path.read_text(encoding='utf-8').split('\n'), 1):
            for char in line:
                hidden = unicodedata.category(char) in INVISIBLE if ord(char) > 0x7F else (
                    ord(char) < 0x20 and char not in '\t\r' or ord(char) == 0x7F)
                assert not hidden, f'{path.name}:{number}: U+{ord(char):04X}'
