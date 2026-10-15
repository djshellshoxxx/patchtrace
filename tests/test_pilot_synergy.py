"""PIL-T: the synergy oracle of the patch-intent localization engine (docs/specs/program-e/PIL-integration-plan.md s5, s9).

A hand-built observation ledger (nine functions, two CVEs) and a validator-clean synthetic CSAF are fixed in
``tests/fixtures/pilot/synergy-1/``. The checks that need no engine pass today: the fixtures validate against the
pilot/1 contracts and the real K pipeline, the expected tables are the plan's tables, the goldens are byte-stable, and
the fake ports obey the A1 Protocols. Everything that needs fusion and ranking (PIL-B2) is ``PIL_B2``:
``xfail(strict=True)`` that expects only ``EngineMissing``, so it flips loudly when ``patchtrace.pilot.service`` appears
and never hides a wrong class, rank or cap.

Synthetic data only; nothing here is live evidence.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
from pilot_synergy_support import (
    FIXTURES,
    PIL_B2,
    ZERO_COUNTS,
    Sources,
    arms,
    assert_strictly_pending,
    channel_statuses,
    classes,
    derive_context,
    expected,
    identities,
    lead_map,
    ledger_reports,
    load_ledger,
    ranked,
    run_arm,
    sources_for,
    tie_partners,
    window_from_reports,
)

from patchtrace.intelligence.hypotheses import rules_digest
from patchtrace.intelligence.lexicon import lexicon_digest
from patchtrace.pilot import contracts as c
from patchtrace.pilot import keys, origins, ports
from patchtrace.unified import keys as unified_keys

ROOT = Path(__file__).resolve().parents[1]
PLAN = ROOT / 'docs' / 'specs' / 'program-e' / 'PIL-integration-plan.md'
CVE1, CVE2 = 'CVE-2099-20001', 'CVE-2099-20002'
FUNCTION_IDS = ('F1', 'F2', 'F3', 'F4', 'F5', 'F6', 'F7', 'F8', 'F9')
ARM_IDS = ['adv', 'b1', 'cf', 'floss', 'adv-b1', 'adv-cf', 'no-names', 'window-unknown']  # the plan's test ids
ALL_ARMS = ['full', *ARM_IDS]
# The kinds of the plan's evidence column, one set per function (the ledger holds exactly these).
KINDS = {
    'F1': {'b1:BND', 'cf:comparison', 'call:added'}, 'F6': {'b1:BND', 'cf:comparison'},
    'F8': {'b1:BND', 'cf:comparison'}, 'F9': {'b1:BND', 'cf:cosmetic'},
    'F4': {'b1:SIZE'}, 'F5': {'cf:call-added'}, 'F2': {'cf:string', 'str:added'},
    'F3': {'cf:register-only', 'cf:address-only', 'die:toolchain-changed'}, 'F7': {'cf:callee'}}
PREFIX_OF_SOURCE = {'b1': 'b1', 'cf': 'cf', 'calls': 'call', 'floss': 'str', 'die': 'die'}  # capa: no deltas here


def generator():
    spec = importlib.util.spec_from_file_location('generate_pilot_synergy', FIXTURES / 'generate.py')
    module = importlib.util.module_from_spec(spec)
    previous, sys.dont_write_bytecode = sys.dont_write_bytecode, True  # no __pycache__ inside the fixtures
    try:
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous
    return module


def plan_text() -> str:
    return PLAN.read_text(encoding='utf-8')


def plan_table(header: str) -> list[list[str]]:
    """Rows (cells stripped) of the markdown table under a header line of the plan."""
    lines = plan_text().splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith(header))
    rows = []
    for line in lines[start + 2:]:
        if not line.startswith('|'):
            break
        rows.append([cell.strip() for cell in line.strip().strip('|').split('|')])
    return rows


# --- goldens: byte-stable, LF, pinned ---------------------------------------------------------------------------------

def test_committed_files_equal_a_fresh_render():
    """Regenerate-and-compare: every JSON file is exactly what ``generate.py`` renders now, and nothing else lives here."""
    rendered = generator().render()
    present = {p.name for p in FIXTURES.iterdir() if p.name != '__pycache__'}
    assert present == {'README.md', 'generate.py', *[p.name for p in rendered]}
    for path, text in rendered.items():
        assert path.read_bytes() == text.encode('utf-8'), f'{path.name} is stale: run generate.py'


def test_the_render_does_not_depend_on_the_hash_seed():
    for seed in ('1', '2'):
        env = dict(os.environ, PYTHONPATH=str(ROOT / 'src'), PYTHONHASHSEED=seed)
        result = subprocess.run([sys.executable, str(FIXTURES / 'generate.py'), '--check'], capture_output=True,
                                text=True, env=env, cwd=ROOT)
        assert result.returncode == 0, result.stderr


def test_the_fixtures_are_ascii_lf_and_pinned_by_gitattributes():
    attributes = (ROOT / '.gitattributes').read_text(encoding='utf-8').splitlines()
    assert 'tests/fixtures/pilot/** text eol=lf' in attributes  # covers synergy-1/*: no new line is needed
    for path in (p for p in FIXTURES.iterdir() if p.is_file()):
        raw = path.read_bytes()
        assert b'\r' not in raw, f'{path.name} has CR'
        assert raw.endswith(b'\n') and not raw.endswith(b'\n\n'), f'{path.name} must end with one newline'
        if path.suffix == '.json':
            raw.decode('ascii')  # escapes keep the goldens independent of the checkout encoding
            json.loads(raw)


# --- the ledger is valid pilot/1 data ---------------------------------------------------------------------------------

def test_the_ledger_validates_against_the_pilot_contracts():
    ledger = load_ledger()
    older, newer = ledger.builds['older_sha256'], ledger.builds['newer_sha256']
    assert [f.id for f in ledger.functions] == ['F1', 'F6', 'F8', 'F9', 'F4', 'F5', 'F2', 'F3', 'F7']  # the plan's order
    for f in ledger.functions:
        assert f.key == keys.candidate_key(older, newer, [f.older.rva], [f.newer.rva])
        assert f.key == unified_keys.row_id(older, newer, [f.older.rva], [f.newer.rva])  # the SPEC-31 row id
        assert f.older.name == f.newer.name and f.older.rva != f.newer.rva
    assert len({f.key for f in ledger.functions}) == 9 and len({f.older.rva for f in ledger.functions}) == 9
    pool = [obs for _, obs in ledger.observations] + [obs for items in ledger.advisory.values() for _, obs in items]
    assert all(keys.observation_id(obs) == obs.obs_id for obs in pool)
    assert len({obs.obs_id for obs in pool}) == len(pool)
    assert all(obs.role in ('shape', 'context', 'conflict') for obs in pool)  # locality is computed by PIL, not stored
    assert all(ctx.counts == ZERO_COUNTS for ctx in ledger.contexts)  # counts are an output of localization
    assert [ctx.cve for ctx in ledger.contexts] == [CVE1, CVE2]
    assert len(ledger.tool_keys) == 6 and len(ledger.secondary_set_ids) == 1 and ledger.kev_listed == {CVE1: '2099-02-10'}


def test_the_ledger_holds_exactly_the_evidence_column_of_the_plan():
    ledger = load_ledger()
    by_function: dict[str, dict[str, c.Observation]] = {}
    for fid, obs in ledger.observations:
        by_function.setdefault(fid, {})[obs.kind] = obs
    assert {fid: set(items) for fid, items in by_function.items()} == KINDS
    one = by_function
    shape = {o.kind for _, o in ledger.observations if o.role == 'shape'}
    assert shape == {'b1:BND', 'b1:SIZE', 'cf:comparison', 'call:added'}  # what a guard fix looks like
    assert {o.kind for _, o in ledger.observations if o.role == 'conflict'} == {'cf:cosmetic'}  # the only counter
    assert one['F1']['call:added'].ref.id == 'RtlSizeTAdd' and one['F1']['call:added'].verification == 'label-only'
    assert one['F1']['cf:comparison'].detail.endswith('material, anchored by C6')
    assert one['F1']['b1:BND'].nav.start_line == one['F1']['cf:comparison'].nav.start_line == 14
    assert one['F9']['cf:cosmetic'].role == 'conflict' and 'COS-LAYOUT/1' in one['F9']['cf:cosmetic'].detail
    assert '0x40' in one['F4']['b1:SIZE'].detail and '0x80' in one['F4']['b1:SIZE'].detail
    assert 'Dropped oversize fragment' in one['F2']['str:added'].detail and one['F2']['str:added'].origins == ('D_bytes',)
    assert one['F2']['str:added'].ref.sha256 == hashlib.sha256(b'dropped oversize fragment').hexdigest()
    assert one['F3']['die:toolchain-changed'].role == 'context'
    assert one['F7']['cf:callee'].detail == 'callee of one call replaced'
    contested = {f.id for f in ledger.functions if f.identity == 'contested'}
    assert contested == {'F8'}  # "pairing contested (Ghidriff versus BinDiff)"; every other pair is corroborated
    assert [f.older.name for f in ledger.functions] == [row[1] for row in plan_table('| Id |')]


def test_origins_reproduce_the_independence_claims_of_the_plan():
    ledger = load_ledger()
    advisory = [obs.origins for _, obs in ledger.advisory[CVE1]]
    assert len(advisory) == 4 and origins.components(advisory) == (('D_vendor_text',),)  # CSAF, NVD, MSRC, KEV: one
    shape = {fid: [o for f, o in ledger.observations if f == fid and o.role == 'shape'] for fid in FUNCTION_IDS}
    f1 = [o.origins for o in shape['F1']]
    assert origins.components(f1) == (('D_ghidra',),)  # B1, ChangeFacts and the call label: one component
    assert origins.components(f1[:2]) == (('D_ghidra',),)  # B1 and ChangeFacts alone
    assert origins.components([*advisory, *f1]) == (('D_ghidra',), ('D_vendor_text',))  # the plan: "components 2"
    lead = origins.lead_components([*advisory, *f1])
    assert (lead.count, lead.tags) == (2, ('D_ghidra', 'D_vendor_text'))
    # why the engine counts supporting shape observations only: F2's two context observations would add a witness
    f2 = [o.origins for f, o in ledger.observations if f == 'F2']
    assert len(origins.components(f2)) == 2 and not shape['F2']


# --- the advisory is real K input -------------------------------------------------------------------------------------

def test_the_advisory_is_validator_clean_and_maps_the_synthetic_builds():
    ledger = load_ledger()
    reports = ledger_reports()
    assert sorted(reports) == [CVE1, CVE2] and hashlib.sha256(ledger.csaf).hexdigest() == ledger.csaf_sha256
    for cve, (rule, cwe) in {CVE1: ('R-MEMORY-WRITE', 'CWE-787'), CVE2: ('R-MEMORY-READ', 'CWE-125')}.items():
        report = reports[cve]
        a = report.applicability
        assert (a.older.resolution, a.newer.resolution) == ('affected', 'fixed') and not a.contradictions
        assert (a.older.product_mapping_status, a.newer.product_mapping_status) == ('candidate', 'candidate')
        assert len(report.sources) == 1 and report.sources[0].source.sha256 == ledger.csaf_sha256
        assert report.cwe_profile.status == 'explicit' and report.cwe_profile.classifications[0].cwe_id == cwe
        best = report.hypotheses.hypotheses[0]
        assert (best.rule_id, best.rule_revision, best.cwe_id, best.basis) == (rule, 1, cwe, 'explicit-csaf-cwe')
    # the plan's description ("heap-based buffer overflow") also hits CWE-122: a second hypothesis of the same rule
    cwes = [h.cwe_id for h in reports[CVE1].hypotheses.hypotheses]
    assert cwes[0] == 'CWE-787' and 'CWE-122' in cwes  # the explicit CWE first; the vocabulary hit is the second
    assert {h.rule_id for h in reports[CVE1].hypotheses.hypotheses} == {'R-MEMORY-WRITE'}
    anchors = {cve: {(a.kind, a.value) for a in reports[cve].anchors.anchors} for cve in (CVE1, CVE2)}
    assert {('module', 'examplenet.sys'), ('feature', 'IPv6')} <= anchors[CVE1]
    assert ('component', 'SYNTHETIC Example Net IPv6 Fragment Reassembly') in anchors[CVE1]
    assert ('component', 'SYNTHETIC Example Net IPv6 Options Parse') in anchors[CVE2]
    csaf = json.loads(ledger.csaf)
    hashes = {p['product_identification_helper']['hashes'][0]['file_hashes'][0]['value']
              for p in csaf['product_tree']['full_product_names']}
    assert hashes == {ledger.builds['older_sha256'], ledger.builds['newer_sha256']}


def test_the_ledger_contexts_are_what_the_k_reports_derive():
    ledger = load_ledger()
    reports = ledger_reports()
    window = window_from_reports(reports)
    assert (window.state, window.cves) == ('yes', (CVE1, CVE2))  # two CVEs fixed on the newer build
    states = expected()['kev']['states']
    for ctx in ledger.contexts:
        date = states[ctx.cve].get('date_added')
        kev = (c.Kev(state='listed', date_added=date, snapshot_id=ledger.kev_snapshot_id) if date
               else c.Kev(state='not-in-snapshot', snapshot_id=ledger.kev_snapshot_id))
        assert derive_context(reports[ctx.cve], kev, window) == ctx
    older, newer = identities(ledger.builds['older_sha256'], ledger.builds['newer_sha256'])
    assert (older.side, newer.side) == ('older', 'newer') and older.facts_state == 'record-only'


# --- the expected tables are the plan's tables ------------------------------------------------------------------------

def test_the_expected_tables_are_the_plan_s5_tables():
    plan = ' '.join(plan_text().split())
    want = expected()
    assert [[f['id'], f['function'], f['evidence']] for f in want['function_table']] == plan_table('| Id |')
    assert [[r['arm'], r['f1_rank'], r['fits'], r['short_of']] for r in want['arm_table']] == plan_table('| Arm |')
    for quote in want['quotes']:
        assert quote in plan, f'plan s5 no longer says: {quote}'
    for badge in want['badges'].values():
        assert f'"{badge}"' in plan  # the badge words of plan s8
    assert [f.plan_evidence for f in load_ledger().functions] == [f['evidence'] for f in want['function_table']]


def test_the_structured_arms_are_the_parsed_plan_cells():
    rows = {row[0]: row for row in plan_table('| Arm |')}
    for arm_id, arm in expected()['arms'].items():
        _, rank, fits, _ = rows[arm['label']]
        numbers = re.match(r'(\d+)(?:-(\d+))?', rank)
        assert arm['f1_rank'] == [int(numbers[1]), int(numbers[2] or numbers[1])], arm_id
        partners = re.search(r'\(with ([^)]*)\)', rank)
        assert arm['ties_with'] == (sorted(re.findall(r'F\d', partners[1])) if partners else []), arm_id
        top = re.search(r'top is ([A-Z0-9/]+)', rank)
        assert arm['top'] == (sorted(top[1].split('/')) if top else []), arm_id
        assert arm['fit_leads'] == (None if fits == 'n/a' else sorted(re.findall(r'F\d', fits))), arm_id
    assert sorted(arm['label'] for arm in expected()['arms'].values()) == sorted(rows)
    assert sorted(expected()['arms']) == sorted(ALL_ARMS)


def test_the_expected_arms_are_self_consistent():
    arms_ = expected()['arms']
    for arm_id, arm in arms_.items():
        first, last = arm['f1_rank']
        assert 1 <= first <= last <= 9, arm_id
        assert arm['code_only'] == (arm['fit_leads'] is None), arm_id  # no advisory: the plan prints n/a, not "none"
        assert last - first + 1 >= 1 + len(arm['ties_with']), arm_id  # the tie group holds F1 and its named partners
        assert set(arm['ties_with'] + arm['top'] + (arm['fit_leads'] or [])) <= set(FUNCTION_IDS), arm_id
        if arm['top']:  # the named leaders occupy the first positions, so F1 starts right below them
            assert first == len(arm['top']) + 1 and 'F1' not in arm['top'], arm_id
    assert {a for a, v in arms_.items() if not v['code_only'] and v['fit_leads'] == []} == {'adv', 'no-names'}
    assert {a for a, v in arms_.items() if v['fit_leads']} == {'full', 'adv-b1', 'adv-cf', 'window-unknown'}
    assert all('F1' in v['fit_leads'] for v in arms_.values() if v['fit_leads'])  # the truth fits wherever anything does
    assert arms_['full']['f1_rank'] == [1, 1] and arms_['window-unknown']['fit_leads'] == ['F1', 'F6']
    assert {a for a, v in arms_.items() if v['code_only']} == {'b1', 'cf', 'floss'}
    # the arms only ever name evidence sources of the full arm
    assert {s for v in arms_.values() for s in v['sources']} == set(arms_['full']['sources'])


def classes_of(leads: dict, name: str) -> list[str]:
    return sorted(fid for fid, v in leads.items() if v['class'] == name)


def test_the_full_arm_expectations_are_self_consistent():
    want = expected()['full']
    first = want[CVE1]
    leads = first['leads']
    assert sorted(leads) == sorted(FUNCTION_IDS)
    counts = {name: sum(1 for v in leads.values() if v['class'] == name) for name in c.LEAD_CLASSES}
    assert counts == first['counts'] and classes_of(leads, 'fit') == first['fit_leads'] == ['F1']
    blocks: dict[tuple[int, int], int] = {}
    for spec in leads.values():
        assert spec['badge'] == expected()['badges'][spec['class']]
        assert spec.get('mechanism', c.CLASS_MECHANISMS[spec['class']][0]) in c.CLASS_MECHANISMS[spec['class']]
        blocks[tuple(spec['rank'])] = blocks.get(tuple(spec['rank']), 0) + 1
        assert spec.get('met', 0) <= spec.get('total', 3)
    # every rank block holds as many leads as it has positions; the blocks tile 1..9 in class order
    assert all(hi - lo + 1 == n for (lo, hi), n in blocks.items())
    tiles = sorted(blocks)
    assert tiles[0][0] == 1 and tiles[-1][1] == 9 and all(a[1] + 1 == b[0] for a, b in zip(tiles, tiles[1:], strict=False))
    by_block = sorted(leads.values(), key=lambda v: v['rank'][0])
    assert [c.CLASS_RANK[v['class']] for v in by_block] == sorted(c.CLASS_RANK[v['class']] for v in by_block)
    f1 = leads['F1']
    assert f1['rank'] == [1, 1] and (f1['met'], f1['total'], f1['components'], f1['local_hits'], f1['tie_size']) == (
        2, 3, 2, 2, 1)  # the plan: "expected changes 2 of 3, components 2, locality 2, tie size 1"
    assert leads['F9']['rank'][0] < leads['F8']['rank'][0] and leads['F8']['identity'] == 'contested'
    assert leads['F6']['caps'] == ['confounded-window-needs-locality']
    second = want[CVE2]
    assert second['fit_leads'] == ['F6'] == classes_of(second['leads'], 'fit')
    assert second['leads']['F1']['class'] == 'partial' and second['leads']['F1']['caps'] == [
        'confounded-window-needs-locality']
    assert first['window'] == second['window'] == 'yes'


def test_the_kev_and_why_facts_agree_with_the_ledger():
    ledger = load_ledger()
    kev = expected()['kev']
    listed = [cve for cve in (CVE1, CVE2) if kev['states'][cve]['state'] == 'listed']
    unlisted = [cve for cve in (CVE1, CVE2) if cve not in listed]
    assert kev['picker_order'] == listed + unlisted == [CVE1, CVE2]  # KEV orders CVEs; it never orders functions
    assert set(ledger.kev_listed) == set(listed) and kev['snapshot_id'] == ledger.kev_snapshot_id
    why = expected()['why_f1']
    f1 = expected()['full'][CVE1]['leads']['F1']
    assert why['summary'] == {'class': 'fit', 'expected_changes_seen': f1['met'], 'expected_changes_total': f1['total'],
                              'required_seen': 1, 'required_total': 1, 'independent_groups': f1['components'],
                              'depth': f1['depth']}
    mine = {o.kind: o for fid, o in ledger.observations if fid == 'F1'}
    guard = next(x for x in why['expected_changes'] if x['id'] == 'guard-added')
    assert set(guard['kinds']) <= set(mine)
    assert guard['go_to'] == {'side': 'newer', 'line': mine['b1:BND'].nav.start_line}
    checked = next(x for x in why['expected_changes'] if x['id'] == 'checked-arithmetic')
    assert checked['verification'] == mine['call:added'].verification and checked['api'] == mine['call:added'].ref.id
    assert [x['state'] for x in why['expected_changes']].count('met') == f1['met']
    assert why['independent_evidence'][0]['advisory_sources'] == sorted(s for s, _ in ledger.advisory[CVE1])
    assert why['independent_evidence'][1]['kinds'] == sorted(mine)
    assert why['window']['cves'] == [CVE1, CVE2] and why['alternatives'] == [{'cve': CVE2, 'class': 'partial'}]


# --- the fake ports obey the A1 Protocols -----------------------------------------------------------------------------

def observed(s: Sources, candidate_keys: list[str]) -> list[tuple[str, c.Observation]]:
    return [pair for port in (s.changes, s.calls, s.tools) for pair in port.observations(candidate_keys)]


@pytest.mark.parametrize('arm_id', ALL_ARMS, ids=ALL_ARMS)
def test_the_fake_ports_satisfy_the_a1_protocols(arm_id):
    ledger = load_ledger()
    s = sources_for(arms()[arm_id])
    for port, protocol in ((s.advisory, ports.AdvisorySource), (s.changes, ports.ChangeEvidenceSource),
                           (s.tools, ports.ToolEvidenceSource), (s.kev, ports.KevSource),
                           (s.calls, ports.CallDeltaSource), (s.pairing, ports.PairingSource)):
        assert isinstance(port, protocol)
    candidates = list(s.pairing.candidates())
    assert [x.candidate_key for x in candidates] == [
        f.key for f in sorted(ledger.functions, key=lambda f: f.older.rva)]  # every candidate once, deterministic order
    assert list(s.pairing.candidates()) == candidates
    assert s.pairing.unified_result_id() is None and len(s.pairing.secondary_set_ids()) == 1
    wanted = [x.candidate_key for x in candidates]
    assert observed(s, wanted) == observed(s, wanted[::-1])  # the answer does not depend on the request order
    assert not observed(s, []) and not observed(s, ['0' * 64])
    assert [x.channel for x in s.tools.statuses()] == ['strings', 'capa', 'build']
    assert (s.changes.status().channel, s.calls.status().channel, s.pairing.status().channel) == (
        'code', 'calls', 'pairing')
    cache_keys = list(s.tools.cache_keys())
    assert cache_keys == sorted(cache_keys, key=lambda k: (k.engine, k.side)) and len(set(cache_keys)) == len(cache_keys)


@pytest.mark.parametrize('arm_id', ALL_ARMS, ids=ALL_ARMS)
def test_an_excluded_source_is_not_run_and_yields_nothing(arm_id):
    ledger = load_ledger()
    arm = arms()[arm_id]
    s = sources_for(arm)
    found = {obs.kind.split(':')[0] for _, obs in observed(s, [f.key for f in ledger.functions])}
    assert found == {prefix for source, prefix in PREFIX_OF_SOURCE.items() if source in arm.sources}
    states = {x.channel: x.state for x in channel_statuses(arm)}
    for source, channel in (('floss', 'strings'), ('capa', 'capa'), ('die', 'build'), ('calls', 'calls'),
                            ('advisory', 'advisory')):
        assert (states[channel] == 'not-run') == (source not in arm.sources), (arm_id, channel)
    code = {'b1', 'cf'} & arm.sources
    assert states['code'] == ('available' if len(code) == 2 else 'partial' if code else 'not-run')
    assert states['pairing'] == 'available'  # the candidate universe is context in every arm
    assert (not s.advisory.cves()) == arm.code_only == (not s.contexts) == (not s.advisory_observations)
    engines = {k.engine for k in s.tools.cache_keys()}
    assert engines == {e for x, e in (('floss', 'floss'), ('die', 'diec'), ('capa', 'capa')) if x in arm.sources}


def test_the_full_arm_loses_no_ledger_observation():
    ledger = load_ledger()
    s = sources_for(arms()['full'])
    got = {obs.obs_id for _, obs in observed(s, [f.key for f in ledger.functions])}
    assert got == {obs.obs_id for _, obs in ledger.observations}
    assert {cve: tuple(s.advisory_observations[cve]) for cve in (CVE1, CVE2)} == {
        cve: tuple(obs for _, obs in items) for cve, items in ledger.advisory.items()}
    assert s.contexts == ledger.contexts and sorted(s.advisory.cves()) == [CVE1, CVE2]
    assert all(s.advisory.report(cve) == ledger_reports()[cve] for cve in (CVE1, CVE2))
    assert s.advisory.report('CVE-2099-99999') is None


def pilot_inputs(s: Sources, config: c.PilotConfig) -> c.PilotInputs:
    """The ``result_id`` payload as the ports supply it (plan s7); the digests are the real K and PIL ones."""
    return c.PilotInputs(
        older_sha256=s.older_sha256, newer_sha256=s.newer_sha256, ghidriff_run_id=s.ghidriff_run_id,
        raw_sha256=s.raw_sha256, unified_result_id=s.pairing.unified_result_id(),
        secondary_set_ids=tuple(s.pairing.secondary_set_ids()), tool_keys=tuple(s.tools.cache_keys()),
        advisory_facts_ids=tuple(s.advisory.facts_ids()), kev_snapshot_id=s.kev.snapshot_id(),
        lexicon_digest=lexicon_digest(), rules_digest=rules_digest(),
        pilot_rules_digest=hashlib.sha256(b'pilot rules: PIL-B1 owns the table').hexdigest(),
        origins_digest=origins.digest(), tiers_version=1, config_digest=keys.config_digest(config))


def test_the_ports_supply_every_input_of_the_result_id():
    config = keys.default_config()
    ids = {arm_id: keys.result_id(pilot_inputs(sources_for(arms()[arm_id]), config)) for arm_id in ALL_ARMS}
    assert ids == {arm_id: keys.result_id(pilot_inputs(sources_for(arms()[arm_id]), config)) for arm_id in ALL_ARMS}
    assert len({ids[a] for a in ('full', 'adv', 'floss', 'b1')}) == 4  # other tools or advisory facts: another result
    full = pilot_inputs(sources_for(arms()['full']), config)
    assert len(full.tool_keys) == 6 and len(full.advisory_facts_ids) == 1 and full.kev_snapshot_id
    assert pilot_inputs(sources_for(arms()['full'].with_(kev='unknown')), config).kev_snapshot_id is None
    swapped = full.model_copy(update={'older_sha256': full.newer_sha256, 'newer_sha256': full.older_sha256})
    assert keys.result_id(swapped) != keys.result_id(full)  # an orientation swap is a different result


def test_the_arm_knobs_do_what_they_say():
    ledger = load_ledger()
    hidden = sources_for(arms()['no-names'])
    assert all(x.older[0].name.startswith('FUN_') and x.newer[0].name.startswith('FUN_')
               for x in hidden.pairing.candidates())  # a Ghidra placeholder: a stop word, never locality
    assert {x.older[0].name for x in sources_for(arms()['full']).pairing.candidates()} == {
        f.older.name for f in ledger.functions}
    assert all(ctx.confounding.state == 'unknown' and not ctx.confounding.cves
               for ctx in sources_for(arms()['window-unknown']).contexts)
    assert all(ctx.confounding.state == 'yes' for ctx in sources_for(arms()['full']).contexts)
    for variant, states in (('ledger', ('listed', 'not-in-snapshot')), ('other', ('not-in-snapshot', 'listed')),
                            ('unknown', ('unknown', 'unknown'))):
        s = sources_for(arms()['full'].with_(kev=variant))
        assert tuple(ctx.kev.state for ctx in s.contexts) == states
        assert tuple(s.kev.lookup(cve).state for cve in (CVE1, CVE2)) == states
        assert (s.kev.snapshot_id() is None) == (variant == 'unknown')
    only_csaf = sources_for(arms()['full'].with_(advisory_sources=frozenset({'stated'})))
    assert [o.kind for o in only_csaf.advisory_observations[CVE1]] == ['adv:cwe-stated']
    assert len(sources_for(arms()['full']).advisory_observations[CVE1]) == 4
    (flag,) = sources_for(arms()['adv-b1'].with_(binary_toolchain_flag=True)).tools.pair_observations()
    assert flag.kind == 'die:toolchain-changed' and flag.role == 'context' and flag.origins == ('D_compiler',)
    assert flag.obs_id not in {o.obs_id for _, o in ledger.observations}  # not F3's own build fact
    dropped = ledger.observations[0][1].obs_id
    reduced = sources_for(arms()['full'].with_(dropped=frozenset({dropped})))
    assert dropped not in {o.obs_id for _, o in observed(reduced, [f.key for f in ledger.functions])}


# --- the engine: PIL-B2 (xfail strict; expects only EngineMissing) ----------------------------------------------------

CHECKS = {
    'class': lambda lead: lead.lead_class, 'mechanism': lambda lead: lead.mechanism,
    'identity': lambda lead: lead.identity, 'depth': lambda lead: lead.depth, 'caps': lambda lead: list(lead.caps),
    'components': lambda lead: lead.components.count, 'local_hits': lambda lead: lead.local_hits,
    'tie_size': lambda lead: lead.tie.size}
FIT_CHECKS = {'basis': lambda fit: fit.basis, 'rule': lambda fit: fit.rule_id, 'cwe': lambda fit: fit.cwe_id}


def check_lead(fid: str, lead: c.Lead, spec: dict) -> None:
    """Assert every field the oracle states for one lead (fields it does not state are not asserted)."""
    for name, read in CHECKS.items():
        if name in spec:
            assert read(lead) == spec[name], f'{fid}: {name}'
    if 'rank' in spec:
        assert spec['rank'][0] <= lead.rank <= spec['rank'][1], f'{fid}: rank {lead.rank} outside {spec["rank"]}'
    if 'met' in spec:
        assert (lead.fits[0].met, lead.fits[0].total) == (spec['met'], spec['total']), f'{fid}: expected changes'
    for name, read in FIT_CHECKS.items():
        if name in spec:
            assert read(lead.fits[0]) == spec[name], f'{fid}: {name}'  # fits are ordered best first


@PIL_B2
def test_synergy_full_arm_isolates_truth():
    want = expected()['full'][CVE1]
    assessment = run_arm('full')
    keys.verify_assessment(assessment)  # the result certifies its own identity
    assert assessment.status != 'abstained'
    leads = lead_map(assessment, CVE1)
    assert sorted(leads) == sorted(FUNCTION_IDS)
    for fid, spec in want['leads'].items():
        check_lead(fid, leads[fid], spec)
    assert sorted(lead.rank for lead in leads.values()) == list(range(1, 10))
    assert classes(leads, 'fit') == want['fit_leads'] == ['F1']  # the truth is the only FITS lead ...
    assert leads['F1'].rank == 1 and leads['F1'].tie == c.Tie(size=1, first=1, last=1)  # ... and it is first, alone
    assert leads['F9'].rank == 2 and leads['F8'].rank == 3  # identity: the contested pairing is listed last
    context = next(x for x in assessment.cves if x.cve == CVE1)
    assert context.gate == 'applies' and context.counts.model_dump() == want['counts']
    assert context.confounding.state == 'yes' and context.confounding.cves == (CVE1, CVE2)
    assert context.kev.state == 'listed' and context.kev.date_added == '2099-02-10'
    assert context.cwe.status == 'explicit' and 'CWE-787' in context.cwe.ids
    assert {f.rule_id for f in leads['F1'].fits} == {'R-MEMORY-WRITE'}


@PIL_B2
@pytest.mark.parametrize('arm_id', ARM_IDS, ids=ARM_IDS)
def test_synergy_single_channel_arms_fall_short(arm_id):
    spec = expected()['arms'][arm_id]
    assessment = run_arm(arm_id)
    leads = lead_map(assessment, None if spec['code_only'] else CVE1)
    assert sorted(leads) == sorted(FUNCTION_IDS)
    assert [leads['F1'].tie.first, leads['F1'].tie.last] == spec['f1_rank']  # the table's "n-m (tie)"
    if spec['ties_with']:
        assert tie_partners(leads, 'F1') == spec['ties_with']
    if spec['top']:
        assert sorted(f for f, lead in leads.items() if lead.tie.last <= len(spec['top'])) == spec['top']
    if spec['fit_leads'] is None:  # no advisory: code evidence can order functions, never fit them to a CVE
        assert not assessment.cves and {lead.gate for lead in leads.values()} == {'none'}
        assert {lead.lead_class for lead in leads.values()} <= {'code', 'queue'}
    else:
        assert classes(leads, 'fit') == spec['fit_leads']
    if arm_id == 'window-unknown':
        assert leads['F6'].rank == 2  # "F6 listed second"
        assert all(x.confounding.state == 'unknown' for x in assessment.cves)


@PIL_B2
def test_second_cve_gets_its_own_fit_lead():
    assessment = run_arm('full')
    want = expected()['full'][CVE2]
    second = lead_map(assessment, CVE2)
    for fid, spec in want['leads'].items():
        check_lead(fid, second[fid], spec)
    assert classes(second, 'fit') == want['fit_leads'] == ['F6'] and second['F6'].rank == 1
    assert second['F1'].lead_class == 'partial' and 'confounded-window-needs-locality' in second['F1'].caps
    assert classes(lead_map(assessment, CVE1), 'fit') == ['F1']  # the first CVE keeps its own
    contexts = {x.cve: x for x in assessment.cves}
    assert contexts[CVE2].counts.fit == 1 and contexts[CVE2].cwe.ids == ('CWE-125',) and contexts[CVE2].gate == 'applies'
    assert second['F6'].fits[0].rule_id == 'R-MEMORY-READ' and second['F6'].fits[0].cwe_id == 'CWE-125'


def summary(assessment: c.PilotAssessment) -> list:
    """Everything a lead says except which observations back it (the pool differs when the sources differ)."""
    return [(lead.cve, lead.rank, lead.candidate_key, lead.lead_class, lead.mechanism, lead.tie, lead.identity,
             lead.depth, lead.caps, lead.components,
             tuple((f.rule_id, f.cwe_id, f.met, f.total, tuple((e.id, e.state) for e in f.expected_changes))
                   for f in lead.fits)) for lead in assessment.leads]


@PIL_B2
def test_more_advisory_sources_do_not_add_independence():
    steps = [('stated',), ('stated', 'nvd'), ('stated', 'nvd', 'msrc'), ('stated', 'nvd', 'msrc', 'kev')]
    results = []
    for step in steps:  # the CWE is repeated by one, two, three and four sources of the same origin
        assessment = run_arm(arms()['full'].with_(advisory_sources=frozenset(step)))
        f1 = lead_map(assessment, CVE1)['F1']
        assert (f1.components.count, f1.components.tags) == (2, ('D_ghidra', 'D_vendor_text')), step
        results.append(summary(assessment))
    assert all(result == results[0] for result in results), 'repeating the advisory changed a lead'


@PIL_B2
@pytest.mark.parametrize('sources', [('b1',), ('cf',), ('b1', 'cf'), ('b1', 'cf', 'calls')],
                         ids=['b1', 'cf', 'b1-cf', 'b1-cf-calls'])
def test_b1_and_changefacts_are_one_component(sources):
    arm = arms()['full'].with_(sources=frozenset({'advisory', 'die', 'pairing', *sources}))
    leads = lead_map(run_arm(arm), CVE1)
    f1 = leads['F1']
    assert (f1.components.count, f1.components.tags) == (2, ('D_ghidra', 'D_vendor_text'))  # B1 shares D_ghidra
    assert f1.lead_class == 'fit' and f1.depth == ('lexical' if sources == ('b1',) else 'typed')
    assert all(lead.components.count <= 2 for lead in leads.values())  # nothing reaches a third independent witness


def channel_state(assessment: c.PilotAssessment, channel: str) -> str:
    return next(x.state for x in assessment.channels if x.channel == channel)


@PIL_B2
@pytest.mark.parametrize('dropped', ['capa', 'floss'], ids=['capa', 'floss'])
def test_unavailable_channel_is_unknown_not_unmet(dropped):
    full = run_arm('full')
    base = arms()['full']
    reduced = run_arm(base.with_(sources=base.sources - {dropped}))
    channel = {'capa': 'capa', 'floss': 'strings'}[dropped]
    assert channel_state(full, channel) == 'available' and channel_state(reduced, channel) == 'not-run'
    assert reduced.status != 'abstained' and len(full.leads) == len(reduced.leads)
    for before, after in zip(full.leads, reduced.leads, strict=True):
        assert (before.cve, before.candidate_key, before.rank, before.lead_class, before.mechanism, before.tie,
                before.components, before.caps) == (after.cve, after.candidate_key, after.rank, after.lead_class,
                                                    after.mechanism, after.tie, after.components, after.caps)
        for old, new in zip(before.fits, after.fits, strict=True):
            assert old.met == new.met  # a channel that did not run never removes a met change
            for was, now in zip(old.expected_changes, new.expected_changes, strict=True):
                # the only move allowed: an unmet change that needed the missing channel becomes unknown
                assert now.state == was.state or (was.state, now.state) == ('not-observed', 'unknown')


@PIL_B2
def test_kev_never_changes_function_order():
    expected_states = {'ledger': {CVE1: 'listed', CVE2: 'not-in-snapshot'},
                       'other': {CVE1: 'not-in-snapshot', CVE2: 'listed'},
                       'unknown': {CVE1: 'unknown', CVE2: 'unknown'}}
    runs = {}
    for variant, states in expected_states.items():
        assessment = run_arm(arms()['full'].with_(kev=variant))
        assert {x.cve: x.kev.state for x in assessment.cves} == states
        runs[variant] = assessment
    assert summary(runs['ledger']) == summary(runs['other']) == summary(runs['unknown'])
    for cve in (CVE1, CVE2):
        assert ranked(lead_map(runs['ledger'], cve)) == ranked(lead_map(runs['other'], cve))
    assert ranked(lead_map(runs['ledger'], CVE1))[0] == 'F1' and ranked(lead_map(runs['other'], CVE2))[0] == 'F6'


@PIL_B2
def test_die_flag_caps_lexical_only_lead():
    plain = lead_map(run_arm('adv-b1'), CVE1)
    assert classes(plain, 'fit') == ['F1', 'F9']  # lexical B1 evidence alone reaches moderate (plan s11, question 5)
    flagged = lead_map(run_arm(arms()['adv-b1'].with_(binary_toolchain_flag=True)), CVE1)
    for fid in ('F1', 'F9'):
        assert flagged[fid].lead_class == 'partial' and flagged[fid].depth == 'lexical', fid
        assert 'toolchain-changed-lexical-only' in flagged[fid].caps, fid
    assert classes(flagged, 'fit') == []  # a compiler change explains lexical-only evidence: nothing is promoted
    typed = lead_map(run_arm(arms()['full'].with_(binary_toolchain_flag=True)), CVE1)
    assert typed['F1'].lead_class == 'fit' and typed['F1'].depth == 'typed' and not typed['F1'].caps
    assert typed['F8'].lead_class == 'review'  # material ChangeFacts support is not capped by the same flag
    assert typed['F9'].lead_class == 'partial' and 'toolchain-changed-lexical-only' in typed['F9'].caps


@PIL_B2
def test_equal_evidence_forms_tie_group():
    ledger = load_ledger()
    leads = lead_map(run_arm('b1'), None)
    group = sorted(f for f, lead in leads.items() if lead.tie.size == 5)
    assert group == ['F1', 'F4', 'F6', 'F8', 'F9']  # the five pairs that carry a B1 detection (plan: "five pairs")
    assert {leads[f].tie for f in group} == {c.Tie(size=5, first=1, last=5)}
    assert {leads[f].lead_class for f in group} == {'code'}
    assert sorted(leads[f].rank for f in group) == [1, 2, 3, 4, 5]  # one display position each, tied evidence
    assert all(lead.rank > 5 for f, lead in leads.items() if f not in group)
    # inside a tie the display order is the candidate key (no attention rank is given), never the RVA
    by_rank = sorted(group, key=lambda f: leads[f].rank)
    assert by_rank == sorted(group, key=ledger.key_of)
    assert by_rank != sorted(group, key=lambda f: next(x.older.rva for x in ledger.functions if x.id == f))
    assert ranked(lead_map(run_arm('b1'), None)) == ranked(leads)  # and it is stable across runs


@PIL_B2
def test_removing_support_never_raises_a_tier():
    ledger = load_ledger()
    full = arms()['full']
    support = [obs.obs_id for _, obs in ledger.observations if obs.role == 'shape']
    assert len(support) == 9

    def class_ranks(assessment: c.PilotAssessment) -> dict:
        return {(cve, fid): c.CLASS_RANK[lead.lead_class] for cve in (CVE1, CVE2)
                for fid, lead in lead_map(assessment, cve).items()}

    def raised(before: dict, after: dict) -> dict:
        """(context, function) -> (class rank before, after) for every lead that moved to a stronger class."""
        return {key: (before[key], after[key]) for key in before if after[key] < before[key]}

    reference = class_ranks(run_arm(full))
    for obs_id in support:  # one observation at a time
        reduced = class_ranks(run_arm(full.with_(dropped=frozenset({obs_id}))))
        assert not raised(reference, reduced), (obs_id, raised(reference, reduced))
    previous = reference
    dropped: set[str] = set()
    for obs_id in support:  # and cumulatively: each step can only keep or lower every tier
        dropped.add(obs_id)
        current = class_ranks(run_arm(full.with_(dropped=frozenset(dropped))))
        assert not raised(previous, current), (obs_id, raised(previous, current))
        previous = current


ENGINE_TESTS = (
    test_synergy_full_arm_isolates_truth, test_synergy_single_channel_arms_fall_short,
    test_second_cve_gets_its_own_fit_lead, test_more_advisory_sources_do_not_add_independence,
    test_b1_and_changefacts_are_one_component, test_unavailable_channel_is_unknown_not_unmet,
    test_kev_never_changes_function_order, test_die_flag_caps_lexical_only_lead,
    test_equal_evidence_forms_tie_group, test_removing_support_never_raises_a_tier)


def test_every_engine_test_of_the_plan_is_strictly_pending_until_the_engine_exists():
    assert len(ENGINE_TESTS) == 10  # the ten names of plan s5 "Tests on the same ledger"
    assert_strictly_pending(*ENGINE_TESTS)
