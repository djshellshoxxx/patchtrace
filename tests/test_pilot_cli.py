"""PIL-C1 `patchtrace pilot leads|why|review` (PIL-integration-plan.md s8, s9 PIL-C1).

The `enrichment-cli/1` envelope, exit codes 0/2/3/4/5 through REAL processes, one JSON document with `--json`, no Qt
import, results stored beside the project and explained from the stored copy, review events appended. The project is the
committed synthetic sample (a bounds check added to `read_item`) and the advisories are SYNTHETIC; nothing here is live
evidence.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import unicodedata
from pathlib import Path

import pytest
from pilot_synergy_support import FIXTURES
from unified_s0_fixtures import make_project as make_s0_project

from patchtrace import cli, cli_commands
from patchtrace.enrichment.storage import EnrichmentStore
from patchtrace.intelligence.storage import FACTS_DIR, AdvisoryStore
from patchtrace.pilot import cli as pilot_cli
from patchtrace.pilot import collect, keys, limits, store, why
from patchtrace.sample import synthetic_pe
from patchtrace.service import ProjectService
from patchtrace.unified.pipeline import UnifiedOptions, run_unified

SRC = str(Path(cli.__file__).resolve().parents[1])
ROOT = Path(__file__).resolve().parents[1]
SAMPLE_ADVISORY = FIXTURES / 'sample-cwe125-advisory.json'  # CVE-2099-30001, CWE-125, maps the sample's two builds
TWO_CVE_ADVISORY = FIXTURES / 'synthetic-pilot-advisory.json'  # CVE-2099-20001/20002: products the sample does not match
CVE = 'CVE-2099-30001'
BANNED_IN_OUTPUT = ('probab', 'likelihood', 'vulnerab', 'confiden', 'percent')


@pytest.fixture
def project(tmp_path):
    with ProjectService.sample(tmp_path / 'case') as service:
        return service.root


def import_advisory(root: Path, source: Path = SAMPLE_ADVISORY) -> None:
    with ProjectService.open(root) as service:
        AdvisoryStore(service.root, EnrichmentStore(service.store), service.project.id, service.project.revision).add(
            source.read_bytes(), origin='local-import', uri=None, file_name=source.name,
            retrieved_at='2099-03-01T00:00:00Z')


@pytest.fixture
def advised(project):
    import_advisory(project)
    return project


def call(args, capsys):
    code = cli.main([str(a) for a in args])
    out, err = capsys.readouterr()
    return code, out, err


def doc(out: str) -> dict:
    assert out.endswith('\n') and out.count('\n') == 1, out[:300]
    value = json.loads(out)
    assert value['contract'] == 'enrichment-cli/1'
    return value


def leads_json(root, capsys, *extra, expect=0):
    code, out, err = call(['pilot', 'leads', root, '--json', *extra], capsys)
    assert code == expect, (code, err[-400:])
    return doc(out)


def by_name(result: dict, cve=CVE) -> dict[str, dict]:
    return {row['newer'][0]['name'] if row['newer'] else row['older'][0]['name']: row
            for row in result['leads'] if row['cve'] == cve}


def stored(root: Path):
    with ProjectService.open(root) as service:
        return store.load(EnrichmentStore(service.store))


def key_of(root: Path, capsys, name: str = 'read_item', cve=CVE) -> str:
    return by_name(leads_json(root, capsys, '--dry-run', '--limit', '0')['result'], cve)[name]['candidate_key']


# --- registration -----------------------------------------------------------------------------------------------------

def test_the_verb_is_a_thin_registry_adapter_over_the_qt_free_dispatcher():
    assert 'pilot' in cli_commands.names() and 'pilot' not in cli.COMMANDS  # no cli.py line was needed
    verbs, failed = cli_commands.discover()
    assert 'pilot' in verbs and 'pilot' not in failed.values()
    adapter = ROOT / 'src' / 'patchtrace' / 'cli_commands' / 'pilot.py'
    assert len(adapter.read_text(encoding='utf-8').splitlines()) <= 25
    assert set(pilot_cli.RUNNERS) == {'leads', 'why', 'review'}


def test_help_lists_the_three_actions_and_imports_no_qt():
    code = ('import sys\nfrom patchtrace import cli\nrc = cli.main(["pilot", "--help"])\n'
            'bad = [m for m in sys.modules if m.startswith(("PySide6", "shiboken6", "patchtrace.ui"))]\n'
            'print("BAD", bad, file=sys.stderr)\nraise SystemExit(90 if bad else (rc or 0))\n')
    result = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True,
                            env=dict(os.environ, PYTHONPATH=SRC), timeout=120)
    assert result.returncode == 0 and 'leads' in result.stdout and 'why' in result.stdout and 'review' in result.stdout
    assert 'BAD []' in result.stderr


def test_no_action_imports_qt(advised):
    code = ('import sys\nfrom patchtrace import cli\nroot = sys.argv[1]\n'
            'codes = [cli.main(["pilot", "leads", root, "--json"])]\n'
            'import json, io, contextlib\n'
            'bad = [m for m in sys.modules if m.startswith(("PySide6", "shiboken6", "patchtrace.ui"))]\n'
            'print("BAD", bad, codes, file=sys.stderr)\nraise SystemExit(90 if bad else 0)\n')
    result = subprocess.run([sys.executable, '-c', code, str(advised)], capture_output=True, text=True,
                            env=dict(os.environ, PYTHONPATH=SRC), timeout=180)
    assert result.returncode == 0 and 'BAD []' in result.stderr, result.stderr[-500:]


# --- exit codes through real processes -------------------------------------------------------------------------------

def process(*args, cwd=None):
    return subprocess.run([sys.executable, '-m', 'patchtrace', *map(str, args)], capture_output=True, text=True,
                          encoding='utf-8', env=dict(os.environ, PYTHONPATH=SRC), cwd=cwd, timeout=180)


def no_run_project(tmp_path) -> Path:
    older, newer = tmp_path / 'older.exe', tmp_path / 'newer.exe'
    older.write_bytes(synthetic_pe(0))
    newer.write_bytes(synthetic_pe(1))
    service = ProjectService.create(older, newer, 'no analysis yet', tmp_path / 'blank')
    root = service.root
    service.close()
    return root


def damaged_advisory(root: Path) -> None:
    """The stored facts AND the source bytes no longer match their digests: nothing of the advisory can be used."""
    with ProjectService.open(root) as service:
        found = AdvisoryStore(service.root, EnrichmentStore(service.store), service.project.id,
                              service.project.revision).advisories()[0][0]
        files = [service.root / found.source.raw_path, service.root / FACTS_DIR / f'{found.facts.facts_id}.json']
    for path in files:
        path.write_bytes(path.read_bytes() + b' ')


def test_cli_leads_exit_codes(tmp_path, advised):
    ok = process('pilot', 'leads', advised, '--json')
    document = doc(ok.stdout)
    assert ok.returncode == 0 and document['status'] == 'complete' and 'Traceback' not in ok.stderr
    assert document['result']['status'] == 'complete'
    assert document['command'] == 'pilot leads' and len(document['result']['result_id']) == 64
    # exit 4: nothing to list (a CVE with no stored advisory; a project that was never analysed)
    unknown = process('pilot', 'leads', advised, '--cve', 'CVE-2099-77777', '--json')
    assert unknown.returncode == 4 and doc(unknown.stdout)['result']['leads'] == []
    blank = process('pilot', 'leads', no_run_project(tmp_path), '--json')
    assert blank.returncode == 4 and doc(blank.stdout)['result']['status'] == 'abstained'
    assert 'Traceback' not in blank.stderr
    # exit 2: invalid input, always before any work
    for args in (['--cve', 'nope'], ['--class', 'bogus'], ['--limit', '-1'], ['--export', tmp_path / 'x.txt'],
                 ['--export', tmp_path / 'nodir' / 'x.md'], ['--assume-applies', 'CVE-2099-12345'],
                 ['--assume-applies', 'garbage']):
        bad = process('pilot', 'leads', advised, '--json', *args)
        assert bad.returncode == 2 and 'Traceback' not in bad.stderr, args
    assert process('pilot', 'leads', tmp_path / 'absent', '--json').returncode == 2
    assert process('pilot', 'why', advised, '--candidate', 'abc').returncode == 2
    # exit 3: an adapter failed (the stored advisory no longer matches its digest): partial, still listed
    damaged_advisory(advised)
    partial = process('pilot', 'leads', advised, '--json', '--dry-run')
    result = doc(partial.stdout)
    assert partial.returncode == 3 and result['status'] == 'partial' and result['result']['leads']
    assert {c['channel']: c['state'] for c in result['result']['channels']}['advisory'] == 'failed'


def test_cancellation_exits_5_through_a_real_process(advised):
    code = ('import sys\nfrom patchtrace import cli\nfrom patchtrace.pilot import service\n'
            'def interrupted(*_a, **_k):\n    raise KeyboardInterrupt\n'
            'service.localize = interrupted\n'
            'raise SystemExit(cli.main(["pilot", "leads", sys.argv[1], "--json"]))\n')
    result = subprocess.run([sys.executable, '-c', code, str(advised)], capture_output=True, text=True,
                            encoding='utf-8', env=dict(os.environ, PYTHONPATH=SRC), timeout=180)
    assert result.returncode == 5 and doc(result.stdout)['status'] == 'cancelled' and 'Traceback' not in result.stderr
    assert stored(advised).state == 'none'


# --- leads -------------------------------------------------------------------------------------------------------------

def test_leads_json_names_the_fit_and_what_it_is_not(advised, capsys):
    document = leads_json(advised, capsys)
    result = document['result']
    rows = by_name(result)
    assert rows['read_item']['class'] == 'fit' and rows['read_item']['badge'] == 'FITS ADVISORY'
    assert rows['read_item']['expected_changes']['met'] == 1 and rows['read_item']['expected_changes']['total'] >= 1
    assert rows['read_item']['rank'] == 1 and 'text evidence only' in rows['read_item']['flags']
    assert rows['get_version']['class'] == 'queue' and rows['get_version']['badge'] == 'NOT ASSESSED'  # no change evidence
    assert result['cves'][0]['cve'] == CVE and result['cves'][0]['gate'] == 'applies'
    assert result['cves'][0]['kev']['state'] == 'unknown' and result['cves'][0]['counts']['fit'] == 1
    assert {c['channel']: c['state'] for c in result['channels']}['capa'] == 'not-run'
    assert result['stored'] is True and result['stale'] is False and result['status'] == 'complete'
    assert any(line.startswith('Summary') for line in rows['read_item']['why'])
    assert why.FOOTER in rows['read_item']['why'][-1]
    assert not [w for w in BANNED_IN_OUTPUT if w in json.dumps(result).lower().replace(why.FOOTER.lower(), '')]


def test_leads_text_is_a_plain_listing_with_the_standing_caption(advised, capsys):
    code, out, _ = call(['pilot', 'leads', advised], capsys)
    assert code == 0 and CVE in out and 'FITS ADVISORY' in out and 'read_item' in out and out.endswith(why.FOOTER + '\n')
    assert 'CISA KEV: unknown' in out and '\x1b' not in out
    assert not [w for w in BANNED_IN_OUTPUT if w in out.replace(why.FOOTER, '').lower()]


def test_the_result_is_stored_and_the_same_run_again_changes_nothing(advised, capsys):
    first = leads_json(advised, capsys)['result']
    loaded = stored(advised)
    assert loaded.state == 'current' and loaded.assessment.result_id == first['result_id']
    sidecars = sorted(p.name for p in (advised / 'intelligence' / 'pilot').iterdir())
    again = leads_json(advised, capsys)['result']
    assert again['result_id'] == first['result_id']
    assert sorted(p.name for p in (advised / 'intelligence' / 'pilot').iterdir()) == sidecars
    assert [r['candidate_key'] for r in again['leads']] == [r['candidate_key'] for r in first['leads']]


def test_a_dry_run_persists_nothing(advised, capsys):
    result = leads_json(advised, capsys, '--dry-run')['result']
    assert result['stored'] is False and stored(advised).state == 'none'
    assert not (advised / 'intelligence' / 'pilot').exists()


def test_filters_choose_what_is_shown_not_what_is_computed(advised, capsys):
    everything = leads_json(advised, capsys, '--limit', '0')['result']
    only_fit = leads_json(advised, capsys, '--class', 'fit')['result']
    assert [r['class'] for r in only_fit['leads']] == ['fit'] and only_fit['result_id'] == everything['result_id']
    two = leads_json(advised, capsys, '--limit', '2')['result']
    assert len([r for r in two['leads'] if r['cve'] == CVE]) == 2
    named = leads_json(advised, capsys, '--cve', CVE)['result']
    assert {r['cve'] for r in named['leads']} == {CVE} and named['result_id'] == everything['result_id']
    none = leads_json(advised, capsys, '--class', 'review', expect=4)['result']
    assert none['leads'] == [] and none['result_id'] == everything['result_id']


def test_without_an_advisory_the_code_evidence_alone_is_listed(project, capsys):
    result = leads_json(project, capsys)['result']
    assert result['cves'] == [] and {r['cve'] for r in result['leads']} == {None}
    assert {r['class'] for r in result['leads']} <= {'code', 'queue'}
    assert {c['channel']: c['state'] for c in result['channels']}['advisory'] == 'not-run'
    assert any(r['badge'] == 'CODE CHANGE' for r in result['leads'])


def test_an_assumption_turns_an_unmapped_advisory_into_an_asserted_gate_and_is_part_of_the_result(project, capsys):
    import_advisory(project, TWO_CVE_ADVISORY)
    plain = leads_json(project, capsys)['result']
    assert {c['cve']: c['gate'] for c in plain['cves']} == {'CVE-2099-20001': 'unverified', 'CVE-2099-20002': 'unverified'}
    assumed = leads_json(project, capsys, '--assume-applies', 'CVE-2099-20001')['result']
    assert {c['cve']: c['gate'] for c in assumed['cves']} == {'CVE-2099-20001': 'asserted', 'CVE-2099-20002': 'unverified'}
    assert assumed['result_id'] != plain['result_id']  # the analyst's assumption is an input of the result
    assert stored(project).assessment.inputs.asserted_gates == ('CVE-2099-20001',)
    classes = {r['class'] for r in assumed['leads'] if r['cve'] == 'CVE-2099-20002'}
    assert 'fit' not in classes  # an unverified gate caps at partial fit
    code, out, _ = call(['pilot', 'leads', project], capsys)
    assert code == 0 and 'could not be tied to these builds' in out.replace('\n', ' ')


def test_a_cve_the_run_cannot_hold_must_be_named_and_then_narrows_it():
    names = [f'CVE-2099-{n:05d}' for n in range(1, 6)]
    assert collect.universe(names, [], cap=64) == (tuple(names), tuple(names))
    assert collect.universe(names, ['CVE-2099-00002'], cap=64) == (tuple(names), ('CVE-2099-00002',))
    narrowed = collect.universe(names, ['CVE-2099-00002', 'CVE-2099-00004'], cap=3)
    assert narrowed == (('CVE-2099-00002', 'CVE-2099-00004'), ('CVE-2099-00002', 'CVE-2099-00004'))
    with pytest.raises(limits.PilotError) as raised:
        collect.universe(names, [], cap=3)
    assert raised.value.code == 'PT-PILOT-INPUT' and raised.value.reason == 'too-many-cves'
    with pytest.raises(limits.PilotError) as raised:
        collect.universe(names, ['CVE-2099-99999'], cap=64)
    assert raised.value.code == 'PT-PILOT-NOTFOUND'


def test_a_current_unified_result_is_the_pairing_unless_it_is_switched_off(tmp_path, capsys):
    service = make_s0_project(tmp_path / 'unified')  # the same synthetic builds as the sample, with a unified-ready run
    run_unified(service, UnifiedOptions(isolate=False))
    root = service.root
    service.close()
    import_advisory(root)
    typed = leads_json(root, capsys)['result']
    used = stored(root).assessment
    assert used.inputs.unified_result_id is not None and used.inputs.secondary_set_ids == ()
    plain = leads_json(root, capsys, '--no-unified', '--dry-run')['result']
    assert plain['result_id'] != typed['result_id']
    kinds = {o.kind for o in used.observations}
    assert any(kind.startswith('cf:') for kind in kinds)  # typed ChangeFacts reached the leads
    assert {c['channel']: c['state'] for c in typed['channels']}['pairing'] in ('available', 'partial')
    assert 'cf:call-added' in kinds  # read_item gained a call: a typed observation, not a guard


def test_a_stale_unified_result_is_named_and_never_mixed_with_the_ghidriff_pairing(advised, capsys):
    with ProjectService.open(advised) as service:
        run_unified(service, UnifiedOptions(isolate=False))  # the sample's own result is stored as out of date
    code, out, err = call(['pilot', 'leads', advised, '--json', '--dry-run'], capsys)
    document = doc(out)
    assert code == 0 and any('unified result could not be used' in w for w in document['warnings'])
    assert by_name(document['result'])['read_item']['class'] == 'fit'


def test_export_writes_the_report_in_the_format_of_the_suffix(advised, capsys, tmp_path):
    md, js = tmp_path / 'leads.md', tmp_path / 'leads.json'
    result = leads_json(advised, capsys, '--export', md)['result']
    assert result['export']['format'] == 'md' and result['export']['bytes'] == md.stat().st_size
    assert hashlib.sha256(md.read_bytes()).hexdigest() == result['export']['sha256']
    assert md.read_text(encoding='utf-8').startswith('# Patch-intent leads\n') and b'\r' not in md.read_bytes()
    leads_json(advised, capsys, '--export', js)
    assert json.loads(js.read_text(encoding='utf-8'))['result_id'] == result['result_id']
    assert sorted(p.name for p in tmp_path.iterdir() if p.is_file()) == ['leads.json', 'leads.md']


def test_the_export_target_is_checked_before_any_work(advised, capsys, tmp_path):
    code, out, err = call(['pilot', 'leads', advised, '--export', tmp_path / 'leads.txt', '--json'], capsys)
    assert code == 2 and stored(advised).state == 'none'
    code, _, _ = call(['pilot', 'leads', advised, '--export', tmp_path, '--json'], capsys)
    assert code == 2


# --- why ---------------------------------------------------------------------------------------------------------------

def test_why_explains_a_stored_lead_without_recomputing(advised, capsys):
    leads_json(advised, capsys)
    key = by_name(json.loads(call(['pilot', 'leads', advised, '--json', '--dry-run'], capsys)[1])['result'])['read_item'][
        'candidate_key']
    code, out, _ = call(['pilot', 'why', advised, '--candidate', key, '--cve', CVE, '--json'], capsys)
    document = doc(out)
    row = document['result']['leads'][0]
    assert code == 0 and document['command'] == 'pilot why' and row['cve'] == CVE and row['class'] == 'fit'
    assert row['why'][0] == 'Summary' and any('guard added' in line for line in row['why'])
    assert document['result']['stale'] is False and document['result']['candidate_key'] == key
    text = call(['pilot', 'why', advised, '--candidate', key], capsys)[1]
    assert 'Expected changes' in text and 'Independent evidence' in text and text.rstrip().endswith(why.FOOTER)
    assert '\n  Next step: Open the newer function' in text  # the indentation of the stored lines is kept


def test_why_says_nothing_it_cannot_find(advised, capsys):
    assert call(['pilot', 'why', advised, '--candidate', '0' * 64, '--json'], capsys)[0] == 4  # no stored result at all
    leads_json(advised, capsys)
    code, out, _ = call(['pilot', 'why', advised, '--candidate', '1' * 64, '--json'], capsys)
    assert code == 4 and doc(out)['result']['leads'] == []
    key = by_name(leads_json(advised, capsys, '--dry-run')['result'])['read_item']['candidate_key']
    assert call(['pilot', 'why', advised, '--candidate', key, '--cve', 'CVE-2099-77777', '--json'], capsys)[0] == 4


def test_a_stored_result_after_an_orientation_swap_is_shown_as_out_of_date(advised, capsys):
    result = leads_json(advised, capsys)['result']
    key = by_name(result)['read_item']['candidate_key']
    with ProjectService.open(advised) as service:
        service.swap_orientation()
    code, out, _ = call(['pilot', 'why', advised, '--candidate', key, '--json'], capsys)
    document = doc(out)
    assert code == 0 and document['result']['stale'] is True
    assert set(document['result']['changed']) >= {'older_sha256', 'newer_sha256'}
    code, text, err = call(['pilot', 'why', advised, '--candidate', key], capsys)
    assert code == 0 and 'These leads are out of date (the older build, the newer build changed)' in err
    assert 'Summary' in text


def test_why_with_a_damaged_stored_result_is_exit_3(advised, capsys):
    leads_json(advised, capsys)
    loaded = stored(advised)
    (advised / loaded.pointer.relative_dir / 'assessment.json.gz').write_bytes(b'garbage')
    code, out, err = call(['pilot', 'why', advised, '--candidate', '0' * 64, '--json'], capsys)
    assert code == 3 and 'Traceback' not in err and doc(out)['status'] == 'failed'


# --- review ------------------------------------------------------------------------------------------------------------

def test_review_events_append_only_through_the_cli(advised, capsys):
    leads_json(advised, capsys)
    result = leads_json(advised, capsys, '--dry-run', '--limit', '0')['result']
    rows = by_name(result)
    fit, other = rows['read_item']['candidate_key'], rows['get_version']['candidate_key']
    code, out, _ = call(['pilot', 'review', advised, '--candidate', other, '--cve', CVE, '--action', 'pin', '--json'], capsys)
    assert code == 0 and doc(out)['result']['event']['action'] == 'pin' and doc(out)['command'] == 'pilot review'
    before = review_rows(advised)
    pinned = by_name(leads_json(advised, capsys, '--dry-run', '--limit', '0')['result'])
    assert pinned['get_version']['pinned'] is True and pinned['get_version']['class'] == 'queue'  # class never changes
    ordered = [r['candidate_key'] for r in leads_json(advised, capsys, '--dry-run', '--limit', '0')['result']['leads']
               if r['cve'] == CVE]
    assert ordered[0] == other and ordered[1] == fit  # the Pinned band comes first
    code, _, _ = call(['pilot', 'review', advised, '--candidate', fit, '--cve', CVE, '--action', 'dismiss',
                       '--text', 'compiler churn', '--json'], capsys)
    assert code == 0
    hidden = leads_json(advised, capsys, '--dry-run', '--limit', '0')['result']
    assert fit not in {r['candidate_key'] for r in hidden['leads'] if r['cve'] == CVE}  # that list only
    assert fit in {r['candidate_key'] for r in hidden['leads'] if r['cve'] is None}
    shown = by_name(leads_json(advised, capsys, '--dry-run', '--limit', '0', '--show-dismissed')['result'])
    assert shown['read_item']['dismissed'] is True and shown['read_item']['class'] == 'fit'
    code, _, _ = call(['pilot', 'review', advised, '--candidate', fit, '--cve', CVE, '--action', 'restore', '--json'], capsys)
    assert code == 0
    code, _, _ = call(['pilot', 'review', advised, '--candidate', fit, '--cve', CVE, '--action', 'note',
                       '--text', 'Looks like the real check.', '--json'], capsys)
    text = call(['pilot', 'why', advised, '--candidate', fit, '--cve', CVE], capsys)[1]
    assert 'Analyst statement' in text and 'Looks like the real check.' in text and 'compiler churn' in text
    after = review_rows(advised)
    assert set(before) <= set(after) and all(after[i] == v for i, v in before.items())  # earlier rows are untouched
    assert len(after) == 4
    reread = leads_json(advised, capsys, '--limit', '0')['result']  # a recompute keeps every review
    assert len(review_rows(advised)) == 4 and by_name(reread)['read_item']['class'] == 'fit'


def review_rows(root: Path) -> dict:
    with ProjectService.open(root) as service:
        rows = service.store.connection.execute(
            "SELECT id, body_sha256, created FROM enrichment_entries WHERE id LIKE 'pilot-review:%'").fetchall()
    return {row[0]: row[1:] for row in rows}


def test_review_refuses_what_it_cannot_attach_to(advised, capsys):
    key = '2' * 64
    assert call(['pilot', 'review', advised, '--candidate', key, '--action', 'pin', '--json'], capsys)[0] == 4  # no result
    leads_json(advised, capsys)
    assert call(['pilot', 'review', advised, '--candidate', key, '--action', 'pin', '--json'], capsys)[0] == 4
    real = by_name(leads_json(advised, capsys, '--dry-run')['result'])['read_item']['candidate_key']
    assert call(['pilot', 'review', advised, '--candidate', real, '--cve', 'CVE-2099-77777', '--action', 'pin',
                 '--json'], capsys)[0] == 4
    assert call(['pilot', 'review', advised, '--candidate', real, '--cve', CVE, '--action', 'note', '--json'],
                capsys)[0] == 2  # a note needs text
    assert call(['pilot', 'review', advised, '--candidate', real, '--cve', CVE, '--action', 'note', '--text', 'bell\x07',
                 '--json'], capsys)[0] == 2
    assert call(['pilot', 'review', advised, '--candidate', real, '--cve', CVE, '--action', 'note', '--text', 'x' * 2049,
                 '--json'], capsys)[0] == 2
    assert call(['pilot', 'review', advised, '--candidate', real, '--action', 'shred', '--json'], capsys)[0] == 2
    assert review_rows(advised) == {}


# --- whole-run properties ---------------------------------------------------------------------------------------------

def test_the_listing_never_prints_a_control_character_or_a_bidi_mark(advised, capsys):
    code, out, err = call(['pilot', 'leads', advised, '--limit', '0'], capsys)
    for text in (out, err):
        assert not [ch for ch in text if ch != '\n' and unicodedata.category(ch) in ('Cc', 'Cf', 'Cs', 'Co', 'Cn')]


def hostile_project(tmp_path) -> Path:
    """The S0 fixture project whose `read_item` is named like an attack: markup, a Markdown link, a pipe, a bidi override."""
    from types import SimpleNamespace

    from unified_s0_fixtures import patch_document
    name = f'<img src=x onerror=alert(1)>[x](javascript:alert(1))|a{chr(0x202e)}b'
    stub = SimpleNamespace(artifacts=[SimpleNamespace(side='older', sha256=hashlib.sha256(synthetic_pe(0)).hexdigest()),
                                      SimpleNamespace(side='newer', sha256=hashlib.sha256(synthetic_pe(1)).hexdigest())])
    document = json.loads(json.dumps(patch_document(stub)).replace('read_item', json.dumps(name)[1:-1]))
    service = make_s0_project(tmp_path / 'hostile', document=document)
    root = service.root
    service.close()
    import_advisory(root)
    return root


def test_hostile_function_names_stay_inert_in_the_terminal_listing_and_the_report(tmp_path, capsys):
    root = hostile_project(tmp_path)
    md = tmp_path / 'hostile.md'
    code, out, err = call(['pilot', 'leads', root, '--limit', '0', '--export', md], capsys)
    text = md.read_text(encoding='utf-8')
    assert code == 0 and 'onerror=alert(1)' in out  # the name is on the terminal, as text
    for shown in (out, err, text):
        assert not [ch for ch in shown if ch != '\n' and unicodedata.category(ch) in ('Cc', 'Cf', 'Cs', 'Co', 'Cn')]
    prose = '\n'.join(line.removeprefix('> ') for line in text.splitlines())
    assert '<' not in prose and '>' not in prose and '](' not in text and 'javascript:' not in text
    assert 'onerror\\=alert' in text  # present, escaped
    width = None
    for line in text.splitlines():  # the pipe in the name did not add a cell to any row
        if not line.startswith('|'):
            width = None
        elif width is None:
            width = line.count(' | ')
        else:
            assert line.count(' | ') == width, line
    document = leads_json(root, capsys, '--dry-run', '--limit', '0')
    names = {ref['name'] for row in document['result']['leads'] for ref in row['newer']}
    assert any(n and 'onerror=alert(1)' in n for n in names)  # JSON carries it as data


def test_the_stored_result_follows_the_contract(advised, capsys):
    leads_json(advised, capsys)
    loaded = stored(advised)
    keys.verify_assessment(loaded.assessment)
    keys.verify_manifest(loaded.manifest, loaded.assessment)
    assert loaded.assessment.inputs.unified_result_id is None
    assert {r.rva for lead in loaded.assessment.leads for r in lead.newer} >= {0x1080}
