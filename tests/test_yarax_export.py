"""R5 export: exact header, hard gates, warnings, destination policy, and that accepting never exports."""
# ruff: noqa: F811  (the imported `project` fixture is re-declared as a test argument)
from __future__ import annotations

import threading
from pathlib import Path

import pytest

yara_x = pytest.importorskip('yara_x')

import yarax_fixtures as fx  # noqa: E402
from intel_tools_support import image_getter  # noqa: E402
from test_intel_tools_pe import PAIRS  # noqa: E402
from test_yarax_store import NOW, project  # noqa: E402, F401  (project is a fixture)

from patchtrace.yarax import candidates, export, matrix  # noqa: E402
from patchtrace.yarax.adapters import tools_delta  # noqa: E402
from patchtrace.yarax.contracts import Gate, RuleDecision, RuleVersion, text_sha256  # noqa: E402
from patchtrace.yarax.errors import RulesError  # noqa: E402
from patchtrace.yarax.synth import parse_rule  # noqa: E402

GOLDEN = Path(__file__).resolve().parent / 'fixtures' / 'yarax' / 'golden' / 'export-newer-v1.yar'
TESTED_AT = '2026-10-14T10:30:00Z'
PRODUCT = '0.1.0'


def anchors_of(project):
    out = {}
    for artifact in project.service.project.artifacts:
        out[artifact.side] = matrix.file_target(project.service.root / artifact.relative_path,
                                                f'{artifact.side}-anchor', None, label=artifact.name,
                                                sha256=artifact.sha256, size=artifact.size)
    return out


def fixed_candidates(project, tmp_path):
    """Deterministic candidates (project id 'proj-1') whose compile and sep gates come from the real engine."""
    (tmp_path / 'img').mkdir(exist_ok=True)
    get, close = image_getter(tmp_path / 'img')
    try:
        delta, readers = fx.floss_delta(get, 'floss-static')
        pair = fx.pair_source(get, 'floss-static', match_id='m1', category='modified')
        found = candidates.propose(pair, writer=matrix.synth_writer(), engine=fx.ENGINE,
                                   strings=tools_delta.FlossStringSource(delta, readers))
    finally:
        close()
    engine = matrix.worker_engine(cancel=threading.Event(), private_dir=tmp_path)
    anchors = {side: made.worker() for side, made in anchors_of(project).items()}
    return {c.direction: matrix.evaluate(c, anchors, engine) for c in found}


def accepted(project, tmp_path, direction='newer', *, tested=True):
    candidate = fixed_candidates(project, tmp_path)[direction]
    _decision, version = project.store.decide(candidate, 'accept', label='Length check added',
                                              cve=['CVE-2026-0001'], now=lambda: NOW)
    if tested:
        engine = matrix.worker_engine(cancel=threading.Event(), private_dir=tmp_path)
        clean = tmp_path / 'clean'
        clean.mkdir(exist_ok=True)
        (clean / 'other.dll').write_bytes(PAIRS['capa-api']()[0])
        targets = matrix.collect_targets(tuple(anchors_of(project).values()), clean_dir=clean)
        rule = matrix.MatrixRule(name=candidate.rule_name, text=version.rule_text, direction=direction,
                                 version_id=version.version_id, rule_sha256=version.rule_sha256)
        run = matrix.run_matrix([rule], targets.targets, engine=engine, stamp=fx.ENGINE, cancel=threading.Event(),
                                run_id='run-a', skipped=())
        project.store.add_test(run, [version])
    return candidate, version


def render(project, version, **kwargs):
    return export.render(project.store, version, product_version=PRODUCT, older_name='older.dll',
                         newer_name='newer.dll', include_names=kwargs.get('include_names', False))


def freeze_time(project, monkeypatch):
    original = project.store.latest_test
    monkeypatch.setattr(project.store, 'latest_test',
                        lambda version_id: (lambda found: (found[0], TESTED_AT) if found else None)(original(version_id)))


def do_export(project, version, out, **kwargs):
    kwargs.setdefault('with_warnings', True)
    return export.export_rule(project.store, version, out, product_version=PRODUCT, older_name='older.dll',
                              newer_name='newer.dll', now=lambda: NOW, **kwargs)


def test_export_matches_the_golden_file_byte_for_byte(project, tmp_path, monkeypatch):
    _candidate, version = accepted(project, tmp_path)
    freeze_time(project, monkeypatch)
    text = render(project, version)
    assert text == GOLDEN.read_text(encoding='utf-8')
    assert '\r' not in text and text.startswith('// patchtrace-rule-export/1\n')


def test_header_lines_are_the_specified_ones_and_leak_nothing(project, tmp_path, monkeypatch):
    _candidate, version = accepted(project, tmp_path)
    freeze_time(project, monkeypatch)
    text = render(project, version)
    head, body = text.split('\nimport "pe"', 1)
    lines = head.splitlines()
    assert all(line.startswith('// ') for line in lines) and len(lines) == 10
    assert lines[2] == '// Built by PatchTrace 0.1.0 with YARA-X 1.21.0 (BSD-3-Clause) and iced-x86 1.21.0'
    assert lines[6].startswith('// Accepted 2026-10-14T10:00:00Z. Tested 2026-10-14T10:30:00Z: 2 builds, 1 clean files, ')
    assert lines[7] == ('// Advisory anchors given by the analyst and not checked by this rule: CVE-2026-0001')
    assert 'function names omitted' in lines[5] and 'function_newer_name' not in text
    assert str(tmp_path) not in text and str(Path.home()) not in text
    assert parse_rule('import "pe"' + body) == parse_rule(version.rule_text)


def test_accept_and_export_are_separate_actions(project, tmp_path):
    out = tmp_path / 'out' / 'rule.yar'
    out.parent.mkdir()
    _candidate, version = accepted(project, tmp_path)
    assert not out.exists() and project.store.exports() == []
    record, _warnings = do_export(project, version, out)
    assert out.is_file() and [e.export_id for e in project.store.exports()] == [record.export_id]
    assert record.basename == 'rule.yar' and record.version_id == version.version_id


def test_a_hard_gate_that_has_not_passed_refuses_the_export(project, tmp_path):
    candidate = project.candidates['newer']   # gates were never run on the engine: sep and compile are unknown
    _d, version = project.store.decide(candidate, 'accept', label='unchecked', now=lambda: NOW)
    with pytest.raises(RulesError) as caught:
        do_export(project, version, tmp_path / 'x.yar')
    assert caught.value.code == 'PT-RULE-GATE' and 'sep is unknown' in caught.value.message
    assert not (tmp_path / 'x.yar').exists()


def test_secret_strings_never_exported(project, tmp_path):
    candidate = fixed_candidates(project, tmp_path)['newer']
    flagged = candidate.model_copy(update={'gates': tuple(
        Gate(gate_id='secret', state='fail', measured=1) if g.gate_id == 'secret' else g for g in candidate.gates)})
    project.store.add_candidate(flagged)
    version = _unchecked_version(project, flagged)
    with pytest.raises(RulesError) as caught:
        do_export(project, version, tmp_path / 'secret.yar')
    assert caught.value.code == 'PT-RULE-GATE' and 'secret is fail' in caught.value.message


def _unchecked_version(project, candidate):
    """A version row whose accept skipped the gates (as an older client could have written it): export still checks."""
    decision = RuleDecision(decision_id='e' * 64, candidate_id=candidate.candidate_id, action='accept',
                            analyst_label='forced', decided_at=NOW)
    project.store.add_decision(decision, candidate)
    version = RuleVersion(version_id='d' * 64, lineage_id=candidate.lineage_id, version=1,
                          candidate_id=candidate.candidate_id, decision_id=decision.decision_id,
                          rule_text=candidate.rule_text, rule_sha256=text_sha256(candidate.rule_text),
                          source=candidate.source, engine=candidate.engine, created_at=NOW)
    project.store.add_version(version)
    return version


def test_untested_rules_need_the_warning_box_and_say_so(project, tmp_path):
    _c, version = accepted(project, tmp_path, tested=False)
    with pytest.raises(RulesError) as caught:
        do_export(project, version, tmp_path / 'a.yar', with_warnings=False)
    assert caught.value.code == 'PT-RULE-GATE' and 'not tested' in caught.value.message
    record, warnings = do_export(project, version, tmp_path / 'a.yar', with_warnings=True)
    assert warnings == ('not tested on any build or clean file',) and record.warnings == warnings
    text = (tmp_path / 'a.yar').read_text(encoding='utf-8')
    assert 'Accepted 2026-10-14T10:00:00Z. Not tested\n' in text


def test_a_changed_engine_makes_the_grid_stale(project, tmp_path):
    candidate, version = accepted(project, tmp_path)
    run, _at = project.store.latest_test(version.version_id)
    found = export.checklist(version, candidate, run, '1.22.0')
    assert 'the test grid is stale: the YARA-X version changed' in found.warnings and found.hard == ()
    assert export.checklist(version, candidate, run, '1.21.0').warnings == ()


def test_function_names_are_exported_only_when_asked(project, tmp_path):
    _c, version = accepted(project, tmp_path)
    plain, named = render(project, version), render(project, version, include_names=True)
    assert 'function_newer_name' not in plain and 'function_newer_name' in named
    assert 'function names omitted' in plain and 'function names included' in named
    assert ('function_newer_name', 'fn') in parse_rule('import "pe"' + named.split('\nimport "pe"', 1)[1]).meta


@pytest.mark.parametrize('name', ['a\nb.dll', 'x" // y', 'é‮.dll', '\\\\srv\\share\\c.dll'],
                         ids=['newline', 'quote', 'bidi', 'unc'])
def test_hostile_build_names_cannot_break_out_of_the_header(project, tmp_path, name):
    _c, version = accepted(project, tmp_path, tested=False)
    text = export.render(project.store, version, product_version=PRODUCT, older_name=name, newer_name=name,
                         include_names=False)
    head = text.split('\nimport "pe"', 1)[0]
    assert all(line.startswith('// ') for line in head.splitlines()) and len(head.splitlines()) == 10
    assert '‮' not in text and '\\' not in head


def test_destination_policy(project, tmp_path):
    _c, version = accepted(project, tmp_path)
    for bad in ('rule.txt', 'bad name.yar', 'nodir/rule.yar'):
        with pytest.raises(RulesError) as caught:
            do_export(project, version, tmp_path / bad)
        assert caught.value.code == 'PT-RULE-EXPORT'
    existing = tmp_path / 'there.yar'
    existing.write_text('keep', encoding='utf-8')
    with pytest.raises(RulesError):
        do_export(project, version, existing)
    assert existing.read_text(encoding='utf-8') == 'keep'
    repo = tmp_path / 'repo'
    (repo / '.git').mkdir(parents=True)
    with pytest.raises(RulesError) as caught:
        do_export(project, version, repo / 'rule.yar')
    assert caught.value.code == 'PT-RULE-EXPORT' and 'Git working tree' in caught.value.message
    do_export(project, version, repo / 'rule.yar', allow_git_tree=True)
    assert (repo / 'rule.yar').is_file()


def test_the_exported_file_is_what_the_record_hashes(project, tmp_path):
    _c, version = accepted(project, tmp_path)
    record, _w = do_export(project, version, tmp_path / 'r.yar')
    assert record.sha256 == text_sha256((tmp_path / 'r.yar').read_bytes().decode('utf-8'))
    assert b'\r' not in (tmp_path / 'r.yar').read_bytes()
