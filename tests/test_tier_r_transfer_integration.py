"""Recovery seams: current diagnostics, exclusive reruns and explicit CI payloads."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from test_tier_r_output_persistence import provider
from test_tier_r_training_artifacts import built as built
from test_tier_r_training_artifacts import merge, plan

from tools.calibration.common import canonical_json
from tools.calibration.tier_r import cli
from tools.calibration.tier_r import shard as S
from tools.calibration.tier_r import training_artifacts as TA


@pytest.mark.parametrize('collect', [False, True])
def test_actual_failed_evaluator_retains_each_mode_contract(built, monkeypatch, tmp_path, collect):
    monkeypatch.setattr(cli.E, 'default_providers', lambda *a, **k: [provider(returned_engine='ghidriff')])
    monkeypatch.setattr(S, 'default_runner', built.runner)
    plan_path = tmp_path / 'plan.json'
    plan_path.write_bytes(canonical_json(plan()))
    out = tmp_path / 'shards'
    args = ['run-shard', '--plan', str(plan_path), '--shard', '0', '--out', str(out)]
    assert S.main(args + (['--collect-artifacts'] if collect else [])) == (S.FINDINGS if collect else S.OK)
    [doc] = S.load_shards(out, plan=plan())
    evaluation = next(row for row in doc['cases'] if row['id'] == 'evaluate:rz-diff')
    assert evaluation['status'] == ('failed' if collect else 'findings')
    assert not any(row['status'] == 'ok' for report in doc['reports'] for row in report['pairs'])


@pytest.mark.parametrize('rc', [0, 1])
@pytest.mark.parametrize('status', ['failed', 'error'])
def test_declared_failed_builder_cannot_grant_transfer_ownership(built, rc, status):
    def failed(argv, timeout, env):
        code, output, reason = built.runner(argv, timeout, env)
        if argv[3] != 'evaluate':
            summary = json.loads(output)
            summary.update(command='build-suite', status=status)
            return rc, json.dumps(summary), reason
        return code, output, reason

    doc, source, observed = built(modify_runner=failed)
    assert doc['cases'][0]['status'] == 'failed'
    assert not doc['pair_cases']
    assert doc['cases'][-1]['id'] == 'transfer:training'
    assert doc['cases'][-1]['status'] == 'failed'
    assert not (source / 'training' / 'shard-0' / TA.MANIFEST).exists()
    assert Path(observed['evaluation']['report']).exists()


def test_refused_transfer_rerun_preserves_prior_diagnostic_and_bundle(built, monkeypatch, tmp_path):
    _doc, source, _observed = built()
    diagnostic = source / 'shard-0.json'
    manifest = source / 'training' / 'shard-0' / TA.MANIFEST
    before = diagnostic.read_bytes(), manifest.read_bytes()
    plan_path = tmp_path / 'plan.json'
    plan_path.write_bytes(canonical_json(plan()))
    monkeypatch.setattr(S, 'default_runner', built.runner)
    assert S.main(['run-shard', '--plan', str(plan_path), '--shard', '0', '--out', str(source),
                   '--collect-artifacts']) != S.OK
    assert (diagnostic.read_bytes(), manifest.read_bytes()) == before
    assert merge(source, tmp_path / 'merge-prior') == S.OK


@pytest.mark.parametrize('kind', ['', 'labels', 'outputs', 'reports'])
@pytest.mark.parametrize('damage', ['unknown', 'duplicate'])
def test_bundle_inventory_stops_at_first_extra_entry(built, monkeypatch, tmp_path, kind, damage):
    _doc, source, _observed = built()
    selected = source / 'training' / 'shard-0' / kind
    original = Path.iterdir
    [first, *_remaining] = list(original(selected))
    consumed = []

    def bounded(path):
        if path != selected:
            yield from original(path)
            return
        consumed.append(first.name)
        yield first
        extra = path / 'unexpected.json' if damage == 'unknown' else first
        consumed.append(extra.name)
        yield extra
        raise AssertionError('inventory consumed beyond the first forbidden entry')

    monkeypatch.setattr(Path, 'iterdir', bounded)
    destination = tmp_path / 'merged'
    assert merge(source, destination) == S.USAGE
    assert len(consumed) == 2
    assert not destination.exists()


def test_ci_transfer_payload_is_explicit_and_uses_verified_completion():
    yaml = pytest.importorskip('yaml')
    document = yaml.safe_load((Path(__file__).resolve().parents[1] / '.github/workflows/corpus-tier-r.yml').read_text())
    for job, title, step, base in (
            ('shard', 'Upload completed training bundle', 'run-shard', 'shard-out/training/shard-${{ matrix.shard }}'),
            ('merge', 'Upload completed merged training bundle', 'merge', 'merged/training')):
        upload = next(item for item in document['jobs'][job]['steps'] if item.get('name') == title)
        assert upload['if'] == f"always() && steps.{step}.outputs.verified_training == 'true'"
        assert upload['with']['include-hidden-files'] is True
        expected = {f'{base}/manifest.json', f'{base}/outputs/.tier-r-output-run.json',
                    *(f'{base}/{kind}/[A-Za-z0-9]*.json' for kind in ('labels', 'reports', 'outputs'))}
        if job == 'shard':
            expected.add('shard-out/shard-${{ matrix.shard }}.json')
        assert set(upload['with']['path'].splitlines()) == expected
    aggregate = next(item for item in document['jobs']['merge']['steps']
                     if item.get('with', {}).get('name') == 'tier-r-aggregate')
    assert aggregate['if'] == 'always()'
    assert set(aggregate['with']['path'].splitlines()) == {
        'merged/tier-r-aggregate.json', 'merged/tier-r-merge.json', 'merged/tier-r-report.md',
        'merged/ci-summary.json', 'merged/ci-summary.md'}
