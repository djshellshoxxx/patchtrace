"""Static invariants of .github/workflows/backend-bundle.yml (BUNDLE slice B5b).

These parse the workflow only; they prove nothing about a live Actions run (see docs/modules.md [B5b])."""
from __future__ import annotations

import re
from pathlib import Path

import pytest

yaml = pytest.importorskip('yaml')

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / '.github' / 'workflows' / 'backend-bundle.yml'
ALLOWED_ACTIONS = {'actions/checkout@v4', 'actions/setup-python@v5', 'actions/upload-artifact@v4',
                   'actions/download-artifact@v4', 'actions/cache@v4', 'ilammy/msvc-dev-cmd@v1'}
JOB_IDS = {'pin', 'bld-win', 'acc-win', 'bld-lin', 'acc-lin', 'pub'}


@pytest.fixture(scope='module')
def doc() -> dict:
    return yaml.safe_load(WORKFLOW.read_text(encoding='utf-8'))


def triggers(doc: dict) -> dict:
    return doc.get('on', doc.get(True))  # YAML 1.1 parses the key `on` as boolean true


def steps(job: dict) -> list[dict]:
    return job['steps']


def all_run_text(job: dict) -> str:
    return '\n'.join(str(s.get('run', '')) for s in steps(job))


def test_triggers_are_dispatch_call_and_tags_only(doc):
    on = triggers(doc)
    assert set(on) == {'workflow_dispatch', 'workflow_call', 'push'}
    assert on['push'] == {'tags': ['v*']}  # never branches: not on every merge
    for name in ('workflow_dispatch', 'workflow_call'):
        assert {'version', 'platforms', 'publish_prerelease', 'pin_report_only'} <= set(on[name]['inputs'])
    assert on['workflow_dispatch']['inputs']['publish_prerelease']['default'] is False
    assert 'schedule' not in on and 'pull_request' not in on


def test_job_ids_short_and_explicit(doc):
    assert set(doc['jobs']) == JOB_IDS
    for job_id, job in doc['jobs'].items():
        assert len(job_id) <= 8 and job.get('name')
        assert job['timeout-minutes'] <= 60


def test_least_privilege_permissions(doc):
    assert doc['permissions'] == {'contents': 'read'}
    writers = [j for j, job in doc['jobs'].items() if 'permissions' in job]
    assert writers == ['pub']
    assert doc['jobs']['pub']['permissions'] == {'contents': 'write'}


def test_actions_pinned_like_other_workflows(doc):
    used = {s['uses'] for job in doc['jobs'].values() for s in steps(job) if 'uses' in s}
    assert used <= ALLOWED_ACTIONS, used - ALLOWED_ACTIONS
    assert all(re.fullmatch(r'[\w./-]+@v\d+', u) for u in used)
    assert not any('softprops' in u for u in used)  # release uses the gh CLI so failures are explicit


def test_names_and_descriptions_have_no_colon_space(doc):
    texts = [doc['name']]
    for job in doc['jobs'].values():
        texts.append(job['name'])
        texts.extend(str(s.get('name', '')) for s in steps(job))
    for spec in triggers(doc)['workflow_dispatch']['inputs'].values():
        texts.append(spec['description'])
    assert not [t for t in texts if ': ' in t]  # would break a plain YAML scalar (and fail to parse)


def test_pin_job_enforces_release_gate_and_reports(doc):
    text = all_run_text(doc['jobs']['pin'])
    assert 'check_backend_pin.py --release' in text
    gate = next(s for s in steps(doc['jobs']['pin']) if 'check_backend_pin.py --release' in s.get('run', ''))
    assert "steps.plan.outputs.build == 'true'" in gate['if']
    report = [s for s in steps(doc['jobs']['pin']) if s.get('uses', '').startswith('actions/upload-artifact')]
    assert report and report[0]['with']['name'] == 'pin-report'


def test_builders_gate_on_pin_and_use_full_flags(doc):
    for job_id, platform in (('bld-win', 'windows'), ('bld-lin', 'linux')):
        job = doc['jobs'][job_id]
        assert job['needs'] == 'pin'
        assert "needs.pin.outputs.build == 'true'" in job['if']
        text = all_run_text(job)
        assert f'build_backend_bundle.py build --platform {platform}' in text
        assert '--split' in text and '--cache-dir' in text
        assert re.search(r'build_(windows|linux)\.py --full --backend-payload bundle-out/backend --version "\$VERSION"', text)
        assert text.index('build_backend_bundle.py') < text.index('--full')
    assert doc['jobs']['bld-lin']['runs-on'] == 'ubuntu-22.04'
    assert doc['jobs']['bld-win']['runs-on'] == 'windows-latest'


def test_evidence_and_assets_are_uploaded(doc):
    for job_id in ('bld-win', 'bld-lin'):
        uploads = [s for s in steps(doc['jobs'][job_id]) if s.get('uses', '').startswith('actions/upload-artifact')]
        names = {u['with']['name'] for u in uploads}
        assert len(names) == 2 and any(n.startswith('evidence-') for n in names)
        evidence = next(u for u in uploads if u['with']['name'].startswith('evidence-'))
        assert evidence['if'] == 'always()'
        assert all(u['with']['retention-days'] == 7 for u in uploads)
        text = all_run_text(doc['jobs'][job_id])
        for needle in ('SHA256SUMS.txt', 'manifest.json', 'LICENSES', 'ghidriff-', 'THIRD-PARTY.json',
                       '2147483647c'):
            assert needle in text, needle


def test_acceptance_uses_release_artifact_and_harness(doc):
    for job_id, needs in (('acc-win', 'bld-win'), ('acc-lin', 'bld-lin')):
        job = doc['jobs'][job_id]
        assert needs in job['needs']
        text = all_run_text(job)
        assert 'bundle_acceptance' in text and '--evidence' in text and 'sha256sum -c' in text
        assert 'UNICODE_DIRNAME' in text  # hostile extraction path
        assert any(s.get('uses', '').startswith('actions/download-artifact') for s in steps(job))
        up = [s for s in steps(job) if s.get('uses', '').startswith('actions/upload-artifact')]
        assert up and up[-1]['if'] == 'always()'
        assert 'JAVA_HOME' not in text and 'GHIDRA_INSTALL_DIR' not in text  # the harness scrubs the env itself
    assert set(doc['jobs']['acc-lin']['strategy']['matrix']['os']) == {'ubuntu-22.04', 'ubuntu-24.04'}
    assert '--run-uid' in all_run_text(doc['jobs']['acc-lin'])  # non-owner, so the read-only tree is effective
    assert doc['jobs']['acc-lin']['strategy']['fail-fast'] is False


def test_publish_is_prerelease_only_and_fails_loudly(doc):
    pub = doc['jobs']['pub']
    condition = ' '.join(str(pub['if']).split())
    assert "needs.pin.outputs.publish == 'true'" in condition
    assert "needs.acc-win.result == 'success'" in condition and "needs.acc-lin.result == 'success'" in condition
    assert '!cancelled()' in condition
    text = all_run_text(pub)
    assert '--prerelease' in text and 'isPrerelease' in text
    assert 'refusing to touch it' in text  # an existing final release is never modified
    assert '--clobber' in text and 'Nothing' in text
    assert 'secrets.GITHUB_TOKEN' in WORKFLOW.read_text(encoding='utf-8')
    assert 'gh release create' in text and 'make_latest' not in text and '--latest' not in text
    assert 'echo "$GH_TOKEN' not in text


def test_publish_requires_explicit_input_never_tag_alone(doc):
    plan = next(s for s in steps(doc['jobs']['pin']) if s.get('id') == 'plan')['run']
    assert re.search(r'publish=false; \[ "\$IN_PUBLISH" = true \] && \[ "\$report" = false \] && publish=true', plan)


def test_inputs_reach_shell_only_through_env(doc):
    for job in doc['jobs'].values():
        for step in steps(job):
            assert '${{ inputs.' not in str(step.get('run', ''))
            assert '${{ github.ref_name' not in str(step.get('run', ''))
