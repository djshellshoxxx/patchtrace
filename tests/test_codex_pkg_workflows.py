"""Hermetic source checks for codex-workflows-1.md; no Actions or network execution."""
from __future__ import annotations

import io
import re
import runpy
import socket
import subprocess
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / '.github' / 'workflows'


def workflow_sources():
    paths = sorted([*WORKFLOWS.glob('*.yml'), *WORKFLOWS.glob('*.yaml')])
    assert paths, 'No workflows discovered'
    return [(path.name, path.read_text(encoding='utf-8')) for path in paths]


def job_blocks(source):
    """Read job mappings at their declared indentation, without requiring a YAML extra.

    Reject an unfamiliar layout instead of silently treating it as no jobs. These
    workflows use block mappings with two-space job keys and four-space fields.
    """
    assert '\njobs:\n' in source
    body = source.split('\njobs:\n', 1)[1]
    headers = list(re.finditer(r'^  ([\w-]+):\s*$', body, re.MULTILINE))
    assert headers, 'Unsupported jobs layout'
    return {
        header[1]: body[header.end():headers[index + 1].start() if index + 1 < len(headers) else len(body)]
        for index, header in enumerate(headers)
    }


def run_scripts(source):
    """Yield run fields and their indented bodies, excluding env/with expressions."""
    lines = source.splitlines()
    scripts = []
    for index, line in enumerate(lines):
        match = re.match(r'^(\s*)(?:- )?run:\s*(.*)$', line)
        if not match:
            continue
        # The '- run:' spelling aligns the value block two spaces after the '-'.
        field_indent = len(match[1]) + (2 if line.lstrip().startswith('- ') else 0)
        script = [match[2]]
        if match[2] in {'|', '>-', '>', '|-'}:
            for following in lines[index + 1:]:
                if following.strip() and len(following) - len(following.lstrip()) <= field_indent:
                    break
                script.append(following)
        scripts.append('\n'.join(script))
    return scripts


@pytest.fixture(autouse=True)
def forbid_external_io(monkeypatch):
    def denied(*args, **kwargs):
        pytest.fail('Audit tests must never launch a process or access the network')

    monkeypatch.setattr(subprocess, 'run', denied)
    monkeypatch.setattr(subprocess, 'Popen', denied)
    monkeypatch.setattr(socket, 'socket', denied)
    monkeypatch.setattr(socket, 'create_connection', denied)
    monkeypatch.setattr(urllib.request, 'urlopen', denied)


@pytest.fixture
def gate():
    # The module's __main__ guard stays false; only pure helpers are called below.
    return runpy.run_path(str(ROOT / 'tools' / 'release_gate.py'))


@pytest.mark.xfail(strict=True, reason='CODEX-1')
def test_remote_actions_are_immutable():
    mutable = []
    for name, source in workflow_sources():
        for line, text in enumerate(source.splitlines(), 1):
            match = re.search(r'\buses:\s*([^\s#]+)', text)
            if match and not match[1].startswith(('./', 'docker://')):
                if not re.fullmatch(r'[^@]+@[0-9a-fA-F]{40}', match[1]):
                    mutable.append(f'{name}:{line}: {match[1]}')
    assert not mutable, '\n'.join(mutable)


def test_every_job_has_timeout():
    missing = [f'{name}:{job}' for name, source in workflow_sources()
               for job, block in job_blocks(source).items()
               if not re.search(r'^    timeout-minutes:\s*[1-9][0-9]*\s*$', block, re.MULTILINE)]
    assert not missing, missing


def test_pages_build_has_read_only_permissions():
    source = (WORKFLOWS / 'pages.yml').read_text(encoding='utf-8')
    build = job_blocks(source)['build']
    assert re.search(r'^    permissions:\n      contents: read\s*$', build, re.MULTILINE)
    assert not re.search(r'^      (?:pages|id-token): write', build, re.MULTILINE)


def test_workflows_declare_permissions():
    missing = [name for name, source in workflow_sources()
               if not re.search(r'^permissions:', source, re.MULTILINE)
               and any(not re.search(r'^    permissions:', block, re.MULTILINE)
                       for block in job_blocks(source).values())]
    assert not missing, missing


@pytest.mark.xfail(strict=True, reason='CODEX-5')
def test_pip_downloads_require_hashes():
    unhashed = [name for name, source in workflow_sources()
               for script in run_scripts(source)
               if 'pip install' in script and '--require-hashes' not in script
               and '--no-index' not in script]
    assert not unhashed, unhashed


@pytest.mark.xfail(strict=True, reason='CODEX-6')
def test_corpus_cache_does_not_skip_verification():
    source = (WORKFLOWS / 'corpus-tier-r.yml').read_text(encoding='utf-8')
    scripts = '\n'.join(run_scripts(source))
    # Pin verification must not disappear just because the extracted tree was restored.
    assert "steps.rizin-cache.outputs.cache-hit != 'true'" not in source
    assert 'steps.ghidra-cache.outputs.cache-hit' not in scripts


def test_gate_parse_error_cannot_publish_for_pr(gate):
    out, err = io.StringIO(), io.StringIO()
    gate['main'](['--event', 'pull_request', '--ref', 'refs/pull/1/merge'],
                 environ={}, out=out, err=err)
    assert 'publish=true' not in out.getvalue(), out.getvalue()


@pytest.mark.parametrize('trailer', ['skip-checks:true', 'skip-checks: true'])
def test_skip_check_trailers_are_recognised(gate, trailer):
    message = f'Ordinary squash subject\n\n\n{trailer}\n'
    assert gate['skips_ci'](message)


def test_valid_pr_and_non_main_events_never_publish(gate):
    for event, ref in [('pull_request', 'refs/pull/1/merge'),
                       ('workflow_dispatch', 'refs/heads/main'),
                       ('push', 'refs/heads/codex/audit-2')]:
        decision = gate['ref_decision'](event, ref)
        assert decision is not None and decision.publish is False


def test_no_pr_release_publication_in_current_workflows():
    for name, source in workflow_sources():
        if not re.search(r'^  pull_request(?:_target)?:', source, re.MULTILINE):
            continue
        jobs = job_blocks(source)
        for job, block in jobs.items():
            publishes = re.search(r'action-gh-release@|deploy-pages@|gh release (?:create|upload)', block)
            if not publishes:
                continue
            # The sole current PR-capable publishing workflow depends on a push-only gate.
            assert re.search(r'^    needs:.*release-gate', block, re.MULTILINE), f'{name}:{job}'
            condition = re.search(r'^    if:(.*)$', block, re.MULTILINE)
            assert condition and 'always()' not in condition[1]
            assert "needs.release-gate.outputs.publish == 'true'" in condition[1]
            assert "    if: github.event_name == 'push'" in jobs['release-gate']


def test_run_blocks_do_not_embed_dispatch_or_pr_text():
    unsafe = re.compile(r'\$\{\{\s*(?:inputs\.|github\.event\.(?:inputs|pull_request|issue)\.)')
    offenders = [name for name, source in workflow_sources()
                 for script in run_scripts(source) if unsafe.search(script)]
    assert not offenders, offenders


def test_job_reader_and_run_reader_do_not_confuse_step_fields():
    source = '\njobs:\n  sample:\n    steps:\n      - run: |\n          echo ok\n        env:\n          X: value\n'
    assert 'timeout-minutes' not in job_blocks(source)['sample']
    assert run_scripts(source) == ['|\n          echo ok']
