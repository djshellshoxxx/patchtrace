"""The Pages workflow: trigger paths, least-privilege permissions, pinned actions, one deployment at a time.
Text checks only (no YAML dependency); the workflow itself can only run on GitHub."""
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from site_helpers import ROOT  # noqa: E402

TEXT = (ROOT / '.github' / 'workflows' / 'pages.yml').read_text(encoding='utf-8')


def test_triggers_are_push_to_main_on_site_paths_and_manual_dispatch():
    assert re.search(r"push:\n\s+branches: \[main\]\n\s+paths:\n\s+- 'site/\*\*'\n\s+- 'tools/site/\*\*'", TEXT)
    assert 'workflow_dispatch:' in TEXT
    assert 'pull_request' not in TEXT  # never deploys from a pull request


def test_deployment_hold_is_push_only_and_uses_the_actual_head_message():
    # Static source contract: GitHub evaluates contains case-insensitively; no expression engine runs here.
    deploy = TEXT.split('\n  deploy:\n', 1)[1]
    condition = re.search(r'^    if: (.+)$', deploy, re.M)
    assert condition is not None
    assert condition.group(1) == (
        "github.event_name != 'push' || !contains(github.event.head_commit.message, '[no deploy]')")
    assert re.search(r'^    needs: build$', deploy, re.M)


def test_permissions_are_minimal_for_pages_deployment():
    # Workflow level is read-only; only the deploy job may write Pages / mint the OIDC token (CODEX-3).
    block = TEXT.split('permissions:\n', 1)[1].split('\nconcurrency:', 1)[0]
    assert sorted(line.strip() for line in block.splitlines()) == ['contents: read']
    deploy = TEXT.split('\n  deploy:\n', 1)[1]
    deploy_perms = deploy.split('    permissions:\n', 1)[1].split('\n    environment:', 1)[0]
    assert sorted(line.strip() for line in deploy_perms.splitlines()) == ['id-token: write', 'pages: write']
    build = TEXT.split('\n  build:\n', 1)[1].split('\n  deploy:\n', 1)[0]
    assert 'pages: write' not in build and 'id-token: write' not in build


def test_one_deployment_at_a_time_without_cancelling_a_running_one():
    assert re.search(r'concurrency:\n\s+group: pages\n\s+cancel-in-progress: false', TEXT)


def test_official_pages_actions_use_reviewed_immutable_commits():
    uses = re.findall(r'^\s*(?:- )?uses: (\S+)', TEXT, re.M)
    for action in (
        'actions/configure-pages@983d7736d9b0ae728b81ab479565c72886d7745b',
        'actions/upload-pages-artifact@56afc609e74202658d3ffba0e8f6dda462b719fa',
        'actions/deploy-pages@d6db90164ac5ed86f2b6aed7e0febac5b3c0c03e',
    ):
        assert action in uses, action
    assert all(re.fullmatch(r'[\w./-]+@[0-9a-f]{40}', u) for u in uses), uses


def test_builds_with_the_site_tool_and_deploys_the_dist_artifact_to_github_pages():
    build = TEXT.split('\n  build:\n', 1)[1].split('\n  deploy:\n', 1)[0]
    assert '[no deploy]' not in TEXT.split('\n  deploy:\n', 1)[0]
    assert not re.search(r'^    if:', build, re.M)
    assert 'run: python -m pytest --noconftest --disable-plugin-autoload -q tests/test_site_*.py' in build
    assert 'run: python tools/site/build_site.py\n' in build
    assert 'actions/upload-pages-artifact@' in build
    assert re.search(
        r'^\s*- uses: actions/upload-pages-artifact@56afc609e74202658d3ffba0e8f6dda462b719fa'
        r'(?: +#[^\n]*)?\n\s+with:\n\s+path: site/dist', TEXT, re.M)
    assert 'needs: build' in TEXT
    assert re.search(r'environment:\n\s+name: github-pages\n\s+url: \$\{\{ steps\.deployment\.outputs\.page_url \}\}', TEXT)
    assert 'tools/site/requirements-ci.lock' in TEXT  # site tools only; never the app's dependencies


def test_no_secret_or_untrusted_event_data_is_interpolated_into_shell_commands():
    runs = re.findall(r'run: (.*)', TEXT)
    assert runs and not any('${{' in command for command in runs)
    assert 'secrets.' not in TEXT
    assert not any('github.event.' in command for command in runs)
