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


def test_permissions_are_minimal_for_pages_deployment():
    block = TEXT.split('permissions:\n', 1)[1].split('\nconcurrency:', 1)[0]
    assert sorted(line.strip() for line in block.splitlines()) == ['contents: read', 'id-token: write',
                                                                    'pages: write']


def test_one_deployment_at_a_time_without_cancelling_a_running_one():
    assert re.search(r'concurrency:\n\s+group: pages\n\s+cancel-in-progress: false', TEXT)


def test_official_pages_actions_are_pinned_to_a_major_version():
    uses = re.findall(r'uses: (\S+)', TEXT)
    for action in ('actions/configure-pages', 'actions/upload-pages-artifact', 'actions/deploy-pages'):
        assert any(re.fullmatch(re.escape(action) + r'@v\d+', u) for u in uses), action
    assert all(re.fullmatch(r'[\w./-]+@v\d+', u) for u in uses), uses  # no @main / @master / branch refs


def test_builds_with_the_site_tool_and_deploys_the_dist_artifact_to_github_pages():
    assert 'run: python tools/site/build_site.py\n' in TEXT
    assert re.search(r'upload-pages-artifact@v\d+\n\s+with:\n\s+path: site/dist', TEXT)
    assert 'needs: build' in TEXT
    assert re.search(r'environment:\n\s+name: github-pages\n\s+url: \$\{\{ steps\.deployment\.outputs\.page_url \}\}', TEXT)
    assert 'tools/site/requirements.txt' in TEXT  # site tools only; never the app's dependencies


def test_no_secret_or_untrusted_event_data_is_interpolated_into_shell_commands():
    runs = re.findall(r'run: (.*)', TEXT)
    assert runs and not any('${{' in command for command in runs)
    assert 'secrets.' not in TEXT and 'github.event.' not in TEXT
