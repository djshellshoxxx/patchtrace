"""PIL-D2: the evaluation workflow is dispatch-only, advisory, read-only and pinned to the preregistration."""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = (ROOT / '.github' / 'workflows' / 'pilot-eval.yml').read_text(encoding='utf-8')


def test_dispatch_only_no_push_or_pull_request_trigger():
    assert 'workflow_dispatch:' in WORKFLOW
    assert 'push:' not in WORKFLOW and 'pull_request:' not in WORKFLOW and 'schedule:' not in WORKFLOW


def test_read_only_token_and_no_secrets():
    assert 'contents: read' in WORKFLOW and 'secrets.' not in WORKFLOW


def test_runs_the_evaluation_tests_and_records_the_preregistration_hash():
    assert 'tests/test_pilot_eval_' in WORKFLOW
    assert 'pilot-preregistration-v1.md' in WORKFLOW and 'sha256sum' in WORKFLOW


def test_uploads_aggregate_report_only():
    assert 'upload-artifact' in WORKFLOW and 'report.json' in WORKFLOW
    assert '.exe' not in WORKFLOW and '.dll' not in WORKFLOW
