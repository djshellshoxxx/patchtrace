"""The workflow-contract tests read .github/workflows with PyYAML via pytest.importorskip.

PyYAML is not pulled in by any dev-extra dependency, so a clean `.[dev]` install skipped those
tests silently. The dev extra must declare it so the contracts execute.
"""
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def dev_requirement_names():
    project = tomllib.loads((ROOT / 'pyproject.toml').read_text(encoding='utf-8'))['project']
    return {re.match(r'[A-Za-z0-9._-]+', requirement).group(0).lower().replace('_', '-')
            for requirement in project['optional-dependencies']['dev']}


def test_dev_extra_declares_pyyaml_for_workflow_contract_tests():
    assert 'pyyaml' in dev_requirement_names()
