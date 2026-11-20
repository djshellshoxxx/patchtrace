"""Independent benign history-selection controls for stored Strings admission."""
from __future__ import annotations

import json

import pytest
from test_intel_tools_admission import admit
from test_intel_tools_admission import case as case
from test_intel_tools_admission import seeds as seeds

from patchtrace.intelligence.tools.common import ToolError, ToolRun


def test_unsuccessful_new_attempt_keeps_the_last_produced_source(case):
    original = admit(case)
    body = original.run.model_dump(mode='json')
    body.update(run_id='peer-authored-failed-attempt', status='failed',
                error='authored interrupted producer', error_code='PT-TOOL-OUTPUT',
                evidence_count=0, cache_hit=False)
    attempt = ToolRun.model_validate_json(json.dumps(body))
    case.store.publish_run(attempt)
    assert case.store.enrichment.entries('tool-run')[0].id == attempt.run_id
    assert admit(case) == original


def test_new_produced_attempt_without_evidence_cannot_reuse_older_output(case):
    original = admit(case)
    body = original.run.model_dump(mode='json')
    body.update(run_id='peer-authored-uncommitted-evidence', cache_hit=False)
    attempt = ToolRun.model_validate_json(json.dumps(body))
    case.store.publish_run(attempt)
    assert case.store.enrichment.entries('tool-run')[0].id == attempt.run_id
    before = tuple(case.db.iterdump())
    with pytest.raises(ToolError, match='no stored evidence'):
        admit(case)
    assert tuple(case.db.iterdump()) == before
