"""Stale assessments retain explanations while every outgoing navigation refuses them."""
from __future__ import annotations

from dataclasses import replace

import pytest
from leads_support import CVE_A, FakeProject, lead_of, sample_assessment
from pilot_freshness_support import add_advisory, withdraw_pair
from test_ui_leads import put, real_start, start

from patchtrace.service import ProjectService


@pytest.mark.parametrize('action', ['button', 'direct', 'evidence-line', 'anchor'])
def test_stale_assessment_never_navigates_even_when_the_function_map_is_present(qtbot, action):
    from types import SimpleNamespace

    assessment = sample_assessment()
    lead = lead_of(assessment, 'read_item', CVE_A)
    project = FakeProject()
    project.matches.append(SimpleNamespace(id='match-1', older=[SimpleNamespace(id='old')],
                                           newer=[SimpleNamespace(id='new')]))
    controller, nav, shell, _project = start(
        qtbot, assessment, state='stale', changed=('advisory_facts_ids',), project=project,
        resolver=lambda _r, _s, _t: {lead.candidate_key: 'match-1'})
    controller.select_key(f'{CVE_A}|{lead.candidate_key}')
    assert controller.presentation.state == 'L6'
    assert controller.panel.detail.toPlainText()
    if action == 'button':
        assert not controller.panel.buttons['goto'].isEnabled()
        assert 'out of date' in controller.panel.buttons['goto'].toolTip()
    elif action == 'direct':
        controller.go()
    elif action == 'evidence-line':
        found = next(o for o in controller.model.observations(controller.current_row()) if o.nav is not None)
        controller._observation_activated(found.obs_id)
    else:
        found = controller.model.observations(controller.current_row())[0]
        obs = controller.model.pool[found.obs_id]
        controller.model.pool[found.obs_id] = obs.model_copy(update={'anchor_ids': ('advisory_phrase:authored',)})
        controller._open_anchor(replace(found, nav=None))
    assert not nav.selected and not nav.revealed and not nav.anchors
    controller.copy_explanation()
    assert shell.copied and 'Summary' in shell.copied[-1]


@pytest.mark.parametrize('change', ['pairing', 'advisory'])
def test_navigation_rechecks_changes_after_loading_without_requiring_refresh(qtbot, tmp_path, change):
    with ProjectService.sample(tmp_path / 'case') as service:
        assessment = put(service)
        lead = lead_of(assessment, 'read_item', CVE_A)
        match = next(m for m in service.project.matches if m.older and m.older[0].name == 'read_item')
        controller, nav, shell, _project = real_start(
            qtbot, service, resolver=lambda _r, _s, _t: {lead.candidate_key: match.id})
        controller.select_key(f'{CVE_A}|{lead.candidate_key}')
        assert controller.stored.loaded.state == 'current' and controller.panel.buttons['goto'].isEnabled()
        if change == 'pairing':
            withdraw_pair(service)
        else:
            add_advisory(service, revision=2, cves=(CVE_A,))
        controller.go()
        assert not nav.selected and not nav.revealed and not nav.anchors
        assert controller.stored.loaded.state == 'stale' and controller.presentation.state == 'L6'
        assert 'out of date' in shell.announced[-1][0]
