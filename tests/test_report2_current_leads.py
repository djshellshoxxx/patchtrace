"""Report export shares PIL's current-evidence boundary; history and layouts remain intact."""
from __future__ import annotations

import json

import pytest
from kev_helpers import document, entry, parse_bytes, render
from pilot_freshness_support import CVE, add_advisory, put_current, sidecar_bytes, withdraw_pair

from patchtrace import cli
from patchtrace.kev import store as kev_store
from patchtrace.report2.adapters import collect_from_service
from patchtrace.service import ProjectService


@pytest.mark.parametrize('change', ['none', 'pairing', 'advisory', 'kev', 'missing-advisory'])
def test_current_leads_export_but_changed_evidence_is_explicitly_omitted(tmp_path, capsys, monkeypatch, change):
    folder = tmp_path / 'catalog'
    monkeypatch.setattr(kev_store, 'default_kev_dir', lambda: folder)
    with ProjectService.sample(tmp_path / 'case') as service:
        root = service.root
        add_advisory(service)
        put_current(service)
        assert collect_from_service(service).leads
        before = sidecar_bytes(service)
        if change == 'pairing':
            withdraw_pair(service)
        elif change == 'advisory':
            add_advisory(service, revision=2)
        elif change == 'kev':
            raw = render(document([entry(cveID=CVE)]))
            kev_store.KevStore(folder).install(raw, parse_bytes(raw), now='2099-03-02T00:00:00Z')
        elif change == 'missing-advisory':
            for path in (service.root / 'intelligence' / 'csaf').rglob('*.json'):
                path.unlink()
        sections = collect_from_service(service)
        if change == 'none':
            assert sections.leads and not any(u.startswith('leads:') for u in sections.unknowns)
        else:
            assert sections.leads is None
            assert any('stored pilot result is stale' in u and 'leads omitted' in u for u in sections.unknowns)
        assert sidecar_bytes(service) == before
    destination = tmp_path / 'report.json'
    assert cli.main(['export', str(root), '--out', str(destination), '--report-version', '2', '--json']) == 0
    capsys.readouterr()
    report = json.loads(destination.read_text(encoding='utf-8'))
    if change == 'none':
        assert report['leads'] and 'leads' in report['sections_present']
    else:
        assert not report.get('leads') and 'leads' not in report['sections_present']
        assert any('stored pilot result is stale' in u and 'leads omitted' in u for u in report['unknowns'])
