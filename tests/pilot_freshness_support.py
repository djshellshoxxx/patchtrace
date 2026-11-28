"""Authored local sources for current-assessment controls; no target or analyzer runs."""
from __future__ import annotations

import copy
import json
import threading
from pathlib import Path

from patchtrace.enrichment.storage import EnrichmentStore
from patchtrace.intelligence.storage import AdvisoryStore
from patchtrace.pilot import cli as pilot_cli

CVE = 'CVE-2099-30001'
ADVISORY = Path(__file__).parent / 'fixtures/pilot/synergy-1/sample-cwe125-advisory.json'


def advisory_document(*, revision=1, cves=(CVE,)):
    document = json.loads(ADVISORY.read_bytes())
    tracking = document['document']['tracking']
    if revision != 1:
        tracking['version'] = str(revision)
        tracking['current_release_date'] = f'2099-03-{revision:02d}T00:00:00.000Z'
        tracking['revision_history'].append({'date': tracking['current_release_date'], 'number': str(revision),
                                            'summary': 'Authored freshness revision'})
    vulnerability = document['vulnerabilities'][0]
    document['vulnerabilities'] = []
    for cve in cves:
        item = copy.deepcopy(vulnerability)
        item['cve'] = cve
        item['title'] = f'Authored advisory for {cve}, revision {revision}'
        document['vulnerabilities'].append(item)
    return document


def add_advisory(service, *, revision=1, cves=(CVE,)):
    return AdvisoryStore(service.root, EnrichmentStore(service.store), service.project.id,
                         service.project.revision).add(
        json.dumps(advisory_document(revision=revision, cves=cves)).encode(), origin='local-import', uri=None,
        file_name='authored-freshness.json', retrieved_at=f'2099-03-{revision:02d}T00:00:00Z')


def withdraw_pair(service):
    match = next(m for m in service.project.matches if m.older and m.older[0].name == 'read_item')
    service.correct_match(match.id, [f.id for f in match.older], [], 'unmatched',
                          'Authored control: withdraw the earlier two-sided correspondence')


def loaded(service, route):
    if route == 'desktop':
        from patchtrace.ui_leads import load_stored
        return load_stored(service, service.project).loaded
    return pilot_cli._stored(service, EnrichmentStore(service.store))


def sidecar_bytes(service):
    return {p.relative_to(service.root).as_posix(): p.read_bytes()
            for p in (service.root / 'intelligence' / 'pilot').rglob('*') if p.is_file()}


def put_current(service):
    from patchtrace.pilot import collect, keys, store
    from patchtrace.pilot.service import localize

    enrichment = EnrichmentStore(service.store)
    assessment = localize(collect.collect(service, enrichment, cancel=threading.Event()), keys.default_config(),
                          threading.Event())
    store.publish(enrichment, assessment, keys.default_config(),
                  current=store.current_guard(service.project, assessment.result_id))
    return assessment
