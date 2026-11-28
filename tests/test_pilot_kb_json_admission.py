"""Retained bodies must be unambiguous JSON before they can supply Pilot evidence."""
from __future__ import annotations

import hashlib
import json

import pytest
from test_pilot_kb_context import CVE, captured, case, gathered, offline

from patchtrace.enrichment.storage import EnrichmentStore
from patchtrace.pilot.limits import PilotError
from patchtrace.service import ProjectService

__all__ = ['case', 'offline']


def replace_body(service, row, text):
    digest = hashlib.sha256(text.encode()).hexdigest()
    with service.store.connection as db:
        db.execute('UPDATE enrichment_entries SET body=?,body_sha256=? WHERE id=?', (text, digest, row.id))
    return text, digest


@pytest.mark.parametrize('location', ['root', 'root-escaped', 'card', 'card-escaped'])
def test_duplicate_members_with_matching_checksum_withhold_all_retained_context(case, location):
    with ProjectService.open(case) as service:
        row, = EnrichmentStore(service.store).entries('kb-context')
        before = captured(service)
        assert not before.unavailable and CVE in before.cves
        if location.startswith('root'):
            key = r'\u0062ase_revision' if location.endswith('escaped') else 'base_revision'
            text = '{"' + key + '":0,' + row.body_json[1:]
        else:
            key = r'stated_\u0063we' if location.endswith('escaped') else 'stated_cwe'
            text = row.body_json.replace('"stated_cwe":', '"' + key + '":"CWE-000","stated_cwe":', 1)
        assert json.loads(text) == row.body  # A permissive last-value decoder hides the ambiguity.
        saved = replace_body(service, row, text)

        refused = captured(service)
        assert refused.unavailable and not refused.cves and not refused.bundles
        assert refused.digest and refused.digest != before.digest
        assert refused.warnings == ('a retained context failed validation; CVRF evidence is unknown.',)
        with pytest.raises(PilotError) as error:
            gathered(service, named=(CVE,))
        assert error.value.code == 'PT-PILOT-STALE'
        assert error.value.reason == 'advisory-context-unavailable'
        actual = service.store.connection.execute(
            'SELECT body,body_sha256 FROM enrichment_entries WHERE id=?', (row.id,)).fetchone()
        assert actual == saved  # Refusal cannot rewrite retained evidence.

        replace_body(service, row, row.body_json)
        assert captured(service) == before
        assert gathered(service, named=(CVE,)).advisory.context(CVE).gate == 'unverified'


def test_valid_json_whitespace_keeps_the_same_admitted_context(case):
    with ProjectService.open(case) as service:
        row, = EnrichmentStore(service.store).entries('kb-context')
        before = captured(service)
        replace_body(service, row, json.dumps(row.body, indent=2, ensure_ascii=False))
        after = captured(service)
        assert not after.unavailable and not after.warnings
        assert after.bundles == before.bundles and after.cves == before.cves
