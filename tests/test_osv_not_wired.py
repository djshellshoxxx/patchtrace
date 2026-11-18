"""Guard-lock: OSV is NOT a wired data source for the beta (vendor-feeds-and-source-matrix-spec Q1, default out).

Remove or rewrite this file only together with an explicit decision change in that spec.
"""
from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlparse

import pytest

from patchtrace.enrichment import cve, intelligence, profiles
from patchtrace.enrichment.contracts import EnrichmentError

SRC = Path(__file__).resolve().parents[1] / 'src' / 'patchtrace'
OSV_NAME = re.compile(r'(?<![a-z0-9])osv(?![a-z0-9])', re.IGNORECASE)


def _is_osv(value: str) -> bool:
    return bool(OSV_NAME.search(value)) or 'osv.dev' in value.lower()


def test_osv_absent_from_provider_registries():
    registries = {
        'intelligence.PROVIDERS': set(intelligence.PROVIDERS),
        'intelligence.KEY_HEADER': set(intelligence.KEY_HEADER),
        'cve.PROVIDERS': set(cve.PROVIDERS),
        'profiles.CVE_PROVIDERS': set(profiles.CVE_PROVIDERS),
    }
    # Non-vacuous: the real registries are populated with the two wired providers.
    assert set(intelligence.PROVIDERS) == {'msrc', 'nvd'}
    assert set(cve.PROVIDERS) == {'msrc', 'nvd'}
    assert set(profiles.CVE_PROVIDERS) == {'msrc', 'nvd'}
    for name, keys in registries.items():
        assert not [k for k in keys if _is_osv(k)], name


def test_osv_absent_from_urls_and_allowed_hosts():
    assert not [h for h in intelligence.ALLOWED_HOSTS if _is_osv(h)]
    for provider, template in intelligence.PROVIDERS.items():
        assert not _is_osv(template), provider
        assert urlparse(template).hostname in intelligence.ALLOWED_HOSTS


def test_osv_cannot_be_planned_or_normalized():
    with pytest.raises(EnrichmentError):
        intelligence.plan_requests(['CVE-2024-0001'], ['osv'])
    with pytest.raises(EnrichmentError):
        intelligence.plan_requests(['CVE-2024-0001'], ['msrc', 'osv'])
    # Control: a wired provider still plans, so the refusal above is about osv specifically.
    assert intelligence.plan_requests(['CVE-2024-0001'], ['nvd'])


def test_no_osv_string_anywhere_under_src():
    files = [p for p in SRC.rglob('*') if p.is_file() and p.suffix in {'.py', '.json', '.toml', '.txt', '.md', '.yaml', '.yml'}]
    assert len(files) > 100  # the scan really covers the source tree
    hits = []
    for path in files:
        text = path.read_text(encoding='utf-8', errors='replace')
        for number, line in enumerate(text.splitlines(), 1):
            if _is_osv(line):
                hits.append(f'{path.relative_to(SRC)}:{number}: {line.strip()[:80]}')
    assert not hits, 'OSV is not a wired source (spec Q1); found:\n' + '\n'.join(hits)
