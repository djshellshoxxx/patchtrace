"""ACQ-13: CLI consent remains bound to the URL list printed before fetching."""
from patchtrace import cli
from patchtrace.enrichment import intelligence
from patchtrace.enrichment.contracts import EnrichmentError


def test_acq13_cli_refuses_plan_changed_after_preview(tmp_path, monkeypatch, capsys):
    original_plan = intelligence.plan_requests
    plan = list(original_plan(['CVE-2024-38063'], ['msrc']))
    calls = []

    def changed_after_preview(_name):
        plan[0] = original_plan(['CVE-2024-38064'], ['msrc'])[0]
        return None

    def planning(cves, providers):
        if list(cves) == ['CVE-2024-38063']:
            return plan
        return original_plan(cves, providers)

    def opener(*args, **kwargs):
        calls.append(args)
        raise EnrichmentError('PT-ENRICH-NETWORK', 'unexpected request')

    monkeypatch.setattr(intelligence, 'plan_requests', planning)
    monkeypatch.setattr(intelligence, 'urllib_open', opener)
    monkeypatch.setattr(cli, '_api_key', changed_after_preview)
    code = cli.main(['correlate', str(tmp_path), '--cve', 'CVE-2024-38063', '--fetch',
                     '--providers', 'msrc', '--consent-providers', 'msrc', '--json', '--dry-run'])
    _out, err = capsys.readouterr()
    assert code == 3
    assert 'request: msrc ' + original_plan(['CVE-2024-38063'], ['msrc'])[0].url in err
    assert 'request not covered by user consent' in err
    assert calls == []


def test_acq13_unchanged_preview_is_covered(tmp_path, monkeypatch, capsys):
    seen = []

    def fetch(plan, consent, **kwargs):
        intelligence._validate(tuple(plan), consent, kwargs['api_key'])
        seen.extend(request.url for request in plan)
        assert consent.providers == ('msrc',)
        assert consent.urls == frozenset(seen)
        raise EnrichmentError('PT-ENRICH-CANCEL', 'test stops before network')

    monkeypatch.setattr(intelligence, 'fetch_all', fetch)
    monkeypatch.setattr(cli, '_api_key', lambda _name: None)
    code = cli.main(['correlate', str(tmp_path), '--cve', 'CVE-2024-38063', '--fetch',
                     '--providers', 'msrc', '--consent-providers', 'msrc', '--json', '--dry-run'])
    _out, err = capsys.readouterr()
    assert code == 5 and len(seen) == 1
    assert 'request: msrc ' + seen[0] in err
