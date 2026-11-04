"""OSV is not a beta source (KBF-02 vendor-feeds spec s3.1 and s11): no `osv` CVE provider and no `api.osv.dev`
host anywhere in `src/`. Green on arrival; it turns red when someone wires OSV without changing the decision (then
update the spec, the consent census and this test together)."""
from __future__ import annotations

from pathlib import Path

from patchtrace.enrichment import cve

SRC = Path(__file__).resolve().parents[1] / 'src' / 'patchtrace'


def test_no_source_file_names_the_osv_host():
    assert SRC.is_dir()
    hits = [path.relative_to(SRC).as_posix() for path in sorted(SRC.rglob('*'))
            if path.is_file() and path.suffix in ('.py', '.json', '.toml', '.yml', '.yaml', '.txt')
            and 'api.osv.dev' in path.read_text(encoding='utf-8', errors='replace').lower()]
    assert hits == []


def test_osv_is_not_a_cve_provider():
    assert 'osv' not in cve._PARSERS
    assert set(cve._PARSERS) == {'nvd', 'msrc'}
