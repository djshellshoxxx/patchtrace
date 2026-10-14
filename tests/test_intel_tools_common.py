"""SPEC-29 tools T2: strict `tool-evidence/1` records and shared helpers (pure; no tool is run)."""
from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from patchtrace.intelligence.tools import common as c

SHA_A, SHA_B = 'a' * 64, 'b' * 64


def manifest(**kw) -> c.ToolManifest:
    base = dict(engine='capa', version='9.4.0', version_text='capa 9.4.0', cli_path='/opt/capa/capa',
                executable_sha256=SHA_A, capabilities=('json', 'backend:vivisect'), license='Apache-2.0',
                rules_source='embedded', supported=True)
    return c.ToolManifest(**{**base, **kw})


def run(**kw) -> c.ToolRun:
    base = dict(run_id='r1', engine='capa', side='older', input_artifact_hash=SHA_A, config_digest=SHA_B,
                cache_key=SHA_B, started_at='2026-10-14T00:00:00+00:00', elapsed=12, status='ok', error=None,
                error_code=None, returncode=0, stderr_digest=None, stdout_digest=SHA_A, profile='basic',
                manifest=manifest())
    return c.ToolRun(**{**base, **kw})


def test_records_are_strict_frozen_and_round_trip():
    record = run()
    with pytest.raises(ValidationError):
        c.ToolRun.model_validate({**record.model_dump(), 'surprise': 1})
    with pytest.raises(ValidationError):
        run(elapsed='12')  # strict: no string-to-int coercion
    with pytest.raises(ValidationError):
        run(status='done')
    with pytest.raises((ValidationError, TypeError)):
        record.status = 'failed'  # frozen
    assert c.ToolRun.model_validate_json(record.model_dump_json()) == record
    assert record.contract == 'tool-evidence/1'


def test_none_found_is_distinct_from_absent_and_failure():
    assert c.produced(run(status='ok', evidence_count=3)) and c.produced(run(status='none-found'))
    for status in ('absent', 'unsupported', 'failed', 'timeout', 'cancelled'):
        assert not c.produced(run(status=status, error_code='PT-TOOL-RUN', error='x'))
    with pytest.raises(ValidationError):
        run(status='none-found', evidence_count=2)  # none-found means zero evidence
    with pytest.raises(ValidationError):
        run(status='failed')  # a failure always names its PT-TOOL code


def test_rules_identity_falls_back_to_the_executable_for_embedded_rules():
    assert manifest().rules_identity() == f'embedded:{SHA_A}'
    assert manifest(rules_source='directory', rules_sha256=SHA_B).rules_identity() == SHA_B
    with pytest.raises(ValidationError):
        manifest(rules_source='directory')  # a directory pack must carry its digest


def test_cache_key_covers_artifact_engine_rules_backend_and_options():
    key = c.cache_key(SHA_A, manifest(), {'backend': 'vivisect'})
    assert key == c.cache_key(SHA_A, manifest(cli_path='/elsewhere/capa'), {'backend': 'vivisect'})  # path-free
    assert key != c.cache_key(SHA_B, manifest(), {'backend': 'vivisect'})
    assert key != c.cache_key(SHA_A, manifest(executable_sha256=SHA_B), {'backend': 'vivisect'})
    assert key != c.cache_key(SHA_A, manifest(rules_source='directory', rules_sha256=SHA_B), {'backend': 'vivisect'})
    assert key != c.cache_key(SHA_A, manifest(backend='ghidra'), {'backend': 'vivisect'})
    assert key != c.cache_key(SHA_A, manifest(), {'backend': 'ghidra'})
    assert key != c.cache_key(SHA_A, manifest(version='9.5.0'), {'backend': 'vivisect'})
    assert c.config_digest(manifest(), {'x': '1'}) == c.config_digest(manifest(cli_path='/b'), {'x': '1'})


def test_strict_json_rejects_hostile_documents():
    assert c.load_json_strict(b'{"a": [1, 2]}', max_bytes=100) == {'a': [1, 2]}
    for payload, needle in ((b'{"a": 1, "a": 2}', 'duplicate'), (b'{"a": NaN}', 'non-finite'),
                            (b'{"a": Infinity}', 'non-finite'), (b'\xff\xfe{}', 'UTF-8'),
                            (b'{"a": ', 'invalid JSON'), (b'[' * 200 + b']' * 200, 'nest'),
                            (b'   ', 'empty')):
        with pytest.raises(c.ToolError, match=needle) as info:
            c.load_json_strict(payload, max_bytes=10_000, max_depth=96)
        assert info.value.code == 'PT-TOOL-OUTPUT'
    with pytest.raises(c.ToolError) as info:
        c.load_json_strict(b'{"a": 1}', max_bytes=4)
    assert info.value.code == 'PT-TOOL-LIMIT'


def test_display_values_are_plain_text_and_bounded():
    shown = c.display_text('a\nb\x00c‮d​e' + 'x' * 400)
    assert '\n' not in shown and '\x00' not in shown and '‮' not in shown and '​' not in shown
    assert '\\n' in shown and '\\x00' in shown and '\\u202e' in shown
    assert len(shown) <= c.DISPLAY_LIMIT
    assert c.display_text('<script>alert(1)</script>') == '<script>alert(1)</script>'  # escaping is the renderer's job


@pytest.mark.parametrize('value, kind', [
    ('aws_access_key_id=AKIAIOSFODNN7EXAMPLE', 'aws-access-key'),
    ('-----BEGIN RSA PRIVATE KEY-----', 'private-key'),
    ('ghp_' + 'a1B2' * 9, 'github-token'),
    ('password=hunter2hunter2', 'credential-assignment'),
    ('eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.c2lnbmF0dXJlLXRleHQ', 'jwt'),
    ('Server=db;User Id=sa;Password=Sup3rS3cret;', 'credential-assignment'),
    ('PatchTrace synthetic: configuration loaded', None),
    ('GetProcAddress', None),
])
def test_secret_patterns(value, kind):
    assert c.secret_kind(value) == kind


def test_redaction_keeps_identity_but_hides_the_value():
    text = 'aws_access_key_id=AKIAIOSFODNN7EXAMPLE'
    shown = c.redacted_display(text, c.secret_kind(text))
    assert 'AKIA' not in shown and 'aws-access-key' in shown
    assert c.redacted_display('plain', None) == 'plain'


def test_evidence_link_and_capability_validation():
    link = c.EvidenceLink(tool_run_id='r1', artifact_sha256=SHA_A, function_id='rva:0x1030', rva=0x1030,
                          attribution='function-start')
    cap = c.CapabilityEvidence(rule_id='get hostname', rule_sha256=SHA_B, namespace='host-interaction/os/hostname',
                               scope='function', address_space='absolute', address=0x140001030, location=link,
                               kind='capability', source_run_id='r1')
    assert c.CapabilityEvidence.model_validate_json(cap.model_dump_json()) == cap
    with pytest.raises(ValidationError):  # a localized attribution needs an RVA
        c.EvidenceLink(tool_run_id='r1', artifact_sha256=SHA_A, attribution='function-start')
    with pytest.raises(ValidationError):
        c.EvidenceLink(tool_run_id='r1', artifact_sha256=SHA_A, function_id='0x1030', rva=1,
                       attribution='function-start')  # function ids are rva:0x<hex>
    with pytest.raises(ValidationError):
        cap.model_copy(update={'scope': 'process'}).model_validate(cap.model_dump() | {'scope': 'process'})


def test_evidence_set_counts_must_match():
    good = c.ToolEvidenceSet(run_id='r1', engine='diec', side='older', artifact_sha256=SHA_A, cache_key=SHA_B,
                             config_digest=SHA_B, environment=(), counts={'environment': 0})
    assert good.evidence_count() == 0
    with pytest.raises(ValidationError):
        c.ToolEvidenceSet(run_id='r1', engine='diec', side='older', artifact_sha256=SHA_A, cache_key=SHA_B,
                          config_digest=SHA_B, counts={'environment': 3})
    body = json.loads(good.model_dump_json())
    assert body['contract'] == 'tool-evidence/1'


def test_no_qt_or_process_imports():
    import os
    import subprocess
    import sys
    from pathlib import Path
    src = str(Path(__file__).resolve().parents[1] / 'src')  # this checkout, not an installed copy
    code = ('import sys; import patchtrace.intelligence.tools.common, patchtrace.intelligence.tools.normalize, '
            'patchtrace.intelligence.tools.delta, patchtrace.intelligence.tools.capa, '
            'patchtrace.intelligence.tools.floss, patchtrace.intelligence.tools.diec; '
            'bad = [m for m in sys.modules if m.startswith(("PySide6", "patchtrace.ui"))]; print(bad)')
    env = {**os.environ, 'PYTHONPATH': src + os.pathsep + os.environ.get('PYTHONPATH', '')}
    out = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, check=True, env=env).stdout
    assert out.strip() == '[]'
