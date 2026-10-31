"""GT-01 consolidation regressions: real failure states never create native evidence.

All tests substitute Ghidriff; they do not claim native gate acceptance.
"""
from __future__ import annotations

from types import SimpleNamespace

from patchtrace.backend import BackendConfig
from tools.unified import live_pairs
from unified_s6_helpers import label_doc


def test_failed_native_both_orientations_keep_redacted_log_without_completion(tmp_path, monkeypatch):
    doc = label_doc('failed-native-diagnostic', 'release')
    image = tmp_path / 'synthetic.dll'
    image.write_bytes(b'synthetic-not-executable')
    quarantine = tmp_path / 'quarantine'
    quarantine.mkdir()
    (quarantine / 'analysis.log').write_text(
        'Authorization: Bearer supersecret1234567890\n'
        'Ghidriff process exit code 1: native subprocess failed\n',
        encoding='utf-8',
    )

    class Service:
        root = tmp_path / 'owned-project'
        project = SimpleNamespace(runs=[])

        def apply_analysis(self, *_args):
            raise AssertionError('failed native evidence must not be committed')

        def close(self):
            pass

    monkeypatch.setattr(live_pairs, 'image_path', lambda *_: image)
    monkeypatch.setattr(live_pairs.ProjectService, 'create', lambda *_: Service())
    monkeypatch.setattr(
        live_pairs.backend_module, 'run_comparison',
        lambda *_: (quarantine, SimpleNamespace(status='failed', error='PT-BACKEND: native failed')),
    )
    done, failed = live_pairs.run_all(
        [doc], tmp_path, BackendConfig('python', str(tmp_path)),
        swap=True, work=tmp_path,
    )
    assert done == [] and len(failed) == 2
    for item, orientation in zip(failed, ('forward', 'swapped'), strict=True):
        assert orientation in item
        assert 'Ghidriff process exit code 1' in item
        assert 'supersecret1234567890' not in item
        assert '[redacted]' in item


def test_retained_failure_sidecar_redacts_credentials(tmp_path, monkeypatch):
    doc = label_doc('redacted-native', 'release')
    monkeypatch.setattr(live_pairs, 'load_labels', lambda *_: [doc])
    monkeypatch.setattr(
        live_pairs, 'run_all',
        lambda *_args, **_kwargs: ([], ['Authorization: Bearer secretcredential123456789']),
    )
    output = tmp_path / 'outcomes-redacted.json'
    code = live_pairs.main([
        '--labels', str(tmp_path), '--store', str(tmp_path),
        '--ghidra-dir', str(tmp_path), '--out', str(output),
    ])
    sidecar = output.with_suffix('.failures.txt').read_text(encoding='utf-8')
    assert code == live_pairs.PAIR_FAILED
    assert 'secretcredential123456789' not in sidecar
    assert '[redacted]' in sidecar
