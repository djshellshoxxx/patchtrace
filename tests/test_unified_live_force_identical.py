"""GT-01 native A/A opt-in regression with existing fake external runner.

Fake executable and synthetic bytes are NOT native Ghidra gate results.
"""
from __future__ import annotations

import dataclasses
import hashlib
import threading
from types import SimpleNamespace

import pytest
from test_jobs import fake_runtime, write_backend  # noqa: F401 - fixture reuse
from unified_s6_helpers import label_doc

from patchtrace import backend
from patchtrace.backend import BackendConfig
from tools.unified import live_pairs


def test_flag_default_and_boolean_validation():
    config = BackendConfig('python', '/ghidra')
    assert config.force_identical_diff is False
    with pytest.raises(dataclasses.FrozenInstanceError):
        config.force_identical_diff = True
    forged = dataclasses.replace(config, force_identical_diff='yes')
    assert any('force_identical_diff must be a boolean' in error
               for error in backend._config_errors(forged))


def test_equal_images_only_analyzed_when_native_opt_in(fake_runtime):
    root, package, project, config = fake_runtime
    content = (root / 'older.bin').read_bytes()
    (root / 'newer.bin').write_bytes(content)
    project.artifacts[1].sha256 = hashlib.sha256(content).hexdigest()
    write_backend(
        package,
        'import hashlib\n'
        'old,new = (pathlib.Path(p) for p in sys.argv[1:3])\n'
        'assert old.name != new.name\n'
        'assert old.read_bytes() == new.read_bytes()\n'
        'assert "--force-diff" in sys.argv\n'
        'gzfs = pathlib.Path(sys.argv[sys.argv.index("--gzfs-path")+1])\n'
        'gzfs.mkdir(parents=True)\n'
        'for p in (old,new):\n'
        '    name = p.name + "-" + hashlib.sha1(p.read_bytes()).hexdigest()[:6] + ".gzf"\n'
        '    (gzfs/name).write_bytes(b"GZF" + p.read_bytes())\n'
        '(out/"json"/"diff.ghidriff.json").write_text('
        'json.dumps({"functions":{"added":[],"deleted":[],"modified":[]}}))\n',
    )
    old_path, skipped = backend.run_comparison(
        config, project, root, threading.Event(), lambda _: None,
    )
    assert old_path.is_dir() and skipped.status == 'identical'
    assert 'force_identical_diff' not in skipped.settings

    requested = dataclasses.replace(config, retain_gzf=True, force_identical_diff=True)
    result, run = backend.run_comparison(
        requested, project, root, threading.Event(), lambda _: None,
    )
    assert run.status == 'completed', run.error
    assert result.is_file() and run.settings['force_identical_diff'] is True
    assert set(run.settings['gzf']) == {'older', 'newer'}
    assert run.settings['gzf']['older']['name'] != run.settings['gzf']['newer']['name']
    for side in ('older', 'newer'):
        path = root / 'runs' / run.id / 'unified' / 'gzf' / f'{side}.gzf'
        assert path.read_bytes() == b'GZF' + content


@pytest.mark.parametrize('orientation', ['forward', 'swapped'])
def test_harness_never_counts_an_identical_shortcut(tmp_path, monkeypatch, orientation):
    digest = '0' * 64
    doc = label_doc('native-aa', 'release', older=digest, newer=digest)
    image = tmp_path / 'image.dll'
    image.write_bytes(b'not-executed')
    seen = []

    class Service:
        root = tmp_path / 'case'
        project = SimpleNamespace(runs=[])

        def apply_analysis(self, *_args):
            raise AssertionError('shortcut must not persist as completed')

        def close(self):
            pass

    monkeypatch.setattr(live_pairs, 'image_path', lambda *_: image)
    monkeypatch.setattr(live_pairs.ProjectService, 'create', lambda *_: Service())

    def comparison(config, *_args):
        seen.append(config)
        return tmp_path, SimpleNamespace(status='identical')

    monkeypatch.setattr(live_pairs.backend_module, 'run_comparison', comparison)
    with pytest.raises(RuntimeError, match='not executed'):
        live_pairs.analyse_pair(
            doc, tmp_path, BackendConfig('python', str(tmp_path)), tmp_path,
            orientation,
        )
    assert len(seen) == 1
    assert seen[0].force_identical_diff and seen[0].retain_gzf
    assert seen[0].no_cache and not seen[0].refresh
