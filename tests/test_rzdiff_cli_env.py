"""SPEC-07h H7 for rz-diff: `secondary run` children get the audited `for_tool='rizin'` allow-list.

Fake rz-diff (portable launcher from tests/fake_exe.py) dumps the environment it received; mocked engine,
so this is wiring evidence only, not live rizin compatibility.
"""
from __future__ import annotations

import json

from fake_exe import make_fake_exe
from test_cli_secondary_run import GOOD, project, run_cli  # noqa: F401 - pytest fixture import

SECRETS = {'GITHUB_TOKEN': 'sentinel-token', 'AWS_SECRET_ACCESS_KEY': 'sentinel-aws',
           'JAVA_TOOL_OPTIONS': '-javaagent:sentinel.jar', 'PYTHONSTARTUP': 'sentinel.py',
           'HTTPS_PROXY': 'http://sentinel-proxy:3128', 'LD_PRELOAD': 'sentinel.so'}


def test_secondary_run_child_env_is_allow_listed(project, tmp_path, capsys, monkeypatch):  # noqa: F811
    root, _ = project
    for name, value in SECRETS.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv('RZ_PREFIX', 'rz-sentinel')
    dumps = tmp_path / 'dumps'
    dumps.mkdir()
    source = ("import json, os, sys, uuid\n"
              f"open(os.path.join({str(dumps)!r}, uuid.uuid4().hex + '.json'), 'w').write(json.dumps(dict(os.environ)))\n"
              "if sys.argv[1:] == ['-v']:\n    print('rz-diff 0.9.1')\n    sys.exit(0)\n"
              f"print({GOOD!r})\n")
    exe = str(make_fake_exe(tmp_path / 'bin', 'rz-diff', source))
    code, doc = run_cli(root, '--rz-diff', exe, '--engine', 'rz-diff', '--no-cache', capsys=capsys)
    assert code == 0 and doc['result']['runs'][0]['status'] == 'ok'
    seen = [json.loads(p.read_text()) for p in sorted(dumps.iterdir())]
    assert len(seen) >= 2  # the version probe and the diff run
    for env in seen:
        upper = {k.upper() for k in env}
        assert not upper & {k.upper() for k in SECRETS}, sorted(upper & set(SECRETS))
        assert env.get('RZ_PREFIX') == 'rz-sentinel' and 'PATH' in upper
