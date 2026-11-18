"""Bounded independent ZIP-reader controls; authored inert members only."""
import hashlib
import io
import json
import socket
import subprocess
import sys
import tempfile
import types
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).parent
REPO = Path('/workspace/scratch/e83fbf4505c3/pw01-retention-integration')
COMMITS = {
    'current304': '6cc6b6b77564e12eaec2917877d94525a69c7102',
    'new302': '121ffb0bcdd6af4f24e5035389d4709dffddf263',
}
modules = {}
for label, commit in COMMITS.items():
    body = subprocess.check_output(['git', 'show', commit + ':tools/verify_release.py'], cwd=REPO)
    module = types.ModuleType('review_verify_release_' + label)
    sys.modules[module.__name__] = module
    exec(compile(body, commit + '/tools/verify_release.py', 'exec'), module.__dict__)
    modules[label] = module


def authored_zip(extra):
    stream = io.BytesIO()
    members = {
        'PatchTrace/PatchTrace.exe': b'authored inert text; never executed',
        'PatchTrace/file-inventory.json': b'[]',
        'PatchTrace/dependency-versions.json': b'{}',
        **extra,
    }
    with zipfile.ZipFile(stream, 'w') as archive:
        for name, data in members.items():
            archive.writestr(zipfile.ZipInfo(name, date_time=(2025, 1, 1, 0, 0, 0)), data)
    return stream.getvalue()


def denied(*args, **kwargs):
    raise AssertionError('network/subprocess operation forbidden during authored controls')


literal = b'PatchTrace/optional?notes.txt'
raw = authored_zip({literal.decode(): b'ordinary inert note'})
assert raw.count(literal) == 2
inputs = {
    'backslash': raw.replace(literal, literal.replace(b'?', b'\\')),
    'nul': raw.replace(literal, literal.replace(b'?', b'\x00')),
    'case-alias': authored_zip({'PatchTrace/Note.txt': b'a', 'patchtrace/note.TXT': b'b'}),
}
results = []
with tempfile.TemporaryDirectory(prefix='pw01-authored-zip-') as temporary:
    paths = {}
    for kind, body in inputs.items():
        paths[kind] = Path(temporary) / (kind + '.zip')
        paths[kind].write_bytes(body)
    with patch.object(socket, 'socket', denied), patch.object(socket, 'create_connection', denied), \
            patch.object(subprocess, 'Popen', denied):
        for kind, path in paths.items():
            for separator in ('/', '\\'):
                outcomes = {}
                with patch.object(zipfile.os, 'sep', separator):
                    for label, module in modules.items():
                        outcomes[label] = module.read_zip(path).problems
                expected_accept = kind == 'backslash'
                assert (not outcomes['new302']) == expected_accept
                expected_old = expected_accept and separator == '/'
                assert (not outcomes['current304']) == expected_old
                results.append({
                    'input': kind, 'reader_separator': separator,
                    'authored_zip_sha256': hashlib.sha256(inputs[kind]).hexdigest(),
                    'expected_accept': expected_accept, 'problems': outcomes,
                })
result = {
    'checked_at': datetime.now(timezone.utc).isoformat(), 'commits': COMMITS,
    'scope': 'six authored ZIP cases across two source versions on Linux; simulated reader separators, not native Windows qualification',
    'target_acquisition': False, 'target_execution': False,
    'cases': results, 'source_version_case_evaluations': 12,
    'finding': 'Current304 falsely labels benign backslash normalization as NUL truncation with the Windows separator. New302 accepts that case; both retain NUL and case-alias rejection.',
}
with (ROOT / 'zip-normalization-review.json').open('x') as stream:
    json.dump(result, stream, indent=2)
    stream.write('\n')
print(json.dumps(result, indent=2))
