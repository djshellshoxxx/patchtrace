"""Fake `bindiff` executables (SPEC-29 §9.1): a Python script behind the portable `fake_exe` launcher.

The fake's behaviour is fixed at creation (`mode`), so no marker files or environment are needed (the
real child environment is allow-listed and could not carry one anyway). On every call it appends its argv,
cwd and environment to `<dir>/spy.jsonl`, so tests can assert exactly what PatchTrace passed.
Fake BinExport inputs are text files whose first line is `FAKE-BINEXPORT <executable_id>`; the fake copies
those ids into `file.hash` as BinDiff copies BinExport `executable_id`.
This is mocked evidence only; it never substitutes for the live job.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from fake_exe import make_fake_exe

TESTS = Path(__file__).resolve().parent
# Real BinDiff 8 texts (measured 2026-10-14, SPEC-29 §2): `--version` prints exactly this line (exit 0) and
# `--nologo --help` prints the committed fixture on stdout and exits 1.
VERSION_LINE = 'BinDiff 8 (@568181968, Sep 25 2023)'
FULL_HELP = (TESTS / 'fixtures' / 'secondary' / 'bindiff-8-help.txt').read_text(encoding='utf-8')

_SOURCE = r'''
import json, os, sys, time, subprocess
sys.path.insert(0, TESTS)
MODE = MODE_VALUE
args = sys.argv[1:]
here = os.path.dirname(os.path.abspath(__file__))
opts = dict(a[2:].split('=', 1) for a in args if a.startswith('--') and '=' in a)
config = None
if opts.get('config') and os.path.isfile(opts['config']):
    with open(opts['config'], 'rb') as handle:
        config = handle.read().decode('latin-1')
with open(os.path.join(here, 'spy.jsonl'), 'a', encoding='utf-8') as spy:
    spy.write(json.dumps({'argv': args, 'cwd': os.getcwd(), 'env': dict(os.environ), 'config': config}) + '\n')
if args == ['--version']:
    if MODE == 'no-version':
        print('hello'); sys.exit(0)
    if MODE == 'version-exit-1':
        print(VERSION); sys.exit(1)
    print(VERSION); sys.exit(0)
if args == ['--nologo', '--help']:
    text = HELP
    if MODE == 'missing-option':
        text = text.replace('--logo', '--nothing')
    if MODE == 'missing-config':
        text = text.replace('--config', '--konfig')
    sys.stdout.write(text)
    sys.exit(0 if MODE == 'help-exit-0' else 1)
if MODE == 'usage-exit-0':  # measured: --primary without --secondary prints usage on stdout and exits 0
    sys.stdout.write(HELP)
    sys.exit(0)
out = opts.get('output_dir', '')
def ident(path):
    with open(path, encoding='utf-8') as handle:
        return handle.readline().split()[1]
stem = lambda p: os.path.splitext(os.path.basename(p))[0]
target = os.path.join(out, stem(opts['primary']) + '_vs_' + stem(opts['secondary']) + '.BinDiff')
primary, secondary = ident(opts['primary']), ident(opts['secondary'])
from bindiff_builder import build
if MODE == 'hang':
    time.sleep(120)
if MODE == 'spawn-grandchild':
    beat = os.path.join(here, 'heartbeat.txt')
    code = 'import time\nwhile True:\n    open(%r, "a").write("x")\n    time.sleep(0.05)\n' % beat
    subprocess.Popen([sys.executable, '-c', code])
    time.sleep(120)
if MODE == 'exit-1-error':
    sys.stderr.write('\x1b[31mError: could not load /secret/home/user/older.BinExport: bad\x1b[0m\n')
    sys.exit(1)
if MODE == 'exit-0-no-file':
    sys.exit(0)
if MODE == 'huge-output':
    with open(target, 'wb') as handle:
        handle.write(b'\0' * (2 * 1024 * 1024))
    time.sleep(120)
if MODE == 'stderr-flood':
    sys.stderr.write('progress\n' * 200000)
hashes = (primary, secondary)
if MODE == 'wrong-hashes':
    hashes = ('c' * 64, secondary)
if MODE == 'reversed-hashes':
    hashes = (secondary, primary)
journal = target + '-journal'
def write_journal():  # after the database is closed: SQLite deletes a stale journal when it creates a file
    with open(journal, 'wb') as handle:  # rollback-journal magic, as BinDiff leaves it while writing
        handle.write(bytes.fromhex('d9d505f920a163d7') + bytes(504))
if MODE in ('partial-then-hang', 'partial-then-kill'):
    # Measured with the real BinDiff 8: a kill during the write phase leaves a valid SQLite file with every
    # table but an empty `function` table (plus the journal). It must never be preserved or imported.
    build(target, hashes=hashes, functions=[])
    write_journal()
    sys.stdout.write('Writing results\n')
    sys.stdout.flush()
    if MODE == 'partial-then-hang':
        time.sleep(120)
    import signal
    if hasattr(signal, 'SIGKILL'):
        os.kill(os.getpid(), signal.SIGKILL)
    os._exit(137)
extra = ('CREATE TRIGGER t AFTER INSERT ON file BEGIN DELETE FROM function; END',) if MODE == 'trigger-in-db' else ()
functions = [] if MODE in ('empty', 'claims-matches-empty-db') else None
if MODE == 'symlink-output':
    os.symlink(os.path.join(out, '..', 'in', 'older.BinExport'), target)
    sys.exit(0)
if MODE == 'wrong-name':
    target = os.path.join(out, 'other.BinDiff')
if MODE == 'writes-outside-out':
    open(os.path.join(os.getcwd(), 'stray.txt'), 'w').write('x')
build(target, hashes=hashes, extra=extra, functions=functions)
if MODE == 'two-files':
    build(os.path.join(out, 'extra.BinDiff'), hashes=hashes)
if MODE == 'zero-size':
    open(target, 'wb').close()
if MODE in ('journal-transient', 'journal-left'):
    write_journal()
if MODE == 'journal-transient':  # the guard polls every 50 ms: let it see the journal, then finish cleanly
    time.sleep(0.4)
    os.remove(journal)
matched = 5 if MODE == 'claims-matches-empty-db' else (0 if functions == [] else 2)
print('matched: %d of 3/3 (primary/secondary, 3/3 non-library)' % matched)
print('Similarity: 81.2% (Confidence: 95.0%)')
sys.exit(0)
'''


def make_fake_bindiff(directory: Path, mode: str = 'ok', *, version: str = VERSION_LINE,
                      help_text: str = FULL_HELP) -> Path:
    source = (_SOURCE.replace('TESTS', repr(str(TESTS)), 1).replace('MODE_VALUE', repr(mode))
              .replace('VERSION', repr(version)).replace('HELP', repr(help_text)))
    return make_fake_exe(directory, 'bindiff', source)


def spy_calls(directory: Path) -> list[dict]:
    path = directory / 'spy.jsonl'
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines() if line.strip()]


def launcher_names() -> frozenset[str]:
    """Executable names the probe must accept for the fake launcher on this OS (`.cmd` on Windows)."""
    return frozenset({'bindiff.cmd'}) if os.name == 'nt' else frozenset()


def write_fake_binexport(path: Path, executable_id: str, payload: str = '') -> Path:
    path.write_text(f'FAKE-BINEXPORT {executable_id}\n{payload}\n', encoding='utf-8')
    return path

