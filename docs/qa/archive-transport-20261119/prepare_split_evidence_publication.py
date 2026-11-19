"""Create a separate append-only publication branch; preserve original local history."""
import hashlib
import io
import json
from pathlib import Path
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parent.parent
REPO = ROOT / 'continuation-integration'
OLD_HEAD = 'b2b170e343ab4da680b3629b3ab2e89ce6f42774'
BASE = 'f16d41062a5d558d889ef6a6bda922004e0ac3b4'
CHECKPOINT = '29192f7837ebdb268d5c47e0a2536c67148cbe9f'
BRANCH = 'codex/verified-publication-split-20261119'
DIRECTORY = 'docs/qa/admission-diagnostics-integration-20261119'
ARCHIVE_SHA = 'ab11b8c014d5fdf0cfe94b2e29f661bd20974019f7c4f9a91151b7593dce4ece'


def git(*args):
    return subprocess.check_output(['git', '-C', str(REPO), *args])


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


assert git('rev-parse', 'HEAD').decode().strip() == OLD_HEAD
assert git('rev-parse', 'refs/heads/codex/verified-continuation-20261118').decode().strip() == OLD_HEAD
assert not git('status', '--porcelain')
original_archive = git('show', CHECKPOINT + ':' + DIRECTORY + '/evidence.zip')
assert len(original_archive) == 13132985 and sha(original_archive) == ARCHIVE_SHA
with zipfile.ZipFile(io.BytesIO(original_archive)) as z:
    assert z.testzip() is None and len(z.namelist()) == 421
changed = git('diff', '--name-only', BASE, CHECKPOINT).decode().splitlines()
assert len(changed) == 9
assert all(name.startswith('docs/') or name == 'tasks/todo.md' for name in changed)
subprocess.run(['git', '-C', str(REPO), 'switch', '-c', BRANCH, BASE], check=True)
for name in changed:
    if name.endswith('/evidence.zip'):
        continue
    path = REPO / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(git('show', CHECKPOINT + ':' + name))
out = REPO / DIRECTORY
original = out / 'original-checkpoint'
original.mkdir()
for name in ['README.md', 'manifest.json']:
    (original / name).write_bytes((out / name).read_bytes())
parts = []
for number, offset in enumerate(range(0, len(original_archive), 8 * 1024 * 1024), 1):
    raw = original_archive[offset:offset + 8 * 1024 * 1024]
    name = 'evidence.zip.part-' + str(number).zfill(3)
    (out / name).open('xb').write(raw)
    parts.append(dict(path=name, bytes=len(raw), sha256=sha(raw)))
assert len(parts) == 2
layout = dict(schema='patchtrace-lossless-archive-parts/1', original_checkpoint=CHECKPOINT,
              original_local_head=OLD_HEAD, preserved_branch='codex/verified-continuation-20261118',
              archive='evidence.zip', archive_bytes=len(original_archive), archive_sha256=ARCHIVE_SHA,
              parts=parts, original_manifest='original-checkpoint/manifest.json',
              original_readme='original-checkpoint/README.md',
              reason='The connector rejects requests over16MiB; base64 of this archive exceeds that limit. Canonical Git fetch works but push has no credentials. No remote ref moved during either failed transport attempt.')
(out / 'archive-parts.json').write_text(json.dumps(layout, indent=2) + '\n')
helper = '''"""Verify lossless archive parts; optionally write an exclusive output file."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import zipfile

root = Path(__file__).resolve().parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output', type=Path, help='Write the verified archive; existing output is refused.')
args = parser.parse_args()
layout = json.loads((root / 'archive-parts.json').read_bytes())
assert layout['archive_bytes'] == 13132985
assert layout['archive_sha256'] == 'ab11b8c014d5fdf0cfe94b2e29f661bd20974019f7c4f9a91151b7593dce4ece'
assert [r['path'] for r in layout['parts']] == ['evidence.zip.part-001', 'evidence.zip.part-002']
chunks = []
for row in layout['parts']:
    assert 0 < row['bytes'] <= 8 * 1024 * 1024
    with (root / row['path']).open('rb') as stream:
        raw = stream.read(row['bytes'] + 1)
    assert len(raw) == row['bytes'] and hashlib.sha256(raw).hexdigest() == row['sha256']
    chunks.append(raw)
raw = b''.join(chunks)
assert len(raw) == layout['archive_bytes']
assert hashlib.sha256(raw).hexdigest() == layout['archive_sha256']
manifest = json.loads((root / layout['original_manifest']).read_bytes())
with zipfile.ZipFile(io.BytesIO(raw)) as archive:
    assert archive.testzip() is None
    rows = manifest['payloads']
    assert len(rows) == 420 and len(archive.namelist()) == 421
    for row in rows:
        data = archive.read(row['path'])
        assert len(data) == row['bytes'] and hashlib.sha256(data).hexdigest() == row['sha256']
if args.output is not None:
    with args.output.open('xb') as stream:
        stream.write(raw)
print(json.dumps(dict(archive_bytes=len(raw), archive_sha256=layout['archive_sha256'],
                      payloads=len(rows), zip_crc_verified=True,
                      output=str(args.output) if args.output else None)))
'''
(out / 'reassemble_evidence.py').write_text(helper)
prefix = '''> **Archive transfer layout:** The original 13,132,985-byte `evidence.zip`
> is retained without changing a byte as `evidence.zip.part-001` and
> `evidence.zip.part-002`. `archive-parts.json` records both part hashes and the
> original checksum. Run `python reassemble_evidence.py` in this directory to
> verify all parts, all420 original payloads and ZIP CRCs without writing a file.
> To reconstruct the original archive, use
> `python reassemble_evidence.py --output evidence.zip`; an existing destination
> is refused. Run this reconstruction before `compact_inventory.py`.
> The original README and manifest remain byte-for-byte in `original-checkpoint/`.
> This transfer layout changes no source, test, acceptance result or archived
> evidence. Original local commits remain on `codex/verified-continuation-20261118`.

'''
(out / 'README.md').write_text(prefix + (original / 'README.md').read_text())
manifest = json.loads((original / 'manifest.json').read_bytes())
manifest['publication_transport'] = dict(layout='archive-parts.json', original_checkpoint=CHECKPOINT,
                                        original_manifest='original-checkpoint/manifest.json')
manifest['companion_files'] = [dict(path=name, bytes=(out / name).stat().st_size,
                                  sha256=sha((out / name).read_bytes()))
                               for name in ['README.md', 'branch-inventory.json', 'compact_inventory.py',
                                            'archive-parts.json', 'reassemble_evidence.py']]
(out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
history = REPO / 'docs/qa/archive-transport-20261119'
(history / 'original-local-commits').mkdir(parents=True)
refs = git('rev-list', '--reverse', '361dd495a7e050121f2b3cae4e7678faad7fee35..' + OLD_HEAD).decode().splitlines()
assert len(refs) == 37
for ref in refs:
    (history / 'original-local-commits' / (ref + '.commit')).write_bytes(git('cat-file', 'commit', ref))
attempts = ROOT / 'qa/core-admission-integration-publication'
for name in ['formatter-qt-blob-transport-error.json', 'canonical-fetch-result.json',
             'canonical-fetch.stdout', 'canonical-fetch.stderr',
             'canonical-prepared-fetch-result.json', 'canonical-prepared-fetch.stdout',
             'canonical-prepared-fetch.stderr', 'canonical-push-dry-run-result.json',
             'canonical-push-dry-run.stdout', 'canonical-push-dry-run.stderr',
             'formatter-qt-plan-metadata.json']:
    (history / name).write_bytes((attempts / name).read_bytes())
(history / 'prepare_split_evidence_publication.py').write_bytes(Path(__file__).read_bytes())
(history / 'README.md').write_text('''# Lossless evidence transport — 2026-11-19

The connector rejected the 13,132,985-byte checkpoint archive because its base64
request exceeds the16MiB transport limit. Canonical Git read-only fetch succeeded;
the normal push dry run failed because this checkout has no Git push credentials.
Neither attempt moved a remote ref. This is a transport limitation, not an
approval rejection or a qualification result.

The original local branch `codex/verified-continuation-20261118` remains intact at
`b2b170e343ab4da680b3629b3ab2e89ce6f42774`, retaining all37 local commits since
`361dd495a7e050121f2b3cae4e7678faad7fee35`. Their exact Git commit objects are
retained under `original-local-commits/`. The already prepared33 remote commits
remain unchanged. A new publication branch from their local source parentf16
carries the checkpoint with two lossless parts, followed by the original formatter
spec/source and final Qt observation commits with explicit source attribution.
No existing local or remote history is rewritten; no branch is removed.

The original archive is reproduced byte-for-byte by the bounded verifier in
`../admission-diagnostics-integration-20261119/reassemble_evidence.py`. Part hashes,
the original manifest/README,420 original payload hashes, ZIP CRCs and the full
archive checksum remain available. The compact316-branch inventory is unchanged.
This layout change adds no production code or acceptance claim. The prior9- and
2043-test results retain their original exact sources and limits. Main merge and
release remain blocked. The existing `[no release]` hold is preserved.
''')
assert not git('diff', '--name-only', BASE, '--', 'src', 'tests', 'tools', '.github', 'pyproject.toml')
assert git('rev-parse', 'refs/heads/codex/verified-continuation-20261118').decode().strip() == OLD_HEAD
print(json.dumps(dict(branch=BRANCH, baseline=BASE, original_branch_head=OLD_HEAD,
                     archive_sha256=ARCHIVE_SHA, parts=parts, original_commit_headers=len(refs))))
