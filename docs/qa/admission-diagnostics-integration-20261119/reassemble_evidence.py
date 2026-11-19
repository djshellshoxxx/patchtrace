"""Verify lossless archive parts; optionally write an exclusive output file."""
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
    assert len(rows) == 420 and len(archive.namelist()) == 420
    for row in rows:
        data = archive.read(row['path'])
        assert len(data) == row['bytes'] and hashlib.sha256(data).hexdigest() == row['sha256']
if args.output is not None:
    with args.output.open('xb') as stream:
        stream.write(raw)
print(json.dumps(dict(archive_bytes=len(raw), archive_sha256=layout['archive_sha256'],
                      payloads=len(rows), zip_crc_verified=True,
                      output=str(args.output) if args.output else None)))
