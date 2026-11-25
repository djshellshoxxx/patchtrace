"""Verify or reconstruct the unchanged sealed Sigstore evidence archive."""
from pathlib import Path
from io import BytesIO
import argparse
import hashlib
import json
import zipfile

EXPECTED_SHA256 = '81a7e43597b9100c7b41a0a4ebcb477db8511d7f222a589faa1e5821140959b3'
EXPECTED_PARTS = (('sigstore-independent.zip.part01', 9999999),
                  ('sigstore-independent.zip.part02', 6865754))


def require(condition, message):
    if not condition:
        raise ValueError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument('--verify-only', action='store_true')
    choice.add_argument('--output', type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    index = json.loads((root / 'sigstore-tooling-archive-parts.json').read_text())
    require(index['original_archive_sha256'] == EXPECTED_SHA256
            and index['original_archive_bytes'] == 16865753
            and index['original_archive_members'] == 145, 'Wrong original archive identity')
    require(len(index['parts']) == 2, 'Exactly two archive segments are required')
    chunks, offset = [], 0
    for part, (name, size) in zip(index['parts'], EXPECTED_PARTS):
        require(part['name'] == name and part['bytes'] == size
                and part['offset'] == offset, 'Wrong segment name, size, order or offset')
        path = root / name
        require(not path.is_symlink() and path.is_file() and path.stat().st_size == size,
                'Segment must be a regular non-symlink file of the expected size')
        data = path.read_bytes()
        require(len(data) == size and hashlib.sha256(data).hexdigest() == part['sha256'],
                'Segment digest mismatch')
        chunks.append(data)
        offset += size
    data = b''.join(chunks)
    require(offset == 16865753 and hashlib.sha256(data).hexdigest() == EXPECTED_SHA256,
            'Reassembled archive does not match the original seal')
    with zipfile.ZipFile(BytesIO(data)) as archive:
        names = archive.namelist()
        require(len(names) == len(set(names)) == 145 and archive.testzip() is None,
                'Archive member count, uniqueness or CRC verification failed')
    if args.output:
        with args.output.open('xb') as target:
            target.write(data)
    print(json.dumps({'verified': True, 'bytes': len(data), 'sha256': EXPECTED_SHA256,
                      'members': 145, 'output': str(args.output) if args.output else None}))


if __name__ == '__main__':
    main()
