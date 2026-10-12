"""CI-only: reproduce a user's pre-populated Ghidra symbol store natively.

Copies the PDB named by a PE's CodeView RSDS record into a level-1 symbol
store (<store>/<name>/<GUID><age>/<name>), the layout Ghidriff creates on
Windows. Used before a manual symbol-enabled Ghidriff run persists that store
in global Ghidra preferences. Never run on analyst machines.
"""
from __future__ import annotations

import shutil
import struct
import sys
import uuid
from pathlib import Path


def rsds(binary: Path) -> tuple[str, str]:
    data = binary.read_bytes()
    offset = data.find(b'RSDS')
    if offset < 0:
        raise SystemExit(f'{binary}: no CodeView RSDS record; build with /Zi /DEBUG')
    guid = uuid.UUID(bytes_le=data[offset + 4:offset + 20])
    age = struct.unpack_from('<I', data, offset + 20)[0]
    name = data[offset + 24:data.index(b'\0', offset + 24)].decode('utf-8', 'replace')
    return f'{str(guid).replace("-", "").upper()}{age:X}', Path(name.replace('\\', '/')).name


def main(store: Path, binaries: list[Path]) -> None:
    for binary in binaries:
        key, name = rsds(binary)
        source = binary.with_name(name)
        target = store / name / key / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        print(f'seeded {target}')


if __name__ == '__main__':
    main(Path(sys.argv[1]), [Path(p) for p in sys.argv[2:]])
