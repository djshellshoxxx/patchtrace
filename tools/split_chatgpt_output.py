"""Split a saved ChatGPT answer into the files it contains.

ChatGPT prompts in docs/plans/chatgpt-prompts.md ask for `=== FILE: <path> ===` headers followed by the full file. Save the
raw answers (all messages of one prompt, pasted one after another) to one text file, then:

    python tools/split_chatgpt_output.py saved.md            # dry run: lists what would be written
    python tools/split_chatgpt_output.py saved.md --apply    # writes the files

Safety: only relative POSIX paths under docs/, tests/ or tools/calibration/ are accepted (no '..', no absolute paths, no
backslashes); an existing file is never overwritten unless --overwrite is given; `NEXT:` lines and code fences around a
file body are removed; content is written as UTF-8 with LF line endings. Nothing from the answer is executed.
"""
from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

ALLOWED_ROOTS = ('docs', 'tests', 'tools/calibration')
HEADER = re.compile(r'^\s*(?:\*\*)?=== FILE: (?P<path>.+?) ===(?:\*\*)?\s*$')
NEXT_LINE = re.compile(r'^\s*(?:\*\*)?NEXT:.*$')
FENCE = re.compile(r'^\s*(```|~~~)')
MAX_BYTES = 2_000_000


@dataclass(frozen=True)
class Block:
    path: str
    text: str


def parse(text: str) -> list[Block]:
    blocks: list[tuple[str, list[str]]] = []
    for line in text.replace('\r\n', '\n').split('\n'):
        match = HEADER.match(line)
        if match:
            blocks.append((match.group('path').strip().strip('`'), []))
        elif blocks and not NEXT_LINE.match(line):
            blocks[-1][1].append(line)
    return [Block(path, _body(lines)) for path, lines in blocks]


def _body(lines: list[str]) -> str:
    while lines and not lines[0].strip():
        lines = lines[1:]
    while lines and not lines[-1].strip():
        lines = lines[:-1]
    if len(lines) >= 2 and FENCE.match(lines[0]) and FENCE.match(lines[-1]):
        lines = lines[1:-1]
    return '\n'.join(lines).rstrip('\n') + '\n'


def check_path(raw: str) -> str | None:
    """Return a problem description, or None when the path is acceptable."""
    if not raw or '\\' in raw or raw.startswith('/') or re.match(r'^[A-Za-z]:', raw):
        return 'must be a relative POSIX path'
    path = PurePosixPath(raw)
    if '..' in path.parts or '.' in path.parts[:1] and len(path.parts) == 1:
        return 'must not contain ..'
    if not any(raw == root or raw.startswith(root + '/') for root in ALLOWED_ROOTS):
        return f'must be under one of {ALLOWED_ROOTS}'
    return None


def plan(blocks: list[Block], root: Path, overwrite: bool) -> list[tuple[Block, str]]:
    result = []
    seen: set[str] = set()
    for block in blocks:
        problem = check_path(block.path)
        if problem is None and block.path in seen:
            problem = 'appears twice in the answer'
        if problem is None and len(block.text.encode('utf-8')) > MAX_BYTES:
            problem = 'larger than 2 MB'
        if problem is None and (root / block.path).exists() and not overwrite:
            problem = 'already exists (use --overwrite)'
        seen.add(block.path)
        result.append((block, problem or 'ok'))
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('source', type=Path)
    parser.add_argument('--root', type=Path, default=Path.cwd())
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--overwrite', action='store_true')
    args = parser.parse_args(argv)
    blocks = parse(args.source.read_text(encoding='utf-8-sig'))
    if not blocks:
        print('no "=== FILE: <path> ===" headers found', file=sys.stderr)
        return 2
    planned = plan(blocks, args.root, args.overwrite)
    written = 0
    for block, status in planned:
        print(f'{status:<40} {block.path} ({len(block.text.splitlines())} lines)')
        if status == 'ok' and args.apply:
            target = args.root / block.path
            target.parent.mkdir(parents=True, exist_ok=True)
            with open(target, 'w', encoding='utf-8', newline='\n') as handle:
                handle.write(block.text)
            written += 1
    rejected = sum(1 for _, status in planned if status != 'ok')
    print(f'{len(planned)} files found, {written} written, {rejected} rejected' + ('' if args.apply else ' (dry run)'))
    return 1 if rejected else 0


if __name__ == '__main__':
    sys.exit(main())
