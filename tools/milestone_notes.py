"""Generate milestone release-notes text (windows-acceptance spec section 4). Stdlib only.

Everything in the output comes from an argument or a file you pass; nothing is inferred or invented. A check
with no input is reported as not run / open, never as passed. The text never claims production readiness.

usage: milestone_notes.py --tag TAG --sha SHA --run-url URL --run-number N [--ref-kind main|tag]
          [--assets DIR] [--junit linux|windows=FILE ...] [--result NAME=STATE ...] [--manual FILE.json]
          [--preamble FILE] [--output FILE]

--result NAME=STATE: NAME in qa-ubuntu, qa-windows, linux-smoke, live-backend, live-rizin; STATE is one of
  success, failure, cancelled, skipped, not-run. Only `success` renders as pass. qa-* success also implies the
  Ruff step of that job passed (it is a step of the same job); live-backend/live-rizin are separate workflows
  and must be passed only when they ran on the SHA being described.
--manual FILE.json: {"M01": {"result": "pass", "evidence": "docs/qa.md#..."}, ...}. A pass without an evidence
  link counts as not-run.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

MANUAL_IDS = tuple(f'M{i:02d}' for i in range(1, 19))
STATES = ('success', 'failure', 'cancelled', 'skipped', 'not-run')
RESULT_NAMES = ('qa-ubuntu', 'qa-windows', 'linux-smoke', 'live-backend', 'live-rizin')
ASSET_NAMES = ('PatchTrace-0.1.0-windows-x64.zip', 'PatchTrace-0.1.0-linux-x86_64.tar.gz')

# Automated checks that exist in the repository. Update when new checks land; the spec lists the rest.
SECTION2_RAN = ('A1 help for all 7 commands, A2 usage error, A3 missing project, A4 --self-test, A5 JSON contract, '
                'A10 path cases (spaces, Unicode, OneDrive-style, long) through the CLI, A6 imported-result '
                '3-build series (tools/frozen_smoke.py on the Windows package)')
SECTION2_NOT = ('A6 native 3-build series with a real Ghidra run, A7, A8, A9, A11, A12 and the trailing-dot/'
                'reserved-name halves of A10')


def pretty(state: str | None) -> str:
    return {'success': 'pass', 'failure': 'FAIL', 'cancelled': 'cancelled', 'skipped': 'skipped'}.get(
        state or '', 'not run')


def junit_counts(path: Path) -> dict[str, int]:
    root = ET.parse(path).getroot()  # input is pytest's own junit file from this workflow, not untrusted
    suites = [root] if root.tag == 'testsuite' else list(root.iter('testsuite'))
    total = {'tests': 0, 'failures': 0, 'errors': 0, 'skipped': 0}
    for suite in suites:
        for key in total:
            total[key] += int(suite.get(key, 0))
    total['passed'] = total['tests'] - total['failures'] - total['errors'] - total['skipped']
    return total


def counts_text(counts: dict[str, int] | None, state: str | None) -> str:
    if counts is None:
        return f'{pretty(state)} (no result file supplied)'
    text = (f"{counts['passed']} passed, {counts['skipped']} skipped, "
            f"{counts['failures'] + counts['errors']} failed")
    return text if state in (None, 'success') else f'{pretty(state)}: {text}'


def describe_assets(directory: Path | None) -> list[str]:
    lines = []
    for name in ASSET_NAMES:
        path = directory / name if directory else None
        if path is None or not path.is_file():
            lines.append(f'- {name} - not present in this build')
            continue
        with path.open('rb') as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        lines.append(f'- {name} - {path.stat().st_size} bytes - SHA-256 {digest}')
    return lines


def manual_summary(record: dict | None) -> tuple[str, list[str], bool]:
    """(text, warnings, all_passed). Only a pass with an evidence link counts."""
    record = record or {}
    unknown = [key for key in record if key not in MANUAL_IDS]
    if unknown:
        raise ValueError(f'unknown manual check id {unknown[0]!r}')
    warnings: list[str] = []
    passed = failed = 0
    for check_id in MANUAL_IDS:
        entry = record.get(check_id) or {}
        result = entry.get('result', 'not-run')
        if result == 'pass' and not str(entry.get('evidence', '')).strip():
            warnings.append(f'{check_id}: pass without evidence link counted as not-run')
            result = 'not-run'
        passed += result == 'pass'
        failed += result == 'fail'
    not_run = len(MANUAL_IDS) - passed - failed
    text = f'{passed} pass, {failed} fail, {not_run} not-run (of {len(MANUAL_IDS)})'
    return text, warnings, passed == len(MANUAL_IDS)


def build(args: argparse.Namespace) -> str:
    results = dict(args.result)
    counts = {label: junit_counts(Path(path)) for label, path in args.junit}
    run = f'[run {args.run_number}]({args.run_url})'
    record = json.loads(Path(args.manual).read_text(encoding='utf-8')) if args.manual else None
    manual, warnings, manual_complete = manual_summary(record)
    title = (f'## PatchTrace {args.tag} - integration build from main, not an acceptance statement'
             if args.ref_kind == 'main' else f'## PatchTrace {args.tag} - tagged build')
    out = [title, '', f'Commit: {args.sha} ({args.ref_kind}) - Run: {args.run_url} (run number {args.run_number})',
           'Assets:', *describe_assets(Path(args.assets) if args.assets else None),
           'Verify: `sha256sum -c <file>.sha256`. Extract the whole ZIP before running PatchTrace.exe.', '',
           '### Automated evidence (this SHA only)', '| Check | Result | Link |', '|---|---|---|']
    separate = ' (separate workflow; no result supplied for this SHA)'
    out += [f"| Linux pytest | {counts_text(counts.get('linux'), results.get('qa-ubuntu'))} | {run} |",
            f"| Windows pytest | {counts_text(counts.get('windows'), results.get('qa-windows'))} | {run} |",
            f"| Ruff | Linux {pretty(results.get('qa-ubuntu'))}, Windows {pretty(results.get('qa-windows'))} "
            f"(a step of each qa job) | {run} |",
            f"| Linux package and smoke, 22.04 and 24.04 | {pretty(results.get('linux-smoke'))} | {run} |",
            f"| Windows frozen self-test, help for all commands and CLI contract smoke | "
            f"{pretty(results.get('qa-windows'))} (steps of the Windows qa job) | {run} |",
            f"| Section 2 additions | ran: {SECTION2_RAN}. Not implemented or not run: {SECTION2_NOT} | {run} |",
            f"| Native Ghidriff matrix (5 variants) | {pretty(results.get('live-backend'))}"
            f"{'' if 'live-backend' in results else separate} | - |",
            f"| Live rz-diff (rizin 0.9.1, CI fixture pair) | {pretty(results.get('live-rizin'))}"
            f"{'' if 'live-rizin' in results else separate} | - |",
            '', '### Manual evidence',
            f'Clean Windows 11 checklist (spec section 3): {manual}. Record: docs/qa.md. '
            'A gate leaves "Open" only with a recorded pass and evidence link.']
    out += [f'- warning: {w}' for w in warnings]
    gates = [] if manual_complete else ['Clean Windows GUI acceptance M01-M18 (unless listed as pass above)']
    gates += ['Live local and remote AI provider acceptance (no credentials supplied)',
              'Relocatable offline backend bundle and disconnected Windows acceptance',
              'Confirmed Windows OneDrive-backed real Ghidriff analysis',
              'BinDiff live run' if results.get('live-rizin') == 'success' else 'rz-diff and BinDiff live runs',
              'Matching accuracy and performance: unmeasured, no claim made']
    out += ['', '### Open gates (not passed in this build)', *[f'- {g}' for g in gates], '',
            '- Limitations: unsigned beta; Ghidra, Java and Ghidriff external. Release publication: this text is '
            'generated by the release job before upload; verify the published release with the spec section 1.3 '
            'commands.']
    text = '\n'.join(out) + '\n'
    if args.preamble:
        text = Path(args.preamble).read_text(encoding='utf-8').rstrip('\n') + '\n\n' + text
    return text


def _kv(value: str) -> tuple[str, str]:
    key, sep, rest = value.partition('=')
    if not sep or not key or not rest:
        raise argparse.ArgumentTypeError('expected NAME=VALUE')
    return key, rest


def _result(value: str) -> tuple[str, str]:
    key, state = _kv(value)
    if key not in RESULT_NAMES or state not in STATES:
        raise argparse.ArgumentTypeError(f'NAME must be one of {RESULT_NAMES}, STATE one of {STATES}')
    return key, state


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--tag', required=True)
    parser.add_argument('--sha', required=True)
    parser.add_argument('--run-url', required=True)
    parser.add_argument('--run-number', required=True)
    parser.add_argument('--ref-kind', choices=('main', 'tag'), default='main')
    parser.add_argument('--assets')
    parser.add_argument('--junit', action='append', default=[], type=_kv, metavar='linux|windows=FILE')
    parser.add_argument('--result', action='append', default=[], type=_result)
    parser.add_argument('--manual')
    parser.add_argument('--preamble')
    parser.add_argument('--output')
    args = parser.parse_args(argv)
    if any(label not in ('linux', 'windows') for label, _ in args.junit):
        parser.error('--junit label must be linux or windows')
    try:
        text = build(args)
    except (OSError, ValueError, ET.ParseError) as exc:
        print(f'milestone_notes: {exc}', file=sys.stderr)
        return 2
    if args.output:
        Path(args.output).write_text(text, encoding='utf-8', newline='\n')
    else:
        sys.stdout.write(text)
    return 0


if __name__ == '__main__':
    sys.exit(main())
