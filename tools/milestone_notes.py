"""Generate milestone release-notes text (windows-acceptance spec section 4). Stdlib only.

Everything in the output comes from an argument or a file you pass; nothing is inferred or invented. A check
with no input is reported as not run / open, never as passed. The text never claims production readiness.

usage: milestone_notes.py --tag TAG --sha SHA --run-url URL --run-number N [--ref-kind main|tag]
          [--assets DIR] [--junit linux|windows=FILE ...] [--journey linux|windows=FILE ...]
          [--result NAME=STATE ...] [--manual FILE.json] [--attestation-url https://...] [--supersedes TAG]
          [--preamble FILE] [--output FILE]

--assets DIR: every package is listed with bytes, SHA-256 and its `.sha256` sidecar state; a sidecar mismatch or a
  Portable ZIP that differs from the ZIP adds an Open-gates line and still exits 0, because a non-zero exit makes
  the workflow fall back to the static preamble and would hide it. The Signed line reads at most 4096 header bytes
  of PatchTrace/PatchTrace.exe inside the Windows ZIP (never executed) and never says `yes`.
--journey linux|windows=FILE: the tools/journey_gate.py summary (automated offscreen evidence with a fake backend,
  not native acceptance). A malformed or inconsistent summary counts as not run.

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
import re
import struct
import sys
import xml.etree.ElementTree as ET
import zipfile
import zlib
from pathlib import Path

MANUAL_IDS = tuple(f'M{i:02d}' for i in range(1, 19))
STATES = ('success', 'failure', 'cancelled', 'skipped', 'not-run')
RESULT_NAMES = ('qa-ubuntu', 'qa-windows', 'linux-smoke', 'live-backend', 'live-rizin')
WINDOWS_ZIP = 'PatchTrace-0.1.0-windows-x64.zip'
PORTABLE_ZIP = 'PatchTrace-Windows-x64-Portable.zip'  # byte copy of the ZIP made by the release job
ASSET_NAMES = (WINDOWS_ZIP, PORTABLE_ZIP, 'PatchTrace-Windows-x64-Setup.exe', 'PatchTrace-0.1.0-linux-x86_64.tar.gz')
EXE_MEMBER = 'PatchTrace/PatchTrace.exe'
SIDECAR_LIMIT = HEADER_LIMIT = 4096
JOURNEY_LIMIT = 64 * 1024
MAX_EXTRA_ASSETS = 20
INTACT = 'SHA-256 shows the download is intact. It does not show who built it.'  # SPEC-52 s6, fixed wording
SIGNED = {'no': 'no (PatchTrace.exe has no Authenticode signature)',
          'present': 'certificate table present; signer and trust not evaluated by this generator'}
SMARTSCREEN = ('SmartScreen: unsigned or low-reputation builds can show "Windows protected your PC". Choose "More '
               'info" then "Run anyway" only after checking the SHA-256 above.')  # SPEC-52 s7.5, verbatim
LIMITATION = {'no': 'unsigned beta', 'present': 'beta with a certificate table this generator did not evaluate',
              'not-checked': 'beta, signature not checked'}
TAG_RE = re.compile(r'v\d{1,5}\.\d{1,5}\.\d{1,5}(?:-[0-9A-Za-z]+(?:\.[0-9A-Za-z]+)*)?')
URL_RE = re.compile(r'https://[A-Za-z0-9.-]+(?::\d{1,5})?(?:/[A-Za-z0-9._~/%:@+=?&#-]*)?')

# Automated checks that exist in the repository. Update when new checks land; the spec lists the rest.
SECTION2_RAN = ('A1 help for every CLI command, A2 usage error, A3 missing project, A4 --self-test, A5 JSON contract, '
                'A10 path cases (spaces, Unicode, OneDrive-style, long) through the CLI, A6 imported-result '
                '3-build series, A13 unified-engine package contents and unified CLI (U1, U2), plus the BinExport '
                'worker (B1, B2) and intelligence import/explain (C1-C4) checks (tools/frozen_smoke.py on the '
                'Windows package)')
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


def safe_text(text: str, limit: int) -> str:
    """Printable ASCII only, without Markdown table, code, link or tag characters; at most `limit` characters."""
    return ''.join(c if ' ' <= c <= '~' and c not in '|`<>[]\\' else '?' for c in text[:limit])


def file_facts(path: Path) -> tuple[int, str]:
    with path.open('rb') as stream:
        return path.stat().st_size, hashlib.file_digest(stream, 'sha256').hexdigest()


def sidecar_state(path: Path, digest: str) -> str:
    """`sidecar verified` only for a bounded `<hex>  <name>` first line naming this file with its digest."""
    sidecar = path.with_name(path.name + '.sha256')
    if not sidecar.is_file():
        return 'no sidecar'
    with sidecar.open('rb') as stream:
        raw = stream.read(SIDECAR_LIMIT + 1)
    lines = raw.decode('ascii', 'replace').splitlines()
    parts = lines[0].split(None, 1) if lines else []
    ok = (len(raw) <= SIDECAR_LIMIT and len(parts) == 2 and parts[0].lower() == digest
          and parts[1].removeprefix('*') == path.name)
    return 'sidecar verified' if ok else 'SIDECAR MISMATCH'


def describe_assets(directory: Path | None) -> tuple[list[str], list[str]]:
    """(asset lines, open gates). Every file in the directory is listed; the known packages come first."""
    lines: list[str] = []
    gates: list[str] = []
    facts: dict[str, tuple[int, str]] = {}
    for name in ASSET_NAMES:
        path = directory / name if directory else None
        if path is None or not path.is_file():
            lines.append(f'- {name} - not present in this build')
            continue
        facts[name] = file_facts(path)
        state = sidecar_state(path, facts[name][1])
        line = f'- {name} - {facts[name][0]} bytes - SHA-256 {facts[name][1]} - {state}'
        if state == 'SIDECAR MISMATCH':
            gates.append(f'Asset integrity: {name} does not match its .sha256 sidecar')
        if name == PORTABLE_ZIP:
            if WINDOWS_ZIP not in facts:
                line += f' - not compared ({WINDOWS_ZIP} not present)'
            elif facts[WINDOWS_ZIP] == facts[name]:
                line += f' - same bytes as {WINDOWS_ZIP}'
            else:
                line += f' - BYTES DIFFER from {WINDOWS_ZIP}'
                gates.append(f'Asset integrity: {PORTABLE_ZIP} bytes differ from {WINDOWS_ZIP}')
        lines.append(line)
    known = {*ASSET_NAMES, *(f'{name}.sha256' for name in facts)}  # an orphan sidecar is listed as extra
    listed = directory is not None and directory.is_dir()
    extra = sorted(p for p in directory.iterdir() if p.is_file() and p.name not in known) if listed else []
    for path in extra[:MAX_EXTRA_ASSETS]:
        size, digest = file_facts(path)
        lines.append(f'- {safe_text(path.name, 120)} - {size} bytes - SHA-256 {digest} - not a listed package')
    if len(extra) > MAX_EXTRA_ASSETS:
        lines.append(f'- {len(extra) - MAX_EXTRA_ASSETS} further files not listed')
    return lines, gates


def certificate_table_size(head: bytes) -> int | None:
    """Size of PE data directory 4 (certificate table), or None when `head` is not a readable PE header."""
    if len(head) < 0x40 or head[:2] != b'MZ':
        return None
    pe = struct.unpack_from('<I', head, 0x3C)[0]
    if pe + 26 > len(head) or head[pe:pe + 4] != b'PE\0\0':
        return None
    magic = struct.unpack_from('<H', head, pe + 24)[0]
    if magic not in (0x20B, 0x10B):
        return None
    count = pe + 24 + (108 if magic == 0x20B else 92)
    entry = count + 4 + 4 * 8
    if entry + 8 > len(head) or struct.unpack_from('<I', head, count)[0] < 5:
        return None
    return struct.unpack_from('<I', head, entry + 4)[0]


def signed_state(archive_path: Path | None) -> tuple[str, str]:
    """(no | present | not-checked, Signed text). Reads at most HEADER_LIMIT bytes of the member; never runs it."""
    if archive_path is None or not archive_path.is_file():
        return 'not-checked', f'not checked ({WINDOWS_ZIP} not present)'
    try:
        with zipfile.ZipFile(archive_path) as archive:
            if EXE_MEMBER not in archive.namelist():
                return 'not-checked', f'not checked ({EXE_MEMBER} is not in {WINDOWS_ZIP})'
            with archive.open(EXE_MEMBER) as stream:
                head = stream.read(HEADER_LIMIT)
    except (zipfile.BadZipFile, OSError, RuntimeError, NotImplementedError, EOFError, ValueError, zlib.error):
        return 'not-checked', f'not checked ({WINDOWS_ZIP} is unreadable)'
    size = certificate_table_size(head)
    if size is None:
        return 'not-checked', 'not checked (PatchTrace.exe is not a readable PE image)'
    state = 'present' if size else 'no'
    return state, SIGNED[state]


def journey_counts(summary: object) -> tuple[int, int, str] | None:
    """(runs, passed, evidence class) of a consistent tools/journey_gate.py summary, else None."""
    if not isinstance(summary, dict):
        return None
    runs, passed, failed = (summary.get(key) for key in ('runs', 'passed', 'failed'))
    if not all(type(v) is int and v >= 0 for v in (runs, passed, failed)) or runs < 1 or passed + failed != runs:
        return None
    codes = summary.get('exit_codes')
    if codes is not None and (not isinstance(codes, list) or len(codes) != runs
                              or not all(type(c) is int for c in codes) or codes.count(0) != passed):
        return None
    evidence = summary.get('evidence_class')
    if not isinstance(evidence, str) or not evidence.startswith('automated-'):
        return None
    return runs, passed, safe_text(evidence, 160)


def journey_text(path: str | None) -> str:
    if path is None:
        return 'not run (no summary supplied)'
    source = Path(path)
    if not source.exists():
        return 'not run (summary file not found)'
    try:
        with source.open('rb') as stream:
            raw = stream.read(JOURNEY_LIMIT + 1)
        summary = json.loads(raw.decode('utf-8')) if len(raw) <= JOURNEY_LIMIT else None
    except (OSError, ValueError, RecursionError):
        summary = None
    counts = journey_counts(summary)
    if counts is None:
        return 'unreadable summary, counted as not run'
    runs, passed, evidence = counts
    head = f'{passed}/{runs} runs passed' if passed == runs else f'FAIL: {passed}/{runs} runs passed'
    return f'{head}; evidence class: {evidence}'


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
    journeys = dict(args.journey)
    assets = Path(args.assets) if args.assets else None
    asset_lines, asset_gates = describe_assets(assets)
    signed, signed_text = signed_state(assets / WINDOWS_ZIP if assets else None)
    provenance = (f'attestation {args.attestation_url}' if args.attestation_url
                  else 'attestation not generated: no attestation step in this workflow')
    run = f'[run {args.run_number}]({args.run_url})'
    record = json.loads(Path(args.manual).read_text(encoding='utf-8')) if args.manual else None
    manual, warnings, manual_complete = manual_summary(record)
    title = (f'## PatchTrace {args.tag} - integration build from main, not an acceptance statement'
             if args.ref_kind == 'main' else f'## PatchTrace {args.tag} - tagged build')
    out = [title, '', f'Commit: {args.sha} ({args.ref_kind}) - Run: {args.run_url} (run number {args.run_number})',
           'Assets:', *asset_lines,
           'Verify: `sha256sum -c <file>.sha256`. Extract the whole ZIP before running PatchTrace.exe.', INTACT,
           f'Signed: {signed_text}', *([] if signed == 'present' else [SMARTSCREEN]), f'Provenance: {provenance}',
           f"Supersedes: {args.supersedes or 'not recorded'}", '',
           '### Automated evidence (this SHA only)', '| Check | Result | Link |', '|---|---|---|']
    separate = ' (separate workflow; no result supplied for this SHA)'
    windows, step = pretty(results.get('qa-windows')), ' (step of the Windows qa job)'
    journey = 'automated offscreen, fake backend, not native acceptance'
    out += [f"| Linux pytest | {counts_text(counts.get('linux'), results.get('qa-ubuntu'))} | {run} |",
            f"| Windows pytest | {counts_text(counts.get('windows'), results.get('qa-windows'))} | {run} |",
            f"| Ruff | Linux {pretty(results.get('qa-ubuntu'))}, Windows {pretty(results.get('qa-windows'))} "
            f"(a step of each qa job) | {run} |",
            f"| Panel manifest check (G6) | Linux {pretty(results.get('qa-ubuntu'))}, Windows {windows} "
            f"(a step of each qa job) | {run} |",
            f"| Analyst journey gate (RB-05), Linux leg: {journey} | {journey_text(journeys.get('linux'))} | {run} |",
            f"| Analyst journey gate (RB-05), Windows leg: {journey} | {journey_text(journeys.get('windows'))} "
            f"| {run} |",
            f"| Linux package and smoke, 22.04 and 24.04 | {pretty(results.get('linux-smoke'))} | {run} |",
            f"| Windows frozen self-test, help for all commands and CLI contract smoke | "
            f"{windows} (steps of the Windows qa job) | {run} |",
            f"| Windows exe identity read-back (version resource and icon; tools/check_windows_exe.py inside "
            f"tools/build_windows.py) | {windows}{step} | {run} |",
            f"| Windows portable ZIP extracted and run outside the checkout (tools/test_windows_portable.ps1) | "
            f"{windows}{step} | {run} |",
            f"| Windows Setup.exe per-user install, self-test launch and uninstall (tools/test_windows_installer.ps1) "
            f"| {windows}{step} | {run} |",
            f"| Section 2 additions | ran: {SECTION2_RAN}. Not implemented or not run: {SECTION2_NOT} | {run} |",
            f"| Native Ghidriff matrix (5 variants) | {pretty(results.get('live-backend'))}"
            f"{'' if 'live-backend' in results else separate} | - |",
            f"| Live rz-diff (rizin 0.9.1, CI fixture pair) | {pretty(results.get('live-rizin'))}"
            f"{'' if 'live-rizin' in results else separate} | - |",
            '', '### Manual evidence',
            f'Clean Windows 11 checklist (spec section 3): {manual}. Record: docs/qa.md. '
            'A gate leaves "Open" only with a recorded pass and evidence link.']
    out += [f'- warning: {w}' for w in warnings]
    gates = asset_gates + ([] if manual_complete else
                           ['Clean Windows GUI acceptance M01-M18 (unless listed as pass above)'])
    gates += ['Live local and remote AI provider acceptance (no credentials supplied)',
              'Relocatable offline backend bundle and disconnected Windows acceptance',
              'Confirmed Windows OneDrive-backed real Ghidriff analysis',
              'BinDiff live run' if results.get('live-rizin') == 'success' else 'rz-diff and BinDiff live runs',
              'Code signing and SmartScreen reputation (see the Signed line; this generator never evaluates signer '
              'trust)',
              'Matching accuracy and performance: unmeasured, no claim made']
    out += ['', '### Open gates (not passed in this build)', *[f'- {g}' for g in gates], '',
            f'- Limitations: {LIMITATION[signed]}; Ghidra, Java and Ghidriff external. Release publication: this '
            'text is '
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


def _tag(value: str) -> str:
    if len(value) > 64 or not TAG_RE.fullmatch(value):
        raise argparse.ArgumentTypeError('expected a tag like v0.1.0-beta.8 (at most 64 characters)')
    return value


def _attestation_url(value: str) -> str:
    if len(value) > 300 or not URL_RE.fullmatch(value):
        raise argparse.ArgumentTypeError('expected an https:// URL of at most 300 plain URL characters')
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--tag', required=True)
    parser.add_argument('--sha', required=True)
    parser.add_argument('--run-url', required=True)
    parser.add_argument('--run-number', required=True)
    parser.add_argument('--ref-kind', choices=('main', 'tag'), default='main')
    parser.add_argument('--assets')
    parser.add_argument('--junit', action='append', default=[], type=_kv, metavar='linux|windows=FILE')
    parser.add_argument('--journey', action='append', default=[], type=_kv, metavar='linux|windows=FILE')
    parser.add_argument('--result', action='append', default=[], type=_result)
    parser.add_argument('--attestation-url', type=_attestation_url)
    parser.add_argument('--supersedes', type=_tag)
    parser.add_argument('--manual')
    parser.add_argument('--preamble')
    parser.add_argument('--output')
    args = parser.parse_args(argv)
    if any(label not in ('linux', 'windows') for label, _ in args.junit):
        parser.error('--junit label must be linux or windows')
    if any(label not in ('linux', 'windows') for label, _ in args.journey):
        parser.error('--journey label must be linux or windows')
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
