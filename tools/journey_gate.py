"""Run the RB-05 analyst-journey test N times and write a JSON summary for CI to upload.

    QT_QPA_PLATFORM=offscreen python tools/journey_gate.py --repeat 5 --out journey-summary.json

EVIDENCE CLASS: automated OFFSCREEN evidence with a FAKE comparison backend (tests/test_journey_analyst.py). It is NOT
native Windows acceptance and NOT live evidence. Each repeat is a fresh pytest process, so a flaky or order-dependent
journey cannot hide behind a warm interpreter. Summary: {"runs", "passed", "failed", "durations", ...}.
Exit status: 0 when every run passed, else 1."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEST_FILE = 'tests/test_journey_analyst.py'
EVIDENCE_CLASS = 'automated-offscreen-fake-backend (not native Windows acceptance, not live evidence)'


def build_command(python: str = sys.executable, test_file: str = TEST_FILE) -> list[str]:
    return [python, '-m', 'pytest', '-q', '-p', 'no:cacheprovider', test_file]


def environment(base: dict[str, str] | None = None) -> dict[str, str]:
    env = dict(os.environ if base is None else base)
    env.setdefault('QT_QPA_PLATFORM', 'offscreen')
    env['PYTHONFAULTHANDLER'] = '1'
    return env


def summarize(results: list[tuple[int, float]]) -> dict:
    passed = sum(1 for code, _ in results if code == 0)
    return {'runs': len(results), 'passed': passed, 'failed': len(results) - passed,
            'durations': [round(seconds, 3) for _, seconds in results],
            'exit_codes': [code for code, _ in results], 'test': TEST_FILE, 'evidence_class': EVIDENCE_CLASS}


def run_once(command: list[str], env: dict[str, str], root: Path = ROOT) -> tuple[int, float]:
    start = time.perf_counter()
    code = subprocess.run(command, cwd=root, env=env, check=False).returncode
    return code, time.perf_counter() - start


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('--repeat', type=int, default=5, help='number of runs (default 5)')
    parser.add_argument('--out', type=Path, required=True, help='path of the JSON summary to write')
    args = parser.parse_args(argv)
    if args.repeat < 1:
        parser.error('--repeat must be at least 1')
    command, env = build_command(), environment()
    results = []
    for index in range(args.repeat):
        code, seconds = run_once(command, env)
        results.append((code, seconds))
        print(f'journey run {index + 1}/{args.repeat}: {"PASS" if code == 0 else f"FAIL ({code})"} in {seconds:.1f}s',
              flush=True)
    summary = summarize(results)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, 'w', encoding='utf-8', newline='\n') as stream:
        json.dump(summary, stream, indent=2)
        stream.write('\n')
    print(json.dumps(summary))
    return 0 if summary['failed'] == 0 else 1


if __name__ == '__main__':
    raise SystemExit(main())
