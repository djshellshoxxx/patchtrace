"""Run the native API oracle; refuse incomplete red controls. Research only."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
from collections import Counter
from pathlib import Path

COUNTS = ((1, 1), (1, 2), (2, 1), (2, 2), (1, 0), (0, 1), (2, 0), (0, 2))
ROW = re.compile(r"(\d+):(\d+) overlap=([01]) errors=(\d+)")
IO_ROW = re.compile(r"distinct-io ([12]):([12]) overlap=([01]) errors=([0-9]{1,6}) reads=([0-9]{1,6}),([0-9]{1,6})")
MODE_ARGS = {
    "matrix": (), "io": ("--io-context",),
    "io-wrong-bytes": ("--io-context", "--wrong-bytes"),
    "io-wrong-io": ("--io-context", "--wrong-io"),
}


def control_args(variant: str, mode: str) -> tuple[str, ...]:
    if variant not in ("stock", "corrected"):
        raise ValueError("unknown producer variant")
    if mode not in MODE_ARGS:
        raise ValueError("unknown native control mode")
    if mode in ("io-wrong-bytes", "io-wrong-io") and variant != "corrected":
        raise ValueError("negative IO controls require the corrected producer")
    return MODE_ARGS[mode]


def validate_io(variant: str, returncode: int, stdout: str, mode: str) -> None:
    """Pinned authored oracle: exact inventory, errors and matcher-only reads."""
    control_args(variant, mode)
    if mode == "matrix":
        raise ValueError("matrix is not an IO control")
    expected = {}
    for overlap in ((1,) if mode == "io-wrong-io" else (0, 1)):
        for a, b in ((1, 2), (2, 1)):
            if mode == "io-wrong-io":
                observation = (3 if a == 1 else 2, 4, 0)
            elif mode == "io-wrong-bytes":
                observation = (2, 2, 2)
            else:
                observation = (3 if variant == "stock" and a == 1 else 0, 2, 2)
            expected[(a, b, overlap)] = observation
    seen = {}
    for line in stdout.splitlines():
        match = IO_ROW.fullmatch(line)
        if not match:
            raise ValueError("malformed native IO row")
        a, b, overlap, errors, reads_a, reads_b = map(int, match.groups())
        key = (a, b, overlap)
        if key in seen:
            raise ValueError("duplicated native IO row")
        seen[key] = (errors, reads_a, reads_b)
    if seen != expected:
        raise ValueError("native IO inventory, errors or reads differ from the pinned oracle")
    expected_exit = 0 if variant == "corrected" and mode == "io" else 1
    if returncode != expected_exit:
        raise ValueError("unexpected native IO process exit")


def validate(variant: str, returncode: int, stdout: str, *, mode: str = "matrix") -> None:
    """Check full multiplicity, not just exit 1 (which could mean a crash)."""
    control_args(variant, mode)
    if mode != "matrix":
        validate_io(variant, returncode, stdout, mode)
        return
    expected = Counter(
        (left, right, overlap)
        for a, b in COUNTS for overlap in range(2)
        for left, right in ((a, b), (b, a))
    )
    seen: Counter = Counter()
    red = set()
    for line in stdout.splitlines():
        match = ROW.fullmatch(line)
        if not match:
            raise ValueError("malformed native matrix row")
        a, b, overlap, errors = map(int, match.groups())
        seen[(a, b, overlap)] += 1
        if variant == "stock" and a == 1 and not errors:
            raise ValueError("stock singleton row did not fail")
        if errors:
            if variant != "stock" or a != 1:
                raise ValueError("unexpected ownership failure")
            red.add((a, b, overlap))
    if seen != expected:
        raise ValueError("incomplete or duplicated native matrix")
    # Every singleton stock scenario must expose the known defect; all ordinary
    # scenarios must pass. The corrected run must pass the identical oracle.
    expected_red = {key for key in expected if key[0] == 1}
    if variant == "stock" and red != expected_red:
        raise ValueError("stock singleton red control absent")
    if returncode != (1 if variant == "stock" else 0):
        raise ValueError("unexpected native process exit")


def run(variant: str, executable: Path, output: Path, timeout: float = 120, *, mode: str = "matrix") -> bool:
    arguments = control_args(variant, mode)
    output.mkdir(parents=True, exist_ok=True)
    # A marker serializes cooperating attempts; legacy receipts without a marker
    # are refused too. Never let a failed retry replace the first raw evidence.
    for name in ('native-result.json', 'native-matrix.log', 'native-stderr.log'):
        path = output / name
        if path.exists() or path.is_symlink():
            raise FileExistsError(f'native evidence already exists: {path}')
    with (output / '.native-evidence-run').open('x', encoding='utf-8') as marker:
        marker.write('native-api-research/1\n')
    executable = executable.resolve()
    receipt = {
        "variant": variant, "mode": mode, "arguments": list(arguments), "accepted": False,
        "scope": "native public API only; not CLI JSON or application acceptance",
        "source_head": os.environ.get("PATCHTRACE_SOURCE_HEAD"),
        "workflow_sha": os.environ.get("GITHUB_SHA"),
        "run_id": os.environ.get("GITHUB_RUN_ID"),
        "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "executable": str(executable), "returncode": None,
    }
    stdout, stderr = b"", b""
    try:
        receipt["executable_sha256"] = hashlib.sha256(executable.read_bytes()).hexdigest()
        result = subprocess.run(
            [str(executable), *arguments], capture_output=True, timeout=timeout, check=False,
        )
        stdout, stderr = result.stdout, result.stderr
        receipt["returncode"] = result.returncode
        validate(variant, result.returncode, stdout.decode("utf-8"), mode=mode)
        if mode != "matrix" and stderr:
            raise ValueError("unexpected native IO stderr")
        receipt["accepted"] = True
    except subprocess.TimeoutExpired as exc:
        stdout, stderr = exc.stdout or b"", exc.stderr or b""
        receipt["error"] = "native control timed out"
    except (OSError, ValueError) as exc:
        receipt["error"] = str(exc)
    finally:
        # Save raw bytes before reporting failure; never discard first-attempt
        # diagnostics or fabricate a successful native receipt after a crash.
        with (output / "native-matrix.log").open('xb') as handle:
            handle.write(stdout)
        with (output / "native-stderr.log").open('xb') as handle:
            handle.write(stderr)
        receipt["stdout_sha256"] = hashlib.sha256(stdout).hexdigest()
        receipt["stderr_sha256"] = hashlib.sha256(stderr).hexdigest()
        with (output / "native-result.json").open('x', encoding='utf-8') as handle:
            handle.write(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt))
    return receipt["accepted"]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--variant", choices=("stock", "corrected"), required=True)
    parser.add_argument("--executable", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--mode", choices=tuple(MODE_ARGS), default="matrix")
    args = parser.parse_args()
    try:
        control_args(args.variant, args.mode)
    except ValueError as exc:
        parser.error(str(exc))
    raise SystemExit(0 if run(args.variant, args.executable, args.output, mode=args.mode) else 1)


if __name__ == "__main__":
    main()
