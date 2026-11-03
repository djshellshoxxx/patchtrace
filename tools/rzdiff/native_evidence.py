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


def validate(variant: str, returncode: int, stdout: str) -> None:
    """Check full multiplicity, not just exit 1 (which could mean a crash)."""
    if variant not in ("stock", "corrected"):
        raise ValueError("unknown producer variant")
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


def run(variant: str, executable: Path, output: Path, timeout: float = 120) -> bool:
    output.mkdir(parents=True, exist_ok=True)
    executable = executable.resolve()
    receipt = {
        "variant": variant, "accepted": False,
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
            [str(executable)], capture_output=True, timeout=timeout, check=False,
        )
        stdout, stderr = result.stdout, result.stderr
        receipt["returncode"] = result.returncode
        validate(variant, result.returncode, stdout.decode("utf-8"))
        receipt["accepted"] = True
    except subprocess.TimeoutExpired as exc:
        stdout, stderr = exc.stdout or b"", exc.stderr or b""
        receipt["error"] = "native control timed out"
    except (OSError, ValueError) as exc:
        receipt["error"] = str(exc)
    finally:
        # Save raw bytes before reporting failure; never discard first-attempt
        # diagnostics or fabricate a successful native receipt after a crash.
        (output / "native-matrix.log").write_bytes(stdout)
        (output / "native-stderr.log").write_bytes(stderr)
        receipt["stdout_sha256"] = hashlib.sha256(stdout).hexdigest()
        receipt["stderr_sha256"] = hashlib.sha256(stderr).hexdigest()
        (output / "native-result.json").write_text(
            json.dumps(receipt, indent=2) + "\n", encoding="utf-8",
        )
    print(json.dumps(receipt))
    return receipt["accepted"]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--variant", choices=("stock", "corrected"), required=True)
    parser.add_argument("--executable", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    raise SystemExit(0 if run(args.variant, args.executable, args.output) else 1)


if __name__ == "__main__":
    main()
