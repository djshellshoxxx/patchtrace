"""Command line for the research qualification tools. Run from the repository root:

    python -m tools.research_qualification selftest --out build/research-receipts
    python -m tools.research_qualification perf plan -- CMD ARG...
    python -m tools.research_qualification perf run --timeout 600 --out DIR -- CMD ARG...
    python -m tools.research_qualification stages LOGFILE
    python -m tools.research_qualification receipt validate FILE...
    python -m tools.research_qualification receipt compare A B

Exit codes: 0 ok, 1 failed/invalid/differs, 2 blocked or usage error. Nothing here executes target binaries
unless the operator passes the command after `--`.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import perf_harness as P
from . import receipt as R
from .stage_parser import parse_log_text

_STATUS_EXIT = {"PASS": 0, "FAIL": 1, "CANCELLED": 1, "BLOCKED": 2}


def _split_cmd(argv: list[str]) -> tuple[list[str], list[str]]:
    if "--" not in argv:
        return argv, []
    i = argv.index("--")
    return argv[:i], argv[i + 1:]


def _print(obj: object) -> None:
    print(json.dumps(obj, indent=2, sort_keys=True))


def cmd_selftest(a: argparse.Namespace) -> int:
    """Synthetic end-to-end smoke: harness -> receipt -> validate -> reload -> rerun comparison."""
    code = "print('selftest'); print('Sorting functions')"
    out = Path(a.out)
    recs = []
    for n in (1, 2):
        rec, path = P.run([sys.executable, "-c", code], experiment_id="rq-selftest", scenario_id="smoke",
                          out_dir=str(out / f"run{n}"), timeout_s=60)
        problems = R.validate_receipt(R.load_receipt(path))
        if rec["result"]["status"] != "PASS" or problems:
            _print({"selftest": "FAIL", "status": rec["result"]["status"], "problems": problems})
            return 1
        recs.append(rec)
    diffs = R.compare_receipts(recs[0], recs[1])
    _print({"selftest": "PASS" if not diffs else "FAIL", "deterministic_differences": diffs,
            "receipts": [p.name for p in sorted(out.rglob("*.json"))], "psutil": P.psutil is not None})
    return 0 if not diffs else 1


def cmd_perf(a: argparse.Namespace, cmd: list[str]) -> int:
    allow = tuple(P.DEFAULT_ENV_ALLOWLIST) + tuple(a.env or ())
    try:
        if a.action == "plan":
            _print(P.plan(cmd, timeout_s=a.timeout, out_dir=a.out, env_allowlist=allow))
            return 0
        rec, path = P.run(cmd, experiment_id=a.experiment, scenario_id=a.scenario, out_dir=a.out,
                          timeout_s=a.timeout, cwd=a.cwd, env_allowlist=allow,
                          older_sha256=a.older_sha256, newer_sha256=a.newer_sha256)
    except (P.HarnessError, R.ReceiptError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    _print({"status": rec["result"]["status"], "stop_reason": rec["result"]["stop_reason"], "receipt": path.name,
            "duration_s": rec["observed"]["duration_s"]})
    return _STATUS_EXIT[rec["result"]["status"]]


def cmd_stages(a: argparse.Namespace) -> int:
    text = Path(a.log).read_text(encoding="utf-8", errors="replace")
    _print(parse_log_text(text, top_gaps=a.top))
    return 0


def cmd_receipt(a: argparse.Namespace) -> int:
    if a.action == "validate":
        bad = 0
        for f in a.files:
            try:
                R.load_receipt(f)
                print(f"ok   {f}")
            except (R.ReceiptError, OSError, json.JSONDecodeError) as e:
                bad += 1
                print(f"FAIL {f}: {e}")
        return 1 if bad else 0
    if len(a.files) != 2:
        print("error: compare needs exactly two receipts", file=sys.stderr)
        return 2
    diffs = R.compare_receipts(R.load_receipt(a.files[0]), R.load_receipt(a.files[1]))
    _print({"deterministic_differences": diffs})
    return 1 if diffs else 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="python -m tools.research_qualification", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("selftest", help="synthetic end-to-end smoke; needs no native tools")
    s.add_argument("--out", default="build/research-receipts")
    p = sub.add_parser("perf", help="run one bounded command and emit a receipt (command goes after --)")
    p.add_argument("action", choices=["plan", "run"])
    p.add_argument("--timeout", type=float, default=600.0)
    p.add_argument("--out", default="build/research-receipts")
    p.add_argument("--experiment", default="rq01-perf")
    p.add_argument("--scenario", default="adhoc")
    p.add_argument("--cwd")
    p.add_argument("--env", action="append", help="extra environment variable NAME to pass through (repeatable)")
    p.add_argument("--older-sha256")
    p.add_argument("--newer-sha256")
    g = sub.add_parser("stages", help="extract stage times and quiet intervals from a log file")
    g.add_argument("log")
    g.add_argument("--top", type=int, default=5)
    r = sub.add_parser("receipt", help="validate or compare receipts")
    r.add_argument("action", choices=["validate", "compare"])
    r.add_argument("files", nargs="+")
    return ap


def main(argv: list[str] | None = None) -> int:
    head, cmd = _split_cmd(list(sys.argv[1:] if argv is None else argv))
    a = build_parser().parse_args(head)
    if a.cmd == "selftest":
        return cmd_selftest(a)
    if a.cmd == "perf":
        return cmd_perf(a, cmd)
    if a.cmd == "stages":
        return cmd_stages(a)
    return cmd_receipt(a)


if __name__ == "__main__":
    sys.exit(main())
