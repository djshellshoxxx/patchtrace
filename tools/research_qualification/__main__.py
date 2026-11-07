"""Command line for the research qualification tools. Run from the repository root:

    python -m tools.research_qualification selftest --out build/research-receipts
    python -m tools.research_qualification perf plan -- CMD ARG...
    python -m tools.research_qualification perf run --timeout 600 --out DIR -- CMD ARG...
    python -m tools.research_qualification stages LOGFILE
    python -m tools.research_qualification receipt validate FILE...
    python -m tools.research_qualification receipt compare A B
    python -m tools.research_qualification samplesize [--target 0.9 --max-errors 1]
    python -m tools.research_qualification callmodel --pairs 2161955 --old 20000 --new 20000 [--us-per-call X]
    python -m tools.research_qualification fixtures build --out DIR
    python -m tools.research_qualification fixtures score --truth FILE --matches FILE

Exit codes: 0 ok, 1 failed/invalid/differs, 2 blocked or usage error. Nothing here executes target binaries
unless the operator passes the command after `--`.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import call_model as CM
from . import fixture_pairs as FP
from . import perf_harness as P
from . import receipt as R
from . import sample_size as SS
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


def cmd_samplesize(a: argparse.Namespace) -> int:
    try:
        if a.target is None:
            _print(SS.table())
        else:
            _print({'target': a.target, 'max_errors': a.max_errors,
                    'min_independent_cases': SS.min_cases(a.target, a.max_errors)})
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    return 0


def cmd_callmodel(a: argparse.Namespace) -> int:
    try:
        p = CM.Params(a.pairs, a.old, a.new, a.traversals)
        out = CM.analytic(p, a.us_per_call)
        out['sensitivity'] = CM.sensitivity(p)
        if a.simulate:
            out['simulation'] = CM.simulate(CM.Params(min(a.pairs, 4000), min(a.old, 200), min(a.new, 200), a.traversals))
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    _print(out)
    return 0 if not a.simulate or out['simulation']['decisions_identical'] else 1


def cmd_fixtures(a: argparse.Namespace) -> int:
    if a.action == "score":
        try:
            truth = json.loads(Path(a.truth).read_text(encoding="utf-8"))
            matches = json.loads(Path(a.matches).read_text(encoding="utf-8"))
            res = FP.score_matches(truth, matches)
        except (OSError, ValueError, KeyError) as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
        _print(res)
        return 0 if res["passed"] else 1
    out = Path(a.out)
    started = R.utc_now()
    summary, problems, hashes = {}, [], {}
    try:
        for case in FP.CASES:
            truth = FP.build_case(case, out)
            problems += [f"{case}: {m}" for m in FP.verify_truth(case, truth, out)]
            if not FP.check_reproducible(case, out, truth):
                problems.append(f"{case}: rebuild gave different bytes")
            manifest = out / f"{case}.truth.json"
            manifest.write_text(json.dumps(truth, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
            hashes[case] = R.sha256_file(manifest)
            summary[case] = {"old": truth["older"]["sha256"][:12], "new": truth["newer"]["sha256"][:12]}
    except FP.FixtureError as e:
        problems.append(str(e))
    status = "PASS" if not problems else ("BLOCKED" if any("not found on PATH" in m for m in problems) else "FAIL")
    rec = R.build_receipt(
        experiment_id="rq03-fixtures", scenario_id="self-compiled", tool_name="fixture_pairs", status=status,
        exit_code=0 if status == "PASS" else None, stop_reason="; ".join(problems)[:200] or "all cases verified",
        patchtrace_sha=R.git_head(Path(__file__).resolve().parents[2]),
        validations_run=["reproducible_build", "truth_checked_against_bytes"] if status == "PASS" else [],
        unverified=["tool.executable_sha256", "pe_pairs_need_windows_toolchain", "inlining_noise_not_modeled"],
        blocked_reasons=problems if status == "BLOCKED" else [], result_hashes=hashes if status == "PASS" else {},
        counters={"cases": len(FP.CASES)},
        observed={"started_utc": started, "ended_utc": R.utc_now(), "duration_s": 0.0},
    )
    path = R.write_receipt(rec, out)
    _print({"status": status, "problems": problems, "cases": summary, "receipt": path.name})
    return _STATUS_EXIT[status]


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
    z = sub.add_parser("samplesize", help="how many independent cases an accuracy claim needs")
    z.add_argument("--target", type=float)
    z.add_argument("--max-errors", type=int, default=0)
    m = sub.add_parser("callmodel", help="call-count model of the suspected Ghidriff slow path (a model, not a measurement)")
    m.add_argument("--pairs", type=int, required=True)
    m.add_argument("--old", type=int, required=True)
    m.add_argument("--new", type=int, required=True)
    m.add_argument("--traversals", type=int, default=2)
    m.add_argument("--us-per-call", type=float)
    m.add_argument("--simulate", action="store_true")
    f = sub.add_parser("fixtures", help="build self-compiled old/new pairs with ground truth, or score matches")
    f.add_argument("action", choices=["build", "score"])
    f.add_argument("--out", default="build/research-fixtures")
    f.add_argument("--truth")
    f.add_argument("--matches")
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
    if a.cmd == "samplesize":
        return cmd_samplesize(a)
    if a.cmd == "callmodel":
        return cmd_callmodel(a)
    if a.cmd == "fixtures":
        return cmd_fixtures(a)
    return cmd_receipt(a)


if __name__ == "__main__":
    sys.exit(main())
