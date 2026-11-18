"""One predeclared native ELF pilot through the production scheduler and adapter."""
from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import threading
import time

from patchtrace.jobs import run_process
from patchtrace.secondary import rzdiff
from patchtrace.secondary.engine_env import engine_env
from patchtrace.secondary.registry import build_registry
from patchtrace.secondary.scheduler import ProjectRef, run_engines
from tools.research_qualification import cases, receipt as R, scoring
from tools.research_qualification.adapters import rizin as ranking_adapter

root = Path(__file__).resolve().parent
plan_file = root / "pilot-plan.json"
assert R.sha256_file(plan_file) == "d6a2dc2b5a1dc59304fc2a8279b6c186537be267448cf9bd0d700e6617e6dbef"
plan = json.loads(plan_file.read_text())
repo = Path(plan["source_checkout"])
preparation = Path(plan["preparation"])
assert R.git_head(repo) == plan["source_commit"]
assert R.sha256_file(root / "approval.json") == plan["approval_sha256"]
assert R.sha256_file(preparation / "source-oracle-proposal.json") == plan["oracle_sha256"]
for rel, expected in plan["source_sha256"].items():
    assert R.sha256_file(repo / rel) == expected
manifest = json.loads((root / "pilot-case-manifest.json").read_text())
case = manifest["cases"][0]
cases.validate_case(case)
cases.check_frozen(manifest, plan["case_manifest_canonical_sha256"])
old, new = Path(plan["older"]), Path(plan["newer"])
for side, path in (("older", old), ("newer", new)):
    assert R.sha256_file(path) == case[side]["sha256"]
tool = Path(plan["executable"])
assert R.sha256_file(tool) == plan["executable_sha256"]
env = engine_env(os.environ, "rz-diff")
cancel = threading.Event()
operations = []
events = []
started = R.utc_now()
begun = time.monotonic()


def save_json(name, value):
    with (root / name).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def recording_runner(argv, **kwargs):
    """Observe the actual production runner, returning its unmodified result."""
    index = len(operations)
    analysis = list(argv[1:5]) == ["-C", "-j", "-t", "functions"]
    assert argv[0] == str(tool)
    assert analysis or list(argv[1:]) == ["-v"]
    assert R.sha256_file(tool) == plan["executable_sha256"]
    before = {}
    if analysis:
        assert len(argv) == 7
        before = {side: R.sha256_file(argv[pos]) for side, pos in (("older", 5), ("newer", 6))}
        assert before == {side: case[side]["sha256"] for side in ("older", "newer")}
    result = run_process(argv, **kwargs)
    assert result.log_bytes is not None
    stdout = result.log_bytes
    stderr = result.stderr_bytes or b""
    label = f"{index:02d}-" + ("analysis" if analysis else "probe")
    stdout_path, stderr_path = root / "raw" / (label + ".stdout"), root / "raw" / (label + ".stderr")
    with stdout_path.open("xb") as stream:
        stream.write(stdout)
    with stderr_path.open("xb") as stream:
        stream.write(stderr)
    record = {
        "kind": "production-runner-observation/1", "label": label,
        "delegation": "calls jobs.run_process with unchanged argv/kwargs; returns the same ProcessResult object",
        "argv": list(argv), "cwd": str(kwargs["cwd"]),
        "settings": {key: kwargs[key] for key in ("timeout_seconds", "log_limit", "separate_streams", "stderr_limit", "max_output_bytes") if key in kwargs},
        "environment_keys": sorted(kwargs["env"]), "environment_fingerprint": R.env_fingerprint(sorted(kwargs["env"]), dict(kwargs["env"])),
        "prepared_input_sha256": before,
        "returncode": result.returncode, "reason": result.reason,
        "elapsed_seconds": result.elapsed_seconds, "last_output_elapsed_seconds": result.last_output_elapsed_seconds,
        "stdout_total": result.stdout_total, "stderr_total": result.stderr_total,
        "stdout_kept": len(stdout), "stderr_kept": len(stderr),
        "streams_complete": len(stdout) == result.stdout_total and len(stderr) == result.stderr_total,
        "stdout_path": str(stdout_path.relative_to(root)), "stderr_path": str(stderr_path.relative_to(root)),
        "stdout_sha256": hashlib.sha256(stdout).hexdigest(), "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
        "tool_sha256_after": R.sha256_file(tool),
    }
    if analysis:
        record["prepared_input_sha256_after"] = {side: R.sha256_file(argv[pos]) for side, pos in (("older", 5), ("newer", 6))}
        assert record["prepared_input_sha256_after"] == before
    save_json("receipts/" + label + ".json", record)
    operations.append(record)
    return result


cap = rzdiff.probe(tool, env, cancel, runner=recording_runner)
save_json("receipts/preflight-capability.json", cap.model_dump(mode="json"))
outcome = None
ranking = None
blocked = []
if not cap.supported or cap.version != "0.9.1":
    blocked.append("Pinned native preflight did not support version 0.9.1")
else:
    project = ProjectRef(old, new, case["older"]["sha256"], case["newer"]["sha256"])
    (outcome,) = run_engines(project, ["rz-diff"], max_parallel=1,
                            per_engine_timeout={"rz-diff": plan["engine_timeout_seconds"]},
                            cancel=cancel, cache=None, env=env,
                            on_event=lambda event: events.append(asdict(event)),
                            registry=build_registry(rz_diff=str(tool)), runner=recording_runner,
                            stdout_limit=plan["stdout_limit_bytes"])
    save_json("engine-run.json", outcome.run.model_dump(mode="json"))
    if outcome.match_set is not None:
        save_json("secondary-match-set.json", outcome.match_set.model_dump(mode="json"))
    if outcome.error is not None:
        save_json("engine-error.json", {"code": outcome.error.code, "message": outcome.error.message,
                                       "kind": outcome.error.kind, "reason": outcome.error.reason})
    if outcome.run.status != "ok" or outcome.match_set is None:
        blocked.append("Production scheduler/adapter did not accept a complete native match set")
    elif not operations[-1]["streams_complete"]:
        blocked.append("Native streams were truncated; complete raw evidence is unavailable")
    else:
        native_stdout = (root / operations[-1]["stdout_path"]).read_bytes()
        assert hashlib.sha256(native_stdout).hexdigest() == outcome.match_set.file_sha256
        try:
            ranking = ranking_adapter.parse(native_stdout)
        except ValueError as error:
            blocked.append("Existing ranking adapter rejected native output: " + str(error))
comparison = scoring.score_case(case, ranking, plan["k"])
result = {
    "kind": "scoped-native-l2-pilot-result/1", "source_commit": R.git_head(repo),
    "source_tree": plan["source_tree"], "oracle_sha256": plan["oracle_sha256"],
    "case_manifest_canonical_sha256": cases.canonical_hash(manifest),
    "scope": "One independent ELF/GCC source-backed matching pilot; not Windows/MSVC acceptance, desktop acquisition, vulnerability attribution accuracy, or L3",
    "target_executed": False, "network_during_analysis": "No network operation requested by the harness",
    "production_status": outcome.run.status if outcome else "unsupported",
    "production_error_code": outcome.run.error_code if outcome else None,
    "match_count": len(outcome.match_set.matches) if outcome and outcome.match_set else 0,
    "ranked_names": ranking, "expected_function": case["expected"]["function"],
    "k": plan["k"], "existing_exact_name_comparison": comparison,
    "blocked_reasons": blocked, "events": events, "duration_seconds": round(time.monotonic() - begun, 3),
    "aggregate_accuracy_or_bound": None,
    "candidate_specific_tuning": False,
    "analysis_operation_count": sum(item["label"].endswith("analysis") for item in operations),
}
for rel, expected in plan["source_sha256"].items():
    assert R.sha256_file(repo / rel) == expected
assert result["source_commit"] == plan["source_commit"]
for side, path in (("older", old), ("newer", new)):
    assert R.sha256_file(path) == case[side]["sha256"]
save_json("pilot-result.json", result)
status = "BLOCKED" if blocked else ("PASS" if comparison["outcome"] == "HIT" else "FAIL")
exit_code = {"PASS": 0, "FAIL": 1, "BLOCKED": 2}[status]
raw_artifacts = []
for path in sorted((root / "raw").iterdir()):
    raw_artifacts.append({"path": str(path.relative_to(root)), "bytes": path.stat().st_size, "sha256": R.sha256_file(path)})
receipt = R.build_receipt(
    experiment_id="rq-l2-native-pilot", scenario_id="http-parser-cve-2020-8287-elf-gcc",
    tool_name="rz-diff-production-adapter", status=status, exit_code=exit_code,
    stop_reason="Existing exact-name per-case comparison: " + comparison["outcome"],
    patchtrace_sha=result["source_commit"], tool_version=cap.version,
    upstream_url="https://github.com/rizinorg/rizin", upstream_ref="c3a90e9226d977f58f4e9c75f78fa6b07afe13c7",
    executable_sha256=plan["executable_sha256"], fixture_source="open-source-compiled-elf",
    fixture_license="MIT", older_sha256=case["older"]["sha256"], newer_sha256=case["newer"]["sha256"],
    options={"argv_template": plan["argv_template"], "timeout_seconds": plan["engine_timeout_seconds"],
             "stdout_limit_bytes": plan["stdout_limit_bytes"], "k": plan["k"],
             "oracle_sha256": plan["oracle_sha256"], "case_manifest_sha256": plan["case_manifest_canonical_sha256"]},
    network_policy="none requested during analysis", env_fp=R.env_fingerprint(sorted(env), dict(env)),
    validations_run=["frozen_oracle", "input_hashes", "tool_hash_version", "production_scheduler_adapter", "existing_ranking_exact_name_comparison"],
    unverified=["Windows_MSVC_L2_acceptance", "desktop_acquisition", "vulnerability_attribution_accuracy", "L3", "corpus_accuracy"],
    blocked_reasons=blocked, result_hashes={"pilot_result": R.sha256_file(root / "pilot-result.json"),
                                          "plan": R.sha256_file(plan_file), "oracle": plan["oracle_sha256"]},
    counters={"cases": 1, "projects": 1, "native_matches": result["match_count"]},
    observed={"started_utc": started, "ended_utc": R.utc_now(), "duration_s": result["duration_seconds"]},
    artifacts=raw_artifacts,
)
receipt_path = R.write_receipt(receipt, root)
print(json.dumps({"result": result, "research_receipt": str(receipt_path)}, indent=2), flush=True)
raise SystemExit(exit_code)
