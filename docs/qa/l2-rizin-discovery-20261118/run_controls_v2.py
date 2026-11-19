"""Frozen authored controls, post-measurement diagnosis; never execute targets."""
from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import threading

from patchtrace.jobs import run_process
from patchtrace.secondary.engine_env import engine_env
from patchtrace.secondary.registry import build_registry
from patchtrace.secondary.scheduler import ProjectRef, run_engines
from tools.research_qualification import receipt as R
from tools.research_qualification.adapters import rizin as ranking_adapter

root = Path(__file__).resolve().parent
plan = json.loads((root / "control-plan.json").read_text())
assert R.sha256_file(root / "control-plan.json") == "51b132d76f0f82edb45c2ba4f82f0f637c63f76f0b43941a13d41739ddba2169"
repo = Path("/workspace/scratch/e83fbf4505c3/repair-receipt-identity")
pilot = Path("/workspace/scratch/e83fbf4505c3/l2-native-pilot/20261118T082742Z-http-parser")
pilot_plan = json.loads((pilot / "pilot-plan.json").read_text())
assert R.git_head(repo) == pilot_plan["source_commit"]
for relative, expected in plan["source_sha256"].items():
    assert R.sha256_file(root / relative) == expected
for relative, expected in pilot_plan["source_sha256"].items():
    assert R.sha256_file(repo / relative) == expected
tool = Path(pilot_plan["executable"])
rizin = tool.with_name("rizin")
assert R.sha256_file(tool) == pilot_plan["executable_sha256"]
assert R.sha256_file(rizin) == "ab5614cf137608cffc5a3f4f471a91c995cfa7c0c35465bfb73876e5b95561ba"
env = engine_env(os.environ, "rz-diff")
records = []


def save_json(relative, value):
    with (root / relative).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def observed(label, argv, **kwargs):
    result = run_process(argv, **kwargs)
    stdout, stderr = result.log_bytes or b"", result.stderr_bytes or b""
    for suffix, data in (("stdout", stdout), ("stderr", stderr)):
        with (root / "raw" / (label + "." + suffix)).open("xb") as stream:
            stream.write(data)
    record = {
        "kind": "post-measurement-native-operation/1", "label": label,
        "argv": list(argv), "cwd": str(kwargs["cwd"]),
        "settings": {key: kwargs[key] for key in ("timeout_seconds", "log_limit", "separate_streams", "stderr_limit", "max_output_bytes") if key in kwargs},
        "environment_keys": sorted(kwargs["env"]),
        "environment_fingerprint": R.env_fingerprint(sorted(kwargs["env"]), dict(kwargs["env"])),
        "returncode": result.returncode, "reason": result.reason,
        "elapsed_seconds": result.elapsed_seconds,
        "stdout_total": result.stdout_total, "stderr_total": result.stderr_total,
        "stdout_kept": len(stdout), "stderr_kept": len(stderr),
        "streams_complete": len(stdout) == result.stdout_total and len(stderr) == result.stderr_total,
        "stdout_path": "raw/" + label + ".stdout", "stderr_path": "raw/" + label + ".stderr",
        "stdout_sha256": hashlib.sha256(stdout).hexdigest(), "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
        "trusted_executable_sha256": R.sha256_file(Path(argv[0]).resolve()),
        "target_execution": False,
    }
    records.append(record)
    save_json("receipts/" + label + ".json", record)
    return result


def static_operation(label, argv, cwd=root):
    return observed(label, argv, cwd=cwd, env=env, cancel=threading.Event(),
                    timeout_seconds=plan["per_run_timeout_seconds"],
                    log_limit=8 * 1024 * 1024, separate_streams=True,
                    stderr_limit=2 * 1024 * 1024, max_output_bytes=10 * 1024 * 1024)


compiler = Path(plan["compiler"])
static_operation("compiler-version", [str(compiler), "--version"])
pairs = []
for form, suffix in (("shared", ".so"), ("executable", ".elf")):
    files = {}
    for side in ("older", "newer"):
        directory = root / "build" / form / side
        directory.mkdir(parents=True, exist_ok=False)
        output = directory / ("control" + suffix)
        source_directory = root / "controls" / side
        argv = [str(compiler), *plan["compiler_flags_common"],
                *plan["compiler_flags_" + form], "-o", str(output), "control.c"]
        if form == "executable":
            argv.append("main.c")
        result = static_operation("build-" + form + "-" + side, argv, source_directory)
        assert result.reason is None and result.returncode == 0, "Authored control build failed"
        output.chmod(0o444)
        files[side] = output
        static_operation("symbols-" + form + "-" + side, ["/usr/bin/readelf", "--dyn-syms", "--wide", str(output)])
    pairs.append((form, files))

pe = repo / "tests/fixtures/tier_w"
assert R.sha256_file(pe / "tiny_v1.pe") == "b69e9b090dd6406eadc734f005513432503652b55cbd70bb2370b10ea018cd41"
assert R.sha256_file(pe / "tiny_v2.pe") == "c2e70030a16b5b9b075b9686ebfa9c7bda389743222e98a373369865e0e015ea"
pairs.append(("authored-pe", {"older": pe / "tiny_v1.pe", "newer": pe / "tiny_v2.pe"}))
results = []
for label, files in pairs:
    hashes = {side: R.sha256_file(path) for side, path in files.items()}
    pair_events = []
    production_operations = []

    def recording_runner(argv, **kwargs):
        assert argv[0] == str(tool)
        analysis = list(argv[1:5]) == plan["native_default_flags"]
        assert analysis or list(argv[1:]) == ["-v"]
        if analysis:
            assert len(argv) == 7
            assert {side: R.sha256_file(argv[pos]) for side, pos in (("older", 5), ("newer", 6))} == hashes
        operation = label + "-production-" + str(len(production_operations)) + ("-analysis" if analysis else "-probe")
        result = observed(operation, argv, **kwargs)
        if analysis:
            assert {side: R.sha256_file(argv[pos]) for side, pos in (("older", 5), ("newer", 6))} == hashes
        production_operations.append(records[-1])
        return result

    project = ProjectRef(files["older"], files["newer"], hashes["older"], hashes["newer"])
    (outcome,) = run_engines(project, ["rz-diff"], max_parallel=1,
                            per_engine_timeout={"rz-diff": plan["per_run_timeout_seconds"]},
                            cancel=threading.Event(), cache=None, env=env,
                            on_event=lambda event: pair_events.append(asdict(event)),
                            registry=build_registry(rz_diff=str(tool)), runner=recording_runner,
                            stdout_limit=8 * 1024 * 1024)
    save_json(label + "-engine-run.json", outcome.run.model_dump(mode="json"))
    if outcome.match_set:
        save_json(label + "-secondary-match-set.json", outcome.match_set.model_dump(mode="json"))
    if outcome.error:
        save_json(label + "-engine-error.json", {"code": outcome.error.code, "message": outcome.error.message, "kind": outcome.error.kind, "reason": outcome.error.reason})
    ranking = None
    raw = None
    if outcome.run.status == "ok" and outcome.match_set:
        capture = production_operations[-1]
        assert capture["streams_complete"]
        data = (root / capture["stdout_path"]).read_bytes()
        assert hashlib.sha256(data).hexdigest() == outcome.match_set.file_sha256
        raw = json.loads(data)
        ranking = ranking_adapter.parse(data)
    inventory_result = static_operation(label + "-inventory", [str(rizin), "-N", "-A", "-q", "-c", "aflj", str(files["older"])])
    inventory = None
    if inventory_result.returncode == 0 and inventory_result.reason is None:
        try:
            inventory = json.loads(inventory_result.log_bytes)
        except ValueError:
            pass
    result = {
        "fixture": label, "phase": "post-measurement diagnosis, not scored",
        "files": {side: str(path) for side, path in files.items()}, "sha256": hashes,
        "production_status": outcome.run.status, "error_code": outcome.run.error_code,
        "match_count": len(outcome.match_set.matches) if outcome.match_set else 0,
        "native_rows": raw, "existing_ranked_names": ranking,
        "independent_inventory_count": len(inventory) if inventory is not None else None,
        "independent_inventory_names": [row.get("name") for row in inventory] if inventory is not None else None,
        "events": pair_events,
    }
    results.append(result)
    print(json.dumps({key: value for key, value in result.items() if key not in ("native_rows", "events")}), flush=True)
    assert {side: R.sha256_file(path) for side, path in files.items()} == hashes
for relative, expected in pilot_plan["source_sha256"].items():
    assert R.sha256_file(repo / relative) == expected
assert R.sha256_file(pilot / "pilot-result.json") == "6d95d0b857d2a2cdb61ceecf6a69d05133dd852677aa6889b10fbd4544de339e"
assert R.sha256_file(pilot / "pilot-plan.json") == "d6a2dc2b5a1dc59304fc2a8279b6c186537be267448cf9bd0d700e6617e6dbef"
save_json("control-results.json", {"phase": "post-measurement diagnosis", "source_commit": R.git_head(repo), "source_tree": pilot_plan["source_tree"], "candidate_reruns": 0, "target_execution": False, "product_edits": False, "results": results})
