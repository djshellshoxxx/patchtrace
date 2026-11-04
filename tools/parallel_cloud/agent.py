"""Bounded PatchTrace API agent. No model-executed shell/tool access."""
import argparse
import json
import os
from pathlib import Path
import sys
import urllib.request

TASKS = {
    "pe": ["src/patchtrace/pe_overview/", "tests/test_pe_overview"],
    "representations": ["src/patchtrace/representations/", "tests/test_representations"],
    "nway": ["src/patchtrace/nway/", "tests/test_nway"],
    "cache": ["src/patchtrace/enrichment/cache.py", "tests/test_enrichment_cache"],
    "diagnostics": ["src/patchtrace/diagnostics.py", "tests/test_diagnostics"],
    "offline": ["src/patchtrace/offline_bundle.py", "tests/test_offline_bundle"],
    "runtime": ["src/patchtrace/runtime_discovery.py", "tests/test_runtime_discovery"],
    "artifact": ["src/patchtrace/artifact_bytes.py", "tests/test_artifact_bytes"],
}
ROOT = Path.cwd().resolve()
MODEL = os.getenv("PT_AGENT_MODEL", "gpt-5-mini")
BUDGET = float(os.getenv("PT_AGENT_BUDGET_USD", "25"))
INPUT_RATE = float(os.getenv("PT_INPUT_USD_PER_M", "20"))
OUTPUT_RATE = float(os.getenv("PT_OUTPUT_USD_PER_M", "100"))
OUTPUT_LIMIT = 4500


def allowed(path, prefixes):
    if not isinstance(path, str) or not path.endswith(".py") or "\\" in path:
        return False
    if path.startswith("/") or ".." in Path(path).parts:
        return False
    return any(path == p or path.startswith(p if p.endswith("/") else p + "_") for p in prefixes)


def scoped_files(prefixes):
    found = set()
    for prefix in prefixes:
        item = ROOT / prefix
        if item.is_dir():
            found.update(item.rglob("*.py"))
        elif item.is_file():
            found.add(item)
        else:
            found.update(item.parent.glob(item.name + "*.py"))
    return sorted(p for p in found if p.is_file() and not p.is_symlink() and p.resolve().is_relative_to(ROOT))


def query_api(messages):
    req = urllib.request.Request(
        "https://api.openai.com/v1/responses",
        data=json.dumps({"model": MODEL, "input": messages, "max_output_tokens": OUTPUT_LIMIT, "store": False}).encode(),
        headers={"Authorization": "Bearer " + os.environ["PATCHTRACE_OPENAI_API_KEY"],
                 "Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=180) as response:
        payload = json.load(response)
    usage = payload.get("usage") or {}
    if not all(isinstance(usage.get(k), int) for k in ("input_tokens", "output_tokens")):
        raise RuntimeError("API did not return usable token accounting")
    parts = [part["text"] for item in payload.get("output", []) if item.get("type") == "message"
             for part in item.get("content", []) if part.get("type") == "output_text"]
    return "\n".join(parts), usage


def parse_edit(message, scope, phase):
    data = json.loads(message)
    edits = data.get("files")
    if not isinstance(edits, list) or not 1 <= len(edits) <= 3:
        raise ValueError("Expected 1-3 complete file replacements")
    result = {}
    for edit in edits:
        path, content = edit["path"], edit["content"]
        if not allowed(path, scope) or not isinstance(content, str) or len(content.encode()) > 65000:
            raise ValueError("Out-of-scope/oversize edit")
        if phase == "test" and not path.startswith("tests/"):
            raise ValueError("Test phase must change tests only")
        if phase == "source" and not path.startswith("src/"):
            raise ValueError("Source phase must change source only")
        dest = ROOT / path
        if dest.is_symlink() or not dest.is_file() or not dest.resolve().is_relative_to(ROOT):
            raise ValueError("Invalid or nonexisting file target")
        result[path] = content
    return result


def main():
    p = argparse.ArgumentParser()
    p.add_argument("task", choices=TASKS)
    task = p.parse_args().task
    receipt = {"task": task, "model": MODEL, "budget_usd": BUDGET,
               "accounting_input_usd_per_m": INPUT_RATE,
               "accounting_output_usd_per_m": OUTPUT_RATE,
               "accounted_cost_usd": 0.0, "attempts": [], "status": "started"}
    try:
        if not 0 < BUDGET <= 25 or INPUT_RATE <= 0 or OUTPUT_RATE <= 0:
            raise ValueError("Invalid budget or price assumptions")
        scope = TASKS[task]
        files = scoped_files(scope)
        context = []
        for path in files[:12]:
            data = path.read_text(encoding="utf-8")
            if len(data) <= 16000:
                context.append(f"FILE {path.relative_to(ROOT)}\n{data}")
        if not context or not any(x.startswith("FILE tests/") for x in context):
            receipt["status"] = "no_test_seam"
            return 0
        instructions = ("PatchTrace task: find one small, reproducible hardening/regression defect in "
                        + task + ". Respect AGENTS.md, no new scope, no network, no target binary execution. "
                        "Respond ONLY as JSON {\"files\":[{\"path\":\"existing/path.py\",\"content\":\"full UTF-8 content\"}]}. "
                        "FIRST supply one failing regression test only, not source changes.\n"
                        + "\n\n".join(context))
        messages = [{"role": "user", "content": instructions}]
        for phase in ("test", "source"):
            # Bytes provide a deliberately conservative upper bound for normal UTF-8 input tokens.
            reserved = (len(json.dumps(messages).encode()) * INPUT_RATE + OUTPUT_LIMIT * OUTPUT_RATE) / 1_000_000
            if receipt["accounted_cost_usd"] + reserved > BUDGET:
                receipt["status"] = "budget_preflight_blocked"
                return 0
            reply, usage = query_api(messages)
            charge = (usage["input_tokens"] * INPUT_RATE + usage["output_tokens"] * OUTPUT_RATE) / 1_000_000
            receipt["attempts"].append({"phase": phase, "input_tokens": usage["input_tokens"],
                                        "output_tokens": usage["output_tokens"],
                                        "accounted_usd": round(charge, 6)})
            receipt["accounted_cost_usd"] = round(receipt["accounted_cost_usd"] + charge, 6)
            if receipt["accounted_cost_usd"] > BUDGET:
                raise ValueError("Conservative accounting ceiling exceeded; refusing publication")
            edits = parse_edit(reply, scope, phase)
            for name, content in edits.items():
                (ROOT / name).write_text(content, encoding="utf-8")
            if phase == "test":
                source_context = "\n\n".join(c for c in context if not c.startswith("FILE tests/"))
                messages = [{"role": "user", "content": (
                    "Implement the smallest source fix for the regression test you just wrote. "
                    "Do not edit tests, do not change unrelated contracts. Reply with complete-file JSON edits.\n"
                    + "\n\n".join(f"FILE {name}\n{data[:14000]}" for name, data in edits.items())
                    + "\nOriginal source:\n" + source_context)}]
        receipt["status"] = "patch_ready_for_validation"
        return 0
    except Exception as exc:
        receipt["status"] = "failed"
        receipt["error_type"] = type(exc).__name__
        print(f"Parallel agent refused: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    finally:
        Path("parallel-agent-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")


if __name__ == "__main__":
    sys.exit(main())
