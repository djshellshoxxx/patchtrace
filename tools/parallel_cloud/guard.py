"""Fail-closed ownership and source-patch receipt validation."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
from agent import TASKS, allowed


def run(*command):
    return subprocess.check_output(command, text=True).strip()


def github_api(path):
    return json.loads(run("gh", "api", path))


def check_ownership(task):
    repo = os.getenv("GITHUB_REPOSITORY", "djshellshoxxx/patchtrace")
    page = 1
    while True:
        prs = github_api(f"repos/{repo}/pulls?state=open&per_page=100&page={page}")
        if not isinstance(prs, list):
            raise RuntimeError("Invalid GitHub PR list")
        for pr in prs:
            head = pr.get("head", {}).get("ref", "")
            if head.startswith(f"codex/parallel-{task}-"):
                print(f"Skipping: task already has PR #{pr['number']}", file=sys.stderr)
                return False
            index = 1
            while True:
                files = github_api(f"repos/{repo}/pulls/{pr['number']}/files?per_page=100&page={index}")
                if not isinstance(files, list):
                    raise RuntimeError("Invalid changed-file response")
                if any(allowed(item.get("filename", ""), TASKS[task]) for item in files):
                    print(f"Skipping: PR #{pr['number']} touches owned paths", file=sys.stderr)
                    return False
                if len(files) < 100:
                    break
                index += 1
        if len(prs) < 100:
            return True
        page += 1


def post_check(task):
    changed = set(run("git", "diff", "--name-only", "HEAD").splitlines())
    changed |= set(run("git", "ls-files", "--others", "--exclude-standard").splitlines())
    changed -= {"parallel-agent-receipt.json", "parallel.patch", "guard-output", "base-sha.txt"}
    if not changed or not all(allowed(path, TASKS[task]) for path in changed):
        raise ValueError(f"Out-of-scope/empty changes: {sorted(changed)}")
    if not any(p.startswith("tests/") for p in changed) or not any(p.startswith("src/") for p in changed):
        raise ValueError("Source and test changes both required")


def validate_artifact(task, folder):
    receipt = json.loads((folder / "parallel-agent-receipt.json").read_text())
    if receipt.get("task") != task or receipt.get("status") != "patch_ready_for_validation":
        raise ValueError("Missing completed task receipt")
    amount, budget = receipt.get("accounted_cost_usd"), receipt.get("budget_usd")
    if not isinstance(amount, (int, float)) or not isinstance(budget, (int, float)):
        raise ValueError("Missing numeric cost values")
    if amount > budget or budget > 25 or len(receipt.get("attempts", [])) != 2:
        raise ValueError("Unverified budget or test-first attempts")
    if receipt.get("red_verified") is not True or receipt.get("green_verified") is not True:
        raise ValueError("Missing verified red/green test evidence")
    if receipt.get("red_exit_code") != 1 or receipt.get("green_exit_code") != 0:
        raise ValueError("Invalid red/green test exit codes")
    attempts = receipt["attempts"]
    if [item.get("phase") for item in attempts] != ["test", "source"]:
        raise ValueError("Incorrect phase ordering")
    if not all(isinstance(item.get("input_tokens"), int) and
               isinstance(item.get("output_tokens"), int) and
               item["input_tokens"] >= 0 and item["output_tokens"] >= 0
               for item in attempts):
        raise ValueError("Unverifiable API usage")
    changes = run("git", "apply", "--numstat", str(folder / "parallel.patch")).splitlines()
    if not changes:
        raise ValueError("Empty patch")
    paths = []
    for entry in changes:
        cols = entry.split("\t")
        if len(cols) != 3 or not allowed(cols[2], TASKS[task]):
            raise ValueError("Invalid patch scope")
        paths.append(cols[2])
    if not any(x.startswith("src/") for x in paths) or not any(x.startswith("tests/") for x in paths):
        raise ValueError("Patch lacks code or tests")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("task", choices=TASKS)
    p.add_argument("--post", action="store_true")
    p.add_argument("--validate-artifact", type=Path)
    args = p.parse_args()
    if args.validate_artifact:
        validate_artifact(args.task, args.validate_artifact)
    else:
        if args.post:
            post_check(args.task)
        print("ready=" + str(check_ownership(args.task)).lower())


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Guard refused: {exc}", file=sys.stderr)
        sys.exit(1)
