#!/usr/bin/env python3
"""Produce offline branch-review evidence; never fetch, change refs or authorize deletion.

Supply the concatenated JSON arrays from every REST /pulls?state=all page.
The legacy TSV columns are retained for readers, with delete_safe always "no".
The note column contains a JSON object, not a deletion recommendation.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import re
import subprocess
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any

COLUMNS = ("branch", "tip_sha", "pr", "last_commit", "category", "delete_safe", "note")
CANONICAL_COMMIT_OID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
MAX_METADATA_BYTES = 32 * 1024 * 1024
PARTIAL_PRS = {144, 168, 174, 176, 289}
DEFERRED_PRS = {61, 167, 170, 171, 186, 279}
DOCUMENTATION_PRS = {68, 72, 98, 125, 129, 130, 133, 134, 135, 137, 150, 172, 179, 187, 222, 224, 284}
# These are scoped human review receipts, not inferred semantic equality. They
# apply only to the exact reviewed candidate and source heads documented in the
# dated decision record. A moved candidate/source returns to ordinary review.
REVIEWED_CANDIDATE = "faddea300daf4058d38d24ff04a270be6f3d832b"
REVIEWED_PORTS = {
    "b29351d41060f8e9330fc9673457d835e188f993": (268, "f64620f7771b205558871fe09448eb1dd6df715a"),
    "cbabc09e9df8a8190c769164ef0fae44f9c5cb1b": (281, "2d330075fbe00209fbe096ee29b60dcfd0e347b4"),
    "552c29453c5de93e22c65e47ad4187ded91e993a": (282, "909cd5f2259bb9caf8afcb681d01589cb4e49244"),
    "6f767ccef8ebfffd1d2373c5124d8a961dc54b41": (283, "2d330075fbe00209fbe096ee29b60dcfd0e347b4"),
}
STACK_PRS = {139, 140, 141, 143, 164, 165}


class Git:
    def __init__(self, repo: Path):
        self.repo = repo
        self._cache: dict[tuple[str, ...], str] = {}

    def read(self, *args: str) -> str:
        if args in self._cache:
            return self._cache[args]
        result = subprocess.run(
            ["git", "-C", str(self.repo), *args], check=True,
            capture_output=True, text=True, encoding="utf-8", timeout=120,
            env={**os.environ, "GIT_OPTIONAL_LOCKS": "0", "GIT_NO_REPLACE_OBJECTS": "1"},
        )
        self._cache[args] = result.stdout
        return result.stdout

    def commit(self, ref: str) -> str:
        if ref.startswith("-"):
            raise ValueError("a commit reference cannot start with '-' ")
        return self.read("rev-parse", "--verify", f"{ref}^{{commit}}").strip()


def read_json(path: Path) -> Any:
    with path.open("rb") as stream:
        raw = stream.read(MAX_METADATA_BYTES + 1)
    if len(raw) > MAX_METADATA_BYTES:
        raise ValueError("pull-request metadata exceeds 32 MiB")
    # Raw snapshots are identity evidence: default JSON decoding silently
    # overwrites duplicate keys and accepts non-finite numeric extensions.
    def unique_object(pairs):
        result = {}
        for key, item in pairs:
            if key in result:
                raise ValueError("invalid pull-request metadata: duplicate JSON key")
            result[key] = item
        return result

    def reject_nonfinite(_constant):
        raise ValueError("invalid pull-request metadata: non-finite JSON number")

    try:
        value = json.loads(raw, object_pairs_hook=unique_object, parse_constant=reject_nonfinite)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise ValueError("invalid pull-request metadata JSON") from None
    if not isinstance(value, list) or not all(isinstance(row, dict) for row in value):
        raise ValueError("pull-request metadata must be an all-pages JSON array")
    return value


def branches(git: Git, remote: str, snapshot: Path | None = None) -> list[tuple[str, str]]:
    if snapshot is not None:
        with snapshot.open("rb") as stream:
            raw = stream.read(MAX_METADATA_BYTES + 1)
        if len(raw) > MAX_METADATA_BYTES:
            raise ValueError("branch snapshot exceeds the input byte limit")
        previous_limit = csv.field_size_limit(MAX_METADATA_BYTES)
        try:
            reader = csv.DictReader(io.StringIO(raw.decode("utf-8"), newline=""), delimiter="\t")
            headers = reader.fieldnames
            if (not headers or len(headers) != len(set(headers))
                    or "branch" not in headers or "tip_sha" not in headers
                    or any(not name.strip() for name in headers)):
                raise ValueError("invalid branch snapshot TSV headers")
            rows = list(reader)
            if any(None in row or any(value is None for value in row.values())
                   or not row["branch"].strip() or not CANONICAL_COMMIT_OID.fullmatch(row["tip_sha"])
                   for row in rows):
                raise ValueError("invalid branch snapshot TSV rows")
        except csv.Error as exc:
            raise ValueError("invalid branch snapshot TSV") from exc
        finally:
            csv.field_size_limit(previous_limit)
        result = []
        for row in rows:
            resolved = git.commit(row["tip_sha"])
            if resolved != row["tip_sha"]:
                raise ValueError("branch snapshot tip does not match commit object")
            result.append((row["branch"], resolved))
    else:
        if not remote or any(char in remote for char in "\r\n\t ") or remote.startswith("-"):
            raise ValueError("invalid remote name")
        prefix = f"refs/remotes/{remote}/"
        rows = git.read("for-each-ref", "--format=%(refname)%09%(objectname)%09%(symref)", prefix)
        result = []
        for line in rows.splitlines():
            name, sha, symbolic = line.split("\t")
            if not symbolic:
                result.append((name.removeprefix(prefix), sha))
    if len({name for name, _ in result}) != len(result):
        raise ValueError("duplicate branch names in snapshot")
    return sorted((name, sha) for name, sha in result if name != "main")


def patches(git: Git, baseline: str, tip: str) -> tuple[list[str], list[str]]:
    unmatched, equivalent = [], []
    for line in git.read("cherry", baseline, tip).splitlines():
        sign, sha = line.split()
        if sign == "+":
            unmatched.append(sha)
        elif sign == "-":
            equivalent.append(sha)
        else:
            raise ValueError("unexpected git cherry output")
    return unmatched, equivalent


def disposition(in_main: bool, in_candidate: bool, unmatched: list[str], prs: list[int], branch: str,
                *, files: set[str], reviewed_port: bool, retained_stack: bool) -> str:
    if in_main:
        return "already-integrated"
    if in_candidate:
        return "contained-in-unmerged-candidate"
    if reviewed_port:
        return "port-verified-in-candidate"
    if retained_stack:
        return "contained-in-retained-unmerged-branch"
    if set(prs) & PARTIAL_PRS or branch == "claude/instance-b-features":
        return "partial-recovery-required"
    if set(prs) & DEFERRED_PRS or branch.startswith("automation/") or "skills-manifest" in branch:
        return "experimental-deferred"
    if not unmatched:
        return "patch-equivalent-review-required"
    if set(prs) & DOCUMENTATION_PRS or branch.startswith("research/"):
        if files and all(name.startswith(("docs/", "tasks/")) for name in files):
            return "historical-documentation-review"
        return "research-tools-review-required"
    return "unresolved"


def inventory(
    git: Git, main: str, candidate: str, refs: list[tuple[str, str]], pulls: list[dict],
    repository: str,
) -> tuple[list[dict[str, str]], dict[str, Any]]:
    if git.read("rev-parse", "--is-shallow-repository").strip() != "false":
        raise ValueError("complete history is required; this repository is shallow")
    main, candidate = git.commit(main), git.commit(candidate)
    main_history = set(git.read("rev-list", main).splitlines())
    candidate_history = set(git.read("rev-list", candidate).splitlines())
    by_branch: dict[str, list[dict]] = {}
    for pull in pulls:
        head = pull.get("head", {})
        head_repo = head.get("repo") or {}
        if head_repo.get("full_name") == repository:
            by_branch.setdefault(head["ref"], []).append(pull)
    survivor = next((pull for pull in pulls if pull.get("number") == 168 and pull.get("state") == "open"
                     and (pull.get("head", {}).get("repo") or {}).get("full_name") == repository), None)
    survivor_history = set(git.read("rev-list", git.commit(survivor["head"]["sha"])).splitlines()) \
        if survivor else set()
    rows = []
    counts: Counter[str] = Counter()
    for branch, tip in refs:
        main_base = git.read("merge-base", main, tip).strip()
        candidate_base = git.read("merge-base", candidate, tip).strip()
        main_unmatched, main_equivalent = patches(git, main, tip)
        unmatched, equivalent = patches(git, candidate, tip)
        matched_prs = sorted(by_branch.get(branch, []), key=lambda pull: pull["number"])
        numbers = [pull["number"] for pull in matched_prs]
        in_main, in_candidate = tip in main_history, tip in candidate_history
        changed_files: set[str] = set()
        for sha in unmatched:
            changed_files.update(filter(None, git.read(
                "diff-tree", "--root", "--no-commit-id", "--name-only", "-r", "-z", sha,
            ).split("\0")))
        reviewed_port = REVIEWED_PORTS.get(tip) if candidate == REVIEWED_CANDIDATE else None
        retained_stack = bool(set(numbers) & STACK_PRS and tip in survivor_history)
        category = disposition(in_main, in_candidate, unmatched, numbers, branch, files=changed_files,
                               reviewed_port=bool(reviewed_port), retained_stack=retained_stack)
        detail = {
            "main": main, "candidate": candidate,
            "main_ancestor": in_main, "candidate_ancestor": in_candidate,
            "main_merge_base": main_base, "candidate_merge_base": candidate_base,
            "main_unique_commits": int(git.read("rev-list", "--count", f"{main}..{tip}").strip()),
            "candidate_unique_commits": int(git.read("rev-list", "--count", f"{candidate}..{tip}").strip()),
            "main_unmatched_nonmerge": main_unmatched, "main_equivalent_nonmerge": main_equivalent,
            "candidate_unmatched_nonmerge": unmatched, "candidate_equivalent_nonmerge": equivalent,
            "unmatched_patch_files": sorted(changed_files),
            "candidate_net_diff_files": sorted(filter(None, git.read(
                "diff", "--name-only", "-z", candidate_base, tip,
            ).split("\0"))),
            "pull_requests": [{
                "number": pull["number"], "state": pull["state"],
                "head": pull["head"]["sha"], "base": pull["base"]["sha"],
                "head_matches_tip": pull["head"]["sha"] == tip,
            } for pull in matched_prs],
            "scope": "ancestry and patch evidence only; semantic residue requires review; retain branch",
        }
        if reviewed_port:
            detail["scoped_port_review"] = {
                "pr": reviewed_port[0], "replacement_commit": reviewed_port[1],
                "record": "docs/qa/branch-consolidation-20261118.md#verified-selective-ports",
                "status": "verified-in-candidate-only; wait for main qualification before closing PR",
            }
        if retained_stack:
            detail["retained_unmerged_stack"] = {
                "pr": survivor["number"], "branch": survivor["head"]["ref"], "tip": survivor["head"]["sha"],
                "status": "ancestor of surviving open PR; not integrated into main",
            }
        rows.append({
            "branch": branch, "tip_sha": tip, "pr": ",".join(map(str, numbers)) or "-",
            "last_commit": git.read("show", "-s", "--format=%cs", tip).strip(),
            "category": category, "delete_safe": "no",
            "note": json.dumps(detail, sort_keys=True, separators=(",", ":"), ensure_ascii=True),
        })
        counts["topic_branches"] += 1
        counts["main_ancestors"] += int(in_main)
        counts["candidate_ancestors"] += int(in_candidate)
        counts["nonancestor_without_unmatched_patch"] += int(not in_candidate and not unmatched)
        counts["branches_with_unmatched_patches"] += int(bool(unmatched))
        counts["with_main_merge_base"] += int(bool(main_base))
        counts[f"disposition:{category}"] += 1
    return rows, {"main": main, "candidate": candidate, "counts": dict(sorted(counts.items()))}


def render(rows: list[dict[str, str]]) -> str:
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=COLUMNS, delimiter="\t", lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue()


def publish(path: Path, content: str) -> None:
    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="", dir=path.parent,
                                         prefix=f".{path.name}.", delete=False) as stream:
            temporary = stream.name
            stream.write(content)
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            Path(temporary).unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--repository", default="djshellshoxxx/patchtrace")
    parser.add_argument("--remote", default="origin")
    parser.add_argument("--main", required=True)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--pulls-json", type=Path, required=True, help="saved all-pages REST PR array")
    parser.add_argument("--refs-tsv", type=Path, help="replay exact branch tips from an earlier inventory")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        git = Git(args.repo)
        pulls = read_json(args.pulls_json)
        refs = branches(git, args.remote, args.refs_tsv)
        rows, summary = inventory(git, args.main, args.candidate, refs, pulls, args.repository)
        publish(args.output, render(rows))
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as exc:
        parser.exit(2, f"branch inventory failed: {exc}\n")
    print(json.dumps(summary, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
