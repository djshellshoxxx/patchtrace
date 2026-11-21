"""Real local Git graphs distinguish reachability, patch equivalence and semantic residue."""
from __future__ import annotations

import csv
import importlib.util
import io
import json
import subprocess
from pathlib import Path

import pytest

TOOL = Path(__file__).resolve().parents[1] / "tools" / "branch_inventory.py"
spec = importlib.util.spec_from_file_location("branch_inventory", TOOL)
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)


def run(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


@pytest.fixture
def graph(tmp_path):
    repo = tmp_path / "repository"
    repo.mkdir()
    run(repo, "init", "--initial-branch=main")
    run(repo, "config", "user.name", "Inventory fixture")
    run(repo, "config", "user.email", "fixture@example.invalid")

    def commit(filename, value, message):
        (repo / filename).write_text(value, encoding="utf-8")
        run(repo, "add", filename)
        run(repo, "commit", "--quiet", "-m", message)
        return run(repo, "rev-parse", "HEAD")

    base = commit("base.txt", "base\n", "Base")
    run(repo, "checkout", "--quiet", "-b", "equivalent")
    equivalent = commit("ported.txt", "initial\n", "Original patch")
    run(repo, "checkout", "--quiet", "main")
    commit("ported.txt", "initial\n", "Separately port the same patch")
    main = commit("ported.txt", "evolved\n", "Evolve implementation after port")
    run(repo, "checkout", "--quiet", "-b", "integration")
    topic = commit("topic.txt", "unmerged\n", "Unmerged feature")
    integration = commit("integration.txt", "candidate\n", "Candidate bookkeeping")
    run(repo, "checkout", "--quiet", "-b", "unresolved", base)
    unresolved = commit("residue.txt", "review required\n", "Independent feature")
    for branch, sha in (("main", main), ("topic", topic), ("integration", integration),
                        ("equivalent", equivalent), ("unresolved", unresolved)):
        run(repo, "update-ref", f"refs/remotes/origin/{branch}", sha)
    run(repo, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")
    return repo, base, main, integration, topic, equivalent, unresolved


def test_candidate_reachability_does_not_mean_merged_and_patch_equivalence_does_not_mean_superseded(graph):
    repo, base, main, candidate, topic, equivalent, unresolved = graph
    git = tool.Git(repo)
    refs = tool.branches(git, "origin")
    assert len(refs) == 4
    assert all(branch not in ("HEAD", "main") for branch, _ in refs)
    refs.append(("integrated", base))
    pulls = [{"number": 12, "state": "open", "head": {
        "ref": "topic", "sha": topic, "repo": {"full_name": "owner/repository"},
    }, "base": {"sha": main}}]
    rows, summary = tool.inventory(git, main, candidate, refs, pulls, "owner/repository")
    indexed = {row["branch"]: row for row in rows}
    assert indexed["integrated"]["category"] == "already-integrated"
    assert indexed["topic"]["category"] == "contained-in-unmerged-candidate"
    assert indexed["topic"]["pr"] == "12"
    topic_note = json.loads(indexed["topic"]["note"])
    assert topic_note["main_ancestor"] is False
    assert topic_note["candidate_ancestor"] is True
    assert topic_note["pull_requests"][0]["head_matches_tip"] is True
    assert indexed["equivalent"]["category"] == "patch-equivalent-review-required"
    assert git.read("show", f"{equivalent}:ported.txt") != git.read("show", f"{candidate}:ported.txt")
    assert json.loads(indexed["equivalent"]["note"])["candidate_equivalent_nonmerge"] == [equivalent]
    residue = json.loads(indexed["unresolved"]["note"])
    assert residue["candidate_unmatched_nonmerge"] == [unresolved]
    assert residue["unmatched_patch_files"] == ["residue.txt"]
    assert residue["main_merge_base"] == base
    assert all(row["delete_safe"] == "no" for row in rows)
    assert summary["counts"]["main_ancestors"] == 1


def test_tsv_roundtrip_replays_exact_tips_after_branch_movement(graph, tmp_path):
    repo, base, main, candidate, topic, *_ = graph
    git = tool.Git(repo)
    refs = tool.branches(git, "origin")
    rows, _ = tool.inventory(git, main, candidate, refs, [], "owner/repository")
    rendered = tool.render(rows)
    parsed = list(csv.DictReader(io.StringIO(rendered), delimiter="\t"))
    assert parsed == rows
    snapshot = tmp_path / "inventory.tsv"
    tool.publish(snapshot, rendered)
    run(repo, "update-ref", "refs/remotes/origin/topic", base)
    replay_git = tool.Git(repo)
    assert dict(tool.branches(replay_git, "origin", snapshot))["topic"] == topic
    assert dict(tool.branches(replay_git, "origin"))["topic"] == base


def test_snapshot_replays_large_quoted_evidence_and_restores_csv_limit(graph, tmp_path):
    repo, base, main, candidate, topic, *_ = graph
    git = tool.Git(repo)
    refs = tool.branches(git, "origin")
    rows, _ = tool.inventory(git, main, candidate, refs, [], "owner/repository")
    rows[0]["note"] = json.dumps({"evidence": 'quoted "value"\t\n' + "x" * (128 * 1024)})
    snapshot = tmp_path / "large-evidence.tsv"
    tool.publish(snapshot, tool.render(rows))
    run(repo, "update-ref", "refs/remotes/origin/topic", base)
    previous_limit = csv.field_size_limit()

    assert tool.branches(tool.Git(repo), "origin", snapshot) == refs
    assert dict(refs)["topic"] == topic
    assert csv.field_size_limit() == previous_limit


def test_oversized_snapshot_preserves_previous_output(graph, tmp_path, monkeypatch, capsys):
    repo, _, main, candidate, topic, *_ = graph
    snapshot = tmp_path / "oversized.tsv"
    snapshot.write_text("branch\ttip_sha\tnote\n" + f"topic\t{topic}\t" + "x" * 200 + "\n")
    pulls = tmp_path / "pulls.json"
    pulls.write_text("[]", encoding="utf-8")
    previous = tmp_path / "previous.tsv"
    previous.write_text("previous successful evidence\n", encoding="utf-8")
    previous_limit = csv.field_size_limit()
    monkeypatch.setattr(tool, "MAX_METADATA_BYTES", 128)

    with pytest.raises(SystemExit) as error:
        tool.main(["--repo", str(repo), "--main", main, "--candidate", candidate,
                   "--pulls-json", str(pulls), "--refs-tsv", str(snapshot), "--output", str(previous)])
    assert error.value.code == 2
    assert "branch snapshot exceeds" in capsys.readouterr().err
    assert previous.read_text() == "previous successful evidence\n"
    assert csv.field_size_limit() == previous_limit


def test_snapshot_decode_failure_restores_csv_limit(graph, tmp_path):
    repo, *_ = graph
    snapshot = tmp_path / "invalid-utf8.tsv"
    snapshot.write_bytes(b"branch\ttip_sha\tnote\n\xff")
    previous_limit = csv.field_size_limit()
    with pytest.raises(UnicodeDecodeError):
        tool.branches(tool.Git(repo), "origin", snapshot)
    assert csv.field_size_limit() == previous_limit


def test_refuses_shallow_history(graph, tmp_path):
    repo, _, main, candidate, *_ = graph
    clone = tmp_path / "shallow"
    subprocess.run(["git", "clone", "--quiet", "--depth=1", repo.as_uri(), str(clone)], check=True)
    with pytest.raises(ValueError, match="complete history"):
        tool.inventory(tool.Git(clone), main, candidate, [], [], "owner/repository")


def test_failed_generation_preserves_previous_report(graph, tmp_path):
    repo, _, main, candidate, *_ = graph
    previous = tmp_path / "inventory.tsv"
    previous.write_text("previous successful evidence\n", encoding="utf-8")
    invalid = tmp_path / "pulls.json"
    invalid.write_text('{"not": "an all-pages array"}', encoding="utf-8")
    with pytest.raises(SystemExit) as error:
        tool.main(["--repo", str(repo), "--main", main, "--candidate", candidate,
                   "--pulls-json", str(invalid), "--output", str(previous)])
    assert error.value.code == 2
    assert previous.read_text() == "previous successful evidence\n"


def test_moved_pr_head_is_recorded_without_upgrading_the_branch(graph):
    repo, _, main, candidate, topic, _, unresolved = graph
    pulls = [{"number": 8, "state": "open", "head": {
        "ref": "topic", "sha": unresolved, "repo": {"full_name": "owner/repository"},
    }, "base": {"sha": main}}]
    rows, _ = tool.inventory(tool.Git(repo), main, candidate, [("topic", topic)], pulls, "owner/repository")
    assert json.loads(rows[0]["note"])["pull_requests"][0]["head_matches_tip"] is False
    assert rows[0]["delete_safe"] == "no"


def test_scoped_port_receipt_expires_when_candidate_changes(graph, monkeypatch):
    repo, _, main, candidate, _, equivalent, _ = graph
    monkeypatch.setattr(tool, "REVIEWED_CANDIDATE", candidate)
    monkeypatch.setattr(tool, "REVIEWED_PORTS", {equivalent: (42, main)})
    git = tool.Git(repo)
    refs = [("equivalent", equivalent)]
    reviewed, _ = tool.inventory(git, main, candidate, refs, [], "owner/repository")
    assert reviewed[0]["category"] == "port-verified-in-candidate"
    changed, _ = tool.inventory(git, main, main, refs, [], "owner/repository")
    assert changed[0]["category"] == "patch-equivalent-review-required"
    assert "scoped_port_review" not in json.loads(changed[0]["note"])


def test_intermediate_is_not_integrated_merely_because_surviving_pr_contains_it(graph):
    repo, _, main, candidate, topic, _, unresolved = graph
    pulls = [{"number": number, "state": "open", "head": {
        "ref": branch, "sha": sha, "repo": {"full_name": "owner/repository"},
    }, "base": {"sha": main}} for number, branch, sha in (
        (139, "topic", topic), (168, "integration", candidate),
    )]
    rows, _ = tool.inventory(tool.Git(repo), main, unresolved, [("topic", topic)], pulls, "owner/repository")
    assert rows[0]["category"] == "contained-in-retained-unmerged-branch"
    note = json.loads(rows[0]["note"])
    assert note["main_ancestor"] is False
    assert note["retained_unmerged_stack"]["tip"] == candidate
    assert rows[0]["delete_safe"] == "no"


@pytest.mark.parametrize("shape", [
    "duplicate-header", "extra-cell", "missing-cell", "missing-tip-header",
    "blank-tip", "blank-branch",
])
def test_snapshot_refuses_malformed_columns_before_any_git_lookup(graph, tmp_path, shape):
    _, _, _, _, topic, *_ = graph
    layouts = {
        "duplicate-header": f"branch\ttip_sha\tbranch\noriginal\t{topic}\tforged\n",
        "extra-cell": f"branch\ttip_sha\tnote\noriginal\t{topic}\tretained\textra\n",
        "missing-cell": f"branch\ttip_sha\tnote\noriginal\t{topic}\n",
        "missing-tip-header": "branch\tnote\noriginal\tretained\n",
        "blank-tip": "branch\ttip_sha\noriginal\t\n",
        "blank-branch": f"branch\ttip_sha\n \t{topic}\n",
    }
    snapshot = tmp_path / "malformed.tsv"
    snapshot.write_text(layouts[shape], encoding="utf-8")

    class NoGitCalls:
        def commit(self, ref):
            pytest.fail(f"invalid snapshot reached Git with {ref!r}")

    old_limit = csv.field_size_limit()
    with pytest.raises(ValueError, match="invalid branch snapshot TSV"):
        tool.branches(NoGitCalls(), "origin", snapshot)
    assert csv.field_size_limit() == old_limit


def test_snapshot_accepts_reordered_columns_and_extra_named_metadata(graph, tmp_path):
    repo, _, _, _, topic, *_ = graph
    snapshot = tmp_path / "compatible.tsv"
    snapshot.write_text(f"note\ttip_sha\tbranch\textra\nretained\t{topic}\ttopic\tdata\n",
                        encoding="utf-8")
    old_limit = csv.field_size_limit()
    assert tool.branches(tool.Git(repo), "origin", snapshot) == [("topic", topic)]
    assert csv.field_size_limit() == old_limit


def test_invalid_snapshot_headers_leave_previous_published_evidence_unchanged(graph, tmp_path, capsys):
    repo, _, main, candidate, topic, *_ = graph
    snapshot = tmp_path / "wrong-heading.tsv"
    snapshot.write_text(f"branch\ttip_sha\tbranch\noriginal\t{topic}\tforged\n", encoding="utf-8")
    pulls = tmp_path / "pulls.json"
    pulls.write_text("[]", encoding="utf-8")
    output = tmp_path / "inventory.tsv"
    output.write_text("previous successful evidence\n", encoding="utf-8")

    with pytest.raises(SystemExit) as error:
        tool.main(["--repo", str(repo), "--main", main, "--candidate", candidate,
                   "--pulls-json", str(pulls), "--refs-tsv", str(snapshot), "--output", str(output)])
    assert error.value.code == 2
    assert "invalid branch snapshot TSV" in capsys.readouterr().err
    assert output.read_text(encoding="utf-8") == "previous successful evidence\n"
