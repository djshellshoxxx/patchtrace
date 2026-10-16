"""LBL-30 preregistration selection and single-use final-run guards.

Synthetic temporary files only; no real locked corpus or target binary is touched.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from tools.calibration import prereg_gate as G
from tools.calibration import train as T


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def inputs(tmp_path: Path) -> tuple[Path, Path, str]:
    prereg = tmp_path / "c9.md"
    prereg.write_bytes(b"frozen protocol\n")
    digest = sha(prereg.read_bytes())
    qa = tmp_path / "qa.md"
    qa.write_text(f"| C9-PREREG-v1 | {digest} | owner approval recorded |\n")
    return prereg, qa, digest


def test_unregistered_default_is_plain_unlocked(tmp_path):
    selected = G.select(None, tmp_path / "missing.md")
    assert selected.sha is None and selected.rehearsal_sha is None and not selected.verified


def test_matching_registered_prereg_is_verified(tmp_path):
    prereg, qa, expected = inputs(tmp_path)
    selected = G.select(prereg, qa)
    assert selected.verified and selected.sha == expected and selected.rehearsal_sha is None


def test_missing_qa_receipt_is_not_locked(tmp_path):
    prereg, _, _ = inputs(tmp_path)
    with pytest.raises(G.PreregGateError, match="no recorded"):
        G.select(prereg, tmp_path / "missing.md")


def test_mismatched_receipt_is_rejected(tmp_path):
    prereg, qa, _ = inputs(tmp_path)
    qa.write_text(f"| C9-PREREG-v1 | {'0' * 64} | owner approval recorded |\n")
    with pytest.raises(G.PreregGateError, match="mismatch"):
        G.select(prereg, qa)


def test_crlf_prereg_is_rejected_even_for_rehearsal(tmp_path):
    prereg, qa, _ = inputs(tmp_path)
    prereg.write_bytes(b"frozen\r\n")
    with pytest.raises(G.PreregGateError, match="CR"):
        G.select(prereg, qa, allow_unlocked=True)


def test_rehearsal_never_labels_a_draft_as_preregistered(tmp_path):
    prereg, qa, expected = inputs(tmp_path)
    qa.unlink()
    selected = G.select(prereg, qa, allow_unlocked=True)
    assert selected.sha is None and not selected.verified and selected.rehearsal_sha == expected


def test_unlocked_flag_without_file_is_invalid(tmp_path):
    with pytest.raises(G.PreregGateError, match="requires"):
        G.select(None, tmp_path / "qa.md", allow_unlocked=True)


def test_malformed_qa_row_cannot_approve(tmp_path):
    prereg, qa, _ = inputs(tmp_path)
    qa.write_text("| C9-PREREG-v1 | PENDING |\n")
    with pytest.raises(G.PreregGateError, match="no recorded"):
        G.select(prereg, qa)


def run_args(tmp_path, prereg, qa, *, extra=()):
    return ["run", "--rows", str(tmp_path / "unused-rows"), "--out", str(tmp_path / "result"),
            "--prereg", str(prereg), "--qa", str(qa), *extra]


def test_cli_rejects_unregistered_prereg_before_loading_rows(tmp_path, monkeypatch, capsys):
    prereg, qa, _ = inputs(tmp_path)
    qa.unlink()
    monkeypatch.setattr(T, "_execute_training", lambda *a, **kw: pytest.fail("training must not run"))
    assert T.main(run_args(tmp_path, prereg, qa)) == T.USAGE
    assert "no recorded" in capsys.readouterr().err


def test_cli_unlocked_rehearsal_uses_placeholder_sha(tmp_path, monkeypatch, capsys):
    prereg, qa, _ = inputs(tmp_path)
    qa.unlink()
    seen = []

    def execute(args, only_shift, prereg_sha):
        seen.append(prereg_sha)
        return T.OK, {"command": "run", "status": "ok"}

    monkeypatch.setattr(T, "_execute_training", execute)
    assert T.main(run_args(tmp_path, prereg, qa, extra=("--unlocked-prereg",))) == T.OK
    assert seen == [None]
    assert "unlocked_rehearsal" in capsys.readouterr().out


@pytest.mark.parametrize("extra", [
    ("--final-locked-test",),
    ("--final-locked-test", "--locked-form", "--smoke", "--corpus-dir", "TEMP"),
    ("--final-locked-test", "--locked-form"),
])
def test_invalid_final_request_never_runs_or_locks(tmp_path, monkeypatch, extra):
    prereg, qa, _ = inputs(tmp_path)
    extra = tuple(str(tmp_path / "corpus") if x == "TEMP" else x for x in extra)
    monkeypatch.setattr(T, "_execute_training", lambda *a, **kw: pytest.fail("training must not run"))
    assert T.main(run_args(tmp_path, prereg, qa, extra=extra)) == T.USAGE
    assert not list(tmp_path.rglob("*.lock"))


def test_final_run_records_a_single_receipt_before_training(tmp_path, monkeypatch, capsys):
    prereg, qa, expected = inputs(tmp_path)
    corpus = tmp_path / "calibration-root"
    seen = []

    def execute(args, only_shift, prereg_sha):
        receipt = list(corpus.glob("locked-test-*.lock"))
        assert len(receipt) == 1
        seen.append(prereg_sha)
        return T.OK, {"command": "run", "status": "ok"}

    monkeypatch.setattr(T, "_execute_training", execute)
    args = run_args(tmp_path, prereg, qa, extra=("--locked-form", "--final-locked-test", "--corpus-dir", str(corpus)))
    assert T.main(args) == T.OK
    assert seen == [expected]
    output = json.loads(capsys.readouterr().out)
    assert output["locked_test_receipt"] == str(corpus / f"locked-test-{expected}.lock")
    assert T.main(args) == T.USAGE
    assert len(seen) == 1


def test_failed_final_run_still_consumes_the_single_use(tmp_path, monkeypatch):
    prereg, qa, expected = inputs(tmp_path)
    corpus = tmp_path / "calibration-root"
    called = []

    def fail(args, only_shift, prereg_sha):
        called.append(prereg_sha)
        raise T.TrainError("PT-KA-EVAL", "injected failure")

    monkeypatch.setattr(T, "_execute_training", fail)
    args = run_args(tmp_path, prereg, qa, extra=("--locked-form", "--final-locked-test", "--corpus-dir", str(corpus)))
    assert T.main(args) == T.USAGE
    assert T.main(args) == T.USAGE
    assert called == [expected]
    assert (corpus / f"locked-test-{expected}.lock").exists()



def test_final_requires_explicit_owner_signoff_in_the_matching_qa_row(tmp_path, monkeypatch):
    prereg, qa, digest = inputs(tmp_path)
    qa.write_text(f"| C9-PREREG-v1 | {digest} | lock digest only |\n")
    monkeypatch.setattr(T, "_execute_training", lambda *a, **kw: pytest.fail("must not run"))
    args = run_args(tmp_path, prereg, qa, extra=("--locked-form", "--final-locked-test",
                                                  "--corpus-dir", str(tmp_path / "corpus")))
    assert T.main(args) == T.USAGE
    assert not list(tmp_path.rglob("*.lock"))


def test_owner_approval_elsewhere_does_not_authorize_an_unsigned_lock(tmp_path):
    prereg, qa, digest = inputs(tmp_path)
    qa.write_text(f"| C9-PREREG-v1 | {digest} | pending |\n| OTHER | owner approved |\n")
    with pytest.raises(G.PreregGateError, match="owner"):
        G.select(prereg, qa, require_signoff=True)

def test_final_run_forbids_rehearsal_flag(tmp_path, monkeypatch):
    prereg, qa, _ = inputs(tmp_path)
    monkeypatch.setattr(T, "_execute_training", lambda *a, **kw: pytest.fail("must not execute"))
    args = run_args(tmp_path, prereg, qa, extra=("--locked-form", "--final-locked-test", "--unlocked-prereg",
                                                  "--corpus-dir", str(tmp_path / "corpus")))
    assert T.main(args) == T.USAGE
