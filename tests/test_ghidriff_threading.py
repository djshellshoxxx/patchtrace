"""Regression for Ghidriff's documented threading switch (Windows file-lock incident)."""

from patchtrace.backend import _ghidriff_threading_args


def test_ghidriff_runs_sequentially_by_default():
    assert _ghidriff_threading_args() == ('--no-threaded',)
