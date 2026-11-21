"""Conservative, side-effect-free audit of pip invocations in workflow run scalars.

This is not a shell interpreter or a hash-lock verifier. See CODEX-5 in
docs/audits/codex-workflows-1.md. No subprocesses or network accesses occur.
"""
from __future__ import annotations

import re
import shlex
from collections.abc import Iterator

_PYTHON = re.compile(r"(?:.*/)?python(?:3(?:\.\d+)?)?$")
_PIP = re.compile(r"(?:.*/)?pip(?:3(?:\.\d+)?)?$")
_RUN = re.compile(r"^(\s*)(?:- )?run:\s*(.*?)\s*$")
_BLOCK = {"|", "|-", "|+", ">", ">-", ">+"}
_SPLIT = {";", ";;", "&&", "||", "|", "&"}
_ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z_0-9]*=.*")


def run_scalars(source: str) -> Iterator[str]:
    """Yield only step run values, never env, with or non-run YAML text."""
    lines = source.splitlines()
    for index, line in enumerate(lines):
        match = _RUN.match(line)
        if match is None:
            continue
        header = match.group(2)
        if header not in _BLOCK:
            yield header
            continue
        indentation = len(match.group(1)) + (2 if line.lstrip().startswith("- ") else 0)
        block: list[str] = []
        for following in lines[index + 1:]:
            if following.strip() and len(following) - len(following.lstrip()) <= indentation:
                break
            block.append(following)
        yield header + "\n" + "\n".join(block)


def _shell_body(scalar: str) -> str:
    first, _, rest = scalar.partition("\n")
    if first in _BLOCK:
        if first.startswith(">"):
            return " ".join(line.strip() for line in rest.splitlines() if line.strip())
        return rest
    if len(first) >= 2 and first[0] == first[-1] and first[0] in {"'", '"'}:
        return first[1:-1]
    return scalar


def _shell_commands(scalar: str) -> Iterator[list[str]]:
    body = _shell_body(scalar)
    body = re.sub(r"\\[ \t]*\n|\`[ \t]*\n", " ", body)
    for line in body.splitlines():
        lexer = shlex.shlex(line, posix=True, punctuation_chars=";&|")
        lexer.whitespace_split = True
        lexer.commenters = "#"
        try:
            tokens = list(lexer)
        except ValueError as exc:
            raise ValueError("unparseable workflow run command") from exc
        command: list[str] = []
        for token in [*tokens, ";"]:
            if token in _SPLIT:
                if command:
                    yield command
                    command = []
            else:
                command.append(token)


def _pip_args(command: list[str]) -> list[str] | None:
    tokens = command[:]
    while tokens and (_ASSIGNMENT.fullmatch(tokens[0]) or tokens[0] in {"env", "sudo"}):
        tokens.pop(0)
    if len(tokens) >= 4 and _PYTHON.fullmatch(tokens[0]) and tokens[1:4] == ["-m", "pip", "install"]:
        return tokens[4:]
    if len(tokens) >= 2 and _PIP.fullmatch(tokens[0]) and tokens[1] == "install":
        return tokens[2:]
    return None


def unhashed_installs(source: str) -> list[tuple[int, str]]:
    """Return (1-based run ordinal, invocation) without per-command hash/no-index.

    This checks explicit CLI flags only. It does not infer safe dependency
    closure, inspect nested scripts, or trust flags from neighboring commands.
    """
    missing: list[tuple[int, str]] = []
    for run_number, scalar in enumerate(run_scalars(source), 1):
        for command in _shell_commands(scalar):
            args = _pip_args(command)
            if args is None:
                continue
            if "--require-hashes" not in args and "--no-index" not in args:
                missing.append((run_number, " ".join(command)))
    return missing
