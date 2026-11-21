"""Source-only CODEX-5 command audit; see docs/specs/ci-pip-command-audit.md.

PyYAML is an existing development dependency. Missing it is an import failure,
never a reason to skip the audit. This module executes no shell or package code.
"""
from __future__ import annotations

import re
import shlex
from collections.abc import Iterator
from dataclasses import dataclass

import yaml

_PYTHON = re.compile(r"(?:.*/)?python(?:3(?:\.\d+)?)?(?:\.exe)?$")
_PIP = re.compile(r"(?:.*/)?pip(?:3(?:\.\d+)?)?(?:\.exe)?$")
_POSSIBLE_INSTALL = re.compile(r"\bpip(?:3(?:\.\d+)?)?(?:\.exe)?\b[^\n]*\binstall\b")
_SPLIT = {";", ";;", "&&", "||", "|", "&"}
_ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z_0-9]*=.*")
_PREFIX = {"if", "elif", "while", "until", "then", "else", "do", "!", "env", "sudo"}
_OUTPUT = {"echo", "printf", "Write-Output", "Write-Host"}
_HEREDOC = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z_0-9]*)\1\s*(?:#.*)?$")
_FLAGS = {"--require-hashes", "--no-index"}
_VALUE_OPTIONS = {
    "-r", "--requirement", "-c", "--constraint", "-e", "--editable", "-t", "--target",
    "--platform", "--python-version", "--implementation", "--abi", "--prefix", "--root",
    "--src", "-C", "--config-settings", "-i", "--index-url", "--extra-index-url",
    "-f", "--find-links", "--only-binary", "--no-binary", "--trusted-host", "--report",
}
_BOOLEAN_OPTIONS = {
    *_FLAGS, "--no-require-hashes", "--no-deps", "--no-build-isolation", "--no-cache-dir",
    "--upgrade", "-U", "--user", "--pre", "--force-reinstall", "--ignore-installed",
    "--no-compile", "--compile", "--disable-pip-version-check", "--no-input", "-q", "-v",
}


class WorkflowAuditError(ValueError):
    """Invalid or unsupported source; never an expected missing-hash failure."""


class _UniqueKeyLoader(yaml.SafeLoader):
    def construct_mapping(self, node, deep=False):
        self.flatten_mapping(node)
        mapping = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            try:
                duplicate = key in mapping
            except TypeError as exc:
                raise WorkflowAuditError("unhashable YAML mapping key") from exc
            if duplicate:
                raise WorkflowAuditError(f"duplicate YAML mapping key: {key!r}")
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


def run_scalars(source: str) -> Iterator[str]:
    """Yield decoded jobs.*.steps[].run strings, excluding all YAML metadata."""
    try:
        workflow = yaml.load(source, Loader=_UniqueKeyLoader)
    except yaml.YAMLError as exc:
        raise WorkflowAuditError("invalid workflow YAML") from exc
    if not isinstance(workflow, dict) or not isinstance(workflow.get("jobs"), dict):
        raise WorkflowAuditError("workflow must contain a jobs mapping")
    for job_name, job in workflow["jobs"].items():
        if not isinstance(job, dict):
            raise WorkflowAuditError(f"job {job_name!r} must be a mapping")
        if "steps" not in job and isinstance(job.get("uses"), str):
            continue
        if not isinstance(job.get("steps"), list):
            raise WorkflowAuditError(f"job {job_name!r} must contain a steps sequence")
        for step_number, step in enumerate(job["steps"], 1):
            if not isinstance(step, dict):
                raise WorkflowAuditError(f"job {job_name!r} step {step_number} must be a mapping")
            if "run" in step:
                if not isinstance(step["run"], str) or not step["run"].strip():
                    raise WorkflowAuditError(f"job {job_name!r} step {step_number} run must be a nonempty string")
                yield step["run"]


def _shell_commands(body: str) -> Iterator[list[str]]:
    body = re.sub(r"(?:\\|`)\r?\n", " ", body)
    heredoc_end: str | None = None
    for line in body.splitlines():
        if heredoc_end is not None:
            if line.strip() == heredoc_end:
                heredoc_end = None
            elif _POSSIBLE_INSTALL.search(line):
                raise WorkflowAuditError("installer text inside an unsupported embedded script")
            continue
        if _POSSIBLE_INSTALL.search(line) and ("$(" in line or "`" in line):
            raise WorkflowAuditError("installer text in unsupported command substitution")
        lexer = shlex.shlex(line, posix=True, punctuation_chars=";&|<>()")
        lexer.whitespace_split = True
        lexer.commenters = "#"
        try:
            tokens = list(lexer)
        except ValueError as exc:
            raise WorkflowAuditError("unparseable workflow run command") from exc
        if (match := _HEREDOC.search(line)) and any(token in {"<<", "<<-"} for token in tokens):
            heredoc_end = match[2]
        command: list[str] = []
        for token in [*tokens, ";"]:
            if token in _SPLIT:
                if command:
                    yield command
                    command = []
            else:
                command.append(token)
    if heredoc_end is not None:
        raise WorkflowAuditError("unterminated embedded script")


def _pip_args(command: list[str]) -> list[str] | None:
    tokens = command[:]
    while tokens and (_ASSIGNMENT.fullmatch(tokens[0]) or tokens[0] in _PREFIX):
        tokens.pop(0)
    if not tokens or tokens[0] in _OUTPUT:
        return None
    possible = _POSSIBLE_INSTALL.search(" ".join(tokens))
    if possible and any(token and set(token) <= set(";&|<>()") for token in tokens):
        raise WorkflowAuditError("unsupported grouping, redirection or separator around installer")
    if len(tokens) >= 4 and _PYTHON.fullmatch(tokens[0]) and tokens[1:4] == ["-m", "pip", "install"]:
        return tokens[4:]
    if len(tokens) >= 2 and _PIP.fullmatch(tokens[0]) and tokens[1] == "install":
        return tokens[2:]
    if possible:
        raise WorkflowAuditError("unsupported or indirect pip install invocation")
    return None


def _has_boundary(arguments: tuple[str, ...]) -> bool:
    if not _FLAGS.intersection(arguments):
        return False
    flags: set[str] = set()
    skip_value = False
    for token in arguments:
        if skip_value:
            skip_value = False
        elif token == "--":
            break
        elif token in _VALUE_OPTIONS:
            skip_value = True
        elif token in _BOOLEAN_OPTIONS:
            flags.add(token)
        elif token.startswith("-") and "=" not in token:
            raise WorkflowAuditError(f"unknown option arity before an install boundary: {token}")
    return "--no-index" in flags or ("--require-hashes" in flags and "--no-require-hashes" not in flags)


@dataclass(frozen=True)
class PipInstall:
    run_number: int
    command: str
    arguments: tuple[str, ...]

    @property
    def has_boundary(self) -> bool:
        """Only explicit command flags; never evidence of artifact hash closure."""
        return _has_boundary(self.arguments)


def pip_installs(source: str) -> list[PipInstall]:
    """Return recognized installs, raising on invalid/unsupported matching input."""
    installs: list[PipInstall] = []
    for run_number, scalar in enumerate(run_scalars(source), 1):
        for command in _shell_commands(scalar):
            args = _pip_args(command)
            if args is not None:
                installs.append(PipInstall(run_number, " ".join(command), tuple(args)))
    return installs


def unhashed_installs(source: str) -> list[tuple[int, str]]:
    """Preserve the donor API; parsing errors are not missing-hash findings."""
    return [(item.run_number, item.command) for item in pip_installs(source) if not item.has_boundary]
