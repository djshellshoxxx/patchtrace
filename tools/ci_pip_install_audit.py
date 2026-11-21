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


def _substitution_end(body: str, start: int) -> int:
    """Keep unsupported substitution opaque through its closing delimiter."""
    backtick = body[start] == "`"
    index = start + (1 if backtick else 2)
    depth = 1
    quote: str | None = None
    while index < len(body):
        char = body[index]
        if char == "\\" and quote != "'":
            index += 2
            continue
        if backtick:
            if char == "`":
                return index + 1
        elif quote is not None:
            if char == quote:
                quote = None
        elif char in {"'", '"'}:
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index + 1
        index += 1
    # An unfinished substitution consumes the rest for matching purposes;
    # installer text there must still cause an explicit unsupported error.
    return len(body)


def _command_segments(body: str) -> list[tuple[str, bool]]:
    """Keep quote/escape context until actual operators and comments are known.

    This establishes lexical boundaries only. It does not evaluate shell syntax;
    executable substitution, including ambiguous backticks, remains unsupported.
    """
    segments: list[tuple[str, bool]] = []
    current: list[str] = []
    quote: str | None = None
    word_start = True
    substitution = False
    index = 0

    def finish() -> str:
        nonlocal substitution
        segment = "".join(current).strip()
        if segment:
            segments.append((segment, substitution))
        current.clear()
        substitution = False
        return segment

    while index < len(body):
        char = body[index]
        if char == "\\" and quote != "'":
            if index + 1 >= len(body):
                raise WorkflowAuditError("trailing shell escape")
            following = body[index + 1]
            if following == "\n":
                index += 2
            elif body.startswith("\r\n", index + 1):
                index += 3
            else:
                current.extend((char, following))
                word_start = False
                index += 2
            continue
        command_substitution = quote != "'" and (char == "`" or body.startswith("$(", index))
        process_substitution = quote is None and body.startswith(("<(", ">("), index)
        if command_substitution or process_substitution:
            end = _substitution_end(body, index)
            current.append(body[index:end])
            substitution = True
            word_start = False
            index = end
            continue
        if quote is not None:
            current.append(char)
            if char == quote:
                quote = None
            index += 1
            continue
        if char in {"'", '"'}:
            quote = char
            current.append(char)
            word_start = False
            index += 1
            continue
        if char == "#" and word_start:
            # Comment text cannot introduce operators, quotes or substitution.
            end = body.find("\n", index)
            index = len(body) if end < 0 else end
            continue
        if char in ";&|":
            end = index + 1
            while end < len(body) and body[end] in ";&|":
                end += 1
            if body[index:end] not in _SPLIT:
                raise WorkflowAuditError("unsupported shell operator")
            finish()
            word_start = True
            index = end
            continue
        if char in "\r\n":
            header = finish()
            index += 2 if body.startswith("\r\n", index) else 1
            word_start = True
            if match := _HEREDOC.search(header):
                # Only a simple literal delimiter is understood. Embedded
                # language source is never interpreted as shell commands.
                terminated = False
                while index < len(body):
                    end = body.find("\n", index)
                    if end < 0:
                        end = len(body)
                    line = body[index:end]
                    index = min(end + 1, len(body))
                    if line.strip() == match[2]:
                        terminated = True
                        break
                    if _POSSIBLE_INSTALL.search(line):
                        raise WorkflowAuditError("installer text inside an unsupported embedded script")
                if not terminated:
                    raise WorkflowAuditError("unterminated embedded script")
            continue
        current.append(char)
        word_start = char.isspace()
        index += 1
    if quote is not None:
        raise WorkflowAuditError("unparseable workflow run command")
    finish()
    return segments


def _shell_commands(body: str) -> Iterator[list[str]]:
    commands: list[list[str]] = []
    for segment, substitution in _command_segments(body):
        # Operators/comments were handled before quotes and escapes are lost.
        lexer = shlex.shlex(segment, posix=True, punctuation_chars="<>()")
        lexer.whitespace_split = True
        lexer.commenters = ""
        try:
            command = list(lexer)
        except ValueError as exc:
            raise WorkflowAuditError("unparseable workflow run command") from exc
        continued = segment.replace("\\\r\n", "").replace("\\\n", "")
        if substitution and (_POSSIBLE_INSTALL.search(" ".join(command))
                             or _POSSIBLE_INSTALL.search(continued)):
            raise WorkflowAuditError("installer text in unsupported command substitution")
        commands.append(command)
    yield from commands


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
