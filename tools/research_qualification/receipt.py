"""RQ-00: research receipt contract, strict validator, atomic immutable writer, rerun comparison.

One JSON record per attempt (plan section 6). Stdlib only. Deterministic fields (identity, inputs, result
verdicts, hashes) must agree between reruns on a fresh runner; the `observed` section (timestamps, CPU/RSS,
stage timings) and `runtime` are observational and are excluded from comparison.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

SCHEMA_VERSION = 1
STATUSES = ("PASS", "FAIL", "BLOCKED", "CANCELLED")

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_SLUG = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
# Absolute user/home style paths and Windows drive paths must never appear in a receipt.
_ABS_PATH = re.compile(r"(?<![\w.:/])/(?:home|Users|root|tmp|var|mnt|private)/\S+|(?<![\w])[A-Za-z]:\\\S+")
_SECRET = re.compile(
    r"gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|AKIA[0-9A-Z]{16}"
)
_ISO_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$")

_TOP_KEYS = {
    "schema_version", "experiment_id", "scenario_id", "patchtrace", "tool", "runtime", "fixture",
    "inputs", "result", "observed", "artifacts", "review",
}
_RESULT_KEYS = {
    "status", "exit_code", "stop_reason", "validations_run", "unverified", "blocked_reasons",
    "result_hashes", "counters",
}


class ReceiptError(ValueError):
    """Raised for an invalid receipt or a refused write."""


def utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def sha256_file(path: str | os.PathLike[str], chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while block := f.read(chunk):
            h.update(block)
    return h.hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def options_hash(options: dict[str, Any]) -> str:
    """Stable hash of a JSON-serializable options mapping (sorted keys, no whitespace)."""
    return sha256_text(json.dumps(options, sort_keys=True, separators=(",", ":"), ensure_ascii=True))


def env_fingerprint(allowlist: list[str], env: dict[str, str] | None = None) -> str:
    """Hash of the allowlisted variable NAMES and values; the values themselves are never stored."""
    env = os.environ if env is None else env
    items = sorted((k, env[k]) for k in allowlist if k in env)
    return options_hash({"env": items})


def runtime_identity() -> dict[str, str]:
    return {
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
        "system": platform.system(),
        "machine": platform.machine(),
        "release": platform.release(),
    }


def build_receipt(
    *,
    experiment_id: str,
    scenario_id: str,
    tool_name: str,
    status: str,
    exit_code: int | None,
    stop_reason: str,
    patchtrace_sha: str | None = None,
    patchtrace_ref: str | None = None,
    tool_version: str | None = None,
    upstream_url: str | None = None,
    upstream_ref: str | None = None,
    executable_sha256: str | None = None,
    fixture_source: str = "synthetic",
    fixture_license: str = "n/a",
    publication_permitted: bool = True,
    older_sha256: str | None = None,
    newer_sha256: str | None = None,
    options: dict[str, Any] | None = None,
    network_policy: str = "none",
    env_fp: str | None = None,
    validations_run: list[str] | None = None,
    unverified: list[str] | None = None,
    blocked_reasons: list[str] | None = None,
    result_hashes: dict[str, str] | None = None,
    counters: dict[str, int] | None = None,
    observed: dict[str, Any] | None = None,
    artifacts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Assemble a receipt dict. Call `validate_receipt` before writing; `write_receipt` does so itself."""
    return {
        "schema_version": SCHEMA_VERSION,
        "experiment_id": experiment_id,
        "scenario_id": scenario_id,
        "patchtrace": {"repo": "djshellshoxxx/patchtrace", "ref": patchtrace_ref, "sha": patchtrace_sha},
        "tool": {
            "name": tool_name,
            "version": tool_version,
            "upstream_url": upstream_url,
            "upstream_ref": upstream_ref,
            "executable_sha256": executable_sha256,
        },
        "runtime": runtime_identity(),
        "fixture": {
            "source": fixture_source,
            "license": fixture_license,
            "publication_permitted": publication_permitted,
        },
        "inputs": {
            "older_sha256": older_sha256,
            "newer_sha256": newer_sha256,
            "options_sha256": options_hash(options or {}),
            "network_policy": network_policy,
            "env_fingerprint": env_fp,
        },
        "result": {
            "status": status,
            "exit_code": exit_code,
            "stop_reason": stop_reason,
            "validations_run": list(validations_run or []),
            "unverified": list(unverified or []),
            "blocked_reasons": list(blocked_reasons or []),
            "result_hashes": dict(result_hashes or {}),
            "counters": dict(counters or {}),
        },
        "observed": observed or {},
        "artifacts": list(artifacts or []),
        "review": None,
    }


def _walk_strings(node: Any, path: str = ""):
    if isinstance(node, str):
        yield path, node
    elif isinstance(node, dict):
        for k, v in node.items():
            yield from _walk_strings(k, f"{path}.<key>")
            yield from _walk_strings(v, f"{path}.{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _walk_strings(v, f"{path}[{i}]")


def _check_hash(errors: list[str], where: str, value: Any, *, nullable: bool, unverified: list[str]) -> None:
    if value is None:
        if not nullable and where not in unverified:
            errors.append(f"{where}: null requires an entry '{where}' in result.unverified")
        return
    if not isinstance(value, str) or not _HEX64.match(value):
        errors.append(f"{where}: must be a lowercase 64-char hex SHA-256")


def validate_receipt(r: Any) -> list[str]:
    """Return a list of problems; an empty list means the receipt is structurally valid."""
    errors: list[str] = []
    if not isinstance(r, dict):
        return ["receipt must be a JSON object"]
    extra = set(r) - _TOP_KEYS
    missing = _TOP_KEYS - set(r)
    if extra:
        errors.append(f"unknown top-level keys: {sorted(extra)}")
    if missing:
        errors.append(f"missing top-level keys: {sorted(missing)}")
        return errors
    if r["schema_version"] != SCHEMA_VERSION:
        errors.append(f"schema_version must be {SCHEMA_VERSION}")
    for k in ("experiment_id", "scenario_id"):
        if not isinstance(r[k], str) or not _SLUG.match(r[k]):
            errors.append(f"{k}: must match {_SLUG.pattern}")
    res = r["result"]
    if not isinstance(res, dict) or set(res) != _RESULT_KEYS:
        errors.append(f"result: keys must be exactly {sorted(_RESULT_KEYS)}")
        return errors
    status = res["status"]
    if status not in STATUSES:
        errors.append(f"result.status must be one of {STATUSES}")
    unverified = res["unverified"] if isinstance(res["unverified"], list) else []
    for k in ("validations_run", "unverified", "blocked_reasons"):
        if not isinstance(res[k], list) or not all(isinstance(x, str) and x for x in res[k]):
            errors.append(f"result.{k}: must be a list of non-empty strings")
    if status == "PASS":
        if res["exit_code"] != 0:
            errors.append("PASS requires result.exit_code == 0")
        if not res["validations_run"]:
            errors.append("PASS requires at least one entry in result.validations_run")
        if res["blocked_reasons"]:
            errors.append("PASS must not carry blocked_reasons")
    if status == "BLOCKED" and not res["blocked_reasons"]:
        errors.append("BLOCKED requires blocked_reasons naming the exact missing prerequisites")
    if status in ("FAIL", "CANCELLED", "BLOCKED") and not (isinstance(res["stop_reason"], str) and res["stop_reason"]):
        errors.append(f"{status} requires a non-empty stop_reason")
    if not isinstance(res["result_hashes"], dict):
        errors.append("result.result_hashes must be an object")
    else:
        for name, h in res["result_hashes"].items():
            _check_hash(errors, f"result.result_hashes.{name}", h, nullable=False, unverified=unverified)
    if not isinstance(res["counters"], dict) or not all(
        isinstance(v, int) and not isinstance(v, bool) for v in res["counters"].values()
    ):
        errors.append("result.counters must map names to integers")
    tool = r["tool"]
    if not isinstance(tool, dict) or not isinstance(tool.get("name"), str) or not tool.get("name"):
        errors.append("tool.name is required")
    else:
        _check_hash(errors, "tool.executable_sha256", tool.get("executable_sha256"), nullable=False, unverified=unverified)
    inputs = r["inputs"]
    if not isinstance(inputs, dict):
        errors.append("inputs must be an object")
    else:
        _check_hash(errors, "inputs.options_sha256", inputs.get("options_sha256"), nullable=False, unverified=unverified)
        for k in ("older_sha256", "newer_sha256"):
            _check_hash(errors, f"inputs.{k}", inputs.get(k), nullable=True, unverified=unverified)
    fx = r["fixture"]
    if not isinstance(fx, dict) or not isinstance(fx.get("publication_permitted"), bool):
        errors.append("fixture.publication_permitted must be a boolean")
    obs = r["observed"]
    if not isinstance(obs, dict):
        errors.append("observed must be an object")
    else:
        for k in ("started_utc", "ended_utc"):
            if k in obs and not (isinstance(obs[k], str) and _ISO_UTC.match(obs[k])):
                errors.append(f"observed.{k}: must be an ISO-8601 UTC timestamp ending in Z")
        dur = obs.get("duration_s")
        if dur is not None and (not isinstance(dur, (int, float)) or isinstance(dur, bool) or dur < 0):
            errors.append("observed.duration_s must be a non-negative number")
        if "started_utc" in obs and "ended_utc" in obs and isinstance(obs["started_utc"], str):
            if isinstance(obs["ended_utc"], str) and obs["ended_utc"] < obs["started_utc"]:
                errors.append("observed.ended_utc precedes started_utc")
    arts = r["artifacts"]
    if not isinstance(arts, list):
        errors.append("artifacts must be a list")
    else:
        for i, a in enumerate(arts):
            if not isinstance(a, dict) or set(a) != {"path", "sha256", "bytes"}:
                errors.append(f"artifacts[{i}]: keys must be path, sha256, bytes")
                continue
            p = a["path"]
            pp = PurePosixPath(p) if isinstance(p, str) else None
            if pp is None or pp.is_absolute() or ".." in pp.parts or "\\" in p or not p:
                errors.append(f"artifacts[{i}].path: must be a relative POSIX path without '..'")
            _check_hash(errors, f"artifacts[{i}].sha256", a["sha256"], nullable=False, unverified=[])
            if not isinstance(a["bytes"], int) or isinstance(a["bytes"], bool) or a["bytes"] < 0:
                errors.append(f"artifacts[{i}].bytes must be a non-negative integer")
    rv = r["review"]
    if rv is not None and (
        not isinstance(rv, dict) or not rv.get("reviewer") or not rv.get("decision") or not rv.get("accepted_commit")
    ):
        errors.append("review, when present, needs reviewer, decision and accepted_commit")
    for where, s in _walk_strings(r):
        if _ABS_PATH.search(s):
            errors.append(f"{where}: contains an absolute or home path")
        if _SECRET.search(s):
            errors.append(f"{where}: contains a secret-like token")
    return errors


def deterministic_view(r: dict[str, Any]) -> dict[str, Any]:
    """The fields that must agree between reruns. Excludes `observed`, `runtime`, `review` and stop_reason text."""
    res = r["result"]
    return {
        "experiment_id": r["experiment_id"],
        "scenario_id": r["scenario_id"],
        "tool": {k: r["tool"].get(k) for k in ("name", "version", "upstream_url", "upstream_ref", "executable_sha256")},
        "inputs": r["inputs"],
        "result": {
            "status": res["status"],
            "exit_code": res["exit_code"],
            "validations_run": sorted(res["validations_run"]),
            "unverified": sorted(res["unverified"]),
            "blocked_reasons": sorted(res["blocked_reasons"]),
            "result_hashes": res["result_hashes"],
            "counters": res["counters"],
        },
        "artifacts": sorted(({"path": a["path"], "sha256": a["sha256"]} for a in r["artifacts"]), key=lambda a: a["path"]),
    }


def deterministic_digest(r: dict[str, Any]) -> str:
    return options_hash(deterministic_view(r))


def compare_receipts(a: dict[str, Any], b: dict[str, Any]) -> list[str]:
    """Names of deterministic fields that differ between two receipts (empty means they agree)."""
    va, vb = deterministic_view(a), deterministic_view(b)
    diffs: list[str] = []

    def walk(x: Any, y: Any, path: str) -> None:
        if isinstance(x, dict) and isinstance(y, dict):
            for k in sorted(set(x) | set(y)):
                walk(x.get(k), y.get(k), f"{path}.{k}" if path else k)
        elif x != y:
            diffs.append(path)

    walk(va, vb, "")
    return diffs


def receipt_key(r: dict[str, Any]) -> str:
    """Key over source + tool + experiment + input hashes (plan section 6), shortened for filenames."""
    basis = {
        "sha": r["patchtrace"].get("sha"),
        "tool": r["tool"]["name"],
        "experiment": r["experiment_id"],
        "scenario": r["scenario_id"],
        "inputs": r["inputs"],
    }
    return options_hash(basis)[:16]


def receipt_filename(r: dict[str, Any]) -> str:
    started = (r["observed"].get("started_utc") or utc_now()).replace(":", "").replace("-", "").replace(".", "")
    return f"{r['experiment_id']}-{receipt_key(r)}-{started}.json"


def write_receipt(r: dict[str, Any], out_dir: str | os.PathLike[str]) -> Path:
    """Validate, then write atomically. Never overwrites an existing receipt (prior results are immutable)."""
    problems = validate_receipt(r)
    if problems:
        raise ReceiptError("invalid receipt: " + "; ".join(problems))
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    target = out / receipt_filename(r)
    if target.exists():
        raise ReceiptError(f"refusing to overwrite existing receipt {target.name}")
    data = json.dumps(r, indent=2, sort_keys=True) + "\n"
    fd, tmp = tempfile.mkstemp(prefix=".receipt-", suffix=".tmp", dir=out)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.link(tmp, target)  # fails if the target appeared meanwhile, unlike os.replace
    except FileExistsError as e:
        raise ReceiptError(f"refusing to overwrite existing receipt {target.name}") from e
    finally:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
    return target


def load_receipt(path: str | os.PathLike[str]) -> dict[str, Any]:
    with open(path, encoding="utf-8") as f:
        data = json.load(f, parse_constant=_reject_constant)
    problems = validate_receipt(data)
    if problems:
        raise ReceiptError(f"{path}: " + "; ".join(problems))
    return data


def _reject_constant(name: str) -> Any:
    raise ReceiptError(f"strict JSON only: {name} is not allowed")


def git_head(repo: str | os.PathLike[str] = ".") -> str | None:
    """Current commit SHA read without invoking git (None when not a checkout)."""
    head = Path(repo) / ".git" / "HEAD"
    try:
        text = head.read_text(encoding="utf-8").strip()
        if text.startswith("ref: "):
            ref = Path(repo) / ".git" / text[5:]
            if ref.exists():
                return ref.read_text(encoding="utf-8").strip()
            packed = Path(repo) / ".git" / "packed-refs"
            if packed.exists():
                for line in packed.read_text(encoding="utf-8").splitlines():
                    if line.endswith(" " + text[5:]):
                        return line.split()[0]
            return None
        return text
    except OSError:
        return None


if __name__ == "__main__":  # pragma: no cover
    sys.exit("use: python -m tools.research_qualification receipt --help")
