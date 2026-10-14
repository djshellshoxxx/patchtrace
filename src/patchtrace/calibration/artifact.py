"""`patchtrace-calibration-model/1` artifact: strict model, digest and a loader that never raises (spec §10).

No pickle/joblib/eval/dynamic import; the artifact is data only. Any problem degrades to "no model"
(ordinal display), never to a looser model. Only package-bundled files are loaded, except an explicit
developer override environment variable which forces `experimental` status.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import math
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .features import FEATURE_SCHEMA, PROFILES, SPEC_BY_NAME, feature_names

CONTRACT = 'patchtrace-calibration-model/1'
MAX_BYTES = 512 * 1024
MAX_FEATURES = 64
MAX_KNOTS = 5000
DEV_OVERRIDE_ENV = 'PATCHTRACE_CALIBRATION_DEV_ARTIFACT'
BUNDLED_DIR = Path(__file__).with_name('models')
Sha256 = Annotated[str, Field(pattern=r'^[0-9a-f]{64}$')]
GateStatus = Literal['pass', 'fail', 'insufficient-data']


class ArtifactError(ValueError):
    pass


def _no_duplicates(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f'duplicate key {key!r}')
        out[key] = value
    return out


def _reject_constant(name):
    raise ValueError(f'non-finite number {name}')


def strict_json(data: bytes | str):
    """UTF-8 JSON with duplicate keys and NaN/Infinity rejected (same discipline as acquisition.winbindex)."""
    text = data.decode('utf-8') if isinstance(data, bytes) else data
    return json.loads(text, object_pairs_hook=_no_duplicates, parse_constant=_reject_constant)


def canonical_json(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                      allow_nan=False).encode('utf-8')


def digest(document: dict, key: str = 'digest_sha256') -> str:
    return hashlib.sha256(canonical_json({k: v for k, v in document.items() if k != key})).hexdigest()


class _Strict(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True)


class ArtifactFeature(_Strict):
    name: str
    kind: Literal['num', 'cat', 'flag']
    median: float
    mean: float
    sd: float = Field(gt=0)
    coef: float


class Platt(_Strict):
    type: Literal['platt']
    a: float
    b: float


class Isotonic(_Strict):
    type: Literal['isotonic']
    knots: tuple[tuple[float, float], ...] = Field(min_length=1, max_length=MAX_KNOTS)


class Band(_Strict):
    lo: float = Field(ge=0, le=1)
    hi: float = Field(ge=0, le=1)
    label: str = Field(min_length=1, max_length=80)


class PolicySpec(_Strict):
    tau: float | None = Field(gt=0, lt=1)
    tau_low: float | None = Field(gt=0, lt=1)
    display: Literal['none', 'band', 'number']
    bands: tuple[Band, ...] = ()


class OodSpec(_Strict):
    names: tuple[str, ...]
    mu: tuple[float, ...]
    chol: tuple[tuple[float, ...], ...]
    d2_soft: float = Field(ge=0)
    d2_cut: float = Field(ge=0)
    ranges: dict[str, tuple[float, float]]
    cat_levels: dict[str, tuple[str, ...]]
    engine_versions: tuple[str, ...]


class Domain(_Strict):
    engines: dict[str, tuple[str, ...]]
    toolchains: tuple[str, ...]
    arch: tuple[str, ...]
    corpus_id: str
    n_pairs: int = Field(ge=0)
    n_lineages: int = Field(ge=0)
    prevalence: float = Field(ge=0, le=1)
    known_blind_spots: tuple[str, ...]


class Evidence(_Strict):
    preregistration_sha256: Sha256 | None
    report_sha256: Sha256 | None
    corpus_manifest_sha256: Sha256 | None
    label_set_sha256: Sha256 | None
    tool_git: str
    gates: dict[Literal['G0', 'G1', 'G2', 'G3'], GateStatus] = {}


class CalibrationArtifact(_Strict):
    contract: Literal['patchtrace-calibration-model/1']
    model_id: str = Field(min_length=1, max_length=120)
    status: Literal['experimental', 'bands-ok', 'numeric-ok']
    target: Literal['A']
    feature_schema: str
    profile: str
    features: tuple[ArtifactFeature, ...] = Field(min_length=1, max_length=MAX_FEATURES)
    intercept: float
    base: Literal['l2-logistic']
    C: float = Field(gt=0)
    calibrator: Platt | Isotonic = Field(discriminator='type')
    policy: PolicySpec
    ood: OodSpec
    calibration_domain: Domain
    evidence: Evidence
    created: str
    expires: str
    digest_sha256: Sha256


@dataclass(frozen=True)
class LoadResult:
    artifact: CalibrationArtifact | None
    reason: str
    developer_override: bool = False


def _finite(value) -> bool:
    if isinstance(value, dict):
        return all(_finite(v) for v in value.values())
    if isinstance(value, list | tuple):
        return all(_finite(v) for v in value)
    return not isinstance(value, float) or math.isfinite(value)


def _semantic(a: CalibrationArtifact, today: dt.date) -> None:
    if a.feature_schema != FEATURE_SCHEMA:
        raise ArtifactError(f'feature schema {a.feature_schema!r} is not the installed {FEATURE_SCHEMA}')
    if a.profile not in PROFILES:
        raise ArtifactError('unknown profile')
    names = tuple(f.name for f in a.features)
    if len(set(names)) != len(names) or not set(names) <= set(feature_names(a.profile)):
        raise ArtifactError('features are duplicated or outside the profile schema')
    if any(SPEC_BY_NAME[f.name].kind != f.kind for f in a.features):
        raise ArtifactError('feature kind differs from the installed schema')
    if isinstance(a.calibrator, Isotonic):
        knots = a.calibrator.knots
        if any(not 0 <= p <= 1 for _, p in knots):
            raise ArtifactError('isotonic knot outside [0,1]')
        if any(k2[0] < k1[0] or k2[1] < k1[1] for k1, k2 in zip(knots, knots[1:], strict=False)):
            raise ArtifactError('isotonic knots are not monotone')
    elif a.calibrator.a <= 0:
        raise ArtifactError('Platt slope must be positive (monotone calibration)')
    pol = a.policy
    if pol.tau is not None and pol.tau_low is not None and pol.tau_low >= pol.tau:
        raise ArtifactError('tau_low must be below tau')
    o = a.ood
    d = len(o.names)
    if len(o.mu) != d or len(o.chol) != d or any(len(row) != i + 1 for i, row in enumerate(o.chol)):
        raise ArtifactError('OOD statistics have inconsistent dimensions')
    if any(o.chol[i][i] <= 0 for i in range(d)) or not set(o.names) <= set(names):
        raise ArtifactError('OOD Cholesky factor is not positive definite or names unknown')
    if not set(o.ranges) <= set(names) or any(lo > hi for lo, hi in o.ranges.values()):
        raise ArtifactError('OOD range invalid')
    created, expires = dt.date.fromisoformat(a.created), dt.date.fromisoformat(a.expires)
    if expires < created or (expires - created).days > 366:
        raise ArtifactError('expiry must be within 12 months of creation')
    if today > expires:
        raise ArtifactError('model expired')
    ev = a.evidence
    gates = ev.gates
    if a.status == 'numeric-ok' and not (ev.report_sha256 and ev.preregistration_sha256
                                         and gates.get('G0') == gates.get('G3') == 'pass'):
        raise ArtifactError('numeric-ok requires report, preregistration and passing G0/G3 evidence')
    if a.status == 'bands-ok' and not (ev.report_sha256 and gates.get('G0') == gates.get('G2') == 'pass'):
        raise ArtifactError('bands-ok requires a report and passing G0/G2 evidence')
    allowed = {'experimental': {'none'}, 'bands-ok': {'none', 'band'}, 'numeric-ok': {'none', 'band', 'number'}}
    if pol.display not in allowed[a.status]:
        raise ArtifactError('policy.display exceeds the artifact status')


def parse_artifact(data: bytes, *, today: dt.date | None = None) -> CalibrationArtifact:
    """Strict parse; raises ArtifactError on any problem. Prefer `load_artifact` in the app."""
    if len(data) > MAX_BYTES:
        raise ArtifactError('artifact exceeds 512 KiB')
    try:
        document = strict_json(data)
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise ArtifactError(f'not strict JSON: {exc}') from None
    if not isinstance(document, dict) or not _finite(document):
        raise ArtifactError('artifact must be a JSON object of finite numbers')
    try:
        artifact = CalibrationArtifact.model_validate_json(data)
    except ValidationError as exc:
        raise ArtifactError(f'schema: {exc.error_count()} validation error(s)') from None
    if digest(document) != artifact.digest_sha256:
        raise ArtifactError('digest mismatch')
    try:
        _semantic(artifact, today or dt.date.today())
    except ValueError as exc:
        raise ArtifactError(str(exc)) from None
    return artifact


def load_artifact(data: bytes, *, today: dt.date | None = None) -> LoadResult:
    try:
        return LoadResult(parse_artifact(data, today=today), 'ok')
    except Exception as exc:  # noqa: BLE001 - any failure means "no model", never a crash
        return LoadResult(None, f'no-model: {exc}')


def load_bundled(directory: Path | None = None, *, today: dt.date | None = None,
                 environ: dict[str, str] | None = None) -> dict[str, LoadResult]:
    """Profile -> loaded artifact. Two artifacts for one profile cancel each other (ambiguous)."""
    env = os.environ if environ is None else environ
    out: dict[str, LoadResult] = {}
    seen: dict[str, int] = {}
    override = env.get(DEV_OVERRIDE_ENV)
    try:
        if override:
            paths = [Path(override)]
        else:
            folder = directory or BUNDLED_DIR
            paths = sorted(folder.glob('*.json')) if folder.is_dir() else []
        for path in paths:
            with open(path, 'rb') as handle:
                result = load_artifact(handle.read(MAX_BYTES + 1), today=today)
            if result.artifact is None:
                continue
            if override:
                forced = result.artifact.model_copy(update={
                    'status': 'experimental',
                    'policy': result.artifact.policy.model_copy(update={'display': 'none'})})
                result = LoadResult(forced, 'developer override: experimental only', True)
            profile = result.artifact.profile
            seen[profile] = seen.get(profile, 0) + 1
            out[profile] = result
    except OSError:
        return {}
    return {p: r for p, r in out.items() if seen[p] == 1}
