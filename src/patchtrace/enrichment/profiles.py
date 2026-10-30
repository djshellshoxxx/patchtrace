"""Analysis profiles `profile/1` (SPEC-07 §12). Pure: no Qt, no network, no project access.

A profile is shared, nonsecret analysis configuration stored as one JSON file per
profile in the desktop settings directory. It deliberately has no field that could
hold a credential (API keys stay session-only, §8), and loading is strict so a
hand-edited file can never smuggle in coerced values or unknown detectors.
"""
from __future__ import annotations

import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from . import identity
from .contracts import DEFAULT_WEIGHTS, DETECTOR_IDS, UINT32_MAX, DetectorId, RankingConfig

PROFILE_CONTRACT = 'profile/1'
DEFAULT_NAME = 'default'
MAX_FILE_BYTES = 64 * 1024
CVE_PROVIDERS: tuple[str, ...] = ('nvd', 'msrc')
# Names become file stems on every platform, so they are limited to characters that are
# portable, never path separators, and never end in a dot or space (Windows strips those).
NAME_PATTERN = r'^[A-Za-z0-9](?:[A-Za-z0-9 _.-]{0,62}[A-Za-z0-9_-])?$'
_WINDOWS_RESERVED = {'con', 'prn', 'aux', 'nul', *(f'com{i}' for i in range(1, 10)),
                     *(f'lpt{i}' for i in range(1, 10))}
FeatureId = Annotated[int, Field(ge=0, le=UINT32_MAX)]


class ProfileError(Exception):
    """User-safe profile failure (validation, storage, lookup)."""


class AnalysisProfile(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True)
    contract: Literal['profile/1'] = PROFILE_CONTRACT
    name: str = Field(min_length=1, max_length=64, pattern=NAME_PATTERN)
    weights: dict[DetectorId, int] = Field(default_factory=lambda: dict(DEFAULT_WEIGHTS))
    enabled: tuple[DetectorId, ...] = DETECTOR_IDS
    feature_ids: tuple[FeatureId, ...] | None = Field(default=None, max_length=256)
    symbol_policy: Literal['disabled', 'local', 'online'] = 'disabled'
    cve_providers: tuple[Literal['nvd', 'msrc'], ...] = CVE_PROVIDERS
    snapshot_max_age_days: int = Field(default=30, ge=1, le=3650)
    cache_dir: str | None = Field(default=None, min_length=1, max_length=1024)
    cache_budget_gib: int = Field(default=20, ge=1, le=1024)

    @model_validator(mode='after')
    def _coherent(self):
        if self.name.split('.')[0].lower() in _WINDOWS_RESERVED:
            raise ValueError('profile name is reserved on Windows')
        # Reuse the ranking validator so weights obey exactly the same rules as RankingConfig.
        RankingConfig(weights=dict(self.weights), enabled=self.enabled)
        if not self.enabled:
            raise ValueError('at least one detector must be enabled')
        if self.feature_ids is not None and len(set(self.feature_ids)) != len(self.feature_ids):
            raise ValueError('duplicate feature ID')
        if len(set(self.cve_providers)) != len(self.cve_providers):
            raise ValueError('duplicate CVE provider')
        if self.cache_dir is not None and not (Path(self.cache_dir).is_absolute()
                                               or _windows_absolute(self.cache_dir)):
            raise ValueError('cache_dir must be an absolute path')
        return self

    @property
    def is_default(self) -> bool:
        return self.name == DEFAULT_NAME

    def ranking_config(self) -> RankingConfig:
        # Canonical detector order so a profile equal to the default yields RankingConfig().
        return RankingConfig(weights=dict(self.weights),
                             enabled=tuple(d for d in DETECTOR_IDS if d in set(self.enabled)))

    def feature_filter(self) -> frozenset[int] | None:
        return None if self.feature_ids is None else frozenset(self.feature_ids)

    @property
    def allow_symbol_downloads(self) -> bool:
        return self.symbol_policy == 'online'


def _windows_absolute(path: str) -> bool:
    return len(path) > 2 and path[0].isalpha() and path[1] == ':' and path[2] in '\\/' or path.startswith('\\\\')


def profile_digest(profile: AnalysisProfile) -> str:
    """Semantic identity: name, cache_dir and cache budget are presentation/operational."""
    return identity.domain_id('analysis-profile', 1, {
        'weights': dict(sorted(profile.weights.items())),
        'enabled': sorted(profile.enabled),
        'feature_ids': None if profile.feature_ids is None else sorted(profile.feature_ids),
        'symbol_policy': profile.symbol_policy,
        'cve_providers': sorted(profile.cve_providers),
        'snapshot_max_age_days': profile.snapshot_max_age_days,
    })


DEFAULT_PROFILE = AnalysisProfile(name=DEFAULT_NAME)


def parse(text: str | bytes) -> AnalysisProfile:
    try:
        return AnalysisProfile.model_validate_json(text)
    except ValidationError as exc:
        raise ProfileError(_message(exc)) from None


def build(data: dict) -> AnalysisProfile:
    """Validate an in-memory profile (GUI editor) through JSON, so exactly the file rules apply."""
    import json
    try:
        text = json.dumps(data, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ProfileError(f'profile is not JSON-serializable: {exc}') from None
    return parse(text)


def _message(exc: ValidationError) -> str:
    parts = []
    for error in exc.errors()[:5]:
        where = '.'.join(str(p) for p in error['loc']) or 'profile'
        parts.append(f'{where}: {error["msg"]}')
    return '; '.join(parts)


def dumps(profile: AnalysisProfile) -> str:
    import json
    return json.dumps(profile.model_dump(mode='json'), indent=2, sort_keys=True) + '\n'


def load_file(path: Path) -> AnalysisProfile:
    try:
        with open(path, 'rb') as handle:
            data = handle.read(MAX_FILE_BYTES + 1)
    except OSError as exc:
        raise ProfileError(f'cannot read profile file {path.name}: {exc.strerror or exc}') from None
    if len(data) > MAX_FILE_BYTES:
        raise ProfileError(f'profile file {path.name} exceeds {MAX_FILE_BYTES} bytes')
    return parse(data)


def default_profiles_dir() -> Path:
    """Headless equivalent of the desktop's native QSettings directory (no Qt import).
    Windows keeps QSettings in the registry, so profiles live under %APPDATA%."""
    if sys.platform == 'win32':
        base = Path(os.environ.get('APPDATA') or Path.home() / 'AppData' / 'Roaming')
    elif sys.platform == 'darwin':
        base = Path.home() / 'Library' / 'Preferences'
    else:
        base = Path(os.environ.get('XDG_CONFIG_HOME') or Path.home() / '.config')
    return base / 'PatchTrace' / 'profiles'


class ProfileStore:
    """One `<name>.json` per user profile. The built-in default is never written."""

    def __init__(self, directory: Path):
        self.directory = Path(directory)

    def _path(self, name: str) -> Path:
        if not isinstance(name, str) or not re.fullmatch(NAME_PATTERN, name) or len(name) > 64:
            raise ProfileError(f'invalid profile name {name!r}')
        return self.directory / f'{name}.json'

    def names(self) -> list[str]:
        if not self.directory.is_dir():
            return []
        return sorted((p.stem for p in self.directory.glob('*.json') if p.is_file()), key=str.casefold)

    def list(self) -> tuple[list[AnalysisProfile], list[str]]:
        """(valid profiles including default first, per-file errors). Invalid files are reported, never repaired."""
        profiles, errors = [DEFAULT_PROFILE], []
        for name in self.names():
            try:
                profiles.append(self.get(name))
            except ProfileError as exc:
                errors.append(str(exc))
        return profiles, errors

    def get(self, name: str) -> AnalysisProfile:
        if name == DEFAULT_NAME:
            return DEFAULT_PROFILE
        path = self._path(name)
        if not path.is_file():
            raise ProfileError(f'profile {name!r} not found')
        profile = load_file(path)
        if profile.name != name:
            raise ProfileError(f'profile file {path.name} names a different profile ({profile.name!r})')
        return profile

    def save(self, profile: AnalysisProfile, replaces: str | None = None) -> None:
        """Atomic write; `replaces` is the previous name when renaming."""
        if profile.name.casefold() == DEFAULT_NAME:
            raise ProfileError('the built-in default profile is read-only')
        clash = {n.casefold() for n in self.names()} - {(replaces or '').casefold()}
        if profile.name.casefold() in clash:
            raise ProfileError(f'a profile named {profile.name!r} already exists')
        self.directory.mkdir(parents=True, exist_ok=True)
        fd, temp = tempfile.mkstemp(prefix='.profile-', suffix='.tmp', dir=self.directory)
        try:
            with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as handle:
                handle.write(dumps(profile))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp, self._path(profile.name))
        except BaseException:
            Path(temp).unlink(missing_ok=True)
            raise
        if replaces and replaces != profile.name:
            old, new = self._path(replaces), self._path(profile.name)
            # On case-insensitive file systems a case-only rename already replaced the old file.
            if old.exists() and not os.path.samefile(old, new):
                old.unlink()

    def delete(self, name: str) -> None:
        if name == DEFAULT_NAME:
            raise ProfileError('the built-in default profile cannot be deleted')
        self._path(name).unlink(missing_ok=True)


def resolve(value: str, store: ProfileStore) -> AnalysisProfile:
    """CLI `--profile NAME|FILE`: anything that looks like a path is a file, else a stored name."""
    if value.endswith('.json') or '/' in value or '\\' in value:
        return load_file(Path(value))
    return store.get(value)
