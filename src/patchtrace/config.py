"""Shared PatchTrace configuration (SPEC-05 section 4.3): strict model, precedence, provenance, migration.

Pure module: no Qt import. Credentials are never part of this model.
"""
from __future__ import annotations

import json
import os
import re
import sys
import tempfile
import types
import typing
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from .models import ConfigOrigin
from .persistence import strict_json

MAX_CONFIG_BYTES = 1024 * 1024
ENGINES = ('version-tracking', 'structural-graph', 'simple')
#: PatchTrace engine name -> upstream ghidriff class (the upstream class is spelled StructualGraphDiff).
ENGINE_CLASSES = {'version-tracking': 'VersionTrackingDiff', 'structural-graph': 'StructualGraphDiff',
                  'simple': 'SimpleDiff'}
ENGINE_ALIASES = {'VersionTrackingDiff': 'version-tracking', 'StructualGraphDiff': 'structural-graph',
                  'StructuralGraphDiff': 'structural-graph', 'SimpleDiff': 'simple'}
EMIT_KINDS = ('ghidriff-md', 'ghidriff-json', 'matches-json', 'sxs-html', 'ghidriff-log', 'report-md',
              'report-html', 'report-json', 'summary', 'metadata', 'all', 'none')
DEFAULT_EMIT = ['ghidriff-md', 'ghidriff-json', 'report-md', 'summary', 'metadata']
NAME_TEMPLATE_TOKENS = frozenset({'old', 'new', 'old_sha8', 'new_sha8', 'engine', 'date', 'time',
                                  'run_id', 'run_id8'})
LogLevel = Literal['debug', 'info', 'warning', 'error', 'critical']
EngineLogLevel = Literal['CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG']
PathText = Annotated[str, Field(min_length=1, max_length=4096)]
_SECRET_KEY = re.compile(r'(api[_-]?key|token|secret|password|passwd|credential|authorization|bearer)',
                         re.IGNORECASE)
_NAME_ELEMENT = re.compile(r'^[A-Za-z0-9._-]{1,96}$')
_BASE_ADDRESS = re.compile(r'^(0[xX][0-9a-fA-F]+|[0-9]+)$')
_BOOL_WORDS = {'yes': True, 'on': True, 'no': False, 'off': False}


class ConfigError(ValueError):
    """Invalid, missing or unsupported configuration; message starts with ``PT-CONFIG:``."""

    def __init__(self, message: str):
        super().__init__(message if message.startswith('PT-CONFIG:') else f'PT-CONFIG: {message}')


class Section(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, validate_assignment=True)


class BackendSettings(Section):
    python_executable: PathText | None = None
    ghidra_install_dir: PathText | None = None
    java_home: PathText | None = None
    timeout_seconds: int = Field(default=3600, ge=1, le=604800)
    workspace: Literal['local', 'project'] = 'local'
    work_root: PathText | None = None
    ghidra_project_location: PathText | None = None
    ghidra_project_name: str = Field(default='pt', pattern=r'^[A-Za-z0-9_-]{1,32}$')
    gzfs_path: PathText | None = None


class AnalysisSettings(Section):
    engine: Literal['version-tracking', 'structural-graph', 'simple'] = 'version-tracking'
    threaded: bool = True
    force_analysis: bool = False
    force_diff: bool = False
    symbols: bool = True
    symbols_path: PathText | None = None
    min_func_len: int = Field(default=10, ge=0)
    max_ram_percent: float = Field(default=60.0, gt=0, le=95)
    bsim: bool = True
    bsim_full: bool = False
    decompiler_timeout: int = Field(default=60, ge=1)
    use_calling_counts: bool = False
    base_address: str | None = None
    program_options: PathText | None = None
    gdt: list[PathText] = Field(default_factory=list)
    verbose_analysis: bool = False
    jvm_args: list[Annotated[str, Field(min_length=1, max_length=4096)]] = Field(default_factory=list)
    max_section_funcs: int = Field(default=200, ge=1)

    @field_validator('engine', mode='before')
    @classmethod
    def engine_alias(cls, value):
        return ENGINE_ALIASES.get(value, value) if isinstance(value, str) else value

    @field_validator('base_address')
    @classmethod
    def base_address_valid(cls, value):
        if value is not None and parse_base_address(value) is None:
            raise ValueError('base_address must be 0x hexadecimal or decimal and at most 2**64-1')
        return value

    @field_validator('jvm_args')
    @classmethod
    def jvm_args_single_line(cls, value):
        if any(c in arg for arg in value for c in '\r\n\0'):
            raise ValueError('jvm_args entries must be single-line text')
        return value


class OutputSettings(Section):
    directory: PathText | None = None
    emit: list[Literal['ghidriff-md', 'ghidriff-json', 'matches-json', 'sxs-html', 'ghidriff-log',
                       'report-md', 'report-html', 'report-json', 'summary', 'metadata', 'all', 'none']] = (
        Field(default_factory=lambda: list(DEFAULT_EMIT)))
    name_template: str = '{old}-{new}'
    report_include_code: bool = False
    report_include_notes: bool = True
    keep_ghidra_project: bool = False
    keep_workspace: bool = False

    @field_validator('emit')
    @classmethod
    def emit_valid(cls, value):
        if len(set(value)) != len(value):
            raise ValueError('emit kinds must be unique')
        if ('all' in value or 'none' in value) and len(value) > 1:
            raise ValueError("'all' and 'none' cannot be combined with other emit kinds")
        return value

    @field_validator('name_template')
    @classmethod
    def template_valid(cls, value):
        validate_name_template(value)
        return value


class LoggingSettings(Section):
    console_level: LogLevel = 'info'
    file_level: LogLevel = 'debug'
    format: Literal['text', 'json'] = 'text'
    engine_level: EngineLogLevel = 'INFO'
    engine_file_level: EngineLogLevel = 'INFO'


class ProviderSettings(Section):
    """Provider selection only. There is deliberately no credential field."""
    kind: Literal['ollama', 'openai'] = 'ollama'
    endpoint: str = Field(default='http://127.0.0.1:11434', min_length=1, max_length=2048)
    model: str = Field(default='', max_length=256)
    context_budget: int = Field(default=24000, ge=512, le=200000)


class DesktopSettings(Section):
    font_size: int = Field(default=11, ge=8, le=28)
    sync_scroll: bool = True


class PatchTraceConfig(Section):
    """Versioned configuration shared by the desktop and the CLI (schema_version exactly 1)."""
    schema_version: Literal[1] = 1
    backend: BackendSettings = Field(default_factory=BackendSettings)
    analysis: AnalysisSettings = Field(default_factory=AnalysisSettings)
    output: OutputSettings = Field(default_factory=OutputSettings)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)
    provider: ProviderSettings = Field(default_factory=ProviderSettings)
    desktop: DesktopSettings = Field(default_factory=DesktopSettings)
    extensions: dict[str, dict] = Field(default_factory=dict)

    @model_validator(mode='after')
    def no_secrets_in_extensions(self):
        def walk(value):
            if isinstance(value, dict):
                for key, item in value.items():
                    if _SECRET_KEY.search(str(key)):
                        raise ValueError('extensions must not contain credential-like keys')
                    walk(item)
            elif isinstance(value, list):
                for item in value:
                    walk(item)
        walk(self.extensions)
        return self


# --- helpers ---------------------------------------------------------------------------------------

def parse_base_address(value: str | int | None) -> int | None:
    """Parse ``0x`` hexadecimal or decimal text; ``None`` if absent or invalid."""
    if value is None:
        return None
    if isinstance(value, int) and not isinstance(value, bool):
        number = value
    elif isinstance(value, str) and _BASE_ADDRESS.match(value.strip()):
        text = value.strip()
        number = int(text, 16) if text.lower().startswith('0x') else int(text, 10)
    else:
        return None
    return number if 0 <= number <= 2**64 - 1 else None


def validate_name_template(template: str) -> None:
    """Reject unknown tokens and literal characters that cannot appear in the rendered stem."""
    if not template or len(template) > 256:
        raise ValueError('name_template must be 1-256 characters')
    if template.startswith('.'):
        raise ValueError('name_template must not start with "."')
    for token in re.findall(r'\{([^{}]*)\}', template):
        if token not in NAME_TEMPLATE_TOKENS:
            raise ValueError(f'name_template has unknown token {{{token}}}')
    literal = re.sub(r'\{[^{}]*\}', '', template)
    if literal and not re.fullmatch(r'[A-Za-z0-9._-]+', literal):
        raise ValueError('name_template literal text must use only [A-Za-z0-9._-]')


def render_name_template(template: str, **tokens: str) -> str:
    """Render a validated template; the result must be one safe path element of 1-96 characters."""
    validate_name_template(template)
    missing = set(re.findall(r'\{([^{}]*)\}', template)) - set(tokens)
    if missing:
        raise ValueError(f'name_template tokens not provided: {sorted(missing)}')
    rendered = re.sub(r'\{([^{}]*)\}', lambda m: str(tokens[m.group(1)]), template)
    if not _NAME_ELEMENT.match(rendered) or rendered.startswith('.'):
        raise ValueError('rendered name must be 1-96 characters of [A-Za-z0-9._-] and not start with "."')
    return rendered


def _leaf_keys(model: type[BaseModel], prefix: str = '') -> list[str]:
    keys = []
    for name, info in model.model_fields.items():
        annotation = info.annotation
        if isinstance(annotation, type) and issubclass(annotation, BaseModel):
            keys.extend(_leaf_keys(annotation, f'{prefix}{name}.'))
        elif name != 'schema_version':
            keys.append(prefix + name)
    return keys


#: Every dotted key accepted by get/set/unset and reported in origins.
CONFIG_KEYS: tuple[str, ...] = tuple(_leaf_keys(PatchTraceConfig))


def _check_key(key: str) -> None:
    if key not in CONFIG_KEYS:
        raise ConfigError(f'unknown configuration key {key!r}')


def _get_path(data: dict, key: str):
    value = data
    for part in key.split('.'):
        value = value[part]
    return value


def _set_path(data: dict, key: str, value) -> None:
    *parents, last = key.split('.')
    target = data
    for part in parents:
        target = target[part]
    target[last] = value


def _field_accepts_str(key: str) -> bool:
    model: type[BaseModel] = PatchTraceConfig
    *parents, last = key.split('.')
    for part in parents:
        model = model.model_fields[part].annotation
    annotation = model.model_fields[last].annotation

    def accepts(tp) -> bool:
        origin = typing.get_origin(tp)
        if tp is str:
            return True
        if origin is Annotated:
            return accepts(typing.get_args(tp)[0])
        if origin in (typing.Union, types.UnionType):
            return any(accepts(arg) for arg in typing.get_args(tp))
        if origin is Literal:
            return all(isinstance(arg, str) for arg in typing.get_args(tp))
        return False
    return accepts(annotation)


def _describe(exc: ValidationError) -> str:
    return '; '.join(f"{'.'.join(str(p) for p in err['loc']) or 'config'}: {err['msg']}"
                     for err in exc.errors()[:5])


def _candidates(key: str, text: str) -> list[Any]:
    candidates: list[Any] = []
    if _field_accepts_str(key):
        candidates.append(text)
    try:
        candidates.append(strict_json(text))
    except ValueError:
        pass
    if text.strip().lower() in _BOOL_WORDS:
        candidates.append(_BOOL_WORDS[text.strip().lower()])
    candidates.append(text)
    candidates.append([part.strip() for part in text.split(',') if part.strip()])
    return candidates


def _with_value(data: dict, key: str, value: Any, typed_from_text: bool) -> dict:
    """Return validated config data with ``key`` replaced; strings are parsed according to the field type."""
    attempts = _candidates(key, value) if typed_from_text and isinstance(value, str) else [value]
    first_error = None
    for candidate in attempts:
        trial = json.loads(json.dumps(data))
        _set_path(trial, key, candidate)
        try:
            return PatchTraceConfig.model_validate(trial).model_dump(mode='json')
        except ValidationError as exc:
            first_error = first_error or exc
    raise ConfigError(f'invalid value for {key}: {_describe(first_error)}')


# --- file I/O --------------------------------------------------------------------------------------

def default_config_path(env: Mapping[str, str] | None = None, platform: str | None = None) -> Path:
    """``PATCHTRACE_CONFIG``, else ``%APPDATA%\\PatchTrace\\config.json`` (Windows) or
    ``$XDG_CONFIG_HOME``/``~/.config`` + ``/patchtrace/config.json`` (POSIX)."""
    env = os.environ if env is None else env
    platform = sys.platform if platform is None else platform
    if env.get('PATCHTRACE_CONFIG'):
        return Path(env['PATCHTRACE_CONFIG'])
    if platform == 'win32':
        appdata = env.get('APPDATA')
        base = Path(appdata) if appdata else Path.home() / 'AppData' / 'Roaming'
        return base / 'PatchTrace' / 'config.json'
    xdg = env.get('XDG_CONFIG_HOME')
    base = Path(xdg) if xdg and Path(xdg).is_absolute() else Path.home() / '.config'
    return base / 'patchtrace' / 'config.json'


def _read_raw(path: Path) -> dict:
    path = Path(path)
    try:
        if not path.is_file():
            raise ConfigError(f'config file not found: {path}')
        if path.stat().st_size > MAX_CONFIG_BYTES:
            raise ConfigError(f'config file exceeds {MAX_CONFIG_BYTES} bytes: {path}')
        text = path.read_bytes().decode('utf-8-sig')
    except UnicodeDecodeError as exc:
        raise ConfigError(f'config file is not UTF-8: {path}') from exc
    except OSError as exc:
        raise ConfigError(f'cannot read config file {path}: {exc.strerror or exc}') from exc
    try:
        data = strict_json(text)
    except ValueError as exc:
        detail = str(exc).removeprefix('PT-SCHEMA: ')
        raise ConfigError(f'invalid JSON in {path}: {detail}') from exc
    if not isinstance(data, dict):
        raise ConfigError(f'config file must contain a JSON object: {path}')
    if data.get('schema_version') != 1:
        raise ConfigError(f'unsupported config schema_version {data.get("schema_version")!r} in {path}; '
                          'expected 1')
    return data


def load_config(path: str | os.PathLike) -> PatchTraceConfig:
    """Load and strictly validate a config file; raise :class:`ConfigError` (``PT-CONFIG:``) on failure."""
    return _load(Path(path))[0]


def _load(path: Path) -> tuple[PatchTraceConfig, dict]:
    data = _read_raw(path)
    try:
        return PatchTraceConfig.model_validate(data), data
    except ValidationError as exc:
        raise ConfigError(f'invalid config {path}: {_describe(exc)}') from exc


def save_config(config: PatchTraceConfig, path: str | os.PathLike) -> Path:
    """Validate and write atomically (sibling temporary file + ``os.replace``)."""
    path = Path(path)
    try:
        data = PatchTraceConfig.model_validate(config.model_dump(mode='json')).model_dump(mode='json')
    except ValidationError as exc:
        raise ConfigError(f'refusing to save invalid config: {_describe(exc)}') from exc
    text = json.dumps(data, indent=2, ensure_ascii=False) + '\n'
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(dir=path.parent, prefix=path.name + '.', suffix='.tmp')
    try:
        with os.fdopen(handle, 'w', encoding='utf-8', newline='\n') as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise
    return path


# --- dotted key access -----------------------------------------------------------------------------

def get_key(config: PatchTraceConfig, key: str) -> Any:
    _check_key(key)
    return _get_path(config.model_dump(mode='json'), key)


def set_key(config: PatchTraceConfig, key: str, value: Any) -> PatchTraceConfig:
    """Return a new config with ``key`` set; string values are parsed by field type
    (JSON literal, yes/no/on/off, or comma-separated list)."""
    _check_key(key)
    return PatchTraceConfig.model_validate(_with_value(config.model_dump(mode='json'), key, value, True))


def unset_key(config: PatchTraceConfig, key: str) -> PatchTraceConfig:
    """Return a new config with ``key`` restored to its built-in default."""
    _check_key(key)
    default = _get_path(PatchTraceConfig().model_dump(mode='json'), key)
    return PatchTraceConfig.model_validate(_with_value(config.model_dump(mode='json'), key, default, False))


# --- precedence ------------------------------------------------------------------------------------

GENERIC_ENV = {'GHIDRA_INSTALL_DIR': 'backend.ghidra_install_dir', 'JAVA_HOME': 'backend.java_home'}
PATCHTRACE_ENV = {'PATCHTRACE_PYTHON': 'backend.python_executable',
                  'PATCHTRACE_WORK_ROOT': 'backend.work_root'}


@dataclass(frozen=True)
class EffectiveConfig:
    """Resolved configuration with the winning layer for every dotted key."""
    config: PatchTraceConfig
    origins: dict[str, ConfigOrigin]
    path: Path | None = None
    sources: tuple[str, ...] = field(default_factory=tuple)

    def get(self, key: str) -> Any:
        return get_key(self.config, key)

    def origin(self, key: str) -> ConfigOrigin:
        _check_key(key)
        return self.origins[key]

    def backend_kwargs(self) -> dict[str, Any]:
        b, o = self.config.backend, self.config.output
        return {'python_executable': b.python_executable or '', 'ghidra_dir': b.ghidra_install_dir or '',
                'timeout_seconds': b.timeout_seconds, 'java_home': b.java_home, 'workspace': b.workspace,
                'work_root': b.work_root, 'ghidra_project_location': b.ghidra_project_location,
                'ghidra_project_name': b.ghidra_project_name, 'gzfs_path': b.gzfs_path,
                'keep_ghidra_project': o.keep_ghidra_project, 'keep_workspace': o.keep_workspace}

    def ghidriff_kwargs(self) -> dict[str, Any]:
        a = self.config.analysis
        return {'engine': a.engine, 'threaded': a.threaded, 'force_analysis': a.force_analysis,
                'force_diff': a.force_diff, 'symbols': a.symbols, 'symbols_path': a.symbols_path,
                'min_func_len': a.min_func_len, 'max_ram_percent': a.max_ram_percent, 'bsim': a.bsim,
                'bsim_full': a.bsim_full, 'decompiler_timeout': a.decompiler_timeout,
                'use_calling_counts': a.use_calling_counts, 'base_address': parse_base_address(a.base_address),
                'program_options': a.program_options, 'gdt': tuple(a.gdt),
                'verbose_analysis': a.verbose_analysis, 'jvm_args': tuple(a.jvm_args),
                'max_section_funcs': a.max_section_funcs}


def _file_leaves(raw: dict) -> dict[str, Any]:
    leaves = {}
    for key in CONFIG_KEYS:
        value = raw
        for part in key.split('.'):
            if not isinstance(value, dict) or part not in value:
                break
            value = value[part]
        else:
            leaves[key] = value
    return leaves


def resolve(file_path: str | os.PathLike | None = None, use_file: bool = True,
            env: Mapping[str, str] | None = None,
            overrides: Mapping[str, Any] | None = None) -> EffectiveConfig:
    """Merge defaults < GHIDRA_INSTALL_DIR/JAVA_HOME < file < PATCHTRACE_PYTHON/PATCHTRACE_WORK_ROOT < flags.

    An explicit ``file_path`` must exist; the default location is optional. ``null`` in the file and
    ``None`` overrides mean "not set here" and do not mask lower layers. String overrides are parsed by
    field type exactly like ``config set``.
    """
    env = os.environ if env is None else env
    data = PatchTraceConfig().model_dump(mode='json')
    origins: dict[str, ConfigOrigin] = dict.fromkeys(CONFIG_KEYS, 'default')
    sources = ['default']

    def apply(key: str, value: Any, origin: ConfigOrigin, typed_from_text: bool) -> None:
        nonlocal data
        data = _with_value(data, key, value, typed_from_text)
        origins[key] = origin

    for name, key in GENERIC_ENV.items():
        if env.get(name):
            apply(key, env[name], 'env-generic', False)
            sources.append(f'env:{name}')
    path = None
    if use_file:
        path = Path(file_path) if file_path is not None else default_config_path(env)
        if file_path is not None or path.exists():
            for key, value in _file_leaves(_load(path)[1]).items():
                if value is not None:
                    apply(key, value, 'file', False)
            sources.append(f'file:{path}')
        else:
            path = None
    for name, key in PATCHTRACE_ENV.items():
        if env.get(name):
            apply(key, env[name], 'env', False)
            sources.append(f'env:{name}')
    for key, value in (overrides or {}).items():
        _check_key(key)
        if value is not None:
            if isinstance(value, tuple):
                value = list(value)
            apply(key, value, 'flag', True)
    if overrides:
        sources.append('flags')
    return EffectiveConfig(PatchTraceConfig.model_validate(data), origins, path, tuple(sources))


# --- QSettings migration ---------------------------------------------------------------------------

QSETTINGS_MAP = {'backend/python': 'backend.python_executable', 'backend/ghidra': 'backend.ghidra_install_dir',
                 'backend/timeout': 'backend.timeout_seconds', 'provider/kind': 'provider.kind',
                 'provider/endpoint': 'provider.endpoint', 'provider/model': 'provider.model',
                 'provider/context_budget': 'provider.context_budget', 'desktop/font_size': 'desktop.font_size',
                 'desktop/sync': 'desktop.sync_scroll'}


def migrate_qsettings(values: Mapping[str, Any], base: PatchTraceConfig | None = None) -> PatchTraceConfig:
    """Map legacy QSettings values (a plain dict) onto a config. Unmapped keys (geometry, splitter
    state, recent projects) are ignored; empty or invalid legacy values keep the base value. Idempotent."""
    data = (base or PatchTraceConfig()).model_dump(mode='json')
    for legacy, key in QSETTINGS_MAP.items():
        if legacy not in values or values[legacy] is None:
            continue
        value = values[legacy]
        if isinstance(value, str):
            value = value.strip()
            if not value and key != 'provider.model':
                continue
        try:
            data = _with_value(data, key, value, True)
        except ConfigError:
            continue
    return PatchTraceConfig.model_validate(data)
