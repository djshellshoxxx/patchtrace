"""Reproducible Windows x64 builds for the factory (SPEC-32 s4).

A build copies the needed source files into a private scratch directory, compiles each translation unit with a fixed
argv (profile template + recipe defines/includes), links one DLL, strips a copy for the engines (asserting that every
loaded section keeps its RVA and bytes) and stores debug image, engine image and PDB content-addressed under
`<calib root>/known-answer/images/`. Recipes are explicit compiler argv over a pinned file list: no project build
script is ever run, and the built images are never executed.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from ..common import canonical_json
from . import msvc
from .pe import loaded_view, read_pe
from .toolchain import Blocked, Toolchain, ToolError, run_tool, tool_env

IMAGE_BASE = 0x180000000
COPY_EXTS = frozenset({'.c', '.h', '.inc', '.def'})
MAX_TREE_BYTES = 512 * 1024 * 1024
MAX_TREE_FILES = 50_000
COMPILE_TIMEOUT = 300.0
OPTS = ('O0', 'O1', 'O2', 'O3', 'Os')
# Freestanding helpers the compiler may call even with -ffreestanding (struct copies, zeroing) plus `_fltused`, one
# archive member each so a suite that defines one of them never collides. Written for this repository (MIT).
RUNTIME_MEMBERS = {
    'ka_memcpy.c': 'void *memcpy(void *d, const void *s, unsigned long long n)\n'
                   '{ unsigned char *o = d; const unsigned char *i = s; while (n--) *o++ = *i++; return d; }\n',
    'ka_memmove.c': 'void *memmove(void *d, const void *s, unsigned long long n)\n'
                    '{ unsigned char *o = d; const unsigned char *i = s;\n'
                    '  if (o < i) { while (n--) *o++ = *i++; } else { o += n; i += n; while (n--) *--o = *--i; }\n'
                    '  return d; }\n',
    'ka_memset.c': 'void *memset(void *d, int c, unsigned long long n)\n'
                   '{ unsigned char *o = d; while (n--) *o++ = (unsigned char)c; return d; }\n',
    'ka_memcmp.c': 'int memcmp(const void *a, const void *b, unsigned long long n)\n'
                   '{ const unsigned char *x = a, *y = b; for (; n; n--, x++, y++) if (*x != *y) return *x - *y;\n'
                   '  return 0; }\n',
    'ka_fltused.c': 'int _fltused = 0;\n',
}


class BuildError(RuntimeError):
    pass


def persist_build_record(debug_dir: Path, record: Mapping) -> Path:
    """Retain every observed full receipt; build.json remains the last-build compatibility view.

    Identical artifact bytes can result from different recipes. Publish a complete
    content-addressed receipt without overwriting an existing one, and refuse a
    corrupted preexisting receipt before updating the legacy view. No historical
    receipts are inferred from a preexisting legacy file.
    """
    data = json.dumps(dict(record), sort_keys=True, indent=1).encode('utf-8') + b'\n'
    folder = Path(debug_dir) / 'builds'
    folder.mkdir(parents=True, exist_ok=True)
    target = folder / f'{hashlib.sha256(data).hexdigest()}.json'
    # A hard-link publication is exclusive and atomic: concurrent readers cannot
    # observe a newly created, partially written receipt.
    with tempfile.TemporaryDirectory(prefix='.receipt-', dir=folder) as private:
        staged = Path(private) / 'record.json'
        staged.write_bytes(data)
        try:
            os.link(staged, target)
        except FileExistsError:
            if target.is_symlink() or not target.is_file() or target.read_bytes() != data:
                raise BuildError(f'build receipt integrity mismatch: {target.name}') from None
        except OSError as exc:
            raise BuildError('atomic build receipt publication requires a store that permits hard links: '
                             f'{exc}') from exc
    (Path(debug_dir) / 'build.json').write_bytes(data)
    return target


NUISANCES = ('icf', 'timestamp', 'guid', 'path')    # P1 of SPEC-31 08 s1 beside link order
NUISANCE_EPOCH = 1700000000                          # the /timestamp the `timestamp` variant stamps instead of /Brepro
PATH_MAPS = ('-ffile-compilation-dir=', '-ffile-prefix-map=', '-fdebug-prefix-map=', '/d1trimfile:')


def nuisance_compile(argv: Sequence[str], nuisance: str) -> list[str]:
    """`path`: the compile argv without the flags that keep the scratch directory out of the object files."""
    if nuisance != 'path':
        return list(argv)
    return [a for a in argv if not a.startswith(PATH_MAPS)]


def nuisance_link(profile: str, link: Sequence[str], nuisance: str) -> list[str]:
    """The link argv of a nuisance variant. `icf` folds identical functions, `timestamp` stamps a fixed other time
    instead of the /Brepro hash, `guid` drops /Brepro (time and GUID come from the linker's defaults). A variant a
    profile's linker cannot express raises BuildError, and the corpus lists it as skipped."""
    out = list(link)
    if nuisance in ('', 'path'):
        return out
    if profile in ('msvc-free', 'msvc'):         # both link with MSVC-style options (case-insensitive)
        if nuisance == 'icf':
            return ['/opt:icf' if a.lower() == '/opt:noicf' else a for a in out]
        if nuisance == 'timestamp':
            return [f'/timestamp:{NUISANCE_EPOCH}' if a.lower() == '/brepro' else a for a in out]
        return [a for a in out if a.lower() != '/brepro']
    if nuisance == 'guid':
        raise BuildError(f'nuisance guid needs the msvc-free profile, not {profile}')
    if nuisance == 'timestamp':
        return [a for a in out if a != '-Wl,--no-insert-timestamp']
    if profile != 'mingw-clang':
        raise BuildError('nuisance icf needs lld (profile mingw-clang or msvc-free)')
    return [*out, '-Wl,--icf=all']


@dataclass(frozen=True)
class BuildSpec:
    project: str
    source_root: Path
    files: tuple[str, ...]
    output: str
    profile: str = 'msvc-free'
    opt: str = 'O2'
    include_dirs: tuple[str, ...] = ('.',)
    defines: tuple[str, ...] = ()
    cflags: tuple[str, ...] = ()
    generated: tuple[tuple[str, str], ...] = ()          # (relative path, text) written into the scratch copy
    dependencies: tuple[tuple[str, Path, tuple[str, ...]], ...] = ()   # (name, root, files) compiled under _dep/name
    link_order: str = 'sorted'
    variant: str = ''
    source_date_epoch: int = 0
    std: str | None = None
    nuisance: str = ''                  # '' or one of NUISANCES: a link/compile difference that must not change a verdict
    libs: tuple[str, ...] = ()                            # bare import-library names, linked after the objects

    def __post_init__(self):
        if self.opt not in OPTS:
            raise BuildError(f'unknown optimisation level {self.opt}')
        if self.profile not in ('msvc-free', 'mingw-gcc', 'mingw-clang', 'msvc'):
            raise BuildError(f'profile {self.profile} cannot build on this host')
        if self.link_order not in ('sorted', 'reversed', 'rotated'):
            raise BuildError('link_order must be sorted, reversed or rotated')
        if self.nuisance and self.nuisance not in NUISANCES:
            raise BuildError(f'nuisance must be empty or one of {", ".join(NUISANCES)}')
        for rel in (*self.files, *self.include_dirs, *(g for g, _ in self.generated)):
            _check_rel(rel)
        if not self.files:
            raise BuildError('no source files')


@dataclass(frozen=True)
class BuildResult:
    spec: BuildSpec
    recipe_digest: str
    debug_image: Path
    engine_image: Path
    pdb: Path | None
    sha256: str
    debug_sha256: str
    pdb_sha256: str | None
    size: int
    image_base: int
    compiler: str
    compiler_version: str
    source_digest: str
    input_files: dict[str, str] = field(default_factory=dict)


def _check_rel(rel: str) -> None:
    parts = rel.replace('\\', '/').split('/')
    if rel.startswith('/') or '..' in parts or ':' in rel:
        raise BuildError(f'unsafe relative path {rel!r}')


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def glob_regex(pattern: str) -> re.Pattern:
    """Path glob with POSIX semantics: `*` and `?` never cross '/', `**/` matches any number of directories."""
    out, i = [], 0
    while i < len(pattern):
        if pattern.startswith('**/', i):
            out.append('(?:[^/]+/)*')
            i += 3
        elif pattern.startswith('**', i):
            out.append('.*')
            i += 2
        elif pattern[i] == '*':
            out.append('[^/]*')
            i += 1
        elif pattern[i] == '?':
            out.append('[^/]')
            i += 1
        elif pattern[i] == '[':
            end = pattern.find(']', i + 1)
            if end < 0:
                out.append(re.escape(pattern[i]))
                i += 1
            else:
                out.append('[' + pattern[i + 1:end].replace('\\', '\\\\') + ']')
                i = end + 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile(''.join(out) + r'\Z')


def select_files(root: Path, include: Sequence[str], exclude: Sequence[str] = ()) -> tuple[str, ...]:
    """Recipe globs (relative, POSIX; `*` stays inside one directory) -> sorted regular files under root
    (symlinks never followed, `.git` ignored)."""
    inc = [glob_regex(g) for g in include]
    exc = [glob_regex(g) for g in exclude]
    found = set()
    for path in sorted(root.rglob('*')):
        if path.is_symlink() or not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        if rel.startswith('.git/'):
            continue
        if any(r.match(rel) for r in inc) and not any(r.match(rel) for r in exc):
            found.add(rel)
    return tuple(sorted(found))


def _copy_tree(root: Path, dest: Path, needed: Sequence[str]) -> dict[str, str]:
    """Copy C sources/headers (plus the listed files) without following symlinks; returns rel -> sha256."""
    copied: dict[str, str] = {}
    total = 0
    wanted = set(needed)
    for path in sorted(root.rglob('*')):
        rel = path.relative_to(root).as_posix()
        if rel.startswith('.git/') or path.is_symlink() or not path.is_file():
            continue
        if path.suffix.lower() not in COPY_EXTS and rel not in wanted:
            continue
        data = path.read_bytes()
        total += len(data)
        if total > MAX_TREE_BYTES or len(copied) >= MAX_TREE_FILES:
            raise BuildError('source tree exceeds the size or file-count limit')
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        copied[rel] = _sha(data)
    missing = sorted(wanted - set(copied))
    if missing:
        raise BuildError(f'missing source files: {missing[:5]}')
    return copied


def _order(objs: list[str], how: str) -> list[str]:
    if how == 'reversed':
        return list(reversed(objs))
    if how == 'rotated' and len(objs) > 1:
        half = len(objs) // 2
        return objs[half:] + objs[:half]
    return objs


def _compile_argv(tools: Toolchain, spec: BuildSpec, src_dir: Path, rel: str, obj: str,
                  include_dirs: Sequence[str]) -> list[str]:
    """Relative paths only, so that no scratch path reaches the image or the debug info: clang gets
    `-ffile-compilation-dir=.` (debug and coverage dirs; a prefix-map flag would itself be recorded in the CodeView
    build info), gcc gets `-ffile-prefix-map` (not recorded in DW_AT_producer)."""
    if spec.profile == 'msvc':
        return msvc.compile_argv(tools.path('cl'), spec, src_dir, rel, obj, include_dirs)
    flags = [f'-{spec.opt}', '-g', '-w']
    if spec.std:
        flags.append(f'-std={spec.std}')
    flags += [f'-D{d}' for d in spec.defines] + [f'-I{d}' for d in include_dirs] + list(spec.cflags)
    if spec.profile == 'msvc-free':
        return [tools.path('clang'), '--target=x86_64-pc-windows-msvc', '-ffreestanding', '-mno-stack-arg-probe',
                '-gcodeview', '-gno-codeview-command-line', '-ffile-compilation-dir=.', *flags, '-c', rel, '-o', obj]
    if spec.profile == 'mingw-clang':
        return [tools.path('clang'), '--target=x86_64-w64-windows-gnu', '-ffile-compilation-dir=.', *flags, '-c', rel,
                '-o', obj]
    return [tools.path('mingw-gcc'), f'-ffile-prefix-map={src_dir}=.', f'-fdebug-prefix-map={src_dir}=.', *flags,
            '-c', rel, '-o', obj]


def link_lib_args(spec: BuildSpec) -> list[str]:
    """`-l<name>` arguments for the mingw profiles (names are validated bare words in the recipe contract)."""
    return [f'-l{name}' for name in spec.libs] if spec.profile in ('mingw-gcc', 'mingw-clang') else []


def _template(argv: Sequence[str], src_dir: Path) -> list[str]:
    """argv with the scratch path replaced, so the recipe digest is independent of the build directory."""
    return [a.replace(str(src_dir), '<SRC>') for a in argv[1:]]


def build(spec: BuildSpec, tools: Toolchain, store: Path, *, scratch_parent: Path | None = None,
          keep_scratch: bool = False) -> BuildResult:
    """Build one image. `store` is `<calib root>/known-answer`. Raises Blocked (tools) or BuildError."""
    from .toolchain import PROFILE_TOOLS
    tools.require(*PROFILE_TOOLS[spec.profile])
    if status := tools.profile_status(spec.profile):    # a profile that only builds on another host
        raise Blocked(status)
    root = Path(spec.source_root)
    if not root.is_dir():
        raise BuildError(f'source root {root} does not exist')
    parent = Path(scratch_parent or store / 'build')
    parent.mkdir(parents=True, exist_ok=True)
    scratch = Path(tempfile.mkdtemp(prefix=f'{spec.project}-{spec.variant or "b"}-', dir=parent))
    try:
        return _build_in(spec, tools, store, root, scratch)
    finally:
        if not keep_scratch:
            shutil.rmtree(scratch, ignore_errors=True)


def _build_in(spec: BuildSpec, tools: Toolchain, store: Path, root: Path, scratch: Path) -> BuildResult:
    src_dir, obj_dir, out_dir, tmp = (scratch / n for n in ('src', 'obj', 'out', 'tmp'))
    for d in (src_dir, obj_dir, out_dir, tmp):
        d.mkdir(parents=True, exist_ok=True)
    generated_names = {g for g, _ in spec.generated}
    inputs = _copy_tree(root, src_dir, [f for f in spec.files if f not in generated_names])
    for rel, text in spec.generated:
        target = src_dir / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding='utf-8', newline='\n')
        inputs[rel] = _sha(text.encode('utf-8'))
    units = list(spec.files)
    for name, dep_root, dep_files in spec.dependencies:
        dep_inputs = _copy_tree(Path(dep_root), src_dir / '_dep' / name, dep_files)
        inputs.update({f'_dep/{name}/{k}': v for k, v in dep_inputs.items()})
        units += [f'_dep/{name}/{f}' for f in dep_files]
    include_dirs = list(spec.include_dirs) + sorted({f'_dep/{n}' for n, _, _ in spec.dependencies})
    tool_dirs = sorted({str(Path(tools.path(n)).parent) for n in ('clang', 'lld-link', 'mingw-gcc', 'cl', 'msvc-link')
                        if tools.get(n).ok})
    extra = {'SOURCE_DATE_EPOCH': str(spec.source_date_epoch)}
    if spec.profile == 'msvc':
        extra.update(msvc.env_extra(os.environ))
    env = tool_env(tmp=tmp, path_dirs=tool_dirs, extra=extra)
    objs, templates = [], []
    for index, rel in enumerate(sorted(units)):
        obj = f'../obj/{index:05d}' + ('.obj' if spec.profile == 'msvc' else '.o')
        argv = nuisance_compile(_compile_argv(tools, spec, src_dir, rel, obj, include_dirs), spec.nuisance)
        templates.append(_template(argv, src_dir))
        try:
            run_tool(argv, cwd=src_dir, env=env, timeout=COMPILE_TIMEOUT, check=True)
        except ToolError as exc:
            raise BuildError(f'compile {rel}: {exc}') from None
        objs.append(obj)
    stem = Path(spec.output).stem
    linked = _order(objs, spec.link_order)
    if spec.profile == 'msvc-free':
        runtime_lib = _runtime_archive(tools, spec, scratch, env)
        source_path = r'C:\ka-src' if os.name == 'nt' else '/ka-src'   # deterministic PDB paths (debuginfo strips)
        link = [tools.path('lld-link'), '/dll', '/noentry', '/nodefaultlib', '/machine:x64', '/debug', '/debug:symtab',
                f'/pdb:../out/{stem}.pdb', '/pdbaltpath:%_PDB%', f'/pdbsourcepath:{source_path}', '/Brepro',
                '/opt:noref', '/opt:noicf', '/incremental:no', '/noimplib', f'/out:../out/{spec.output}', *linked,
                runtime_lib]
    elif spec.profile == 'msvc':
        link = msvc.link_argv(tools.path('msvc-link'), spec, linked, stem)
    elif spec.profile == 'mingw-clang':
        link = [tools.path('clang'), '--target=x86_64-w64-windows-gnu', '-fuse-ld=lld', '-shared', '-o',
                f'../out/{spec.output}', *linked, *link_lib_args(spec), '-Wl,--no-insert-timestamp',
                f'-Wl,--image-base={IMAGE_BASE:#x}']
    else:
        link = [tools.path('mingw-gcc'), '-shared', '-o', f'../out/{spec.output}', *linked, *link_lib_args(spec), '-static-libgcc',
                '-Wl,--no-insert-timestamp', f'-Wl,--image-base={IMAGE_BASE:#x}']
    link = nuisance_link(spec.profile, link, spec.nuisance)
    try:
        run_tool(link, cwd=src_dir, env=env, timeout=COMPILE_TIMEOUT, check=True)
    except ToolError as exc:
        raise BuildError(f'link: {exc}') from None
    debug_path = out_dir / spec.output
    engine_path = out_dir / ('engine-' + spec.output)
    try:
        run_tool([tools.path('llvm-strip'), '--strip-all', '-o', str(engine_path), str(debug_path)], cwd=out_dir,
                 env=env, timeout=COMPILE_TIMEOUT, check=True)
    except ToolError as exc:
        raise BuildError(f'strip: {exc}') from None
    debug_img, engine_img = read_pe(debug_path), read_pe(engine_path)
    if loaded_view(debug_img) != loaded_view(engine_img) or debug_img.image_base != engine_img.image_base:
        raise BuildError('stripping changed a loaded section: engine and debug images would disagree on RVAs')
    pdb_src = out_dir / f'{stem}.pdb'
    compiler = {'mingw-gcc': 'mingw-gcc', 'msvc': 'cl'}.get(spec.profile, 'clang')
    linker = {'msvc-free': 'lld-link', 'msvc': 'msvc-link'}.get(spec.profile, compiler)
    versions = tools.versions(compiler, linker, 'llvm-strip')
    source_digest = _sha(canonical_json(sorted(inputs.items())))
    recipe = {'profile': spec.profile, 'opt': spec.opt, 'link_order': spec.link_order, 'std': spec.std,
              'compile': templates, 'link': _template(link, src_dir), 'versions': versions,
              'defines': list(spec.defines), 'cflags': list(spec.cflags), 'include_dirs': include_dirs,
              'source_date_epoch': spec.source_date_epoch}
    if spec.nuisance:                   # added only when set, so every digest of an ordinary build stays as it was
        recipe['nuisance'] = spec.nuisance
    recipe_digest = _sha(canonical_json(recipe))
    debug_sha = debug_img.sha256
    engine_sha = engine_img.sha256
    debug_dir = store / 'images' / debug_sha
    engine_dir = store / 'images' / engine_sha
    for directory, path in ((debug_dir, debug_path), (engine_dir, engine_path)):
        directory.mkdir(parents=True, exist_ok=True)
        target = directory / spec.output
        if not target.exists():
            shutil.copyfile(path, target)
    pdb_target, pdb_sha = None, None
    if pdb_src.is_file():
        pdb_sha = _sha(pdb_src.read_bytes())
        pdb_target = debug_dir / f'{stem}.pdb'
        if not pdb_target.exists():
            shutil.copyfile(pdb_src, pdb_target)
    record = {'contract': 'tier-r-build/1', 'project': spec.project, 'recipe': recipe, 'recipe_digest': recipe_digest,
              'source_digest': source_digest, 'inputs': inputs, 'debug_sha256': debug_sha, 'sha256': engine_sha,
              'pdb_sha256': pdb_sha, 'output': spec.output}
    persist_build_record(debug_dir, record)
    return BuildResult(spec, recipe_digest, debug_dir / spec.output, engine_dir / spec.output, pdb_target,
                       engine_sha, debug_sha, pdb_sha, len(engine_img.data), engine_img.image_base, compiler,
                       tools.get(compiler).version or 'unknown', source_digest, inputs)


def _runtime_archive(tools: Toolchain, spec: BuildSpec, scratch: Path, env: dict) -> str:
    rt = scratch / 'rt'
    rt.mkdir(exist_ok=True)
    members = []
    for name, text in sorted(RUNTIME_MEMBERS.items()):
        (rt / name).write_text(text, encoding='utf-8', newline='\n')
        obj = name.replace('.c', '.o')
        # absolute debug directory: these helpers are classified `runtime`, never labelled as project code
        run_tool([tools.path('clang'), '--target=x86_64-pc-windows-msvc', '-ffreestanding', '-fno-builtin', '-O1',
                  '-g', '-gcodeview', '-fdebug-compilation-dir=/ka-runtime', '-w', '-c', name, '-o', obj], cwd=rt,
                 env=env, timeout=COMPILE_TIMEOUT, check=True)
        members.append(obj)
    run_tool([tools.path('lld-link'), '/lib', '/out:ka_rt.lib', *members], cwd=rt, env=env, timeout=COMPILE_TIMEOUT,
             check=True)
    return '../rt/ka_rt.lib'


def runtime_files() -> frozenset[str]:
    return frozenset(RUNTIME_MEMBERS)


def env_digest() -> str:
    return _sha(canonical_json({'os': os.name}))
