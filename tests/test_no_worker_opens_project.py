"""Guard (store-threading-spec section 5, R3): the heavy project open stays on the GUI thread.

Pure ``ast`` scan, no Qt. In ``ui_*.py``, ``panel_qt.py`` and ``qt_panel.py`` no callable handed to a worker
``.submit(...)`` (``tasks.submit`` / ``lane.submit``) may call ``ProjectService.open``. Heuristic: a lambda, or a
name resolving to a function defined in the same file (``work``, ``self._load``), is searched including nested
code. The allowed-exceptions list is empty by design.
"""

from __future__ import annotations

import ast
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src" / "patchtrace"
ALLOWED_EXCEPTIONS: frozenset[tuple[str, int]] = frozenset()  # (relative path, line): empty today


def in_scope_files() -> list[Path]:
    found = set(SRC.rglob("ui_*.py")) | set(SRC.rglob("panel_qt.py")) | set(SRC.rglob("qt_panel.py"))
    return sorted(found)


def _project_service_names(tree: ast.AST) -> set[str]:
    names = {"ProjectService"}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            names.update(a.asname for a in node.names if a.name == "ProjectService" and a.asname)
    return names


def _is_open_call(node: ast.AST, names: set[str]) -> bool:
    if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "open"):
        return False
    owner = node.func.value
    return (isinstance(owner, ast.Name) and owner.id in names) or (
        isinstance(owner, ast.Attribute) and owner.attr in names
    )


def _is_submit(node: ast.AST) -> bool:
    return isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "submit"


def scan_source(source: str) -> tuple[int, list[int]]:
    """Return (submit calls seen, lines of ProjectService.open reachable from a submitted callable)."""
    tree = ast.parse(source)
    names = _project_service_names(tree)
    defs: dict[str, list[ast.AST]] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            defs.setdefault(node.name, []).append(node)
    submits = 0
    bad: set[int] = set()
    for call in filter(_is_submit, ast.walk(tree)):
        submits += 1
        for arg in [*call.args, *(k.value for k in call.keywords)]:
            bodies: list[ast.AST] = []
            if isinstance(arg, ast.Lambda):
                bodies.append(arg)
            elif isinstance(arg, ast.Name):
                bodies.extend(defs.get(arg.id, []))
            elif isinstance(arg, ast.Attribute):
                bodies.extend(defs.get(arg.attr, []))
            for body in bodies:
                bad.update(n.lineno for n in ast.walk(body) if _is_open_call(n, names))
    return submits, sorted(bad)


def test_the_scan_finds_the_real_gui_files_and_submit_sites() -> None:
    files = in_scope_files()
    assert len(files) >= 1, "no GUI files matched: the guard would pass vacuously"
    assert sum(scan_source(p.read_text(encoding="utf-8"))[0] for p in files) >= 1, "no worker submit found"


def test_no_worker_callable_opens_the_project() -> None:
    offenders = []
    for path in in_scope_files():
        rel = path.relative_to(SRC).as_posix()
        offenders += [f"{rel}:{n}" for n in scan_source(path.read_text(encoding="utf-8"))[1]
                      if (rel, n) not in ALLOWED_EXCEPTIONS]
    assert not offenders, f"ProjectService.open inside a worker-submitted callable (R3): {offenders}"


def test_the_heuristic_flags_a_violation_and_accepts_gui_thread_opens() -> None:
    bad = (
        "from patchtrace.service import ProjectService as PS\n"
        "class P:\n"
        "    def go(self):\n"
        "        def work(token, report):\n"
        "            return PS.open(self.path)\n"
        "        self.tasks.submit('x', work)\n"
        "        self.lane.submit('y', lambda t, r: ProjectService.open(1))\n"
    )
    submits, lines = scan_source(bad)
    assert submits == 2 and lines == [5, 7]
    good = "def go(self):\n    svc = ProjectService.open(p)\n    self.tasks.submit('x', lambda t, r: svc.read())\n"
    assert scan_source(good) == (1, [])
