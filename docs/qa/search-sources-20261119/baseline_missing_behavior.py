"""Authored local source-comparison probe. Synthetic bytes only; no native engine/network."""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import subprocess
import tempfile
import threading
from pathlib import Path
from types import SimpleNamespace

from patchtrace import cli
from patchtrace.enrichment.storage import EnrichmentStore
from patchtrace.intelligence.storage import AdvisoryStore
from patchtrace.sample import synthetic_pe
from patchtrace.search import cli as search_cli
from patchtrace.search.sources.advisory import advisory_specs
from patchtrace.service import ProjectService
from patchtrace.strings import cli as strings_cli
from patchtrace.strings.qt_panel import Request, scan_builtin
from test_intel_tools_pe import KERNEL32, MSVC_RICH, _image, _strings_code


def invoke(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(argv)
    return {"code": code, "stdout": out.getvalue(), "stderr": err.getvalue()}


def make_project(root, data):
    paths = [root / f"{side}.exe" for side in ("older", "newer")]
    for path, content in zip(paths, data, strict=True):
        path.write_bytes(content)
    return ProjectService.create(*paths, "source binding probe", root / "project")


def search_probe(root):
    service = make_project(root, [synthetic_pe(0), synthetic_pe(1)])
    project = service.root
    service.close()
    imported = invoke(["intelligence", "import", str(project),
                       "tests/fixtures/csaf/synthetic-advisory-rev1.json", "--cve", "CVE-2099-10001"])
    assert imported["code"] == 0, imported
    query = [str(project), "--query", "CVE-2099-10001", "--json", "--cache-dir", str(root / "cache")]
    baseline = invoke(["search", *query])
    service, attention = search_cli._open_project(project)
    port = AdvisoryStore(project, EnrichmentStore(service.store), service.project.id, service.project.revision)
    items, warnings = port.advisories()
    assert len(items) == 1 and not warnings, (len(items), warnings)
    out, err = io.StringIO(), io.StringIO()
    code = search_cli.main(query, opener=lambda _: (service, attention),
                           extra_specs=lambda _: advisory_specs(port, None), stdout=out, stderr=err)
    control = {"code": code, "stdout": out.getvalue(), "stderr": err.getvalue()}
    for result in (baseline, control):
        document = json.loads(result["stdout"])
        result["groups"] = sorted({e["group"] for h in document["result"]["hits"] for e in h["evidence"]})
        result["hit_count"] = len(document["result"]["hits"])
    assert "adv" not in baseline["groups"] and "adv" in control["groups"], (baseline, control)
    return {"import": imported, "stored_advisory_count": len(items), "production": baseline,
            "existing_adapter_injected_control": control}


def strings_probe(root):
    api = "GetProcAddress"
    older = _image(_strings_code, {KERNEL32: ["OutputDebugStringA"]}, {"s_text": b"plain text here\0"}, rich=MSVC_RICH)
    newer = _image(_strings_code, {KERNEL32: ["OutputDebugStringA", api]},
                   {"s_text": b"plain text here\0", "s_api": api.encode() + b"\0"}, rich=MSVC_RICH)
    service = make_project(root, [older, newer])
    try:
        artifacts = {a.side: a for a in service.project.artifacts}
        args = SimpleNamespace(source="builtin", min_length=4, anchors=None)
        computed = strings_cli.compute(args, service, threading.Event())
        request = Request(None, service.root / artifacts["older"].relative_path,
                          service.root / artifacts["newer"].relative_path,
                          artifacts["older"].sha256, artifacts["newer"].sha256,
                          root=service.root, project=service.project)
        dock = scan_builtin(request, threading.Event(), lambda *_: None)
        extract = lambda delta: [{"display": c.display, "status": c.status, "cues": list(c.cues)}
                                 for c in delta.changes if c.display == api]
        a, b = extract(computed.delta), extract(dock.delta)
        assert a and b and "api-name" in a[0]["cues"] and "api-name" not in b[0]["cues"], (a, b)
        return {"cli": a, "dock_loader": b, "fixture_sha256": [hashlib.sha256(d).hexdigest() for d in (older, newer)]}
    finally:
        service.close()


if __name__ == "__main__":
    result = {"source": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()}
    with tempfile.TemporaryDirectory(prefix="patchtrace-residual-probe-") as directory:
        root = Path(directory)
        for name, probe in (("search", search_probe), ("strings", strings_probe)):
            path = root / name
            path.mkdir()
            result[name] = probe(path)
    print(json.dumps(result, indent=2))
