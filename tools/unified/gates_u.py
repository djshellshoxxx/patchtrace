"""Gate report generator for SPEC-31 (08-evaluation s1): G-U1..G-U8 -> `gate-report/1`. Dev-only, never shipped.

Slice S6a fixed the report contract, the status vocabulary and the registry of the eight gates, and it
evaluated G-U5 from `bench-report/1` files and G-U8 from a pytest JUnit file plus attested CI steps. Slice S6b added G-U1,
G-U2 and G-U4 over `unified-outcomes/1` (`tools/unified/evaluators.py`); slice S6c adds G-U3, G-U6 and G-U7
(`tools/unified/rowgates.py`, intervals from `tools/unified/cluster.py`). Every outcome gate also carries the facts of the
corpus it reads (counts from `unified-corpus-manifest/1`), so a missing mutant class or an anti-conservative lineage count
is visible before any engine runs.

Statuses: `pass` / `fail` are verdicts on data; `insufficient-data` means the data supplied (or its size) cannot decide;
`pending` means a slice that is not built yet; `blocked` marks a part that needs something outside the code (a pinned
BinDiff, a Windows runner). Nothing is inferred, nothing averaged, and a missing input is never a pass. The report is
deterministic (sorted keys, LF, no timestamps) and strict on load, with a digest. U-05: the unified flag defaults to ON
only after G-U1..G-U6 pass with report SHAs recorded in docs/qa.md.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import xml.etree.ElementTree as ET
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, ValidationError

from tools.calibration.bootstrap import MIN_GROUPS_HEADLINE
from tools.calibration.common import digest, strict_json
from tools.calibration.tier_r.contracts import ContractError, dump_json
from tools.unified import bench, evaluators, outcomes, rowgates
from tools.unified.corpus import aa
from tools.unified.corpus import manifest as corpus_manifest
from tools.unified.mutations import classes

CONTRACT = 'gate-report/1'
CLAIM = ('Measured on synthetic workloads and test builds of open-source code; says nothing about Windows system '
         'files; no accuracy claim, the unified display stays ordinal.')
U05_RULE = ('U-05: the unified flag defaults to ON only after G-U1..G-U6 pass with report SHAs recorded in '
            'docs/qa.md; alpha builds ship with it OFF.')
U05_GATES = ('G-U1', 'G-U2', 'G-U3', 'G-U4', 'G-U5', 'G-U6')
INTEGRITY_GATE = 'G-U8'
MIN_MUTANTS_PER_CLASS = 20          # 08 s1 G-U2 [inf]
MAX_JUNIT_BYTES = 8 * 2**20
STATUSES = ('pass', 'fail', 'insufficient-data', 'pending', 'blocked')
ATTESTABLE = ('frozen-smoke',)
Status = Literal['pass', 'fail', 'insufficient-data', 'pending', 'blocked']


@dataclass(frozen=True)
class GateSpec:
    id: str
    question: str               # the question and first slice are the cells of the 08 s1 table (a test keeps them equal)
    first_slice: str            # the earliest slice that could run it; NOT what it waits for today (`needs`)
    consumes: str
    needs: tuple[str, ...] = () # what is missing today; G-U5 and G-U8 derive theirs from the inputs
    waits: tuple[str, ...] = ()
    blocked: tuple[str, ...] = ()


GATES = (
    GateSpec('G-U1', 'does the engine invent changes?', 'S3 (S0b for X vs X)',
             'unified-outcomes/1 for every A/A pair of the corpus manifest (P0, P1; P2 is reported, never gated)'),
    GateSpec('G-U2', 'does it see real changes, and never hide them?', 'S3',
             'unified-outcomes/1 for every mutant pair: the verdict of the planted function, per class'),
    GateSpec('G-U3', 'are `matched` pairs right?', 'S2',
             'the ladder correspondence of every release pair joined to its label document, and parity-report/1',
             blocked=('the BinDiff oracle part (MD index parity, tier A/B agreement) needs a pinned BinDiff: '
                      'tools/bindiff_pin.json has no verified assets',)),
    GateSpec('G-U4', 'is it deterministic and symmetric?', 'S0b / S3',
             'unified-outcomes/1 of two runs, a Linux and a Windows run, permuted inputs and the swapped orientation'),
    GateSpec('G-U5', 'does it fit a 60k-function image on a laptop?', 'S2 / S5',
             'bench-report/1 from the Linux runner and from the Windows runner or the frozen EXE',
             waits=('the largest Tier R pair through the whole pipeline needs S3',)),
    GateSpec('G-U6', 'is it worth it?', 'S3',
             'unified-outcomes/1 rows with the legacy tools that flag them, on the planted and A/A pairs'),
    GateSpec('G-U7', 'is narrowed A-IND-1 safe?', 'S3',
             'unified-outcomes/1 rows with their supports and truth: error rate by component pair and evidence-class pair'),
    GateSpec('G-U8', 'did we break anything?', 'every slice',
             'a pytest JUnit file of the full suite and the attested CI steps'),
)
BY_ID = {g.id: g for g in GATES}


@dataclass(frozen=True)
class IntegrityCheck:
    id: str
    text: str
    tests: tuple[str, ...] = ()         # `module::test`; every parametrised instance must pass
    attestation: str | None = None      # a CI step that is not a pytest test
    needs: str | None = None            # slice that has to name the tests first


G_U8_CHECKS = (
    IntegrityCheck('primary-snapshot-unchanged', 'the primary snapshot SHA is unchanged by unified runs',
                   ('test_unified_pipeline::test_unified_run_never_mutates_project_snapshot',)),
    IntegrityCheck('old-reader-ignores-unified-kinds', 'an old reader ignores the unified enrichment kinds',
                   ('test_unified_store::test_old_reader_ignores_unified_kinds',)),
    IntegrityCheck('schema-drift', 'the committed unified schemas equal the regenerated ones',
                   ('test_unified_contracts::test_generate_schemas_reproduces_committed_files',)),
    IntegrityCheck('no-socket-during-run', 'no socket is opened during a full unified run (audit hook)',
                   ('test_unified_pipeline::test_no_network_during_unified_run',)),
    IntegrityCheck('extractor-script-ast', 'the extractor script AST has no network, subprocess or dynamic-code use',
                   ('test_unified_ghidra_script::test_ghidra_script_imports_no_patchtrace',
                    'test_unified_ghidra_script::test_script_runs_no_dynamic_code_and_spawns_nothing')),
    IntegrityCheck('ui-policy', 'tooltips, accessibility and banned words of the Unified view',
                   ('test_ui_unified::test_controls_are_named_tipped_and_plain',
                    'test_ui_unified::test_run_is_off_by_default_and_names_the_reason',
                    'test_unified_panel_spec::test_every_tip_the_read_model_names_is_declared',
                    'test_unified_read_model::test_unified_banned_strings_never_appear')),
    IntegrityCheck('frozen-smoke', 'the frozen smoke including unified --help and unified _worker --self-check',
                   attestation='frozen-smoke'),
)


class _Strict(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True)


class GateRow(_Strict):
    id: str
    question: str
    first_slice: str
    status: Status
    reasons: tuple[str, ...]
    needs: tuple[str, ...]
    observed: dict[str, Any]


class Flag(_Strict):
    default: Literal['off']
    decision_ready: bool
    rule: str


class GateReport(_Strict):
    contract: Literal['gate-report/1']
    claim: str
    inputs: dict[str, Any]
    gates: tuple[GateRow, ...]
    summary: dict[str, int]
    flag: Flag
    report_sha256: str


@dataclass
class Inputs:
    manifest: corpus_manifest.CorpusManifest | None = None
    benches: list[bench.BenchReport] = field(default_factory=list)
    outcomes: list[outcomes.OutcomeSet] = field(default_factory=list)
    junit: dict[str, list[str]] | None = None
    attested: dict[str, str] = field(default_factory=dict)
    digests: dict[str, Any] = field(default_factory=dict)       # 'manifest': sha, 'bench': [sha], 'junit': [sha]


# ---- JUnit -------------------------------------------------------------------------------------------------------------------

def parse_junit(data: bytes) -> dict[str, list[str]]:
    """`module::test` -> outcomes (passed / failed / skipped) of a pytest JUnit file; parametrised instances share a key.
    The file is untrusted data: bounded, strictly UTF-8 without NUL (so a UTF-16 payload cannot hide a declaration from
    the check below) and refused when it declares a DTD or an entity, so no entity is ever expanded."""
    if len(data) > MAX_JUNIT_BYTES:
        raise ContractError('the JUnit file is larger than 8 MiB')
    try:
        text = data.decode('utf-8')
    except UnicodeDecodeError:
        raise ContractError('the JUnit file is not UTF-8') from None
    if '\x00' in text:
        raise ContractError('the JUnit file contains a NUL character')
    if re.search(r'<!\s*(DOCTYPE|ENTITY)', text, re.I):
        raise ContractError('the JUnit file declares a DTD or an entity')
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        raise ContractError(f'the JUnit file is not XML: {exc}') from None
    if root.tag not in ('testsuites', 'testsuite'):
        raise ContractError(f'unexpected JUnit root element {root.tag!r}')
    out: dict[str, list[str]] = {}
    for case in root.iter('testcase'):
        parts = case.get('classname', '').split('.')
        module = next((p for p in reversed(parts) if p.startswith('test_')), parts[-1])
        name = case.get('name', '').split('[', 1)[0]
        failed = case.find('failure') is not None or case.find('error') is not None
        outcome = 'failed' if failed else 'skipped' if case.find('skipped') is not None else 'passed'
        out.setdefault(f'{module}::{name}', []).append(outcome)
    return dict(sorted(out.items()))


def _check_state(check: IntegrityCheck, inputs: Inputs) -> str:
    if check.attestation:
        return {'pass': 'pass', 'fail': 'fail'}.get(inputs.attested.get(check.attestation, ''), 'missing')
    if not check.tests:
        return 'pending'
    found = [inputs.junit.get(t, []) if inputs.junit else [] for t in check.tests]
    if any('failed' in o for o in found):
        return 'fail'
    if any('skipped' in o for o in found):
        return 'blocked'
    return 'pass' if all(o for o in found) else 'missing'


def _g_u8(inputs: Inputs) -> tuple[Status, list[str], tuple[str, ...], dict]:
    if inputs.junit is None and not inputs.attested:
        return 'insufficient-data', ['no JUnit file and no attestation supplied'], (), {}
    states = [(c, _check_state(c, inputs)) for c in G_U8_CHECKS]
    observed = {'checks': [{'id': c.id, 'status': s} for c, s in states]}
    reasons = []
    for check, state in states:
        if state == 'fail':
            reasons.append(f'{check.id}: failed ({", ".join(check.tests) or check.attestation})')
        elif state == 'blocked':
            reasons.append(f'{check.id}: a required test was skipped, which is BLOCKED and not a pass')
        elif state == 'missing':
            reasons.append(f'{check.id}: no result for {", ".join(check.tests) or check.attestation}')
        elif state == 'pending':
            reasons.append(f'{check.id}: waits for {check.needs} to name the tests ({check.text})')
    kinds = {s for _, s in states}
    status: Status = ('fail' if 'fail' in kinds else 'pending' if 'pending' in kinds
                      else 'insufficient-data' if kinds & {'missing', 'blocked'} else 'pass')
    return status, reasons, tuple(sorted({c.needs for c, s in states if s == 'pending' and c.needs})), observed


# ---- G-U5 --------------------------------------------------------------------------------------------------------------------

def _g_u5(inputs: Inputs) -> tuple[Status, list[str], tuple[str, ...], dict]:
    benches = inputs.benches
    if not benches:
        return 'insufficient-data', ['no bench report supplied (python -m tools.unified.bench)'], (), {}
    rows = [row for b in benches for row in b.rows]
    failures = [f'{r.stage} n={r.n}: measurement failed ({r.error})' for r in rows if r.status != 'measured']
    failures += [f'{r.stage} n={r.n}: {g.name} {g.verdict} ({g.observed} against {g.allowed} allowed)'
                 for r in rows for g in r.gates if g.verdict == 'fail']
    failures += [f'{r.stage} n={r.n}: check {c.name} failed ({c.detail})' for r in rows for c in r.checks if not c.ok]
    windows = any('windows' in str(b.environment.get('platform', '')).lower() for b in benches)
    observed = {'measured': [b.verdict for b in benches], 'windows_report': windows,
                'reports': [{'platform': b.environment.get('platform'), 'verdict': b.verdict,
                             'counts_sha256': b.counts_sha256} for b in benches]}
    if failures:
        return 'fail', failures, (), observed
    if not any(r.gates for r in rows):
        return 'insufficient-data', ['no row at a gated size was measured (ladder 10k or 60k, ingest 60k: the sizes '
                                     'L-35 defines)'], (), observed
    reasons = [f'pending: {p.stage} needs {p.needs} ({p.what}; limit {p.limit} = {p.limit_value})'
               for p in benches[0].pending]
    if not windows:
        reasons.append('pending: no bench report from the Windows runner or the frozen EXE (numbers are recorded, '
                       'never extrapolated from Linux)')
    reasons += [f'pending: {w}' for w in BY_ID['G-U5'].waits]
    needs = tuple(sorted({p.needs for p in benches[0].pending} | {'S3'}))
    return ('pending' if reasons else 'pass'), reasons, needs, observed


# ---- G-U1 and G-U2 ------------------------------------------------------------------------------------------------------------

def _g_u_outcomes(gate: GateSpec, inputs: Inputs, facts: dict[str, dict]) -> tuple[Status, list[str], tuple[str, ...], dict]:
    if (inputs.manifest is None and gate.id != 'G-U4') or not inputs.outcomes:
        what = 'corpus manifest' if inputs.manifest is None and gate.id != 'G-U4' else 'unified-outcomes file (python -m tools.unified.live_pairs)'
        return 'insufficient-data', [f'no {what} supplied'], (), {'consumes': gate.consumes, 'corpus': facts.get(gate.id)}
    if gate.id == 'G-U4':
        status, reasons, observed = evaluators.g_u4(inputs.outcomes, inputs.manifest)
    else:
        evaluate = {'G-U1': evaluators.g_u1, 'G-U2': evaluators.g_u2, **rowgates.EVALUATORS}[gate.id]
        status, reasons, observed = evaluate(inputs.manifest, inputs.outcomes)
    return status, reasons, (), {**observed, 'corpus': facts.get(gate.id), 'runs': [o.run for o in inputs.outcomes]}


# ---- corpus readiness ----------------------------------------------------------------------------------------------------------

def corpus_facts(m: corpus_manifest.CorpusManifest | None) -> dict[str, dict]:
    """What the gates that wait for S3 will read, counted from the manifest: coverage, not results."""
    if m is None:
        return {}
    roles = Counter(p.role for p in m.pairs)
    mutants = Counter(p.mutation.unified_class for p in m.pairs if p.mutation)
    gate3 = [p for p in m.pairs if 'G-U3' in p.gates]
    lineages = len({p.lineage for p in gate3})
    return {
        'G-U1': {'P0': roles['P0'], 'P0_x_vs_x': sum(1 for p in m.pairs if p.role == 'P0' and p.x_vs_x),
                 'P1': roles['P1'], 'P2': roles['P2'], 'P1_variants': sorted({p.variant for p in m.pairs if p.role == 'P1' and p.variant}),
                 'pending_p1': [f'P1:{k}' for k in aa.P1_KINDS
                                if k not in {p.variant for p in m.pairs if p.role == 'P1'}]},
        'G-U2': {'mutants_per_class': {c.id: mutants.get(c.id, 0) for c in classes.CLASSES},
                 'classes_below_minimum': [c.id for c in classes.CLASSES if mutants.get(c.id, 0) < MIN_MUTANTS_PER_CLASS],
                 'minimum': MIN_MUTANTS_PER_CLASS,
                 'pending_classes': [{'class': x.item.split(':', 1)[1], 'reason': x.reason} for x in m.pending
                                     if x.item.startswith('mutation:')]},
        'G-U3': {'pairs': len(gate3), 'lineages': lineages, 'anti_conservative': lineages < MIN_GROUPS_HEADLINE}}


# ---- report -----------------------------------------------------------------------------------------------------------------------

def _evaluate(gate: GateSpec, inputs: Inputs, facts: dict[str, dict]) -> GateRow:
    if gate.id == 'G-U5':
        status, reasons, needs, observed = _g_u5(inputs)
    elif gate.id == 'G-U8':
        status, reasons, needs, observed = _g_u8(inputs)
    else:
        status, reasons, needs, observed = _g_u_outcomes(gate, inputs, facts)
    return GateRow(id=gate.id, question=gate.question, first_slice=gate.first_slice, status=status,
                   reasons=tuple(reasons), needs=needs, observed=observed)


def decision_ready(rows: Sequence[GateRow]) -> bool:
    """U-05: G-U1..G-U6 pass. G-U8 (integrity: snapshot untouched, no socket, schemas) additionally must not have failed."""
    return all(r.status == 'pass' for r in rows if r.id in U05_GATES) and not any(
        r.status == 'fail' for r in rows if r.id == INTEGRITY_GATE)


def _inputs_section(inputs: Inputs) -> dict[str, Any]:
    digests = inputs.digests
    return {'manifest': None if inputs.manifest is None else {
                'sha256': digests.get('manifest'), 'manifest_sha256': inputs.manifest.manifest_sha256,
                'pairs': len(inputs.manifest.pairs)},
            'bench': [{'sha256': (digests.get('bench') or [None] * len(inputs.benches))[i], 'verdict': b.verdict,
                       'platform': b.environment.get('platform'), 'counts_sha256': b.counts_sha256}
                      for i, b in enumerate(inputs.benches)],
            'outcomes': [{'sha256': (digests.get('outcomes') or [None] * len(inputs.outcomes))[i], 'run': o.run,
                          'platform': o.platform, 'outcomes_sha256': o.outcomes_sha256} for i, o in enumerate(inputs.outcomes)],
            'junit': None if inputs.junit is None else {'sha256': digests.get('junit'),
                                                        'tests': sum(len(v) for v in inputs.junit.values())},
            'attested': dict(sorted(inputs.attested.items()))}


def build_report(inputs: Inputs) -> GateReport:
    facts = corpus_facts(inputs.manifest)
    rows = [_evaluate(g, inputs, facts) for g in GATES]
    summary = {s: sum(1 for r in rows if r.status == s) for s in STATUSES}
    body = {'contract': CONTRACT, 'claim': CLAIM, 'inputs': _inputs_section(inputs),
            'gates': [r.model_dump(mode='json') for r in rows], 'summary': summary,
            'flag': {'default': 'off', 'decision_ready': decision_ready(rows), 'rule': U05_RULE}}
    return GateReport.model_validate_json(json.dumps({**body, 'report_sha256': digest(body, 'report_sha256')}))


def dump(report: GateReport) -> bytes:
    return dump_json(report.model_dump(mode='json'))


def load(data: bytes) -> GateReport:
    try:
        raw = strict_json(data)
        report = GateReport.model_validate_json(data)
    except (ValueError, ValidationError) as exc:
        raise ContractError(f'gate report invalid: {exc}') from None
    if digest(raw, 'report_sha256') != report.report_sha256:
        raise ContractError('gate report digest mismatch (edited after generation)')
    return report


def _cell(text: str) -> str:
    return ' '.join(text.replace('|', '/').split())


def _interval(ci: dict | None) -> str:
    if not ci or ci.get('point') is None:
        return 'n/a'
    low, high = ci.get('lo'), ci.get('hi')
    span = 'no interval' if low is None else f'95% CI {low:.4f} to {high:.4f}'
    return f'{ci["point"]:.4f} ({span}, {ci["groups"]} lineages{", anti-conservative" if ci["anti_conservative"] else ""})'


def numbers(g: GateRow) -> str:
    """The measured values of a gate on one line: counts, rates and intervals, never prose."""
    o = g.observed
    if g.id == 'G-U1' and 'evaluated' in o:
        states = Counter(o['evaluated'].values())
        return f'{len(o["evaluated"])} A/A pairs: ' + ', '.join(f'{k} {v}' for k, v in sorted(states.items()))
    if g.id == 'G-U2' and 'classes' in o:
        return '; '.join(f'{k} recall {v["recall"]} ({v["detected"]} hits, {v["mutants"]} mutants), leaks {v["leaks"]}'
                         for k, v in o['classes'].items())
    if g.id == 'G-U3' and 'rows' in o:
        return (f'{o["rows"]} matched rows, precision {_interval(o["precision"])}; tier-A contradicted '
                f'{len(o["tier_a_contradicted"])}; Ghidriff exact unmatched {len(o["ghidriff_exact_unmatched"])}; '
                f'demote {o["demote"] or "none"}')
    if g.id == 'G-U4' and 'compared' in o:
        return (f'compared {len(o["compared"])} pairs, mirrored {len(o["mirrored"])}, chains {o["chains"]["found"]} '
                f'({o["chains"]["composable"]} composable functions), COS-PSEUDO violations {o["pseudo_violations"]}')
    if g.id == 'G-U6' and 'per_tool' in o:
        return '; '.join(f'{t}: false leads {v["false_leads_unified"]} against {v["false_leads_legacy"]}, reduction '
                         f'{_interval(v["reduction"])}, recall {v["recall_unified"]} against {v["recall_legacy"]}'
                         for t, v in o['per_tool'].items()) or 'no legacy output'
    if g.id == 'G-U7' and 'class_pairs' in o:
        states = Counter(v['status'] for v in o['class_pairs'].values())
        return (f'tier-A error rate {o["tier_a"]["error_rate"]} over {o["tier_a"]["rows"]} rows; {len(o["class_pairs"])} '
                'class pairs: ' + ', '.join(f'{k} {v}' for k, v in sorted(states.items())))
    if g.id == 'G-U5' and 'measured' in o:
        return f'bench verdicts {o["measured"]}, Windows report {o["windows_report"]}'
    if g.id == 'G-U8' and 'checks' in o:
        return ', '.join(f'{c["id"]} {c["status"]}' for c in o['checks'])
    return '-'


def render_markdown(report: GateReport) -> str:
    waiting = [f'{g.id} {g.status}' for g in report.gates
               if (g.id in U05_GATES and g.status != 'pass') or (g.id == INTEGRITY_GATE and g.status == 'fail')]
    decision = ('READY: G-U1..G-U6 pass; record this report_sha256 in docs/qa.md before the flag changes' if report.flag.decision_ready
                else 'NOT READY, the flag stays OFF (O2); open: ' + ', '.join(waiting))
    lines = ['# SPEC-31 gate report', '', report.claim, '',
             f'Flag default: {report.flag.default}. Decision: {decision}. {report.flag.rule}', '',
             '| Gate | Status | Question | Why |', '|---|---|---|---|']
    lines += [f'| {g.id} | {g.status} | {_cell(g.question)} | {_cell("; ".join(g.reasons)) or "-"} |'
              for g in report.gates]
    lines += ['', '## Numbers', '', '| Gate | Measured |', '|---|---|']
    lines += [f'| {g.id} | {_cell(numbers(g))} |' for g in report.gates]
    lines += ['', 'Summary: ' + ', '.join(f'{k} {v}' for k, v in report.summary.items()),
              f'report_sha256 {report.report_sha256}', '']
    return '\n'.join(lines)


# ---- command line ------------------------------------------------------------------------------------------------------------------------

def _read(path: str) -> bytes:
    try:
        return Path(path).read_bytes()
    except OSError as exc:
        raise ContractError(f'cannot read {path}: {exc.strerror or exc}') from None


def expand_inputs(directory: str) -> dict[str, list[str]]:
    """The files of a download directory by role, sorted; links and sub-directories are ignored, never followed."""
    root = Path(directory)
    if not root.is_dir():
        raise ContractError(f'--inputs {directory} is not a directory')

    def pick(pattern: str) -> list[str]:
        return [str(p) for p in sorted(root.glob(pattern)) if p.is_file() and not p.is_symlink()]
    return {'manifest': pick('unified-corpus-manifest.json'), 'outcomes': pick('outcomes-*.json'),
            'bench': pick('bench-*.json'), 'junit': pick('junit-*.xml')}


def _attestations(items: Sequence[str]) -> dict[str, str]:
    out = {}
    for item in items:
        name, _, value = item.partition('=')
        if name not in ATTESTABLE or value not in ('pass', 'fail'):
            raise ContractError(f'--attest takes NAME=pass|fail with NAME one of {", ".join(ATTESTABLE)}; got {item!r}')
        out[name] = value
    return out


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog='python -m tools.unified.gates_u', description=__doc__.split('\n\n')[0])
    parser.add_argument('--inputs', help='a directory holding unified-corpus-manifest.json, outcomes-*.json, bench-*.json '
                                         'and junit-*.xml (the layout the live workflow downloads); added to the options below')
    parser.add_argument('--manifest', help='unified-corpus-manifest/1')
    parser.add_argument('--bench', action='append', default=[], help='bench-report/1 (repeat for Linux and Windows)')
    parser.add_argument('--outcomes', action='append', default=[], help='unified-outcomes/1 (repeat for every run)')
    parser.add_argument('--junit', action='append', default=[], help='pytest --junitxml file (repeat to merge)')
    parser.add_argument('--attest', action='append', default=[], help='NAME=pass|fail for a CI step that is no test')
    parser.add_argument('--out', help='write gate-report/1 here')
    parser.add_argument('--markdown', help='write the Markdown rendering here')
    parser.add_argument('--strict', action='store_true', help='exit 1 unless every gate passes (default: advisory)')
    args = parser.parse_args(argv)
    try:
        if args.inputs:
            found = expand_inputs(args.inputs)
            args.manifest = args.manifest or (found['manifest'] or [None])[0]
            args.bench, args.outcomes, args.junit = (args.bench + found['bench'], args.outcomes + found['outcomes'],
                                                     args.junit + found['junit'])
        inputs = Inputs(attested=_attestations(args.attest))
        if args.manifest:
            raw = _read(args.manifest)
            inputs.manifest, inputs.digests['manifest'] = corpus_manifest.load(raw), hashlib.sha256(raw).hexdigest()
        raws = [_read(p) for p in args.bench]
        inputs.benches, inputs.digests['bench'] = [bench.load(r) for r in raws], [hashlib.sha256(r).hexdigest() for r in raws]
        raws = [_read(p) for p in args.outcomes]
        inputs.outcomes, inputs.digests['outcomes'] = [outcomes.load(r) for r in raws], [hashlib.sha256(r).hexdigest() for r in raws]
        raws = [_read(p) for p in args.junit]
        if raws:
            inputs.junit = {}
            for raw in raws:
                for key, results in parse_junit(raw).items():
                    inputs.junit.setdefault(key, []).extend(results)
            inputs.digests['junit'] = [hashlib.sha256(r).hexdigest() for r in raws]
        report = build_report(inputs)
    except ContractError as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 2
    text = render_markdown(report)
    print(text)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_bytes(dump(report))
    if args.markdown:
        Path(args.markdown).parent.mkdir(parents=True, exist_ok=True)
        Path(args.markdown).write_text(text, encoding='utf-8', newline='\n')
    return 1 if args.strict and any(g.status != 'pass' for g in report.gates) else 0


if __name__ == '__main__':
    raise SystemExit(main())
