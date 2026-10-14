"""Regenerate the pilot/1 artefacts (PIL-A1; docs/specs/program-e/PIL-integration-plan.md s7).

Run from the repository root:

    PYTHONPATH=src python tools/generate_pilot_schemas.py          # write
    PYTHONPATH=src python tools/generate_pilot_schemas.py --check  # exit 1 on drift

Outputs, all deterministic, offline and SYNTHETIC (CVE-2099-*, sample digests; no Microsoft data, no binaries):
- ``docs/schemas/pilot/<Model>.json``: JSON Schemas of the persisted pilot contracts;
- ``docs/schemas/pilot/examples/<name>.json``: valid and invalid documents; every id and digest of a valid document
  is derived through ``patchtrace.pilot.keys``, so the examples certify themselves;
- ``docs/schemas/pilot/examples/index.json``: model, validity and the reason an invalid example is rejected for.

Kept apart from ``tools/generate_schemas.py``, which another track owns. Files are written with LF on every OS.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'docs' / 'schemas' / 'pilot'
EXAMPLES = OUT / 'examples'
if str(ROOT / 'src') not in sys.path:  # run without PYTHONPATH=src
    sys.path.insert(0, str(ROOT / 'src'))

from patchtrace.pilot import contracts as c  # noqa: E402
from patchtrace.pilot import keys, origins  # noqa: E402

CVE = 'CVE-2099-20001'
CREATED = '2099-03-01T12:00:00+00:00'
FUNCTIONS = {  # name -> (older rva, newer rva); the plan's synergy scenario (s5), shrunk to three functions
    'Ipv6pReassembleFragment': (0x1180, 0x11C0),
    'Ipv6pReassembleFragmentTail': (0x1400, 0x1440),
    'Ipv6pDispatch': (0x1900, 0x1940)}
F1, F9, F7 = 'Ipv6pReassembleFragment', 'Ipv6pReassembleFragmentTail', 'Ipv6pDispatch'


def _h(tag: str) -> str:
    return hashlib.sha256(f'pilot-example-{tag}'.encode()).hexdigest()


OLDER, NEWER = _h('older'), _h('newer')


def _key(name: str) -> str:
    old, new = FUNCTIONS[name]
    return keys.candidate_key(OLDER, NEWER, [old], [new])


def _sides(name: str) -> dict:
    old, new = FUNCTIONS[name]
    return {'older': (c.FunctionRef(rva=old, name=name),), 'newer': (c.FunctionRef(rva=new, name=name),)}


def _nav(name: str, line: int | None = None) -> c.Nav:
    return c.Nav(side='newer', rva=FUNCTIONS[name][1], start_line=line, end_line=line)


# --- the synthetic scenario --------------------------------------------------------------------------------------------

def example_observations() -> dict[str, c.Observation]:
    """The ledger: advisory claim, B1 and ChangeFacts shape for F1 and F9, a call label, locality, a conflict, context."""
    make = keys.make_observation
    return {
        'adv': make(channel='advisory', kind='adv:cwe-stated', role='context', verification='advisory-claim',
                    origins=('D_vendor_text',), evidence_class='E-TEXT',
                    ref=c.ObsRef(kind='csaf-fact', id=CVE, pointer='/vulnerabilities/0/cwe', sha256=_h('csaf-source')),
                    detail='CWE-787 as stated by the advisory'),
        'b1_f1': make(channel='code', kind='b1:BND', role='shape', verification='tool-reported',
                      origins=('D_ghidra',), evidence_class='E-DECOMP',
                      ref=c.ObsRef(kind='b1-signal', id=_h('signal-f1-bnd')), nav=_nav(F1, 14),
                      detail='bounds check added before the copy'),
        'cf_f1': make(channel='code', kind='cf:comparison', role='shape', verification='tool-reported',
                      origins=('D_ghidra',), evidence_class='E-BODY',
                      ref=c.ObsRef(kind='change-facts', id=_key(F1)), nav=_nav(F1, 14),
                      detail='new comparison against the fragment length'),
        'call_f1': make(channel='calls', kind='call:added', role='shape', verification='label-only',
                        origins=('D_ghidra',), evidence_class='E-CALL', anchor_ids=('api:RtlSizeTAdd',),
                        ref=c.ObsRef(kind='call-label', id='RtlSizeTAdd'),
                        detail='call to RtlSizeTAdd added (label only)'),
        'loc_f1': make(channel='code', kind='loc:names', role='local', verification='label-only',
                       origins=('D_symbols',), evidence_class='E-NAME',
                       ref=c.ObsRef(kind='name-tokens', id='fragment+reassemble'),
                       detail=f'{F1} shares fragment and reassemble with the advisory title'),
        'b1_f9': make(channel='code', kind='b1:BND', role='shape', verification='tool-reported',
                      origins=('D_ghidra',), evidence_class='E-DECOMP',
                      ref=c.ObsRef(kind='b1-signal', id=_h('signal-f9-bnd')), nav=_nav(F9, 22),
                      detail='bounds check added before the copy'),
        'cos_f9': make(channel='code', kind='cf:cosmetic', role='conflict', verification='tool-reported',
                       origins=('D_ghidra',), evidence_class='E-LAYOUT',
                       ref=c.ObsRef(kind='change-facts', id=_key(F9)), nav=_nav(F9, 22),
                       detail='proof COS-LAYOUT/1 holds: the old check was only moved'),
        'loc_f9': make(channel='code', kind='loc:names', role='local', verification='label-only',
                       origins=('D_symbols',), evidence_class='E-NAME',
                       ref=c.ObsRef(kind='name-tokens', id='fragment+reassemble'),
                       detail=f'{F9} shares fragment and reassemble with the advisory title'),
        'cf_f7': make(channel='code', kind='cf:callee', role='context', verification='tool-reported',
                      origins=('D_ghidra',), evidence_class='E-CALL',
                      ref=c.ObsRef(kind='change-facts', id=_key(F7)), nav=_nav(F7),
                      detail='callee of one call replaced')}


def _ids(*observations: c.Observation) -> tuple[str, ...]:
    return tuple(sorted(o.obs_id for o in observations))


def _change(change_id: str, state: str, required: bool, *observations: c.Observation) -> c.ExpectedChange:
    return c.ExpectedChange(id=change_id, state=state, required=required, observation_ids=_ids(*observations),
                            teach_id=f'pilot.change.{change_id}')


def _fit(changes: tuple[c.ExpectedChange, ...]) -> c.HypothesisFit:
    return c.HypothesisFit(hypothesis_id=_h('hypothesis-memory-write'), rule_id='R-MEMORY-WRITE', rule_revision=1,
                           cwe_id='CWE-787', basis='explicit-csaf-cwe', expected_changes=changes,
                           met=sum(1 for x in changes if x.state == 'met'), total=len(changes))


def example_leads() -> tuple[c.Lead, c.Lead, c.Lead]:
    o = example_observations()
    advisory = o['adv'].origins
    fit1 = _fit((_change('guard-added', 'met', True, o['b1_f1'], o['cf_f1']),
                 _change('size-recomputed', 'not-observed', False),
                 _change('checked-arithmetic', 'met', False, o['call_f1'])))
    fit9 = _fit((_change('guard-added', 'met', True, o['b1_f9']),
                 _change('size-recomputed', 'not-observed', False),
                 _change('checked-arithmetic', 'not-observed', False)))
    lead1 = c.Lead(
        candidate_key=_key(F1), cve=CVE, lead_class='fit', mechanism='moderate', identity='corroborated',
        gate='applies', depth='typed', fits=(fit1,),
        components=origins.lead_components([advisory, o['b1_f1'].origins, o['cf_f1'].origins, o['call_f1'].origins]),
        local_hits=2, support_ids=_ids(o['adv'], o['b1_f1'], o['cf_f1'], o['call_f1'], o['loc_f1']),
        rank=1, tie=c.Tie(size=1, first=1, last=1), assessment='rule-hypothesis', **_sides(F1))
    lead9 = c.Lead(
        candidate_key=_key(F9), cve=CVE, lead_class='review', mechanism='contested', identity='corroborated',
        gate='applies', depth='lexical', fits=(fit9,),
        components=origins.lead_components([advisory, o['b1_f9'].origins]), local_hits=2,
        support_ids=_ids(o['adv'], o['b1_f9'], o['loc_f9']), counter_ids=_ids(o['cos_f9']),
        rank=2, tie=c.Tie(size=1, first=2, last=2), assessment='rule-hypothesis', **_sides(F9))
    lead7 = c.Lead(
        candidate_key=_key(F7), cve=CVE, lead_class='queue', mechanism='unexplained', identity='corroborated',
        gate='applies', depth='none', components=c.LeadComponents(count=0, tags=()), support_ids=_ids(o['cf_f7']),
        rank=3, tie=c.Tie(size=1, first=3, last=3), assessment='unknown', **_sides(F7))
    return lead1, lead9, lead7


def example_code_lead() -> c.Lead:
    """Code evidence only (no advisory): class `code`, mechanism `not-assessed`, gate `none`."""
    return c.Lead(
        candidate_key=_key(F7), cve=None, lead_class='code', mechanism='not-assessed', identity='unassessed',
        gate='none', depth='none', components=c.LeadComponents(count=0, tags=()),
        support_ids=_ids(example_observations()['cf_f7']), rank=1, tie=c.Tie(size=1, first=1, last=1),
        assessment='unknown', **_sides(F7))


def example_context() -> c.CveContext:
    return c.CveContext(
        cve=CVE, source_ids=(_h('csaf-source'),), gate='applies',
        applicability=c.ApplicabilitySummary(older='affected', newer='fixed', older_mapping='verified',
                                             newer_mapping='verified'),
        cwe=c.CweSummary(status='explicit', ids=('CWE-787',)),
        kev=c.Kev(state='listed', date_added='2099-02-10', snapshot_id=_h('kev-snapshot')),
        confounding=c.Confounding(state='yes', cves=(CVE, 'CVE-2099-20002')),
        counts=c.LeadCounts(fit=1, review=1, partial=0, code=0, queue=1),
        limitations=('capa and FLOSS were not run',))


def example_not_applicable() -> c.CveContext:
    return c.CveContext(
        cve='CVE-2099-20003', source_ids=(_h('csaf-source'),), gate='not-applicable',
        applicability=c.ApplicabilitySummary(older='not_affected', newer='not_affected', older_mapping='verified',
                                             newer_mapping='verified'),
        cwe=c.CweSummary(status='derived', ids=('CWE-125',)), kev=c.Kev(state='not-in-snapshot',
                                                                         snapshot_id=_h('kev-snapshot')),
        confounding=c.Confounding(state='no'), counts=c.LeadCounts(fit=0, review=0, partial=0, code=0, queue=0),
        limitations=('The advisory says these builds are not affected by CVE-2099-20003',))


def example_config() -> c.PilotConfig:
    return keys.default_config()


def example_inputs(**over) -> c.PilotInputs:
    data = dict(older_sha256=OLDER, newer_sha256=NEWER, ghidriff_run_id='run-1', raw_sha256=_h('ghidriff-raw'),
                unified_result_id=_h('unified-result'), secondary_set_ids=(_h('secondary-bindiff'),),
                advisory_facts_ids=(_h('csaf-facts'),), kev_snapshot_id=_h('kev-snapshot'),
                lexicon_digest=_h('lexicon'), rules_digest=_h('k-rules'), pilot_rules_digest=_h('pilot-rules'),
                origins_digest=origins.digest(), tiers_version=1, config_digest=keys.config_digest(example_config()))
    data.update(over)
    return c.PilotInputs(**data)


def _channels(state: dict[str, tuple[str, str | None]]) -> tuple[c.ChannelStatus, ...]:
    return tuple(c.ChannelStatus(channel=name, state=state[name][0], reason=state[name][1]) for name in c.CHANNELS)


def example_assessment() -> c.PilotAssessment:
    inputs = example_inputs()
    channels = _channels({
        'advisory': ('available', None), 'code': ('available', None),
        'calls': ('partial', 'Ghidriff call labels only; no import delta'),
        'strings': ('not-run', 'FLOSS has not been run'), 'capa': ('not-run', 'capa has not been run'),
        'build': ('not-run', 'Detect It Easy has not been run'), 'pairing': ('available', None)})
    return c.PilotAssessment(
        result_id=keys.result_id(inputs), project_id='4f1c2a7e-0b6d-4c1e-9a52-2d7d5a3a9c10', revision=3,
        older_sha256=OLDER, newer_sha256=NEWER, inputs=inputs, channels=channels, cves=(example_context(),),
        leads=example_leads(), queue_count=1,
        observations=tuple(sorted(example_observations().values(), key=lambda x: x.obs_id)), status='complete',
        limitations=('capa and FLOSS were not run: missing evidence is unknown, not a negative result',),
        created_utc=CREATED)


def example_abstained() -> c.PilotAssessment:
    inputs = example_inputs(unified_result_id=None, secondary_set_ids=(), advisory_facts_ids=(), kev_snapshot_id=None)
    channels = _channels({name: ('not-run', 'No comparison result yet' if name == 'pairing' else None)
                          for name in c.CHANNELS})
    return c.PilotAssessment(
        result_id=keys.result_id(inputs), project_id='4f1c2a7e-0b6d-4c1e-9a52-2d7d5a3a9c10', revision=1,
        older_sha256=OLDER, newer_sha256=NEWER, inputs=inputs, channels=channels, status='abstained',
        limitations=('No comparison result yet: leads are computed from stored results only',), created_utc=CREATED)


def example_review(action: str) -> c.ReviewEvent:
    if action == 'pin':
        return c.ReviewEvent(candidate_key=_key(F1), cve=CVE, action='pin', created_utc='2099-03-01T13:00:00+00:00')
    return c.ReviewEvent(
        candidate_key=_key(F9), cve=CVE, action='note', created_utc='2099-03-01T13:05:00+00:00',
        text='Checked the newer function: the bound only moved.\nThe advisory title still fits the name.')


def example_manifest() -> c.PilotManifest:
    return keys.make_manifest(example_assessment(), example_config(), created_utc='2099-03-01T12:00:05+00:00')


# --- documents --------------------------------------------------------------------------------------------------------

def _doc(record) -> dict:
    return json.loads(record.model_dump_json())


def _mut(document, path: tuple, value=None, *, drop: bool = False):
    """A deep copy of `document` with one value replaced (or removed)."""
    out = json.loads(json.dumps(document))
    target = out
    for part in path[:-1]:
        target = target[part]
    if drop:
        del target[path[-1]]
    else:
        target[path[-1]] = value
    return out


def _many(document, *changes):
    for path, value in changes:
        document = _mut(document, path, value)
    return document


def build_examples() -> dict[str, tuple[str, object, str | None]]:
    """File name -> (model name, document, expected rejection text or None for a valid example)."""
    assessment = _doc(example_assessment())
    lead_fit, lead_review, lead_queue = assessment['leads']
    code_lead = _doc(example_code_lead())
    context = assessment['cves'][0]
    observation = assessment['observations'][0]
    die = _doc(keys.make_observation(
        channel='build', kind='die:toolchain-changed', role='context', verification='tool-reported',
        origins=('D_compiler',), evidence_class='E-BUILD', ref=c.ObsRef(kind='die-flag', id='toolchain-changed'),
        detail='The compiler or linker version differs between the builds'))
    conflict = next(o for o in assessment['observations'] if o['kind'] == 'cf:cosmetic')
    pin, note = _doc(example_review('pin')), _doc(example_review('note'))
    manifest = _doc(example_manifest())
    pointer = _doc(keys.make_pointer(example_manifest()))
    none_counts = {'fit': 0, 'review': 0, 'partial': 0, 'code': 0, 'queue': 0}
    reordered = _mut(assessment, ('leads',), [
        lead_fit, {**lead_queue, 'rank': 2, 'tie': {'size': 1, 'first': 2, 'last': 2}},
        {**lead_review, 'rank': 3, 'tie': {'size': 1, 'first': 3, 'last': 3}}])
    ghost = _h('no-such-observation')
    A = 'PilotAssessment'
    return {
        'valid-PilotAssessment.json': (A, assessment, None),
        'valid-PilotAssessment-abstained.json': (A, _doc(example_abstained()), None),
        'valid-Lead-code-only.json': ('Lead', code_lead, None),
        'valid-Observation-conflict.json': ('Observation', conflict, None),
        'valid-Observation-die-context.json': ('Observation', die, None),
        'valid-CveContext-not-applicable.json': ('CveContext', _doc(example_not_applicable()), None),
        'valid-ReviewEvent-pin.json': ('ReviewEvent', pin, None),
        'valid-ReviewEvent-note.json': ('ReviewEvent', note, None),
        'valid-PilotResultPointer.json': ('PilotResultPointer', pointer, None),
        'valid-PilotManifest.json': ('PilotManifest', manifest, None),
        # PilotAssessment: cross-record invariants, the frozen vocabulary and the no-float rule
        'invalid-PilotAssessment-strong-mechanism.json': (
            A, _mut(assessment, ('leads', 0, 'mechanism'), 'strong'), 'reserved'),
        'invalid-PilotAssessment-float-rank.json': (A, _mut(assessment, ('leads', 0, 'rank'), 1.0), 'rank'),
        'invalid-PilotAssessment-dangling-observation.json': (
            A, _mut(assessment, ('leads', 0, 'support_ids'), [ghost]), 'unknown observation'),
        'invalid-PilotAssessment-unknown-cve-context.json': (
            A, _mut(assessment, ('leads', 0, 'cve'), 'CVE-2099-99999'), 'unknown CVE context'),
        'invalid-PilotAssessment-orientation-swapped.json': (
            A, _mut(assessment, ('orientation',), 'newer->older'), 'orientation'),
        'invalid-PilotAssessment-inputs-mismatch.json': (
            A, _mut(assessment, ('inputs', 'older_sha256'), _h('foreign')), 'inputs must match'),
        'invalid-PilotAssessment-channels-out-of-order.json': (
            A, _mut(assessment, ('channels',), assessment['channels'][::-1]), 'channels must be unique'),
        'invalid-PilotAssessment-contract-version.json': (A, _mut(assessment, ('contract',), 'pilot/2'), 'contract'),
        'invalid-PilotAssessment-abstained-with-leads.json': (
            A, _mut(assessment, ('status',), 'abstained'), 'abstained assessment has no leads'),
        'invalid-PilotAssessment-partial-without-limitations.json': (
            A, _many(assessment, (('status',), 'partial'), (('limitations',), [])), 'names its limitations'),
        'invalid-PilotAssessment-rank-order-vs-class.json': (A, reordered, 'class order'),
        'invalid-PilotAssessment-counts-below-persisted.json': (
            A, _mut(assessment, ('cves', 0, 'counts', 'fit'), 0), 'exceed the counts'),
        'invalid-PilotAssessment-lead-for-not-applicable-cve.json': (
            A, _many(assessment, (('cves', 0, 'gate'), 'not-applicable'), (('cves', 0, 'counts'), none_counts)),
            'has no leads'),
        'invalid-PilotAssessment-pool-unsorted.json': (
            A, _mut(assessment, ('observations',), assessment['observations'][::-1]), 'sorted by obs_id'),
        'invalid-PilotAssessment-duplicate-candidate.json': (
            A, _mut(assessment, ('leads', 1, 'candidate_key'), lead_fit['candidate_key']), 'one lead per'),
        'invalid-PilotAssessment-unknown-field.json': (A, _mut(assessment, ('surprise',), 1), 'Extra inputs'),
        # Lead: the class, gate, identity and tier rules of s7
        'invalid-Lead-strong-mechanism.json': ('Lead', _mut(lead_fit, ('mechanism',), 'strong'), 'reserved'),
        'invalid-Lead-fit-with-tentative-mechanism.json': (
            'Lead', _mut(lead_fit, ('mechanism',), 'tentative'), 'requires mechanism'),
        'invalid-Lead-fit-under-unverified-gate.json': (
            'Lead', _mut(lead_fit, ('gate',), 'unverified'), 'unverified CVE gate'),
        'invalid-Lead-fit-under-conflicting-gate.json': (
            'Lead', _mut(lead_fit, ('gate',), 'conflict'), 'conflicting CVE gate'),
        'invalid-Lead-fit-with-contested-pairing.json': (
            'Lead', _mut(lead_fit, ('identity',), 'contested'), 'contested pairing'),
        'invalid-Lead-fit-with-one-component.json': (
            'Lead', _mut(lead_fit, ('components',), {'count': 1, 'tags': ['D_ghidra']}), 'independent components'),
        'invalid-Lead-tie-arithmetic.json': (
            'Lead', _mut(lead_fit, ('tie',), {'size': 3, 'first': 1, 'last': 1}), 'tie size'),
        'invalid-Lead-gate-not-applicable.json': ('Lead', _mut(lead_fit, ('gate',), 'not-applicable'), 'gate'),
        'invalid-Lead-code-lead-with-cve.json': (
            'Lead', _many(code_lead, (('cve',), CVE), (('gate',), 'applies')), 'code-only'),
        'invalid-Lead-cap-without-gate.json': ('Lead', _mut(lead_fit, ('caps',), ['cve-conflict']), 'needs gate'),
        # Observation: plain text, provenance and the "flags never promote" rule
        'invalid-Observation-die-flag-as-shape.json': (
            'Observation', _mut(die, ('role',), 'shape'), 'context only'),
        'invalid-Observation-no-origin.json': ('Observation', _mut(observation, ('origins',), []), 'origins'),
        'invalid-Observation-newline-in-detail.json': (
            'Observation', _mut(observation, ('detail',), 'two\nlines'), 'plain text'),
        'invalid-Observation-bidi-in-detail.json': (
            'Observation', _mut(observation, ('detail',), 'fix‮evil'), 'plain text'),
        'invalid-Observation-kind-channel-mismatch.json': (
            'Observation', _many(observation, (('kind',), 'b1:BND'), (('channel',), 'calls')), 'belongs to channel'),
        # CveContext
        'invalid-CveContext-not-applicable-with-leads.json': (
            'CveContext', _mut(context, ('gate',), 'not-applicable'), 'produces no leads'),
        'invalid-CveContext-kev-listed-without-date.json': (
            'CveContext', _mut(context, ('kev',), {'state': 'listed', 'date_added': None,
                                                   'snapshot_id': _h('kev-snapshot')}), 'needs its date'),
        'invalid-CveContext-window-one-cve.json': (
            'CveContext', _mut(context, ('confounding',), {'state': 'yes', 'cves': [CVE]}), 'at least two'),
        # ReviewEvent
        'invalid-ReviewEvent-note-without-text.json': (
            'ReviewEvent', _many(pin, (('action',), 'note'), (('text',), '')), 'needs text'),
        'invalid-ReviewEvent-unknown-action.json': ('ReviewEvent', _mut(pin, ('action',), 'verify'), 'action'),
        'invalid-ReviewEvent-oversize-text.json': (
            'ReviewEvent', _many(pin, (('action',), 'note'), (('text',), 'é' * 1100)), 'at most 2048 bytes'),
        # pointer and manifest
        'invalid-PilotResultPointer-dir-mismatch.json': (
            'PilotResultPointer', _mut(pointer, ('relative_dir',), 'intelligence/pilot/0000000000000000'),
            'result_id[:16]'),
        'invalid-PilotManifest-missing-assessment-part.json': (
            'PilotManifest', _mut(manifest, ('parts',), []), 'assessment.json.gz'),
        'invalid-PilotManifest-config-float.json': (
            'PilotManifest', _mut(manifest, ('config', 'locality_min_tokens'), 2.0), 'locality_min_tokens'),
    }


# --- rendering ----------------------------------------------------------------------------------------------------------

def _json(value) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + '\n'


def render_schemas() -> dict[Path, str]:
    out = {}
    for model, ident in c.SCHEMA_MODELS:
        schema = model.model_json_schema()
        schema['$id'] = f'https://patchtrace.local/schemas/{ident}/{model.__name__}.json'
        schema['$schema'] = 'https://json-schema.org/draft/2020-12/schema'
        out[OUT / f'{model.__name__}.json'] = _json(schema)
    return out


def render_examples() -> dict[Path, str]:
    out, index = {}, {}
    for name, (model, document, expect) in build_examples().items():
        out[EXAMPLES / name] = _json(document)
        index[name] = {'model': model, 'valid': expect is None, 'expect': expect}
    out[EXAMPLES / 'index.json'] = _json(index)
    return out


def render() -> dict[Path, str]:
    """Every generated file and its exact text (a pure function of the repository contents)."""
    return {**render_schemas(), **render_examples()}


def _shown(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def main(argv: list[str]) -> int:
    check = '--check' in argv
    rendered = render()
    drift = []
    for path, text in rendered.items():
        if check:
            current = path.read_text(encoding='utf-8') if path.is_file() else None
            if current != text:
                drift.append(_shown(path))
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding='utf-8', newline='\n')
    for folder in (OUT, EXAMPLES):  # files nothing renders any more
        for path in sorted(folder.glob('*.json')):
            if path not in rendered:
                if check:
                    drift.append(_shown(path))
                else:
                    path.unlink()
    for item in drift:
        print(f'stale: {item}', file=sys.stderr)
    return 1 if drift else 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
