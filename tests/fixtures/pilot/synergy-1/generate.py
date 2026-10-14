"""Regenerate the PIL-T synergy oracle (docs/specs/program-e/PIL-integration-plan.md s5; slice PIL-T).

Run from the repository root:

    PYTHONPATH=src python tests/fixtures/pilot/synergy-1/generate.py          # write
    PYTHONPATH=src python tests/fixtures/pilot/synergy-1/generate.py --check  # exit 1 on drift

Everything here is SYNTHETIC (CVE-2099-*, invented digests, no Microsoft data, no binaries) and deterministic. The two
tables of plan s5 (the nine functions and the nine arms) are transcribed below exactly as the plan prints them; the
structured values of ``expected.json`` (rank ranges, tie partners, FITS sets) are parsed from those cells, not typed a
second time. ``tests/test_pilot_synergy.py`` checks the transcription against the plan and the files against this module.

Outputs:
- ``synthetic-pilot-advisory.json``: validator-clean CSAF 2.0 for CVE-2099-20001 (CWE-787) and CVE-2099-20002 (CWE-125);
- ``sample-cwe125-advisory.json``: validator-clean CSAF 2.0 for the committed sample project (CWE-125, one CVE);
- ``ledger.json``: the hand-built observation ledger (candidates, observations, CVE contexts, KEV snapshot, tool keys);
- ``expected.json``: the oracle (the s5 tables, the full-arm classes per CVE, KEV and the "why" facts for F1).
Files are written with LF on every OS.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
if str(ROOT / 'src') not in sys.path:  # run without PYTHONPATH=src
    sys.path.insert(0, str(ROOT / 'src'))

from patchtrace.pilot import contracts as c  # noqa: E402
from patchtrace.pilot import keys  # noqa: E402
from patchtrace.sample import synthetic_pe  # noqa: E402

SCENARIO = 'synergy-1'
PLAN = 'docs/specs/program-e/PIL-integration-plan.md'
MODULE = 'examplenet.sys'
CVE1, CVE2 = 'CVE-2099-20001', 'CVE-2099-20002'
CVE_SAMPLE = 'CVE-2099-30001'
IMAGE_BASE = 0x180000000
NEWER_SHIFT = 0x40  # every function moves by the same amount between the builds
CSAF_NAME = 'synthetic-pilot-advisory.json'
SAMPLE_CSAF_NAME = 'sample-cwe125-advisory.json'
KEV_DATE = '2099-02-10'


def _h(tag: str) -> str:
    return hashlib.sha256(f'pilot-synergy-1-{tag}'.encode()).hexdigest()


# No binary exists: these are labels hashed, like the other synthetic digests of the pilot examples.
OLDER = hashlib.sha256(b'PatchTrace synergy-1 SYNTHETIC examplenet.sys older build: no binary exists').hexdigest()
NEWER = hashlib.sha256(b'PatchTrace synergy-1 SYNTHETIC examplenet.sys newer build: no binary exists').hexdigest()

# --- plan s5, table 1: the nine functions (Id, Function (pair), Evidence in the ledger), verbatim -----------------------
FUNCTION_TABLE = (
    ('F1', 'Ipv6pReassembleFragment',
     'B1 BND, ChangeFacts comparison (material, C6-anchored), call added RtlSizeTAdd (label), names fragment+reassemble'),
    ('F6', 'Ipv6pParseOptions', 'same guard shape, names options+parse'),
    ('F8', 'Ipv6pFragmentListReassemble', 'same shape and names, pairing contested (Ghidriff versus BinDiff)'),
    ('F9', 'Ipv6pReassembleFragmentTail',
     'B1 BND but ChangeFacts cosmetic COS-LAYOUT/1 (decompiler moved an old check), names match'),
    ('F4', 'Ipv6pFragmentInit', 'B1 SIZE (allocation 0x40 to 0x80), no guard'),
    ('F5', 'Ipv6pFragmentReassemblyStats', 'call added to a counter, names match, no shape'),
    ('F2', 'Ipv6pLogFragmentDrop', 'new string "Dropped oversize fragment" (FLOSS) and a ChangeFacts string delta'),
    ('F3', 'Ipv6pChecksumFragment', 'register-only and address-only churn, DiE toolchain-changed'),
    ('F7', 'Ipv6pDispatch', 'callee swapped (top ChangeFacts severity)'),
)
OLDER_RVA = {'F1': 0x1180, 'F6': 0x1280, 'F8': 0x1300, 'F9': 0x1400, 'F4': 0x1500, 'F5': 0x1600, 'F2': 0x1700,
             'F3': 0x1800, 'F7': 0x1900}  # F1, F9 and F7 equal the pilot schema examples (tools/generate_pilot_schemas.py)

# --- plan s5, table 2: F1 per arm, verbatim (Arm | F1 rank (tie range) | FITS leads | Why it falls short) --------------
ARM_TABLE = (
    ('Full', '1', 'F1', 'none'),
    ('Advisory text only', '1-3 (with F9, F5)', 'none', 'names cannot separate, no code evidence'),
    ('B1 signals only', '1-5', 'n/a', 'guard shape fits five pairs'),
    ('ChangeFacts only', '3-5, top is F5/F7', 'n/a', 'severity order favours callee changes'),
    ('FLOSS strings only', '2-8, top is F2', 'n/a', 'the new string is the logging decoy'),
    ('Advisory + B1, no ChangeFacts', '1-2 (with F9)', 'F1, F9', 'no cosmetic proof, decompiler churn passes as a fit'),
    ('Advisory + ChangeFacts, no B1', '1', 'F1', 'B1 shares `D_ghidra`, so it adds no independence'),
    ('Full minus name locality', '1', 'none',
     'confounded window: shape alone cannot isolate; F1 still first on expected changes'),
    ('Full, window unknown', '1', 'F1, F6', 'F6 listed second; the caption says the window is unknown'),
)
# Evidence sources an arm lets through (observation kind prefix: advisory adv, b1, cf, calls call, floss str, capa, die;
# `pairing` is the candidate universe with its verdicts). `pairing` and `die` (build facts) are context in every arm; the
# arms ablate the four evidence channels the table names, plus the calls channel, which the single-channel rows leave out.
ALL_SOURCES = ('advisory', 'b1', 'cf', 'calls', 'floss', 'capa', 'die', 'pairing')
ARM_DEFS = {  # id -> (arm label in ARM_TABLE, evidence sources, function names visible, window state)
    'full': ('Full', ALL_SOURCES, True, 'yes'),
    'adv': ('Advisory text only', ('advisory', 'die', 'pairing'), True, 'yes'),
    'b1': ('B1 signals only', ('b1', 'die', 'pairing'), True, 'yes'),
    'cf': ('ChangeFacts only', ('cf', 'die', 'pairing'), True, 'yes'),
    'floss': ('FLOSS strings only', ('floss', 'die', 'pairing'), True, 'yes'),
    'adv-b1': ('Advisory + B1, no ChangeFacts', ('advisory', 'b1', 'die', 'pairing'), True, 'yes'),
    'adv-cf': ('Advisory + ChangeFacts, no B1', ('advisory', 'cf', 'die', 'pairing'), True, 'yes'),
    'no-names': ('Full minus name locality', ALL_SOURCES, False, 'yes'),
    'window-unknown': ('Full, window unknown', ALL_SOURCES, True, 'unknown'),
}
# Sentences of plan s5 ("Expected output ...") that the expected full-arm classes restate; the test finds each verbatim.
PLAN_QUOTES = (
    'F1 rank 1, FITS ADVISORY (expected changes 2 of 3, components 2, locality 2, tie size 1).',
    'F9 and F8 NEEDS REVIEW.',
    'F6 PARTIAL FIT (cap `confounded-window-needs-locality`).',
    'F4 and F5 PARTIAL FIT.',
    'F7, F2, F3 CHANGED, NO FIT.',
    'For CVE-2099-20002, F6 is the only FITS lead and F1 is capped.',
    'KEV only places CVE-2099-20001 first in the picker.',
)
BADGES = {'fit': 'FITS ADVISORY', 'review': 'NEEDS REVIEW', 'partial': 'PARTIAL FIT', 'code': 'CODE CHANGE',
          'queue': 'CHANGED, NO FIT'}  # plan s8


# --- the cells of the arm table -> structured values ------------------------------------------------------------------

def parse_rank(cell: str) -> tuple[int, int]:
    match = re.match(r'(\d+)(?:-(\d+))?', cell)
    first = int(match[1])
    return first, int(match[2] or first)


def parse_ties(cell: str) -> list[str]:
    match = re.search(r'\(with ([^)]*)\)', cell)
    return sorted(part.strip() for part in match[1].split(',')) if match else []


def parse_top(cell: str) -> list[str]:
    match = re.search(r'top is ([A-Z0-9/]+)', cell)
    return sorted(match[1].split('/')) if match else []


def parse_fits(cell: str) -> list[str] | None:
    if cell == 'n/a':
        return None
    return [] if cell == 'none' else sorted(part.strip() for part in cell.split(','))


# --- CSAF documents ---------------------------------------------------------------------------------------------------
VENDOR = 'PatchTrace Synthetic Fixture Vendor'
NS = 'https://example.invalid/patchtrace-synthetic'
RELEASE = '2099-02-10T08:00:00.000Z'
OS_NAME = 'Example OS 22H2 for x64-based Systems'
DISCLAIMER = ('SYNTHETIC CSAF 2.0 fixture written for PatchTrace tests. No vendor published it and it describes no '
              'real vulnerability, product or update.')


def _file_product(product_id: str, name: str, filename: str, sha256: str) -> dict:
    return {'name': name, 'product_id': product_id, 'product_identification_helper': {'hashes': [{
        'file_hashes': [{'algorithm': 'sha256', 'value': sha256}], 'filename': filename}]}}


def _csaf(*, tracking_id: str, title: str, product_family: str, branch_name: str, range_name: str, fixed_name: str,
          ids: tuple[str, str, str, str, str, str], files: tuple[tuple[str, str, str], tuple[str, str, str]],
          vulnerabilities: list[dict]) -> dict:
    """A CSAF 2.0 advisory whose two file products carry the SHA-256 of the older and the newer build."""
    range_id, fixed_id, older_id, newer_id, older_rel, newer_rel = ids
    (older_name, filename, older_sha), (newer_name, _, newer_sha) = files
    older_label = f'{branch_name} {range_name}'
    newer_label = f'{branch_name} {fixed_name}'
    return {
        'document': {
            'category': 'csaf_security_advisory', 'csaf_version': '2.0',
            'distribution': {'text': 'SYNTHETIC test fixture for PatchTrace. Not a real advisory.',
                             'tlp': {'label': 'WHITE', 'url': 'https://www.first.org/tlp/'}},
            'lang': 'en-US',
            'notes': [{'category': 'legal_disclaimer', 'text': DISCLAIMER, 'title': 'Synthetic fixture'}],
            'publisher': {'category': 'vendor', 'contact_details': 'none (synthetic fixture)',
                          'name': f'{VENDOR} (not Microsoft)', 'namespace': NS},
            'references': [{'category': 'self', 'summary': 'Synthetic self reference',
                            'url': f'{NS}/csaf/2099/{tracking_id.lower()}.json'}],
            'title': title,
            'tracking': {'current_release_date': RELEASE,
                         'generator': {'date': RELEASE, 'engine': {'name': 'PatchTrace fixture author', 'version': '1'}},
                         'id': tracking_id, 'initial_release_date': RELEASE,
                         'revision_history': [{'date': RELEASE, 'number': '1', 'summary': 'Initial synthetic release.'}],
                         'status': 'final', 'version': '1'}},
        'product_tree': {
            'branches': [{'category': 'vendor', 'name': VENDOR, 'branches': [{
                'category': 'product_family', 'name': product_family, 'branches': [{
                    'category': 'product_name', 'name': branch_name, 'branches': [
                        {'category': 'product_version_range', 'name': range_name,
                         'product': {'name': older_label, 'product_id': range_id}},
                        {'category': 'product_version', 'name': fixed_name,
                         'product': {'name': newer_label, 'product_id': fixed_id}}]}]}]}],
            'full_product_names': [_file_product(older_id, older_name, filename, older_sha),
                                   _file_product(newer_id, newer_name, filename, newer_sha)],
            'relationships': [
                {'category': 'default_component_of', 'product_reference': older_id,
                 'relates_to_product_reference': range_id,
                 'full_product_name': {'name': f'{older_name} as part of {older_label}', 'product_id': older_rel}},
                {'category': 'default_component_of', 'product_reference': newer_id,
                 'relates_to_product_reference': fixed_id,
                 'full_product_name': {'name': f'{newer_name} as part of {newer_label}', 'product_id': newer_rel}}]},
        'vulnerabilities': vulnerabilities}


def _vulnerability(cve: str, cwe: tuple[str, str], title: str, description: str, ids: tuple[str, ...],
                   update: str, *, on_files: bool = False) -> dict:
    """Statuses sit on the OS products and on their file components; `on_files` adds the file-hash products themselves,
    so a build whose bytes are verified resolves through a verified mapping (the sample project)."""
    range_id, fixed_id, older_id, newer_id, older_rel, newer_rel = ids
    return {'cve': cve, 'cwe': {'id': cwe[0], 'name': cwe[1]}, 'title': title,
            'notes': [{'category': 'description', 'text': description, 'title': 'Description'}],
            'product_status': {
                'fixed': sorted([fixed_id, newer_rel, *([newer_id] if on_files else [])]),
                'known_affected': sorted([range_id, older_rel, *([older_id] if on_files else [])])},
            'remediations': [{'category': 'vendor_fix', 'details': f'Install synthetic update {update}',
                              'product_ids': [older_rel], 'url': f'{NS}/updates/{update}'}]}


def synergy_csaf() -> dict:
    ids = ('PTP-100-1', 'PTP-100-2', 'PTP-800', 'PTP-900', 'PTP-801', 'PTP-901')
    return _csaf(
        tracking_id='PT-SYNTH-PILOT_2099-001',
        title='SYNTHETIC Example Net update for IPv6 fragment reassembly and options parse vulnerabilities',
        product_family='Example OS', branch_name=OS_NAME, range_name='<10.0.22621.5000', fixed_name='10.0.22621.5000',
        ids=ids,
        files=(('Example examplenet.sys 10.0.22621.4999 (synthetic build)', MODULE, OLDER),
               ('Example examplenet.sys 10.0.22621.5000 (synthetic build)', MODULE, NEWER)),
        vulnerabilities=[
            _vulnerability(
                CVE1, ('CWE-787', 'Out-of-bounds Write'),
                'SYNTHETIC Example Net IPv6 Fragment Reassembly Remote Code Execution Vulnerability',
                'SYNTHETIC: A heap-based buffer overflow in the IPv6 fragment reassembly code of examplenet.sys lets '
                'crafted fragments write past the end of a buffer.', ids, 'PT6000001'),
            _vulnerability(
                CVE2, ('CWE-125', 'Out-of-bounds Read'),
                'SYNTHETIC Example Net IPv6 Options Parse Information Disclosure Vulnerability',
                'SYNTHETIC: An out-of-bounds read while parsing IPv6 options in examplenet.sys can disclose adjacent '
                'kernel memory.', ids, 'PT6000001')])


def sample_csaf() -> dict:
    """One CVE, CWE-125, for the committed sample project: the products carry the SHA-256 of its two synthetic PEs."""
    ids = ('PTS-100-1', 'PTS-100-2', 'PTS-800', 'PTS-900', 'PTS-801', 'PTS-901')
    return _csaf(
        tracking_id='PT-SYNTH-PILOT-SAMPLE_2099-001', title='SYNTHETIC Example item library advisory',
        product_family='Example Item Library', branch_name='Example Item Library 1.x', range_name='<1.1.0',
        fixed_name='1.1.0', ids=ids,
        files=(('Example item library older_sample.dll 1.0.9 (synthetic build)', 'sample.dll',
                hashlib.sha256(synthetic_pe(0)).hexdigest()),
               ('Example item library newer_sample.dll 1.1.0 (synthetic build)', 'sample.dll',
                hashlib.sha256(synthetic_pe(1)).hexdigest())),
        vulnerabilities=[_vulnerability(
            CVE_SAMPLE, ('CWE-125', 'Out-of-bounds Read'),
            'SYNTHETIC Example Item Library Indexed Read Out-of-Bounds Read Vulnerability',
            'SYNTHETIC: An out-of-bounds read in the indexed item reader lets a caller read past the end of a buffer '
            'when the index is not checked against the length.', ids, 'PT6000002', on_files=True)])


# --- the ledger -------------------------------------------------------------------------------------------------------
PREFIX_CHANNEL = {'adv': 'advisory', 'b1': 'code', 'cf': 'code', 'call': 'calls', 'str': 'strings', 'capa': 'capa',
                  'die': 'build'}
NAMES = {fid: name for fid, name, _ in FUNCTION_TABLE}
# The pairing verdict is the candidate's identity (PairingSource); F8 is the contested pair (Ghidriff versus BinDiff).
IDENTITY = {fid: 'contested' if fid == 'F8' else 'corroborated' for fid in NAMES}
FRAGMENT = 'Dropped oversize fragment'


def candidate_key(fid: str) -> str:
    rva = OLDER_RVA[fid]
    return keys.candidate_key(OLDER, NEWER, [rva], [rva + NEWER_SHIFT])


def _nav(fid: str, line: int | None) -> c.Nav:
    return c.Nav(side='newer', rva=OLDER_RVA[fid] + NEWER_SHIFT, start_line=line, end_line=line)


def _observation(fid: str, kind: str, role: str, verification: str, origin: str, evidence_class: str,
                 ref: tuple[str, str] | tuple[str, str, str], detail: str, *, line: int | None = None,
                 locate: bool = True, anchors: tuple[str, ...] = ()) -> c.Observation:
    return keys.make_observation(
        channel=PREFIX_CHANNEL[kind.split(':')[0]], kind=kind, role=role, verification=verification,
        origins=(origin,), evidence_class=evidence_class, anchor_ids=anchors,
        ref=c.ObsRef(kind=ref[0], id=ref[1], sha256=ref[2] if len(ref) == 3 else None),
        nav=_nav(fid, line) if locate else None, detail=detail)


def function_observations(fid: str) -> list[c.Observation]:
    """The evidence column of plan s5 for one function as flat ledger observations (no locality: PIL computes it)."""
    key = candidate_key(fid)

    def b1(detector: str, line: int, detail: str) -> c.Observation:
        return _observation(fid, f'b1:{detector}', 'shape', 'tool-reported', 'D_ghidra', 'E-DECOMP',
                            ('b1-signal', _h(f'signal-{fid}-{detector}')), detail, line=line)

    def cf(cls: str, role: str, evidence_class: str, line: int | None, detail: str) -> c.Observation:
        return _observation(fid, f'cf:{cls}', role, 'tool-reported', 'D_ghidra', evidence_class,
                            ('change-facts', key), detail, line=line)

    material = 'material, anchored by C6'
    table = {
        'F1': [b1('BND', 14, 'bounds check added before the copy'),
               cf('comparison', 'shape', 'E-BODY', 14, f'new comparison against the fragment length; {material}'),
               _observation(fid, 'call:added', 'shape', 'label-only', 'D_ghidra', 'E-CALL',
                            ('call-label', 'RtlSizeTAdd'), 'call to RtlSizeTAdd added (label only)',
                            locate=False, anchors=('api:RtlSizeTAdd',))],
        'F6': [b1('BND', 9, 'bounds check added before the read'),
               cf('comparison', 'shape', 'E-BODY', 9, f'new comparison against the options length; {material}')],
        'F8': [b1('BND', 17, 'bounds check added before the copy'),
               cf('comparison', 'shape', 'E-BODY', 17, f'new comparison against the list length; {material}')],
        'F9': [b1('BND', 22, 'bounds check added before the copy'),
               cf('cosmetic', 'conflict', 'E-LAYOUT', 22, 'proof COS-LAYOUT/1 holds: the old check was only moved')],
        'F4': [b1('SIZE', 6, 'allocation size changed from 0x40 to 0x80')],
        'F5': [cf('call-added', 'context', 'E-CALL', 11, 'call added to a statistics counter')],
        'F2': [cf('string', 'context', 'E-DATA', 7, f'string literal "{FRAGMENT}" added'),
               _observation(fid, 'str:added', 'context', 'tool-reported', 'D_bytes', 'E-DATA',
                            ('floss-string', _h('floss-string-dropped'),
                             hashlib.sha256(FRAGMENT.casefold().encode()).hexdigest()),
                            f'FLOSS: new static string "{FRAGMENT}" in the newer build; joined to this function by '
                            'value hash', locate=False)],
        'F3': [cf('register-only', 'context', 'E-BODY', None, 'register-only churn: same instructions, renamed registers'),
               cf('address-only', 'context', 'E-BODY', None, 'address-only churn: operands moved with the image layout'),
               _observation(fid, 'die:toolchain-changed', 'context', 'tool-reported', 'D_compiler', 'E-BUILD',
                            ('die-flag', 'toolchain-changed'),
                            'The compiler or linker version differs between the builds', locate=False)],
        'F7': [cf('callee', 'context', 'E-CALL', None, 'callee of one call replaced')],
    }
    return table[fid]


def advisory_observations(csaf_sha: str) -> dict[str, list[dict]]:
    """adv:* observations per CVE: every source repeating the CWE is one more observation with the SAME origin tag."""
    def make(cve: str, source: str, pointer: str, ref_kind: str, sha: str, detail: str) -> dict:
        observation = keys.make_observation(
            channel='advisory', kind=f'adv:cwe-{source}', role='context', verification='advisory-claim',
            origins=('D_vendor_text',), evidence_class='E-TEXT',
            ref=c.ObsRef(kind=ref_kind, id=cve, pointer=pointer, sha256=sha), detail=detail)
        return {'source': source, 'observation': _doc(observation)}

    kev_sha = _h('kev-snapshot')
    first = [
        make(CVE1, 'stated', '/vulnerabilities/0/cwe', 'csaf-fact', csaf_sha,
             'CWE-787 as stated by the advisory'),
        make(CVE1, 'nvd', '/cve/weaknesses/0/description/0/value', 'nvd-record', _h(f'nvd-{CVE1}'),
             'CWE-787 as recorded by NVD (same origin as the advisory)'),
        make(CVE1, 'msrc', '/cwe', 'msrc-entry', _h(f'msrc-{CVE1}'),
             'CWE-787 as listed by the MSRC entry (same origin as the advisory)'),
        make(CVE1, 'kev', '/cwes/0', 'kev-entry', kev_sha,
             'CWE-787 as listed in KEV cwes (same origin as the advisory)')]
    second = [make(CVE2, 'stated', '/vulnerabilities/1/cwe', 'csaf-fact', csaf_sha,
                   'CWE-125 as stated by the advisory')]
    return {CVE1: first, CVE2: second}


def cve_contexts(csaf_sha: str) -> list[dict]:
    """What the advisory-side adapters (PIL-A2) report per CVE. Counts are zero: they are an output of localization."""
    zero = c.LeadCounts(fit=0, review=0, partial=0, code=0, queue=0)
    window = c.Confounding(state='yes', cves=(CVE1, CVE2))

    def context(cve: str, cwes: tuple[str, ...]) -> c.CveContext:
        return c.CveContext(
            cve=cve, source_ids=(csaf_sha,), gate='applies',
            applicability=c.ApplicabilitySummary(older='affected', newer='fixed', older_mapping='candidate',
                                                 newer_mapping='candidate'),
            cwe=c.CweSummary(status='explicit', ids=cwes),
            kev=c.Kev(state='listed', date_added=KEV_DATE, snapshot_id=_h('kev-snapshot')) if cve == CVE1
            else c.Kev(state='not-in-snapshot', snapshot_id=_h('kev-snapshot')),
            confounding=window, counts=zero)

    return [_doc(context(CVE1, ('CWE-122', 'CWE-787'))), _doc(context(CVE2, ('CWE-125',)))]


def _doc(record) -> dict:
    return json.loads(record.model_dump_json())


def ledger(csaf_sha: str) -> dict:
    candidates, observations = [], []
    for fid, name, evidence in FUNCTION_TABLE:
        rva = OLDER_RVA[fid]
        candidates.append({'id': fid, 'key': candidate_key(fid), 'identity': IDENTITY[fid], 'plan_evidence': evidence,
                           'older': {'name': name, 'rva': rva}, 'newer': {'name': name, 'rva': rva + NEWER_SHIFT}})
        observations += [{'candidate': fid, 'observation': _doc(o)} for o in function_observations(fid)]
    tool_keys = [{'engine': engine, 'side': side, 'cache_key': _h(f'tool-{engine}-{side}')}
                 for engine in ('capa', 'diec', 'floss') for side in ('older', 'newer')]
    return {
        'scenario': SCENARIO, 'contract': c.CONTRACT, 'module': MODULE, 'plan': PLAN,
        'builds': {'older_sha256': OLDER, 'newer_sha256': NEWER, 'ghidriff_run_id': 'run-1',
                   'raw_sha256': _h('ghidriff-raw'), 'image_base': IMAGE_BASE,
                   'project_id': 'synthetic-synergy-1', 'revision': 1},
        'secondary_set_ids': [_h('secondary-bindiff')], 'tool_keys': tool_keys,
        'candidates': candidates, 'observations': observations,
        'advisory_observations': advisory_observations(csaf_sha), 'cve_contexts': cve_contexts(csaf_sha),
        'kev': {'snapshot_id': _h('kev-snapshot'), 'entries': {CVE1: {'date_added': KEV_DATE}}},
        'csaf': {'file': CSAF_NAME, 'sha256': csaf_sha}}


# --- the oracle -------------------------------------------------------------------------------------------------------

def _lead(klass: str, **more) -> dict:
    """One expected lead. The mechanism is stated where the class forces it; a queue row may be `unexplained` or
    `not-assessed` (whether register-only churn counts as change evidence is the engine's call), so none is stated."""
    mechanism = {'fit': 'moderate', 'review': 'contested', 'partial': 'tentative'}
    return {'class': klass, 'badge': BADGES[klass], **({'mechanism': mechanism[klass]} if klass in mechanism else {}),
            **more}


def full_arm_expectations() -> dict:
    """Plan s5 "Expected output" for the full arm. Stated in the plan: the classes, F1's numbers, the cap on F6, the
    fit lead of the second CVE and the cap on F1. Derived from s7 for this ledger: the order of the review pair
    (identity, contested last) and the rank blocks of the other classes. Order inside a block is not asserted."""
    return {
        CVE1: {
            'window': 'yes', 'fit_leads': ['F1'],
            'counts': {'fit': 1, 'review': 2, 'partial': 3, 'code': 0, 'queue': 3},
            'leads': {
                'F1': _lead('fit', rank=[1, 1], identity='corroborated', depth='typed', met=2, total=3,
                            components=2, local_hits=2, caps=[], tie_size=1, basis='explicit-csaf-cwe',
                            rule='R-MEMORY-WRITE', cwe='CWE-787'),
                'F9': _lead('review', rank=[2, 2], identity='corroborated', depth='lexical', met=1, total=3,
                            components=2),
                'F8': _lead('review', rank=[3, 3], identity='contested', depth='typed', met=1, total=3,
                            components=2),
                'F6': _lead('partial', rank=[4, 6], identity='corroborated', met=1, total=3, components=2,
                            caps=['confounded-window-needs-locality']),
                'F4': _lead('partial', rank=[4, 6], identity='corroborated', met=1, total=3),
                'F5': _lead('partial', rank=[4, 6], identity='corroborated'),
                'F7': _lead('queue', rank=[7, 9]),
                'F2': _lead('queue', rank=[7, 9]),
                'F3': _lead('queue', rank=[7, 9])}},
        CVE2: {
            'window': 'yes', 'fit_leads': ['F6'],
            'leads': {
                'F6': _lead('fit', rank=[1, 1], identity='corroborated', depth='typed', met=1, total=3,
                            components=2, local_hits=2, caps=[], tie_size=1, basis='explicit-csaf-cwe',
                            rule='R-MEMORY-READ', cwe='CWE-125'),
                'F1': _lead('partial', caps=['confounded-window-needs-locality'])}}}


def why_f1() -> dict:
    """The "Why this function" facts of plan s5 for F1, tied to ledger observations by kind (no prose is stored)."""
    return {
        'summary': {'class': 'fit', 'expected_changes_seen': 2, 'expected_changes_total': 3, 'required_seen': 1,
                    'required_total': 1, 'independent_groups': 2, 'depth': 'typed'},
        'expected_changes': [
            {'id': 'guard-added', 'state': 'met', 'kinds': ['b1:BND', 'cf:comparison'],
             'go_to': {'side': 'newer', 'line': 14}},
            {'id': 'checked-arithmetic', 'state': 'met', 'kinds': ['call:added'], 'verification': 'label-only',
             'api': 'RtlSizeTAdd'},
            {'id': 'size-recomputed', 'state': 'not-observed', 'kinds': []}],
        'independent_evidence': [
            {'origin': 'D_vendor_text', 'advisory_sources': ['kev', 'msrc', 'nvd', 'stated']},
            {'origin': 'D_ghidra', 'kinds': ['b1:BND', 'call:added', 'cf:comparison']}],
        'against': [], 'unknown_when_tools_not_run': ['capa', 'strings'],
        'window': {'cves': [CVE1, CVE2], 'names_matched': ['fragment', 'reassemble']},
        'alternatives': [{'cve': CVE2, 'class': 'partial'}]}


def expected() -> dict:
    functions = [{'id': fid, 'function': name, 'evidence': evidence} for fid, name, evidence in FUNCTION_TABLE]
    arms = {}
    for arm_id, (label, sources, names, window) in ARM_DEFS.items():
        cells = next(row for row in ARM_TABLE if row[0] == label)
        arms[arm_id] = {
            'label': label, 'sources': list(sources), 'names': names, 'window': window,
            'code_only': 'advisory' not in sources,
            'f1_rank': list(parse_rank(cells[1])), 'ties_with': parse_ties(cells[1]), 'top': parse_top(cells[1]),
            'fit_leads': parse_fits(cells[2])}
    return {
        'scenario': SCENARIO, 'plan': PLAN, 'badges': BADGES, 'quotes': list(PLAN_QUOTES),
        'function_table': functions,
        'arm_table': [{'arm': a, 'f1_rank': r, 'fits': f, 'short_of': s} for a, r, f, s in ARM_TABLE],
        'arms': arms, 'full': full_arm_expectations(),
        'kev': {'snapshot_id': _h('kev-snapshot'), 'picker_order': [CVE1, CVE2],
                'states': {CVE1: {'state': 'listed', 'date_added': KEV_DATE},
                           CVE2: {'state': 'not-in-snapshot'}}},
        'why_f1': why_f1()}


# --- rendering ----------------------------------------------------------------------------------------------------------

def _json(value) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + '\n'


def render() -> dict[Path, str]:
    """Every generated file and its exact text (a pure function of this module and `patchtrace.pilot`)."""
    synergy = _json(synergy_csaf())
    csaf_sha = hashlib.sha256(synergy.encode()).hexdigest()
    return {HERE / CSAF_NAME: synergy, HERE / SAMPLE_CSAF_NAME: _json(sample_csaf()),
            HERE / 'ledger.json': _json(ledger(csaf_sha)), HERE / 'expected.json': _json(expected())}


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
            current = path.read_bytes() if path.is_file() else None
            if current != text.encode('utf-8'):
                drift.append(_shown(path))
        else:
            path.write_text(text, encoding='utf-8', newline='\n')
    for path in sorted(HERE.glob('*.json')):  # files nothing renders any more
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
