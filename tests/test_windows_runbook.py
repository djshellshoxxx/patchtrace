"""Invariants of the Windows acceptance runbook (docs/qa/windows-acceptance-runbook.md; C8 and the manual part of
RB-05). The gate ids are read from the specs, so a new manual check fails here until the runbook covers it. The
committed receipt is a blank form: every result stays not-run, because only a named tester's run may change one."""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNBOOK = ROOT / 'docs' / 'qa' / 'windows-acceptance-runbook.md'
ACCEPTANCE = ROOT / 'docs' / 'specs' / 'windows-acceptance-and-milestone-builds.md'
SPEC_45 = ROOT / 'docs' / 'specs' / 'accessibility-baseline.md'
TODO = ROOT / 'tasks' / 'todo.md'

STEP_HEADING = re.compile(r'^#### (R-[A-Z]{2}\d+) ', re.MULTILINE)
STEP_ID = re.compile(r'\bR-[A-Z]{2}\d+\b')
RECEIPT_ENTRY = re.compile(r'^ {2}([A-Z][\w-]*): \{result: ([^,}]+)')
LINK = re.compile(r'\]\(([^)\s]+)\)')


def _text(path: Path) -> str:
    return path.read_text(encoding='utf-8')


def _section(path: Path, number: int) -> str:
    """The body of `## <number>.` up to the next level-2 heading."""
    match = re.search(rf'^## {number}\. .*?(?=^## )', _text(path), re.MULTILINE | re.DOTALL)
    assert match, f'{path.name} has no section {number}'
    return match.group(0)


def _spec_ids() -> list[str]:
    checks = sorted(set(re.findall(r'^\| (M\d{2}) \|', _section(ACCEPTANCE, 3), re.MULTILINE)))
    gates = sorted(set(re.findall(r'\bAX-M\d+\b', _section(SPEC_45, 9))))
    assert {'M01', 'M28'} <= set(checks) and len(checks) >= 28, checks
    assert {'AX-M1', 'AX-M6'} <= set(gates) and len(gates) >= 6, gates
    return checks + gates


def _receipt() -> list[str]:
    blocks = re.findall(r'^```yaml\n(.*?)^```', _text(RUNBOOK), re.MULTILINE | re.DOTALL)
    assert len(blocks) == 1, 'the runbook holds exactly one YAML receipt'
    return blocks[0].splitlines()


def _receipt_entries(section: str) -> dict[str, str]:
    """`id -> result` of the indented entries under the top-level `section:` key of the receipt."""
    entries: dict[str, str] = {}
    current = None
    for line in _receipt():
        if line and not line.startswith((' ', '#')):
            current = line.split(':', 1)[0]
        elif current == section and (match := RECEIPT_ENTRY.match(line)):
            entries[match.group(1)] = match.group(2).strip()
    return entries


def _value(line: str) -> str:
    return line.split(' #', 1)[0].split(':', 1)[1].strip() if ':' in line.split(' #', 1)[0] else ''


def test_every_manual_check_of_both_specs_appears_in_the_runbook():
    text = _text(RUNBOOK)
    assert [gate for gate in _spec_ids() if not re.search(rf'\b{gate}\b', text)] == []


def test_the_receipt_has_one_not_run_result_per_gate_and_counts_them():
    results = _receipt_entries('results')
    assert sorted(results) == sorted(_spec_ids())
    assert set(results.values()) == {'not-run'}
    counts = {key: _value(line) for line in _receipt() if (key := line.split(':', 1)[0]).endswith('_count')}
    assert counts.pop('case_count') == str(len(results))
    assert set(counts.values()) == {'0'}


def test_every_result_field_is_not_run_and_no_field_says_pass():
    receipt = _receipt()
    fields = [_value(line) for line in receipt if re.match(r'^\s*(outcome|result):', line)]
    fields += [result for result in re.findall(r'\{result: ([^,}]+)', '\n'.join(receipt))]
    assert len(fields) > len(_spec_ids()) and {value.strip() for value in fields} == {'not-run'}
    values = [line.split(' #', 1)[0] for line in receipt]
    assert [line for line in values if re.search(r":\s*['\"]?pass(ed)?\b", line, re.IGNORECASE)] == []
    cells = [cell.strip().lower() for line in _text(RUNBOOK).splitlines() if line.startswith('|')
             for cell in line.strip('|').split('|')]
    assert 'pass' not in cells and 'passed' not in cells


def test_every_procedure_step_has_a_receipt_line_and_the_crosswalk_names_only_real_steps():
    text = _text(RUNBOOK)
    steps = STEP_HEADING.findall(text)
    assert len(steps) == len(set(steps)) and len(steps) >= 8
    assert sorted(_receipt_entries('steps')) == sorted(steps)
    assert set(STEP_ID.findall('\n'.join(_receipt()))) == set(steps)
    cited = set(STEP_ID.findall(_crosswalk()))
    assert cited and cited <= set(steps), sorted(cited - set(steps))


def _crosswalk() -> str:
    match = re.search(r'^## \d+\. Crosswalk.*?(?=^## )', _text(RUNBOOK), re.MULTILINE | re.DOTALL)
    assert match, 'the runbook has a crosswalk section followed by another section'
    return match.group(0)


def test_every_crosswalk_row_names_a_heading_of_the_tracker():
    rows = [line for line in _crosswalk().splitlines() if line.startswith('| `tasks/todo.md:')]
    assert len(rows) >= 11
    headings = [line.lstrip('#').strip() for line in _text(TODO).splitlines() if line.startswith('#')]
    cited = [re.findall(r'`([^`]+)`', row)[1] for row in rows]  # a whole heading or its leading [slice:id] tag
    assert [anchor for anchor in cited if not any(heading.startswith(anchor) for heading in headings)] == []


def test_relative_links_resolve_to_existing_files():
    targets = [target for target in LINK.findall(_text(RUNBOOK)) if not target.startswith(('#', 'mailto:'))]
    absolute = [target for target in targets if target.startswith(('/', 'file:')) or re.match(r'[A-Za-z]:', target)
                or 'github.com/djshellshoxxx/patchtrace/blob/' in target]
    assert absolute == []
    local = [target.split('#', 1)[0] for target in targets if not target.startswith(('http://', 'https://'))]
    assert len(local) >= 8
    assert [target for target in local if not (RUNBOOK.parent / target).resolve().is_file()] == []
