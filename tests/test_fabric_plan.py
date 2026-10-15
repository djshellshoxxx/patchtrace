"""FAB-0 plan parity: the tables of docs/specs/program-e/FAB-integration-plan.md equal the code that implements them.

The plan is the specification (AGENTS.md: update the specification before changing contracts), so a change to a kind,
a role, an error code, a limit or a vocabulary tuple fails here until both sides agree. Pure text checks.
"""
from __future__ import annotations

import re
from pathlib import Path

from patchtrace.fabric import contracts, limits

PLAN = Path(__file__).resolve().parents[1] / 'docs' / 'specs' / 'program-e' / 'FAB-integration-plan.md'
TEXT = PLAN.read_text(encoding='utf-8').replace('\r\n', '\n')
ROW = re.compile(r'^\| `([a-z_]+)` \| (.+?) \| (.+?) \| (.+) \|$', re.MULTILINE)
ROLE_WORDS = re.compile(r'\b(observed|stated|hint)\b')


def section(title: str) -> str:
    start = TEXT.index(f'## {title}')
    end = TEXT.find('\n## ', start + 1)
    return TEXT[start:end if end != -1 else len(TEXT)]


def kind_rows() -> list[tuple[str, str]]:
    """(kind, roles cell) of the key-grammar table of s4."""
    text = section('4. Cross-feature links').split("How each plan's assumption maps")[0]
    return [(m.group(1), m.group(3)) for m in ROW.finditer(text)]


def contract_text() -> str:
    return section('7. Contracts')


def test_the_plan_s4_table_lists_every_kind_in_order_with_the_roles_the_code_allows():
    rows = kind_rows()
    assert tuple(kind for kind, _ in rows) == contracts.KINDS
    for kind, cell in rows:
        words = tuple(dict.fromkeys(ROLE_WORDS.findall(cell)))
        assert words == contracts.ROLES_BY_KIND[kind], kind


def test_the_plan_s7_roles_by_kind_sentence_equals_the_code():
    sentence = re.search(r'Roles by kind: ([^\n]+?)\. Reserved facet', contract_text()).group(1)
    parsed: dict[str, tuple[str, ...]] = {}
    for clause in sentence.split('; '):
        names, roles = [], []
        for token in re.split(r',? |, ', clause):
            if token in contracts.ROLES:
                roles.append(token)
            elif token != 'or':
                names.append(token.strip(','))
        for name in names:
            parsed[name] = tuple(roles)
    assert parsed == dict(contracts.ROLES_BY_KIND)


def test_the_plan_s7_vocabulary_tuples_equal_the_code():
    text = contract_text()
    for label, expected in (('sides', contracts.SIDES), ('roles', contracts.ROLES), ('producers', contracts.PRODUCERS)):
        found = re.search(rf'{label} `([^`]+)`', text).group(1)
        assert tuple(found.split(', ')) == expected, label


def test_the_plan_s7_error_codes_and_exit_codes_equal_the_code():
    sentence = re.search(r'Errors \(exit codes[^\n]*', contract_text()).group(0)
    parsed = {code: int(exit_code) for code, exit_code in re.findall(r'`(PT-FAB-[A-Z]+)` (\d)', sentence)}
    assert parsed == limits.EXIT_CODES
    assert tuple(parsed) == limits.ERROR_CODES  # the plan lists them grouped by exit code, in code order


def test_the_plan_s7_limits_equal_the_code_defaults():
    bullet = re.search(r'`FabricLimits` and `DEFAULT_LIMITS`\. ([^\n]+)', contract_text()).group(1)
    parsed = {number: int(value.replace(',', '')) for number, value in
              re.findall(r'F-(\d\d) [^;]*?([0-9][0-9,]*)(?=[;.](?: |$))', bullet)}
    fields = limits.DEFAULT_LIMITS.as_dict()
    assert {name[1:3]: value for name, value in fields.items()} == parsed
    assert [name[1:3] for name in fields] == sorted(parsed)


def test_the_plan_claims_the_status_it_has():
    head = TEXT.split('\n## 1.')[0]
    assert head.startswith('# FAB integration plan') and 'Status:' in head
    assert len(TEXT.splitlines()) <= 250  # the research brief's size budget for this plan
