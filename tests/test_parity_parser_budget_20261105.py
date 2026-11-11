"""Parity text parsing stays bounded on authored hostile dumps; no native tools run."""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_whitespace_rejection_completes_in_bounded_child():
    script = '''
import json, time
from tools.unified.parity import parse_md_dump
start = time.process_time()
values, unparsed = parse_md_dump('401000' + ' ' * 100_000 + 'X')
print(json.dumps([values, unparsed, time.process_time() - start]))
'''
    result = subprocess.run([sys.executable, '-c', script], cwd=ROOT, capture_output=True, text=True,
                            timeout=3, check=True)
    values, unparsed, elapsed = json.loads(result.stdout)
    assert values == {} and unparsed == 1
    assert elapsed < 1.0


def test_address_separator_and_decimal_grammar_is_preserved():
    from tools.unified.parity import parse_md_dump

    valid = [
        ('  0xAbCd: -01.250  ', 0xABCD, '-01.250'),
        ('FFFFFFFFFFFFFFFF,0.0', 2**64 - 1, '0.0'),
        ('1 = 2.3', 1, '2.3'),
        ('a\t\t-0.5', 10, '-0.5'),
        ('a\u2003:\u2003١.٢', 10, '١.٢'),
        ('1 ' + '9' * 30 + '.' + '8' * 30, 1, '9' * 30 + '.' + '8' * 30),
    ]
    for text, address, decimal in valid:
        assert parse_md_dump(text) == ({address: decimal}, 0)
    invalid = ['0X1 1.0', '1' * 17 + ' 1.0', 'a1.0', 'a::1.0', 'a +1.0', 'a .5',
               'a 1.', 'a 1e2', 'a 1.0 extra', 'a ' + '9' * 31 + '.0', 'a 0.' + '9' * 31]
    for text in invalid:
        assert parse_md_dump(text) == ({}, 1)
    assert parse_md_dump('\n\t\n1: 1.0\n1=2.0\n') == ({1: '2.0'}, 0)
