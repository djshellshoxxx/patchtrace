"""matrix.gather hashes every --extra path without an S_ISREG/size check (the worker has both): /dev/zero never ends."""
import sys
sys.path.insert(0, __import__('os').path.join(__import__('os').path.dirname(__import__('os').path.abspath(__file__)), '../../../..', 'tests'))
from pathlib import Path
from patchtrace.rules import matrix
from patchtrace.rules.contracts import PairSource, FunctionRef
pair = PairSource(project_id='p', revision=1, run_id='r', older_sha256='a'*64, newer_sha256='b'*64, match_id='m', category='added',
                  review='accepted', materiality='material', analyst_confirmed_material=False,
                  newer=FunctionRef(rva=0x1000, size=10, extent='pdata'))
matrix.gather(pair, {}, extra=[Path('/dev/zero')])
print('returned')
