"""BytesWindows.windows(): StopIteration escapes when the 32-evaluation budget is exhausted (repetitive changed code)."""
from patchtrace.rules.window import BytesWindows
from patchtrace.rules.ports import DecodedInstruction
from patchtrace.rules.contracts import PairSource, FunctionRef

class Mask:
    name, version = 'iced-x86', '1.21.0'
    def decode(self, code, rva):
        out, off = [], 0
        while off < len(code):
            size = 1 if code[off] == 0xC3 else 2
            out.append(DecodedInstruction(off, size, 'return' if size == 1 else 'next')); off += size
        return tuple(out)

class Image:
    def __init__(self, sha, code): self._sha, self._code = sha, code
    sha256 = property(lambda s: s._sha)
    def read_backed(self, rva, length): return self._code[rva - 0x1000: rva - 0x1000 + length]
    def function_extent(self, rva): return len(self._code)
    def relocations(self): return ([], [])
    def import_slots(self): return {}
    def rva_to_offset(self, rva): return rva
    def executable_sections(self): yield (0x1000, self._code + self._code)   # the function is also present twice in the section

old = b'\x31\xC0' * 98 + b'\xC3'
new = b'\x31\xC0' * 100 + b'\xC3'
pair = PairSource(project_id='p', revision=1, run_id='r', older_sha256='a' * 64, newer_sha256='b' * 64, match_id='m',
                  category='modified', review='accepted', materiality='material', analyst_confirmed_material=False,
                  older=FunctionRef(rva=0x1000, size=len(old), extent='pdata'),
                  newer=FunctionRef(rva=0x1000, size=len(new), extent='pdata'))
bw = BytesWindows(Mask(), {'older': Image('a' * 64, old), 'newer': Image('b' * 64, new)})
try:
    ws = bw.windows(pair, 'newer')
    print('windows', len(ws.windows), 'failures', [f.detail for f in ws.failures])
except BaseException as e:
    print('RAISED', type(e).__name__, repr(e))
