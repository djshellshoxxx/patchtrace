"""window.diff_opcodes: pair-count guard (1,000,000) does not bound difflib's recursive work; 2 unique-instruction bodies, ~n pairs."""
import sys, time
from patchtrace.rules.masks import MaskedFunction, MaskedInstruction
from patchtrace.rules import window
n = int(sys.argv[1])
def body(order):
    ins, off = [], 0
    for k in order:
        toks = ('B8',) + tuple(f'{b:02X}' for b in k.to_bytes(4, 'little'))     # mov eax, imm32 (5 bytes)
        ins.append(MaskedInstruction(off, 5, toks, (), 'next', None, ())); off += 5
    return MaskedFunction(0x1000, tuple(ins))
older = body(range(1, n + 1))
swapped = [x for i in range(0, n, 2) for x in (i + 2, i + 1)]            # 2,1,4,3,6,5,...
newer = body(swapped)
print('function bytes', older.size, '(cap 65536); equal pairs ~', n)
t = time.time(); ops = window.diff_opcodes(older, newer); print(n, 'instr: %.1fs' % (time.time() - t), len(ops), 'opcodes')
