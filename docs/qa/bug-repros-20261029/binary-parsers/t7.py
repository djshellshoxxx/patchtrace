from h import *
from patchtrace.pe_overview.build_facts import collect_build_facts
import pathlib
# .text raw 0x200 (RVA 0x1000..), CLR dir at last 8 bytes of .text's raw data; the 64 bytes that follow in the FILE belong to .data
cor=struct.pack('<IHHIII',72,2,5,0,0,1)+b'\0'*(72-20)    # a valid-looking COR20 header
text=bytearray(b'\x90'*0x1F8)+cor[:8]                      # only 8 header bytes lie inside .text
d,info=build_pe_ex(PeSpec(sections=[SectionSpec('.text',bytes(text),CODE),SectionSpec('.data',cor[8:]+b'\0'*0x100,DATA)],
                          extra_directories={14:(0x1000+0x1F8,72)}))
p=pathlib.Path('t7.bin'); p.write_bytes(d)
with VerifiedArtifactReader.open_path(p) as r:
    ov=inspect_pe(r); bf=collect_build_facts(r,ov)
print('clr facts:',bf.clr)
print([(s.name,hex(s.virtual_address),s.raw_size) for s in ov.sections])
