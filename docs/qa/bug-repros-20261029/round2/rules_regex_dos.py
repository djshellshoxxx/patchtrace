import time
from patchtrace.rules.export import _STRING_LINE
for n in (10000, 20000, 40000):
    text = 'import "pe"\n' + '\n' * n
    t = time.time(); _STRING_LINE.findall(text); print(n, 'blank lines: %.2fs' % (time.time() - t))
