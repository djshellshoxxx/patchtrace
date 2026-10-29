import random, time, sys
from patchtrace.codetext import tokenize, tokenize_line, open_comment_lines
random.seed(2)
alpha=['/*','*/','"',"'",'\\','\n','//','L"','u8"','0x','.','e+','::','->','a','_','\ud800','\x00','é',' ','\r','1','$','@','?']
bad=0
for it in range(20000):
    s=''.join(random.choice(alpha) for _ in range(random.randint(0,40)))
    for lang in ('c','asm'):
        for mc in (3,4096):
            toks=tokenize(s,lang,max_line_chars=mc)
            pos=0
            for t in toks:
                if t.start!=pos or t.end<=t.start: bad+=1; print('GAP',repr(s),lang,toks); break
                pos=t.end
            else:
                if pos!=len(s): bad+=1; print('END',repr(s),lang)
            if '\n' in s:
                for t in toks:
                    if t.kind!='ws' and '\n' in s[t.start:t.end]: 
                        bad+=1; print('NL in token',repr(s),lang,t); break
    if lang and True:
        oc=open_comment_lines(s)
        # chain
        chain=set(); st=False
        for n,line in enumerate(s.split('\n')):
            if st: chain.add(n)
            st=tokenize_line(line,'c',st).in_comment
        if oc!=frozenset(chain): bad+=1; print('OCL mismatch',repr(s),sorted(oc),sorted(chain)); 
    if bad>5: break
print('bad',bad)
# timing
for name,s in {'a':'a'*1000000,'quotes':'"\\'*500000,'blocks':'/*'*500000,'lines':'/*\n'*300000,'dots':'.'*1000000,'esc':'"'+'\\'*1000000,'nested':'('*1000000, 'nums':'0x'+'1'*1000000, 'stars':'/*'+'*'*1000000}.items():
    for lang in ('c','asm'):
        t=time.time(); tokenize(s,lang); d=time.time()-t
        t=time.time(); open_comment_lines(s); d2=time.time()-t
        print(name,lang,'%.2f %.2f'%(d,d2))
