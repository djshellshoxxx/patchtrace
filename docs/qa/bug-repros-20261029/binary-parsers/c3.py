import random, time, sys
from collections import Counter
from patchtrace.codetext import diff_row, CodeTextModel
random.seed(int(sys.argv[1]))
toks=['FUN_140001000','FUN_140001010','uVar1','uVar2','local_18','param_1','x','y','0x10','10','(',')',',',';','+','-','*','[',']','rax','rsp','rip','call','mov','lock','"s"',"'c'",'/*','*/','//','->','::','\ud800','é',' ','  ','\t','h','0x','10h','PTR_FUN_00401000','LAB_00401000','DAT_00401000','thunk_FUN_00401000']
worst=0; seen=Counter()
for it in range(int(sys.argv[2])):
    n=random.choice([3,10,30,100,250,300]); 
    a=[random.choice(toks) for _ in range(n)]
    b=list(a)
    for _ in range(random.randint(0,n//3+2)):
        op=random.random(); i=random.randrange(len(b)+1)
        if op<.4: b.insert(i,random.choice(toks))
        elif op<.7 and b: b.pop(min(i,len(b)-1))
        elif b: b[min(i,len(b)-1)]=random.choice(toks)
    sep=random.choice([' ',''])
    A,B=sep.join(a),sep.join(b)
    for lang in ('c','asm'):
        t=time.time()
        try:
            oc,nc=random.random()<.2,random.random()<.2; r=diff_row(A,B,lang,old_in_comment=oc,new_in_comment=nc)
            # validate marks inside bounds and non-overlapping
            for ms,line in ((r.old,A),(r.new,B)):
                prev=0
                for mk in ms:
                    if not(0<=mk.start<mk.end<=len(line)) : seen['mark oob']+=1; open('c3_bad.txt','w').write(repr((A,B,lang)))
                    if mk.start<prev: seen['overlap']+=1; open('c3_bad2.txt','w').write(repr((A,B,lang)))
                    prev=mk.end
            # swap symmetry of gate
            r2=diff_row(B,A,lang,old_in_comment=nc,new_in_comment=oc)
            if r.gated!=r2.gated or (r.similarity!=r2.similarity): seen['asym']+=1; open('c3_asym.txt','w').write(repr((A,B,lang)))
        except Exception as e:
            seen[type(e).__name__+str(e)[:50]]+=1; open('c3_exc.txt','w').write(repr((A,B,lang)))
        worst=max(worst,time.time()-t)
print(seen,worst)
