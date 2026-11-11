from patchtrace.codetext import CodeTextModel, open_comment_lines, MAX_DOCUMENT_CHARS, tokenize_line
rows=['/* open comment never closed'] + ['int x = 1;']*130000   # ~1.3M chars
print(sum(len(r)+1 for r in rows), MAX_DOCUMENT_CHARS)
m=CodeTextModel(rows, rows, 'c', paired=[])
ocl=open_comment_lines('\n'.join(rows))
print('rows flagged in-comment:', len(ocl), 'of', len(rows)-1)
last=len(rows)-1
print('last row in comment per model?', last in m._comment_rows('older'))
# true state by chaining tokenize_line
st=False
for r in rows: st=tokenize_line(r,'c',st).in_comment
print('true state at end (comment still open):', st)
sp=m.spans('older',last,rows[last]); print('spans for last row (should be one comment-colored span covering the line):', sp[:3])
sp=m.spans('older',1000,rows[1000]); print('row 1000 spans:', sp[:3])
