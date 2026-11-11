"""Apply the bounded v0.9.1 producer repair; never enables PatchTrace acceptance."""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

UPSTREAM_COMMIT = 'c3a90e9226d977f58f4e9c75f78fa6b07afe13c7'
UPSTREAM_BLOB = '8544259e17a692bcb3c1d8858f104745cd0cba4c'
UPSTREAM_SHA256 = 'a0b196dbc39e4fb3df4f850e156482ba9668838ccf5bb99a25563fd7a8c7ee5a'
OLD = (
    '\t\treturn analysis_match_result_new(opt, list_b, list_a, '
    '(RzThreadFunction)analysis_match_one_function, (AllocateBuffer)function_data_new);'
)
NEW = """\t\tRzAnalysisMatchResult *result = analysis_match_result_new(opt, list_b, list_a, (RzThreadFunction)analysis_match_one_function, (AllocateBuffer)function_data_new);
\t\tif (!result) {
\t\t\treturn NULL;
\t\t}
\t\t// Restore caller ownership only after internal unmatched bookkeeping.
\t\tRzListIter *iter;
\t\tRzAnalysisMatchPair *pair;
\t\trz_list_foreach (result->matches, iter, pair) {
\t\t\tconst void *tmp = pair->pair_a;
\t\t\tpair->pair_a = pair->pair_b;
\t\t\tpair->pair_b = tmp;
\t\t}
\t\tRzList *tmp = result->unmatch_a;
\t\tresult->unmatch_a = result->unmatch_b;
\t\tresult->unmatch_b = tmp;
\t\treturn result;"""


def git_blob(raw: bytes) -> str:
    return hashlib.sha1(b'blob ' + str(len(raw)).encode('ascii') + b'\0' + raw, usedforsecurity=False).hexdigest()


def corrected(raw: bytes) -> bytes:
    """Refuse drift, double application and text-only lookalikes before mutation."""
    if hashlib.sha256(raw).hexdigest() != UPSTREAM_SHA256 or git_blob(raw) != UPSTREAM_BLOB:
        raise ValueError('Rizin source identity mismatch; refusing patch')
    source = raw.decode('utf-8')
    if source.count(OLD) != 1:
        raise ValueError('singleton boundary is not unique')
    return source.replace(OLD, NEW, 1).encode('utf-8')


def main() -> None:
    root = Path(sys.argv[1]).resolve()
    source = (root / 'librz/arch/similarity.c').resolve()
    if not source.is_relative_to(root):
        raise ValueError('Rizin source resolves outside the declared checkout; refusing patch')
    source.write_bytes(corrected(source.read_bytes()))


if __name__ == '__main__':
    main()
