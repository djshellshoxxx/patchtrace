// SPDX-License-Identifier: LGPL-3.0-only
// Native public API ownership oracle. Never executes compared images.
#include <rz_analysis.h>
#include <stdio.h>
#include <string.h>
static bool read_bytes(RzIO *io, ut64 addr, ut8 *buf, size_t len) {
    (void)io; (void)addr;
    memset(buf, 0x90, len);
    return true;
}
static bool owned(RzList *list, const void *ptr) {
    return ptr && rz_list_contains(list, ptr);
}
static bool covered(RzList *input, RzList *unmatched, RzList *matches, bool left) {
    RzListIter *it, *mt, *ut;
    RzAnalysisFunction *f, *u;
    RzAnalysisMatchPair *pair;
    rz_list_foreach (input, it, f) {
        unsigned unmatched_count = 0;
        bool matched = false;
        rz_list_foreach (unmatched, ut, u) {
            if (u == f) unmatched_count++;
        }
        rz_list_foreach (matches, mt, pair) {
            if ((left ? pair->pair_a : pair->pair_b) == f) matched = true;
        }
        // Complete coverage is a partition: exactly one unmatched occurrence
        // OR one/more matches (the singleton intentionally searches all B).
        if (unmatched_count > 1 || (unmatched_count && matched) ||
            (!unmatched_count && !matched)) return false;
    }
    return true;
}
static int check(unsigned na, unsigned nb, bool overlap) {
    RzAnalysis *a = rz_analysis_new(NULL), *b = rz_analysis_new(NULL);
    if (!a || !b) return 1;
    rz_analysis_get_io_bind(a)->read_at = read_bytes;
    rz_analysis_get_io_bind(b)->read_at = read_bytes;
    RzList *la = rz_list_new(), *lb = rz_list_new();
    RzAnalysis *contexts[] = {a,b};
    RzList *lists[] = {la,lb};
    unsigned counts[] = {na,nb};
    for (unsigned side = 0; side < 2; side++) for (unsigned i = 0; i < counts[side]; i++) {
        ut64 addr = 0x1000 + i * 0x100 + (overlap ? 0 : side * 0x10000);
        char name[32];
        snprintf(name, sizeof(name), "fcn.%u.%u", side, i);
        RzAnalysisFunction *f = rz_analysis_create_function(contexts[side], name, addr, RZ_ANALYSIS_FCN_TYPE_FCN);
        RzAnalysisBlock *bb = rz_analysis_create_block(contexts[side], addr, 4);
        if (!f || !bb) return 1;
        rz_analysis_function_add_block(f, bb);
        rz_analysis_block_unref(bb);
        rz_list_append(lists[side], f);
    }
    RzAnalysisMatchOpt opt = {0};
    opt.analysis_a = a; opt.analysis_b = b;
    RzAnalysisMatchResult *r = rz_analysis_match_functions(la, lb, &opt);
    if (!r) {
        // A native API failure must not masquerade as stock orientation red.
        fprintf(stderr, "native API returned NULL for %u:%u overlap=%d\n", na, nb, overlap);
        rz_list_free(la); rz_list_free(lb);
        rz_analysis_free(a); rz_analysis_free(b);
        return 1;
    }
    int errors = 0;
    if (r) {
        RzListIter *it; RzAnalysisMatchPair *pair; RzAnalysisFunction *f;
        rz_list_foreach (r->matches, it, pair) {
            if (!owned(la, pair->pair_a) || !owned(lb, pair->pair_b)) errors++;
        }
        rz_list_foreach (r->unmatch_a, it, f) { if (!owned(la,f)) errors++; }
        rz_list_foreach (r->unmatch_b, it, f) { if (!owned(lb,f)) errors++; }
        if (!covered(la,r->unmatch_a,r->matches,true) || !covered(lb,r->unmatch_b,r->matches,false)) errors++;
        // Singleton searches all B candidates, not a best-match-only replacement.
        if (na == 1 && nb && rz_list_length(r->matches) != nb) errors++;
        if (!nb && rz_list_length(r->unmatch_a) != na) errors++;
        if (!na && rz_list_length(r->unmatch_b) != nb) errors++;
    }
    printf("%u:%u overlap=%d errors=%d\n",na,nb,overlap,errors);
    rz_analysis_match_result_free(r);
    rz_list_free(la); rz_list_free(lb);
    rz_analysis_free(a); rz_analysis_free(b);
    return errors;
}
int main(void) {
    int errors = 0;
    const unsigned counts[][2] = {{1,1},{1,2},{2,1},{2,2},{1,0},{0,1},{2,0},{0,2}};
    for (unsigned i=0; i<8; i++) for (unsigned overlap=0; overlap<2; overlap++) {
        errors += check(counts[i][0],counts[i][1],overlap);
        errors += check(counts[i][1],counts[i][0],overlap);
    }
    return errors ? 1 : 0;
}
