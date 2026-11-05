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
// Constructed input bytes; the matcher and public API objects are actual pinned Rizin.
static RzIO *distinct_io[2];
static RzThreadLock *distinct_read_lock;
static ut64 distinct_base[2];
static unsigned distinct_count[2], distinct_reads[2], distinct_fault;
static const ut8 distinct_data[2][2][4] = {
    {{0x10,0x20,0x30,0x40}, {0x10,0x20,0x30,0x41}},
    {{0x10,0x20,0x30,0x42}, {0x10,0x20,0x43,0x44}}
};
static bool read_distinct(RzIO *io, ut64 addr, ut8 *buf, size_t len) {
    for (unsigned side=0; side<2; side++) {
        if (io != distinct_io[side] || addr < distinct_base[side]) continue;
        ut64 offset = addr - distinct_base[side];
        if (len != 4 || offset % 0x100 || offset / 0x100 >= distinct_count[side]) return false;
        rz_th_lock_enter(distinct_read_lock);
        distinct_reads[side]++;
        rz_th_lock_leave(distinct_read_lock);
        if (distinct_fault == 1) memset(buf, 0x90, len);
        else memcpy(buf, distinct_data[side][offset / 0x100], len);
        return true;
    }
    return false;
}
static int check_distinct(unsigned na, unsigned nb, bool overlap, unsigned fault) {
    RzAnalysis *analysis[2] = {rz_analysis_new(NULL), rz_analysis_new(NULL)};
    RzList *lists[2] = {rz_list_new(), rz_list_new()};
    RzAnalysisFunction *functions[2][2] = {{NULL,NULL},{NULL,NULL}};
    RzAnalysisMatchResult *result = NULL;
    int errors = 1;
    distinct_fault = fault;
    distinct_read_lock = rz_th_lock_new(false);
    if (!distinct_read_lock) goto cleanup;
    for (unsigned side=0; side<2; side++) {
        distinct_io[side] = rz_io_new();
        distinct_count[side] = side ? nb : na;
        distinct_base[side] = 0x1000 + (overlap ? 0 : side * 0x10000);
        distinct_reads[side] = 0;
        if (!analysis[side] || !lists[side] || !distinct_io[side]) goto cleanup;
        RzIOBind *binding = rz_analysis_get_io_bind(analysis[side]);
        binding->io = distinct_io[side];
        binding->read_at = read_distinct;
        for (unsigned i=0; i<distinct_count[side]; i++) {
            ut64 addr = distinct_base[side] + i * 0x100;
            char name[32];
            snprintf(name,sizeof(name),"io.%u.%u",side,i);
            RzAnalysisFunction *function = rz_analysis_create_function(analysis[side],name,addr,RZ_ANALYSIS_FCN_TYPE_FCN);
            RzAnalysisBlock *block = rz_analysis_create_block(analysis[side],addr,4);
            if (!function || !block) {
                if (block) rz_analysis_block_unref(block);
                goto cleanup;
            }
            rz_analysis_function_add_block(function,block);
            rz_analysis_block_unref(block);
            functions[side][i] = function;
            if (!rz_list_append(lists[side],function)) goto cleanup;
        }
    }
    if (fault == 2) rz_analysis_get_io_bind(analysis[1])->io = distinct_io[0];
    RzAnalysisMatchOpt opt = {0};
    opt.analysis_a = analysis[0]; opt.analysis_b = analysis[1];
    result = rz_analysis_match_functions(lists[0],lists[1],&opt);
    if (!result) goto cleanup;
    errors = 0;
    if (!distinct_reads[0] || !distinct_reads[1]) errors++;
    if (!covered(lists[0],result->unmatch_a,result->matches,true) ||
        !covered(lists[1],result->unmatch_b,result->matches,false)) errors++;
    if (rz_list_length(result->matches) != 2) errors++;
    RzListIter *it;
    RzAnalysisMatchPair *pair;
    rz_list_foreach (result->matches,it,pair) {
        unsigned old=0, newer=0;
        while (old<na && functions[0][old] != pair->pair_a) old++;
        while (newer<nb && functions[1][newer] != pair->pair_b) newer++;
        if (old==na || newer==nb) { errors++; continue; }
        // Both older rows differ at one byte from newer[0], and two from newer[1].
        double expected = newer ? 0.5 : 0.75;
        if (pair->similarity != expected) errors++;
    }
    RzAnalysisFunction *unmatched;
    rz_list_foreach (result->unmatch_a,it,unmatched) { if (!owned(lists[0],unmatched)) errors++; }
    rz_list_foreach (result->unmatch_b,it,unmatched) { if (!owned(lists[1],unmatched)) errors++; }
    printf("distinct-io %u:%u overlap=%d errors=%d reads=%u,%u\n",na,nb,overlap,errors,
           distinct_reads[0],distinct_reads[1]);
cleanup:
    if (result) rz_analysis_match_result_free(result);
    for (unsigned side=0; side<2; side++) {
        if (lists[side]) rz_list_free(lists[side]);
        if (analysis[side]) rz_analysis_free(analysis[side]);
        if (distinct_io[side]) rz_io_free(distinct_io[side]);
        distinct_io[side] = NULL;
    }
    if (distinct_read_lock) rz_th_lock_free(distinct_read_lock);
    distinct_read_lock = NULL;
    return errors;
}
int main(int argc, char **argv) {
    if (argc > 1) {
        if (strcmp(argv[1],"--io-context") || argc > 3) return 2;
        unsigned fault = 0;
        if (argc == 3) {
            if (!strcmp(argv[2],"--wrong-bytes")) fault = 1;
            else if (!strcmp(argv[2],"--wrong-io")) fault = 2;
            else return 2;
        }
        int errors = 0;
        for (unsigned overlap=(fault==2); overlap<2; overlap++) {
            errors += check_distinct(1,2,overlap,fault);
            errors += check_distinct(2,1,overlap,fault);
        }
        return errors ? 1 : 0;
    }
    int errors = 0;
    const unsigned counts[][2] = {{1,1},{1,2},{2,1},{2,2},{1,0},{0,1},{2,0},{0,2}};
    for (unsigned i=0; i<8; i++) for (unsigned overlap=0; overlap<2; overlap++) {
        errors += check(counts[i][0],counts[i][1],overlap);
        errors += check(counts[i][1],counts[i][0],overlap);
    }
    return errors ? 1 : 0;
}
