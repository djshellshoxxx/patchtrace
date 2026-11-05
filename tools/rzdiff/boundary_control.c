// SPDX-License-Identifier: LGPL-3.0-only
// Deterministic helper double exercises the ACTUAL extracted public C wrapper.
// Does not test threads, IO, disassembly, scoring or JSON serialization.
#include <stdio.h>
#include <stddef.h>
#include <stdbool.h>
#define RZ_API
#define RZ_OWN
#define RZ_NONNULL
#define rz_return_val_if_fail(c, v) do { if (!(c)) return (v); } while (0)
typedef struct RzListIter { void *val; struct RzListIter *next; } RzListIter;
typedef struct { RzListIter *head; size_t length; } RzList;
typedef struct { const void *pair_a; const void *pair_b; double similarity; } RzAnalysisMatchPair;
typedef struct { RzList *matches; RzList *unmatch_a; RzList *unmatch_b; } RzAnalysisMatchResult;
typedef struct { void *analysis_a; void *analysis_b; } RzAnalysisMatchOpt;
typedef void (*RzThreadFunction)(void);
typedef void (*AllocateBuffer)(void);
static void analysis_match_one_function(void) {}
static void analysis_match_functions(void) {}
static void function_data_new(void) {}
#define rz_list_length(l) ((l)->length)
#define rz_list_foreach(l, it, p) for ((it) = (l)->head; (it) && ((p) = (it)->val, 1); (it) = (it)->next)
static RzList *expected_a, *expected_b;
static bool fail_result, singleton;
static int helper_errors;
static RzAnalysisMatchPair pair;
static RzListIter node;
static RzList matches, ua, ub;
static RzAnalysisMatchResult result;
static RzAnalysisMatchResult *analysis_match_result_new(RzAnalysisMatchOpt *opt,
        RzList *a, RzList *b, RzThreadFunction cb, AllocateBuffer alloc) {
    if (a != (singleton ? expected_b : expected_a) ||
        b != (singleton ? expected_a : expected_b) ||
        cb != (singleton ? analysis_match_one_function : analysis_match_functions) ||
        alloc != function_data_new || opt->analysis_a == opt->analysis_b) helper_errors++;
    if (fail_result) return NULL;
    // Distinct identities, not address overlap or JSON row-count inference.
    pair.pair_a = a; pair.pair_b = b; pair.similarity = 0.375;
    node.val = &pair; node.next = NULL;
    matches.head = &node; matches.length = 1;
    result.matches = &matches; result.unmatch_a = &ua; result.unmatch_b = &ub;
    return &result;
}
/* WRAPPER */
int main(void) {
    RzList a = { NULL, 1 }, b = { NULL, 2 };
    RzAnalysisMatchOpt opt = { &a, &b };
    int errors = 0;
    // 1:1, 1:2, 2:1, 2:2, 1:0 and 0:1; both operand identities.
    const size_t counts[][2] = {{1,1},{1,2},{2,1},{2,2},{1,0},{0,1}};
    for (size_t i = 0; i < 6; i++) for (int reverse = 0; reverse < 2; reverse++) {
        a.length = counts[i][0]; b.length = counts[i][1];
        expected_a = reverse ? &b : &a; expected_b = reverse ? &a : &b;
        singleton = expected_a->length == 1;
        fail_result = false;
        RzAnalysisMatchResult *r = rz_analysis_match_functions(expected_a, expected_b, &opt);
        if (!r || pair.pair_a != expected_a || pair.pair_b != expected_b ||
            pair.similarity != 0.375 ||
            r->unmatch_a != (singleton ? &ub : &ua) ||
            r->unmatch_b != (singleton ? &ua : &ub)) errors++;
        fail_result = true;
        if (rz_analysis_match_functions(expected_a, expected_b, &opt) != NULL) errors++;
    }
    if (rz_analysis_match_functions(&a, &b, NULL) != NULL) errors++;
    printf("12 boundary scenarios; ownership failures=%d helper failures=%d\n", errors, helper_errors);
    return errors || helper_errors ? 1 : 0;
}
