/* PatchTrace known-answer corpus: identity-negatives/tables, version 1. MIT licence.
 * Freestanding C11, no libc.
 *
 * A small stack-machine interpreter dominated by switch statements and lookup tables:
 * opcode length, cost and name, the ALU, the step function, a system-call pointer table
 * and a tokenizer driven by a transition table. optab.c holds the table-like functions,
 * vm.c the interpreter that uses them.
 */
#ifndef TABVM_H
#define TABVM_H

#include <stddef.h>
#include <stdint.h>

#define VM_OK 0
#define VM_HALTED 1
#define VM_E_STACK (-1)
#define VM_E_OPCODE (-2)
#define VM_E_PC (-3)
#define VM_E_GAS (-4)
#define VM_E_SYSCALL (-5)

#define VM_STACK 32u
#define VM_MEM 16u
#define VM_CALLS 8u

enum vm_op {
    OP_NOP = 0, OP_PUSH = 1, OP_POP = 2, OP_DUP = 3, OP_SWAP = 4,
    OP_ADD = 5, OP_SUB = 6, OP_MUL = 7, OP_XOR = 8, OP_SHL = 9, OP_EQ = 10, OP_LT = 11,
    OP_JMP = 12, OP_JZ = 13, OP_LOAD = 14, OP_STORE = 15, OP_CALL = 16, OP_RET = 17,
    OP_SYS = 18, OP_HALT = 19
};

enum lex_class { LC_SPACE = 0, LC_ALPHA, LC_DIGIT, LC_QUOTE, LC_HASH, LC_EOL, LC_OTHER, LC_COUNT };
enum lex_state { LS_START = 0, LS_IDENT, LS_NUMBER, LS_STRING, LS_COMMENT, LS_ERROR, LS_COUNT };

struct vm {
    const uint8_t *code;
    uint32_t code_len;
    uint32_t pc;
    uint32_t sp;
    uint32_t csp;
    uint32_t gas;
    uint32_t rng;
    uint32_t out_count;
    uint32_t last_syscall;
    uint32_t stack[VM_STACK];
    uint32_t mem[VM_MEM];
    uint32_t calls[VM_CALLS];
};

/* optab.c: table-like functions. */
uint32_t vm_op_len(uint32_t op);
uint32_t vm_op_cost(uint32_t op);
const char *vm_op_name(uint32_t op);
uint32_t vm_binop(uint32_t op, uint32_t a, uint32_t b);
uint32_t lex_classify(uint32_t ch);
uint32_t lex_step(uint32_t state, uint32_t cls);

/* vm.c: the interpreter. */
uint32_t vm_rd32(const uint8_t *p);
int32_t vm_step(struct vm *m);
int32_t vm_run(struct vm *m, uint32_t max_steps);
int32_t vm_validate(const uint8_t *code, uint32_t len);
int32_t sys_yield(struct vm *m);
int32_t sys_putc(struct vm *m);
int32_t sys_time(struct vm *m);
int32_t sys_rand(struct vm *m);
int32_t sys_abort(struct vm *m);
int32_t vm_syscall(struct vm *m, uint32_t id);
uint32_t lex_count_tokens(const char *s, uint32_t n, uint32_t *errors);

#endif
