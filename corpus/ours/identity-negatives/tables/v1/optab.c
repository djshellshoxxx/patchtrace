/* PatchTrace known-answer corpus: identity-negatives/tables, version 1. MIT licence.
 * Table-like functions: opcode metadata, the ALU and the tokenizer transition table.
 */
#include "tabvm.h"

/* Instruction length in bytes, opcode included; 0 for an unknown opcode. */
uint32_t vm_op_len(uint32_t op) {
    switch (op) {
    case OP_PUSH:
        return 5u;
    case OP_JMP:
    case OP_JZ:
    case OP_CALL:
        return 3u;
    case OP_LOAD:
    case OP_STORE:
    case OP_SYS:
        return 2u;
    case OP_NOP:
    case OP_POP:
    case OP_DUP:
    case OP_SWAP:
    case OP_ADD:
    case OP_SUB:
    case OP_MUL:
    case OP_XOR:
    case OP_SHL:
    case OP_EQ:
    case OP_LT:
    case OP_RET:
    case OP_HALT:
        return 1u;
    default:
        return 0u;
    }
}

/* Gas charged per instruction. */
uint32_t vm_op_cost(uint32_t op) {
    switch (op) {
    case OP_NOP:
    case OP_PUSH:
    case OP_POP:
    case OP_DUP:
    case OP_SWAP:
        return 1u;
    case OP_ADD:
    case OP_SUB:
    case OP_XOR:
    case OP_EQ:
    case OP_LT:
    case OP_JMP:
        return 2u;
    case OP_SHL:
    case OP_JZ:
        return 3u;
    case OP_MUL:
        return 4u;
    case OP_LOAD:
    case OP_STORE:
    case OP_RET:
        return 5u;
    case OP_CALL:
        return 8u;
    case OP_SYS:
        return 20u;
    default:
        return 0u;
    }
}

const char *vm_op_name(uint32_t op) {
    switch (op) {
    case OP_NOP: return "nop";
    case OP_PUSH: return "push";
    case OP_POP: return "pop";
    case OP_DUP: return "dup";
    case OP_SWAP: return "swap";
    case OP_ADD: return "add";
    case OP_SUB: return "sub";
    case OP_MUL: return "mul";
    case OP_XOR: return "xor";
    case OP_SHL: return "shl";
    case OP_EQ: return "eq";
    case OP_LT: return "lt";
    case OP_JMP: return "jmp";
    case OP_JZ: return "jz";
    case OP_LOAD: return "load";
    case OP_STORE: return "store";
    case OP_CALL: return "call";
    case OP_RET: return "ret";
    case OP_SYS: return "sys";
    case OP_HALT: return "halt";
    default: return "???";
    }
}

/* The ALU: every binary opcode is one arm of this switch. */
uint32_t vm_binop(uint32_t op, uint32_t a, uint32_t b) {
    switch (op) {
    case OP_ADD:
        return a + b;
    case OP_SUB:
        return a - b;
    case OP_MUL:
        return a * b;
    case OP_XOR:
        return a ^ b;
    case OP_SHL:
        return a << (b & 31u);
    case OP_EQ:
        return (a == b) ? 1u : 0u;
    case OP_LT:
        return (a < b) ? 1u : 0u;
    default:
        return 0u;
    }
}

uint32_t lex_classify(uint32_t ch) {
    switch (ch) {
    case ' ':
    case '\t':
    case '\r':
        return LC_SPACE;
    case '\n':
        return LC_EOL;
    case '"':
        return LC_QUOTE;
    case '#':
        return LC_HASH;
    case '_':
        return LC_ALPHA;
    default:
        if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')) {
            return LC_ALPHA;
        }
        if (ch >= '0' && ch <= '9') {
            return LC_DIGIT;
        }
        return LC_OTHER;
    }
}

/* Tokenizer DFA: rows are states, columns are character classes. */
uint32_t lex_step(uint32_t state, uint32_t cls) {
    static const uint8_t next[LS_COUNT][LC_COUNT] = {
        /*             SPACE     ALPHA     DIGIT      QUOTE      HASH        EOL       OTHER    */
        /* START */ {LS_START, LS_IDENT, LS_NUMBER, LS_STRING, LS_COMMENT, LS_START, LS_ERROR},
        /* IDENT */ {LS_START, LS_IDENT, LS_IDENT, LS_ERROR, LS_COMMENT, LS_START, LS_ERROR},
        /* NUMBER */ {LS_START, LS_ERROR, LS_NUMBER, LS_ERROR, LS_COMMENT, LS_START, LS_ERROR},
        /* STRING */ {LS_STRING, LS_STRING, LS_STRING, LS_START, LS_STRING, LS_STRING, LS_STRING},
        /* COMMENT */ {LS_COMMENT, LS_COMMENT, LS_COMMENT, LS_COMMENT, LS_COMMENT, LS_START, LS_COMMENT},
        /* ERROR */ {LS_ERROR, LS_ERROR, LS_ERROR, LS_ERROR, LS_ERROR, LS_START, LS_ERROR}
    };

    if (state >= LS_COUNT || cls >= LC_COUNT) {
        return LS_ERROR;
    }
    return next[state][cls];
}
