/* PatchTrace known-answer corpus: identity-negatives/tables, version 3. MIT licence.
 * The interpreter: step function, run loop, validator, system calls and the token counter.
 */
#include "tabvm.h"

uint32_t vm_rd32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

int32_t vm_step(struct vm *m) {
    uint32_t op, n, a, b, target;
    int32_t rc;

    if (m->pc >= m->code_len) {
        return VM_E_PC;
    }
    op = m->code[m->pc];
    n = vm_op_len(op);
    if (n == 0u || m->pc + n > m->code_len) {
        return VM_E_OPCODE;
    }
    if (m->gas < vm_op_cost(op)) {
        return VM_E_GAS;
    }
    m->gas -= vm_op_cost(op);
    target = (n == 3u) ? ((uint32_t)m->code[m->pc + 1u] | ((uint32_t)m->code[m->pc + 2u] << 8)) : 0u;
    switch (op) {
    case OP_NOP:
        break;
    case OP_PUSH:
        if (m->sp >= VM_STACK) {
            return VM_E_STACK;
        }
        m->stack[m->sp++] = vm_rd32(m->code + m->pc + 1u);
        break;
    case OP_POP:
        if (m->sp < 1u) {
            return VM_E_STACK;
        }
        m->sp--;
        break;
    case OP_DUP:
        if (m->sp < 1u || m->sp >= VM_STACK) {
            return VM_E_STACK;
        }
        m->stack[m->sp] = m->stack[m->sp - 1u];
        m->sp++;
        break;
    case OP_SWAP:
        if (m->sp < 2u) {
            return VM_E_STACK;
        }
        a = m->stack[m->sp - 1u];
        m->stack[m->sp - 1u] = m->stack[m->sp - 2u];
        m->stack[m->sp - 2u] = a;
        break;
    case OP_ADD:
    case OP_SUB:
    case OP_MUL:
    case OP_XOR:
    case OP_SHL:
    case OP_EQ:
    case OP_LT:
    case OP_MIN:
        if (m->sp < 2u) {
            return VM_E_STACK;
        }
        b = m->stack[--m->sp];
        a = m->stack[m->sp - 1u];
        m->stack[m->sp - 1u] = vm_binop(op, a, b);
        break;
    case OP_JMP:
        m->pc = target;
        return VM_OK;
    case OP_JZ:
        if (m->sp < 1u) {
            return VM_E_STACK;
        }
        if (m->stack[--m->sp] == 0u) {
            m->pc = target;
            return VM_OK;
        }
        break;
    case OP_LOAD:
        a = m->code[m->pc + 1u];
        if (a >= VM_MEM || m->sp >= VM_STACK) {
            return VM_E_STACK;
        }
        m->stack[m->sp++] = m->mem[a];
        break;
    case OP_STORE:
        a = m->code[m->pc + 1u];
        if (a >= VM_MEM || m->sp < 1u) {
            return VM_E_STACK;
        }
        m->mem[a] = m->stack[--m->sp];
        break;
    case OP_CALL:
        if (m->csp >= VM_CALLS) {
            return VM_E_STACK;
        }
        m->calls[m->csp++] = m->pc + n;
        m->pc = target;
        return VM_OK;
    case OP_RET:
        if (m->csp < 1u) {
            return VM_E_STACK;
        }
        m->pc = m->calls[--m->csp];
        return VM_OK;
    case OP_SYS:
        rc = vm_syscall(m, m->code[m->pc + 1u]);
        if (rc != VM_OK) {
            return rc;
        }
        break;
    case OP_HALT:
        m->pc += n;
        return VM_HALTED;
    default:
        return VM_E_OPCODE;
    }
    m->pc += n;
    return VM_OK;
}

int32_t vm_run(struct vm *m, uint32_t max_steps) {
    uint32_t i;
    int32_t rc;

    for (i = 0u; i < max_steps; i++) {
        rc = vm_step(m);
        if (rc == VM_HALTED) {
            return VM_OK;
        }
        if (rc != VM_OK) {
            return rc;
        }
    }
    return VM_E_GAS;
}

/* Every opcode must be known, every instruction complete, every jump inside the code. */
int32_t vm_validate(const uint8_t *code, uint32_t len) {
    uint32_t pc = 0u;

    while (pc < len) {
        uint32_t op = code[pc];
        uint32_t n = vm_op_len(op);

        if (n == 0u || pc + n > len) {
            return VM_E_OPCODE;
        }
        if (op == OP_JMP || op == OP_JZ || op == OP_CALL) {
            uint32_t target = (uint32_t)code[pc + 1u] | ((uint32_t)code[pc + 2u] << 8);

            if (target >= len) {
                return VM_E_PC;
            }
        }
        pc += n;
    }
    return VM_OK;
}

/* Counts tokens and error transitions of the tokenizer DFA over a buffer. */
uint32_t lex_count_tokens(const char *s, uint32_t n, uint32_t *errors) {
    uint32_t state = LS_START;
    uint32_t tokens = 0u;
    uint32_t bad = 0u;
    uint32_t i;

    for (i = 0u; i < n; i++) {
        uint32_t next = lex_step(state, lex_classify((unsigned char)s[i]));

        if (state == LS_START && next != LS_START && next != LS_ERROR) {
            tokens++;
        }
        if (next == LS_ERROR && state != LS_ERROR) {
            bad++;
        }
        state = next;
    }
    if (errors != NULL) {
        *errors = bad;
    }
    return tokens;
}
