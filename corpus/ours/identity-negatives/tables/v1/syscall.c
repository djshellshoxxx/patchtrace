/* PatchTrace known-answer corpus: identity-negatives/tables, version 1. MIT licence.
 * System calls, in their own translation unit so that vm_step cannot absorb the dispatcher.
 */
#include "tabvm.h"

int32_t sys_yield(struct vm *m) {
    m->gas += 1u;
    return VM_OK;
}

int32_t sys_putc(struct vm *m) {
    if (m->sp < 1u) {
        return VM_E_STACK;
    }
    m->sp--;
    m->out_count++;
    return VM_OK;
}

int32_t sys_time(struct vm *m) {
    if (m->sp >= VM_STACK) {
        return VM_E_STACK;
    }
    m->stack[m->sp++] = m->gas;
    return VM_OK;
}

int32_t sys_rand(struct vm *m) {
    if (m->sp >= VM_STACK) {
        return VM_E_STACK;
    }
    m->rng = m->rng * 1664525u + 1013904223u;
    m->stack[m->sp++] = m->rng >> 8;
    return VM_OK;
}

int32_t sys_abort(struct vm *m) {
    m->last_syscall = 0xFFFFu;
    return VM_E_SYSCALL;
}

/* Dispatch through a table of handlers, indexed by the system-call number. */
int32_t vm_syscall(struct vm *m, uint32_t id) {
    static int32_t (*const handlers[])(struct vm *) = {sys_yield, sys_putc, sys_time, sys_rand, sys_abort};

    if (id >= sizeof handlers / sizeof handlers[0]) {
        return VM_E_SYSCALL;
    }
    m->last_syscall = id;
    return handlers[id](m);
}
