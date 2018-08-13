#pragma once


void vm_mov(vm_context& context) {
    vm_double_ops_ex_code * ex_code = (vm_double_ops_ex_code *)&context.vm_code[0];

    uint32_t src = context.operands.back();
    uint32_t dst = context.operands.back();

    context.operands.pop_back();
    context.operands.pop_back();

    context.vm_code += sizeof(vm_double_ops_ex_code);
}

void vm_lea(vm_context& context) {
    uint32_t src = context.operands.back();
    uint32_t dst = context.operands.back();

    context.operands.pop_back();
    context.operands.pop_back();

    *(uint32_t*)

}

void vm_xchg(vm_context& context) {
    context.operands.push_back(0);
}