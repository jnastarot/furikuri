#pragma once


void vm_push(vm_context& context) {
    vm_double_ops_ex_code * ex_code = (vm_double_ops_ex_code *)&context.vm_code[0];

    if (ex_code->src_op_by_ptr) {
        context.real_context.regs.esp -= 4;
        *(uint32_t*)context.real_context.regs.esp = 0;
        mov_by_size((uint32_t*)context.real_context.regs.esp, &context.operands.back(), ex_code->ops_size);
    }
    else {
        context.real_context.regs.esp -= 4;
        *(uint32_t*)context.real_context.regs.esp = 0;
        mov_by_size((uint32_t*)context.real_context.regs.esp, (uint32_t*)context.operands.back(), ex_code->ops_size);
    }

    context.operands.pop_back();

    context.vm_code += sizeof(vm_double_ops_ex_code);
}

void vm_pushad(vm_context& context) {
    PUSHAD_VM(context);
}

void vm_pushfd(vm_context& context) {
    PUSHFD_VM(context);
}

void vm_pop(vm_context& context) {
    vm_double_ops_ex_code * ex_code = (vm_double_ops_ex_code *)&context.vm_code[0];

    if (ex_code->src_op_by_ptr) {
        POP_VM(context, context.operands.back());
    }
    else {
        POP_VM(context, *(uint32_t*)context.operands.back());
    }

    context.operands.pop_back();

    context.vm_code += sizeof(vm_double_ops_ex_code);
}

void vm_popad(vm_context& context) {
    POPAD_VM(context);
}

void vm_popfd(vm_context& context) {
    POPFD_VM(context);
}
