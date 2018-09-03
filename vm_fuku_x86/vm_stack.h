#pragma once


void vm_push(vm_context& context) {
    vm_ops_ex_code * ex_code = (vm_ops_ex_code *)&context.vm_code[0];

    uint32_t* src = get_operand(context, ex_code->info.src_is_ptr, 1 , 1);

    context.real_context.regs.esp -= ex_code->info.op_1_size;

    memcpy((uint32_t*)context.real_context.regs.esp, src, ex_code->info.op_1_size);

    free_operand(context, 1);

    context.vm_code += sizeof(vm_ops_ex_code);
}

void vm_pop(vm_context& context) {
    vm_ops_ex_code * ex_code = (vm_ops_ex_code *)&context.vm_code[0];

    uint32_t* src = get_operand(context, ex_code->info.src_is_ptr, 1, 1);

    memcpy(src, (uint32_t*)context.real_context.regs.esp, ex_code->info.op_1_size);
    context.real_context.regs.esp += ex_code->info.op_1_size;

    free_operand(context, 1);

    context.vm_code += sizeof(vm_ops_ex_code);
}

void vm_pushad(vm_context& context) {
    PUSH_VM(context, context.real_context.regs.eax);
    PUSH_VM(context, context.real_context.regs.ecx);
    PUSH_VM(context, context.real_context.regs.edx);
    PUSH_VM(context, context.real_context.regs.ebx);
    PUSH_VM(context, context.real_context.regs.esp + 20);
    PUSH_VM(context, context.real_context.regs.ebp);
    PUSH_VM(context, context.real_context.regs.esi);
    PUSH_VM(context, context.real_context.regs.edi);
}

void vm_pushfd(vm_context& context) {
    PUSH_VM(context, context.real_context.d_flag);
}

void vm_popad(vm_context& context) {
    POP_VM(context, context.real_context.regs.edi);
    POP_VM(context, context.real_context.regs.esi);
    POP_VM(context, context.real_context.regs.ebp);
    POP_VM(context, context.real_context.regs.esp); context.real_context.regs.esp -= 20;
    POP_VM(context, context.real_context.regs.ebx);
    POP_VM(context, context.real_context.regs.edx);
    POP_VM(context, context.real_context.regs.ecx);
    POP_VM(context, context.real_context.regs.eax);
}

void vm_popfd(vm_context& context) {
    POP_VM(context, context.real_context.d_flag);
}
