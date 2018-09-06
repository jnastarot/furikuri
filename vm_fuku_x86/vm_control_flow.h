#pragma once


void vm_jump_local(vm_context& context) {
    vm_jump_code * jump_code = (vm_jump_code *)&context.vm_code[0];
    vm_ops_ex_code * ex_code = (vm_ops_ex_code *)&context.vm_code[1];

    bool jump = is_jump(context, jump_code->condition, jump_code->invert_condition);
   // fprintf(stdout, "jump %d %x %x %08x %08x\n", jump, jump_code->info.condition, jump_code->info.invert_condition, jump_code->info.back_jump, jump_code->offset);
    if (jump) {
      //  fprintf(stdout, "context.vm_code = %x | ", context.vm_code);
        context.vm_code = (uint8_t*)*get_operand(context, *ex_code, 1, 1);
      //  fprintf(stdout, "%x |\n ", context.vm_code);
    }
    else {
        context.vm_code += sizeof(vm_jump_code) + sizeof(vm_ops_ex_code);
    }

    free_operand(context, 1);
}

void vm_jump_external(vm_context& context) {
    vm_jump_code * jump_code = (vm_jump_code *)&context.vm_code[0];
    vm_ops_ex_code * ex_code = (vm_ops_ex_code *)&context.vm_code[1];


    bool jump = is_jump(context, jump_code->condition, jump_code->invert_condition);

    if (jump) {    
        vm_exit(context, *get_operand(context, *ex_code, 1, 1));
    }
    else {
        context.vm_code += sizeof(vm_jump_code) + sizeof(vm_ops_ex_code);
    }

    free_operand(context, 1);
}

void vm_call_local(vm_context& context) {
    vm_ops_ex_code * ex_code = (vm_ops_ex_code *)&context.vm_code[0];

    uint32_t call_dst = *get_operand(context, *ex_code, 1, 1);
    free_operand(context, 1);

    PUSH_VM(context, ((uint32_t)(context.vm_code + sizeof(vm_ops_ex_code)) | 0x80000000));

    context.vm_code = (uint8_t*)call_dst;
}

void vm_call_external(vm_context& context) {
    vm_ops_ex_code * ex_code = (vm_ops_ex_code *)&context.vm_code[0];
    
    uint32_t call_dst = *get_operand(context, *ex_code, 1, 1);

    free_operand(context, 1);
    fprintf(stdout, "call_dst %x\n", call_dst);

    uint8_t inst_[6] = { 0xFF, 0x15, 0, 0, 0, 0 };
    *(uint32_t*)&inst_[2] = (uint32_t)&call_dst;

    vm_pure(context, inst_, 6);

    context.vm_code += sizeof(vm_ops_ex_code);
}

void vm_return(vm_context& context) {

    uint32_t stack_ret = *get_operand(context, vm_ops_ex_code(0, 0, 0, 0), 1, 1);
    free_operand(context, 1);

    context.real_context.regs.esp += stack_ret;

    uint32_t ret_dst;
    POP_VM(context, ret_dst);

    if (ret_dst & 0x80000000) {
        context.vm_code = (uint8_t*)(ret_dst & 0x7FFFFFFF);
    }
    else {
        vm_exit(context, ret_dst);
    }
}