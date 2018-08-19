#pragma once


void vm_jump_local(vm_context& context) {
    vm_jump_code * jump_code = (vm_jump_code *)&context.vm_code[0];

    bool jump = is_jump(context, jump_code->info.condition, jump_code->info.invert_condition);
    
    if (jump) {
        context.vm_code += jump_code->info.back_jump == true ? -((int32_t)(jump_code->offset - 1)) : (jump_code->offset - 1);
    }
    else {
        context.vm_code += sizeof(vm_jump_code);
    }
}

void vm_jump_external(vm_context& context) {
    vm_jump_code * jump_code = (vm_jump_code *)&context.vm_code[0];

    bool jump = is_jump(context, jump_code->info.condition, jump_code->info.invert_condition);

    if (jump) {    
        vm_exit(context, uint32_t(context.vm_code + (jump_code->info.back_jump == true ? -((int32_t)(jump_code->offset - 1)) : (jump_code->offset - 1))));
    }
    else {
        context.vm_code += sizeof(vm_jump_code);
    }
}

void vm_call_local(vm_context& context) {
    vm_call_code * call_code = (vm_call_code *)&context.vm_code[0];

    uint32_t call_dst = uint32_t(context.vm_code + (call_code->back_jump == true ? -((int32_t)(call_code->offset - 1)) : (call_code->offset - 1)));

    PUSH_VM(context, ((uint32_t)(context.vm_code + sizeof(vm_call_code)) | 0x80000000));

    context.vm_code = (uint8_t*)call_dst;
}

void vm_call_external(vm_context& context) {
    vm_call_code * call_code = (vm_call_code *)&context.vm_code[0];
    
    uint32_t call_dst = uint32_t(context.vm_code + (call_code->back_jump == true ? -((int32_t)(call_code->offset - 1)) : (call_code->offset - 1)));
    uint8_t inst_[6] = { 0xFF, 0x25, 0, 0, 0, 0 };
    *(uint32_t*)&inst_[2] = (uint32_t)&call_dst;

    vm_pure(context, inst_, 6);

    context.vm_code += sizeof(vm_call_code);
}

void vm_return(vm_context& context) {

    uint32_t stack_ret = *get_operand(context, 0, 1, 1);
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