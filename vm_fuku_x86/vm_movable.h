#pragma once


void vm_mov(vm_context& context) {
    vm_ops_ex_code * ex_code = (vm_ops_ex_code *)&context.vm_code[0];

    uint32_t* src = get_src_operand(context, *ex_code);
    uint32_t* dst = get_dst_operand(context, *ex_code);

    mov_by_size(src, dst, ex_code->info.ops_size);
 
    free_operand(context, 2);

    context.vm_code += sizeof(vm_ops_ex_code);
}

void vm_lea(vm_context& context) {
    vm_ops_ex_code * ex_code = (vm_ops_ex_code *)&context.vm_code[0];

    uint32_t* src = get_src_operand(context, *ex_code);
    uint32_t* dst = get_dst_operand(context, *ex_code);

    mov_by_size(src, dst, ex_code->info.ops_size);

    free_operand(context, 2);

    context.vm_code += sizeof(vm_ops_ex_code);
}

void vm_xchg(vm_context& context) {
    uint32_t src = context.operands.back();
    uint32_t dst = context.operands.back();

    context.operands.pop_back();
    context.operands.pop_back();


    *(uint32_t*)src = *(uint32_t*)dst;
}