#pragma once

void vm_and(vm_context& context) {
    vm_ops_ex_code * ex_code = (vm_ops_ex_code *)&context.vm_code[0];

    uint64_t op_1 = 0;
    uint64_t op_2 = 0;

    uint32_t* dst = get_operand(context, ex_code->info.dst_is_ptr, 1, 2);
    uint32_t* src = get_operand(context, ex_code->info.src_is_ptr, 2, 2);

    memcpy(&op_1, dst, ex_code->info.op_1_size);
    memcpy(&op_2, src, ex_code->info.op_2_size);

    op_1 &= op_2;

    memcpy(dst, &op_1, ex_code->info.op_1_size);
    
    impl_logical(context, op_1, ex_code->info.op_1_size);

    free_operand(context, 2);

    context.vm_code += sizeof(vm_ops_ex_code);
}

void vm_or(vm_context& context) {
    vm_ops_ex_code * ex_code = (vm_ops_ex_code *)&context.vm_code[0];

    uint64_t op_1 = 0;
    uint64_t op_2 = 0;

    uint32_t* dst = get_operand(context, ex_code->info.dst_is_ptr, 1, 2);
    uint32_t* src = get_operand(context, ex_code->info.src_is_ptr, 2, 2);

    memcpy(&op_1, dst, ex_code->info.op_1_size);
    memcpy(&op_2, src, ex_code->info.op_2_size);

    op_1 |= op_2;

    memcpy(dst, &op_1, ex_code->info.op_1_size);

    impl_logical(context, op_1, ex_code->info.op_1_size);

    free_operand(context, 2);

    context.vm_code += sizeof(vm_ops_ex_code);
}

void vm_xor(vm_context& context) {
    vm_ops_ex_code * ex_code = (vm_ops_ex_code *)&context.vm_code[0];

    uint64_t op_1 = 0;
    uint64_t op_2 = 0;

    uint32_t* dst = get_operand(context, ex_code->info.dst_is_ptr, 1, 2);
    uint32_t* src = get_operand(context, ex_code->info.src_is_ptr, 2, 2);

    memcpy(&op_1, dst, ex_code->info.op_1_size);
    memcpy(&op_2, src, ex_code->info.op_2_size);

    op_1 ^= op_2;

    memcpy(dst, &op_1, ex_code->info.op_1_size);

    impl_logical(context, op_1, ex_code->info.op_1_size);

    free_operand(context, 2);

    context.vm_code += sizeof(vm_ops_ex_code);
}

void vm_not(vm_context& context) {
    vm_ops_ex_code * ex_code = (vm_ops_ex_code *)&context.vm_code[0];

    uint64_t op_1 = 0;

    uint32_t* dst = get_operand(context, ex_code->info.dst_is_ptr, 1, 1);

    memcpy(&op_1, dst, ex_code->info.op_1_size);

    op_1 = ~op_1;

    memcpy(dst, &op_1, ex_code->info.op_1_size);

    free_operand(context, 1);
    context.vm_code += sizeof(vm_ops_ex_code);
}

void vm_test(vm_context& context) {
    vm_ops_ex_code * ex_code = (vm_ops_ex_code *)&context.vm_code[0];

    uint64_t op_1 = 0;
    uint64_t op_2 = 0;

    uint32_t* dst = get_operand(context, ex_code->info.dst_is_ptr, 1, 2);
    uint32_t* src = get_operand(context, ex_code->info.src_is_ptr, 2, 2);

    memcpy(&op_1, dst, ex_code->info.op_1_size);
    memcpy(&op_2, src, ex_code->info.op_2_size);

    op_1 &= op_2;

    impl_logical(context, op_1, ex_code->info.op_1_size);

    free_operand(context, 2);

    context.vm_code += sizeof(vm_ops_ex_code);
}


void vm_shl(vm_context& context) {
    vm_ops_ex_code * ex_code = (vm_ops_ex_code *)&context.vm_code[0];

    uint64_t op_1 = 0;
    uint64_t op_2 = 0;

    uint32_t* dst = get_operand(context, ex_code->info.dst_is_ptr, 1, 2);
    uint32_t* src = get_operand(context, ex_code->info.src_is_ptr, 2, 2);

    memcpy(&op_1, dst, ex_code->info.op_1_size);
    memcpy(&op_2, src, ex_code->info.op_2_size);

    uint8_t sf = (op_1 & (1 << (ex_code->info.op_1_size * 8 - 1))) ? 1 : 0;
    
    op_1 = op_1 << op_2;

    memcpy(dst, &op_1, ex_code->info.op_1_size);

    impl_logical(context, op_1, ex_code->info.op_1_size);

    context.real_context.flags._of = context.real_context.flags._sf != sf;
    context.real_context.flags._cf = op_1 & (1 << (ex_code->info.op_1_size * 8));

    free_operand(context, 2);

    context.vm_code += sizeof(vm_ops_ex_code);
}


void vm_shr(vm_context& context) {
    vm_ops_ex_code * ex_code = (vm_ops_ex_code *)&context.vm_code[0];

    uint64_t op_1 = 0;
    uint64_t op_2 = 0;

    uint32_t* dst = get_operand(context, ex_code->info.dst_is_ptr, 1, 2);
    uint32_t* src = get_operand(context, ex_code->info.src_is_ptr, 2, 2);

    memcpy(&op_1, dst, ex_code->info.op_1_size);
    memcpy(&op_2, src, ex_code->info.op_2_size);

    uint8_t sf = (op_1 & (1 << (ex_code->info.op_1_size * 8 - 1))) ? 1 : 0;
    uint8_t cf = (op_1 & (1 << op_2 >> 1)) ? 1 : 0;

    op_1 = op_1 >> op_2;

    memcpy(dst, &op_1, ex_code->info.op_1_size);

    impl_logical(context, op_1, ex_code->info.op_1_size);

    context.real_context.flags._of = context.real_context.flags._sf != sf;
    context.real_context.flags._cf = cf;

    free_operand(context, 2);

    context.vm_code += sizeof(vm_ops_ex_code);
}


void vm_sar(vm_context& context) {

}


void vm_rol(vm_context& context) {
    vm_ops_ex_code * ex_code = (vm_ops_ex_code *)&context.vm_code[0];

    uint64_t op_1 = 0;
    uint64_t op_2 = 0;

    uint32_t* dst = get_operand(context, ex_code->info.dst_is_ptr, 1, 2);
    uint32_t* src = get_operand(context, ex_code->info.src_is_ptr, 2, 2);

    memcpy(&op_1, dst, ex_code->info.op_1_size);
    memcpy(&op_2, src, ex_code->info.op_2_size);

    uint8_t cf = context.real_context.flags._cf;
    uint8_t sf = (op_1 & (1 << (ex_code->info.op_1_size * 8 - 1))) ? 1 : 0;

    op_1 = op_1 << op_2;

    memcpy(dst, &op_1, ex_code->info.op_1_size);

    impl_logical(context, op_1, ex_code->info.op_1_size);

    context.real_context.flags._of = context.real_context.flags._sf != sf;
    context.real_context.flags._cf = op_1 & (1 << (ex_code->info.op_1_size * 8));

    free_operand(context, 2);

    context.vm_code += sizeof(vm_ops_ex_code);
}


void vm_ror(vm_context& context) {

}


void vm_rcl(vm_context& context) {

}


void vm_rcr(vm_context& context) {

}

