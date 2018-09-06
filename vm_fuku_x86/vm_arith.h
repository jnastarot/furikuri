#pragma once

void vm_add(vm_context& context) {
    vm_ops_ex_code * ex_code = (vm_ops_ex_code *)&context.vm_code[0];

    uint64_t op_1 = 0;
    uint64_t op_2 = 0;

    uint32_t* dst = get_operand(context, *ex_code, 1, 2);
    uint32_t* src = get_operand(context, *ex_code, 2, 2);

    memcpy(&op_1, dst, ex_code->info.op_1_size);
    memcpy(&op_2, src, ex_code->info.op_2_size);

    op_1 = impl_add(context, op_1, op_2, ex_code->info.op_1_size);

    memcpy(dst, &op_1, ex_code->info.op_1_size);

    free_operand(context, 2);

    context.vm_code += sizeof(vm_ops_ex_code);
}

void vm_adc(vm_context& context) {
    vm_ops_ex_code * ex_code = (vm_ops_ex_code *)&context.vm_code[0];

    uint64_t op_1 = 0;
    uint64_t op_2 = 0;

    uint32_t* dst = get_operand(context, *ex_code, 1, 2);
    uint32_t* src = get_operand(context, *ex_code, 2, 2);

    memcpy(&op_1, dst, ex_code->info.op_1_size);
    memcpy(&op_2, src, ex_code->info.op_2_size);

    op_1 = impl_add(context, op_1, op_2 + context.real_context.flags._cf, ex_code->info.op_1_size);

    memcpy(dst, &op_1, ex_code->info.op_1_size);

    free_operand(context, 2);

    context.vm_code += sizeof(vm_ops_ex_code);
}

void vm_sub(vm_context& context) {
    vm_ops_ex_code * ex_code = (vm_ops_ex_code *)&context.vm_code[0];

    uint64_t op_1 = 0;
    uint64_t op_2 = 0;

    uint32_t* dst = get_operand(context, *ex_code, 1, 2);
    uint32_t* src = get_operand(context, *ex_code, 2, 2);

    memcpy(&op_1, dst, ex_code->info.op_1_size);
    memcpy(&op_2, src, ex_code->info.op_2_size);

    op_1 = impl_sub(context, op_1, op_2, ex_code->info.op_1_size);

    memcpy(dst, &op_1, ex_code->info.op_1_size);

    free_operand(context, 2);

    context.vm_code += sizeof(vm_ops_ex_code);
}

void vm_sbb(vm_context& context) {
    vm_ops_ex_code * ex_code = (vm_ops_ex_code *)&context.vm_code[0];

    uint64_t op_1 = 0;
    uint64_t op_2 = 0;

    uint32_t* dst = get_operand(context, *ex_code, 1, 2);
    uint32_t* src = get_operand(context, *ex_code, 2, 2);

    memcpy(&op_1, dst, ex_code->info.op_1_size);
    memcpy(&op_2, src, ex_code->info.op_2_size);

    op_1 = impl_sub(context, op_1, op_2 + context.real_context.flags._cf, ex_code->info.op_1_size);

    memcpy(dst, &op_1, ex_code->info.op_1_size);

    free_operand(context, 2);

    context.vm_code += sizeof(vm_ops_ex_code);
}

void vm_neg(vm_context& context) {
    vm_ops_ex_code * ex_code = (vm_ops_ex_code *)&context.vm_code[0];

    uint64_t op_1 = 0;

    uint32_t* dst = get_operand(context, *ex_code, 1, 1);

    memcpy(&op_1, dst, ex_code->info.op_1_size);

    bool is_null = !op_1;

    if (!is_null) {
        op_1 = -(int64_t)op_1;
        memcpy(dst, &op_1, ex_code->info.op_1_size);
    }

    context.real_context.flags._cf = is_null == true ? 0 : 1;
    context.real_context.flags._of = 0;
    context.real_context.flags._zf = is_null == true ? 1 : 0;
    context.real_context.flags._sf = get_sign_flag(op_1, ex_code->info.op_1_size);
    context.real_context.flags._pf = get_parity_flag(*dst);

    free_operand(context, 1);

    context.vm_code += sizeof(vm_ops_ex_code);
}

void vm_cmp(vm_context& context) {
    vm_ops_ex_code * ex_code = (vm_ops_ex_code *)&context.vm_code[0];

    uint32_t* dst = get_operand(context, *ex_code, 1, 2);
    uint32_t* src = get_operand(context, *ex_code, 2, 2);

    impl_sub(context, *dst, *src, ex_code->info.op_1_size);

    free_operand(context, 2);

    context.vm_code += sizeof(vm_ops_ex_code);
}