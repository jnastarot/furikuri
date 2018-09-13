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

void vm_div(vm_context& context) {
    vm_ops_ex_code * ex_code = (vm_ops_ex_code *)&context.vm_code[0];

    uint64_t op_1 = 0;

    uint32_t* src = get_operand(context, *ex_code, 1, 1);
    memcpy(&op_1, src, ex_code->info.op_2_size);

    uint64_t result = 0;


    if (op_1 == 0) { //divide error

    }

    if (ex_code->info.op_1_size == 1) {
        uint64_t dividend = context.real_context.regs.eax & 0xFFFF;

        result = dividend / op_1;
        if (result > 0xFF) {
            //divide error
        }
        else {
            context.real_context.regs.eax =
                (context.real_context.regs.eax & 0xFFFF0000) | result & 0xFF |
                (((((context.real_context.regs.eax & 0xFF) % op_1)) & 0xFF) << 8);
        }
    }
    else if (ex_code->info.op_1_size == 2) {
        uint64_t dividend = (context.real_context.regs.eax & 0xFFFF) | ((context.real_context.regs.edx & 0xFFFF) << 16);

        result = dividend / op_1;
        if (result > 0xFFFF) {
            //divide error
        }
        else {
            context.real_context.regs.eax = (context.real_context.regs.eax & 0xFFFF0000) | result & 0xFFFF;
            context.real_context.regs.edx = (context.real_context.regs.edx & 0xFFFF0000) | (dividend % op_1) & 0xFFFF;
        }
    }
    else {
        uint64_t dividend = uint64_t(context.real_context.regs.eax) | (uint64_t(context.real_context.regs.edx) << 32);

        result = dividend / op_1;
        if (result > 0xFFFFFFFF) {
            //divide error
        }
        else {
            context.real_context.regs.eax = result & 0xFFFFFFFF;
            context.real_context.regs.edx = (dividend % op_1) & 0xFFFFFFFF;
        }
    }

    free_operand(context, 1);

    context.vm_code += sizeof(vm_ops_ex_code);
}

void vm_idiv(vm_context& context) {
    vm_ops_ex_code * ex_code = (vm_ops_ex_code *)&context.vm_code[0];

    int64_t op_1 = 0;

    int32_t* src = (int32_t*)get_operand(context, *ex_code, 1, 1);
    int64_t result = 0;


    if (op_1 == 0) { //divide error

    }

    if (ex_code->info.op_1_size == 1) { 
        op_1 = *((int8_t *)src);
        int64_t dividend = context.real_context.regs.eax & 0xFFFF;
        result = dividend / op_1;

        if (result > 127 || result < -128) {
            //divide error
        }
        else {
            context.real_context.regs.eax =
                (context.real_context.regs.eax & 0xFFFF0000) | int8_t(result) |
                (int8_t(dividend % op_1) << 8);
        }
    }
    else if (ex_code->info.op_1_size == 2) {
        op_1 = *((int16_t *)src);
        int64_t dividend = (context.real_context.regs.eax & 0xFFFF) | ((context.real_context.regs.edx & 0xFFFF) << 16);
        result = dividend / op_1;

        if (result > 32767 || result < -32768) {
            //divide error
        }
        else {
            context.real_context.regs.eax = (context.real_context.regs.eax & 0xFFFF0000) | int16_t(result);
            context.real_context.regs.edx = (context.real_context.regs.edx & 0xFFFF0000) | int16_t(dividend % op_1);
        }
    }
    else { 
        op_1 = *src;
        int64_t dividend = uint64_t(context.real_context.regs.eax) | (uint64_t(context.real_context.regs.edx) << 32);
        result = dividend / op_1;

        if (result > 2147483647 || result < -int32_t(2147483648)) {
             //divide error
        }
        else {
            context.real_context.regs.eax = result;
            context.real_context.regs.edx = (dividend % op_1);
        }
    }

    free_operand(context, 1);

    context.vm_code += sizeof(vm_ops_ex_code);
}