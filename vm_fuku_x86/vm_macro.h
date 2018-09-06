#pragma once

#define PUSH_VM(context,x) {context.real_context.regs.esp -= 4;*(uint32_t*)context.real_context.regs.esp = x;}
#define POP_VM(context,x)  {x = *(uint32_t*)context.real_context.regs.esp;context.real_context.regs.esp += 4;}


#define SIZE_TO_BITS(size)     (size << 3) //8 16 32
#define SIGN_BIT_BY_SIZE(size) ((1 << SIZE_TO_BITS(size)) - 1)//0x80 0x8000 0x80000000
#define MAX_SIZE_BY_SIZE(size) ( 1 << (SIZE_TO_BITS(size) - 1))//0xFF 0xFFFF 0xFFFFFFFF

/*
imm   //not a ptr
eax   //ptr
[eax] //ptr
*/



inline uint32_t * get_operand(vm_context& context , vm_ops_ex_code excode, uint32_t op_num , uint32_t op_total) {
    uint32_t * operand = &context.operands[context.operands.size() - op_total + (op_num - 1)];

    if (op_num == op_total) {
        if (excode.info.src_is_ptr) {
            operand = (uint32_t *)*operand;
        }
    }
    else {
        if (excode.info.dst_is_ptr) {
            operand = (uint32_t *)*operand;
        }
    }

    return operand;
}

inline  void free_operand(vm_context& context, uint32_t number_of_operand) {
    for (uint32_t i = 0; i < number_of_operand; i++) {
        context.operands.pop_back();
    }
}

inline bool is_jump(vm_context& context, uint8_t condition, bool inverse) {
    bool result = false;

    if (!condition) { //Jump near if overflow (OF=1)
        result = context.real_context.flags._of;
    }
    else if (condition == 1) {//Jump if not above or equal (CF=1)
        result = context.real_context.flags._cf;
    }
    else if (condition == 2) {//Jump if equal (ZF=1)
        result = context.real_context.flags._zf;
    }
    else if (condition == 3) {//Jump if below or equal (CF=1 or ZF=1)
        result = (context.real_context.flags._cf || context.real_context.flags._zf);
    }
    else if (condition == 4) {//Jump if sign (SF=1)
        result = context.real_context.flags._sf;
    }
    else if (condition == 5) {//Jump if parity (PF=1)
        result = context.real_context.flags._pf;
    }
    else if (condition == 6) {//Jump if less (SF<>OF)
        result = (context.real_context.flags._sf != context.real_context.flags._of);
    }
    else if (condition == 7) {//Jump if less or equal (ZF=1 or SF<>OF)
        result = (context.real_context.flags._zf || (context.real_context.flags._sf != context.real_context.flags._of));
    }
    else {
        result = true;
    }

    return inverse == true ? !result : result;
}

inline bool get_parity_flag(uint32_t result) {
   
    bool parity = true;
    for (uint8_t i = 1; i < 8; i++) {

        if (result & (1 << i)) {
            parity = !parity;
       }
    }

    return parity;
}

inline bool get_overflow_flag(uint32_t l_op, uint32_t r_op, uint32_t result, uint8_t size) {
    uint32_t sign_bit = SIGN_BIT_BY_SIZE(size);

    if ( (l_op & sign_bit) == (r_op & sign_bit) ) {
        return (l_op & sign_bit) != (result & sign_bit);
    }
    else {
        return false;
    }
}

inline bool get_sign_flag(uint32_t result, uint8_t size) {
    uint32_t sign_bit = SIGN_BIT_BY_SIZE(size);

    return result & sign_bit;
}

inline bool get_adjust_flag(uint32_t l_op, uint32_t r_op) {
    return (l_op % 0x10 + r_op % 0x10) / 0x10;
}

inline uint32_t impl_add(vm_context& context, uint32_t l_op, uint32_t r_op, uint8_t size) {
    
    uint32_t sign_bit = SIGN_BIT_BY_SIZE(size);
    uint64_t mask = uint64_t(1) << SIZE_TO_BITS(size);

    l_op = l_op & (mask - 1);
    r_op = r_op & (mask - 1);

    uint64_t sum = l_op + r_op;

    context.real_context.flags._zf = !(sum & (mask - 1));
    context.real_context.flags._af = get_adjust_flag(l_op, r_op);
    context.real_context.flags._cf = (sum / mask);
    context.real_context.flags._sf = get_sign_flag(uint32_t(sum), size);
    context.real_context.flags._pf = get_parity_flag(uint32_t(sum));
    context.real_context.flags._of = get_overflow_flag(l_op, r_op, uint32_t(sum), size);

    return uint32_t(sum);
}

inline uint32_t impl_sub(vm_context& context, uint32_t l_op, uint32_t r_op, uint8_t size) {

    uint32_t sign_bit = SIGN_BIT_BY_SIZE(size);
    uint64_t mask = uint64_t(1) << SIZE_TO_BITS(size);

    l_op = l_op & (mask - 1);
    r_op = r_op & (mask - 1);

    uint64_t sum = l_op - r_op;

    context.real_context.flags._zf = !(sum & (mask - 1));
    context.real_context.flags._af = get_adjust_flag(l_op, r_op);
    context.real_context.flags._sf = get_sign_flag(uint32_t(sum), size);
    context.real_context.flags._pf = get_parity_flag(uint32_t(sum));
    context.real_context.flags._of = get_overflow_flag(l_op, r_op, uint32_t(sum), size);

    return uint32_t(sum);
}

inline void impl_logical(vm_context& context, uint32_t result, uint8_t size) {

    uint32_t sign_bit = SIGN_BIT_BY_SIZE(size);
    uint64_t mask = uint64_t(1) << SIZE_TO_BITS(size);

    context.real_context.flags._cf = 0;
    context.real_context.flags._of = 0;
    context.real_context.flags._zf = !(result & (mask - 1));
    context.real_context.flags._sf = result & sign_bit;
    context.real_context.flags._pf = get_parity_flag(result);
}
