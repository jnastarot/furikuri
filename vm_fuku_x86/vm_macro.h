#pragma once

#define PUSH_VM(context,x) {context.real_context.regs.esp -= 4;*(uint32_t*)context.real_context.regs.esp = x;}
#define POP_VM(context,x)  {x = *(uint32_t*)context.real_context.regs.esp;context.real_context.regs.esp += 4;}

/*
imm   //not a ptr
eax   //ptr
[eax] //ptr
*/


inline void mov_by_size(uint32_t * src, uint32_t * dst, uint8_t size) {
    switch (size) {

    case 1: {
        ((uint8_t*)src)[0] = ((uint8_t*)dst)[0];
        break;
    }

    case 2: {
        ((uint16_t*)src)[0] = ((uint16_t*)dst)[0];
        break;
    }

    case 4: {
        *src = *dst;
        break;
    }
    }
}

inline uint32_t * get_operand(vm_context& context , bool is_ptr, uint32_t op_num , uint32_t op_total) {
    uint32_t * operand = &context.operands[context.operands.size() - op_total + (op_num - 1)];

    if (is_ptr) {
        operand = (uint32_t *)*operand;
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

//CF OF ZF SF PF

//CF OF ZF SF

inline bool get_overflow_flag_result() {

    return true;
}

inline bool get_carry_flag_result() {

    return true;
}

inline bool get_zero_flag_result() {

    return true;
}

inline bool get_sign_flag_result() {

    return true;
}