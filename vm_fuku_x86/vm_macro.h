#pragma once

#define PUSH_VM(context,x) {context.real_context.regs.esp -= 4;*(uint32_t*)context.real_context.regs.esp = x;}
#define POP_VM(context,x)  {x = *(uint32_t*)context.real_context.regs.esp;context.real_context.regs.esp += 4;}


#define SIZE_TO_BITS(size)     (size << 3) //8 16 32
#define SIGN_BIT_BY_SIZE(size) (1 << (SIZE_TO_BITS(size) - 1))//0x80 0x8000 0x80000000
#define MAX_SIZE_BY_SIZE(size) ( (1 << (SIZE_TO_BITS(size)) - 1))//0xFF 0xFFFF 0xFFFFFFFF

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
   
    uint32_t parity = 0;

    for (uint8_t i = 0; i < 8; i++) {
        if ( result & (1 << i)) { parity++; }
    }

    return !(parity&1);
}

inline bool get_overflow_flag(uint32_t l_op, uint32_t r_op, uint32_t result, uint8_t size) {
    return (((l_op ^ result) & (r_op ^ result)) >> (SIZE_TO_BITS(size) - 1)) & 1;
}

inline bool get_sign_flag(uint32_t result, uint8_t size) {
    return result & SIGN_BIT_BY_SIZE(size);
}

inline bool get_adjust_flag(uint32_t l_op, uint32_t r_op, uint32_t result) {
    return (l_op ^ r_op ^ result) & 0x10;
}

inline uint32_t impl_add(vm_context& context, uint32_t l_op, uint32_t r_op, uint8_t size) {
    
    uint32_t sign_bit = SIGN_BIT_BY_SIZE(size);
    uint64_t mask = uint64_t(1) << SIZE_TO_BITS(size);

    l_op = l_op & (mask - 1);
    r_op = r_op & (mask - 1);

    uint64_t sum = uint64_t(l_op) + uint64_t(r_op);

    context.real_context.flags._zf = !(sum & (mask - 1));
    context.real_context.flags._af = get_adjust_flag(l_op, r_op, uint32_t(sum));
    context.real_context.flags._cf = (sum / mask);
    context.real_context.flags._sf = get_sign_flag(uint32_t(sum), size);
    context.real_context.flags._pf = get_parity_flag(uint32_t(sum));
    context.real_context.flags._of = get_overflow_flag(l_op, r_op, sum, size);

    return uint32_t(sum);
}

inline uint32_t impl_sub(vm_context& context, uint32_t l_op, uint32_t r_op, uint8_t size) {

    uint32_t sign_bit = SIGN_BIT_BY_SIZE(size);
    uint64_t mask = uint64_t(1) << SIZE_TO_BITS(size);

    l_op = l_op & (mask - 1);
    r_op = r_op & (mask - 1);

    uint64_t sum = uint64_t(l_op) - uint64_t(r_op);

    context.real_context.flags._zf = !(sum & (mask - 1));
    context.real_context.flags._af = get_adjust_flag(l_op, r_op, uint32_t(sum));
    context.real_context.flags._cf = (sum / mask);
    context.real_context.flags._sf = get_sign_flag(uint32_t(sum), size);
    context.real_context.flags._pf = get_parity_flag(uint32_t(sum));
    context.real_context.flags._of = get_overflow_flag(sum, r_op, r_op, size);

    return uint32_t(sum);
}

inline void impl_logical(vm_context& context, uint32_t result, uint8_t size) {

    uint64_t mask = uint64_t(1) << SIZE_TO_BITS(size);

    context.real_context.flags._cf = 0;
    context.real_context.flags._of = 0;
    context.real_context.flags._af = 0;
    context.real_context.flags._zf = !(result & (mask - 1));
    context.real_context.flags._sf = get_sign_flag(result, size);
    context.real_context.flags._pf = get_parity_flag(result);
}



/*
context_flags __declspec(naked) WINAPI test_flags(uint32_t l_op, uint32_t r_op, uint32_t flags) {

    __asm {
        mov eax, [esp + 12]
        push eax
        popfd

        mov eax, [esp + 4]
        mov ecx, [esp + 8]

        and eax, ecx

        pushfd
        pop eax

        ret
    }
}

uint32_t __declspec(naked) WINAPI test_result(uint32_t l_op, uint32_t r_op, uint32_t flags) {

    __asm {
        mov eax, [esp + 12]
        push eax
        popfd

        mov eax, [esp + 4]
        mov ecx, [esp + 8]

        ror eax, cl

        ret
    }
}

void vm_ror(vm_context& context);

void test_arith() {
    srand(122332);
    while (1) {
        uint32_t fl = (uint32_t)rand();
        uint32_t op_1 = (uint32_t)rand() | rand()<<15;
        uint32_t op_2 = (uint32_t)rand() | rand()<<15;

        fl = 0;// &= 1;
        //op_2 &= 0x31;

        vm_context context;
        vm_ops_ex_code code(1, 1, 4, 1);

        context.real_context.d_flag = fl;
        context.real_context.regs.eax = op_1;
        context.real_context.regs.ecx = op_2;
        context.vm_code = (uint8_t*)&code;
        context.operands.push_back((uint32_t)&context.real_context.regs.eax);
        context.operands.push_back((uint32_t)&context.real_context.regs.ecx);
        

        vm_ror(context);


        uint32_t r_result = test_result(op_1, op_2, fl);

        
        if (context.real_context.regs.eax != r_result) {
            printf("error   %08x %08x R: %08x  E: %08x\n", op_1, op_2, context.real_context.regs.eax, r_result);
        }
        else {
            printf("success %08x %08x R: %08x  E: %08x\n", op_1, op_2, context.real_context.regs.eax, r_result);
        }
        

        /*
        if ((uint8_t)context.real_context.regs.eax != (uint8_t)r_result) {
            printf("error   %08x %08x R: %08x  E: %08x\n", op_1, op_2, (uint8_t)context.real_context.regs.eax, (uint8_t)r_result);
        }
        else {
            printf("success %08x %08x R: %08x  E: %08x\n", op_1, op_2, (uint8_t)context.real_context.regs.eax, (uint8_t)r_result);
        }*/
        

        /*
        if (context.real_context.flags._zf != r_fl._zf ||
            context.real_context.flags._af != r_fl._af ||
            context.real_context.flags._cf != r_fl._cf ||
            context.real_context.flags._sf != r_fl._sf ||
            context.real_context.flags._pf != r_fl._pf ||
            context.real_context.flags._of != r_fl._of
            ) {
            printf("sub error   %08x %08x %08x  R: %08x  E: %08x\n", op_1, op_2, fl, context.real_context.d_flag, r_fl);
            printf("        ZF AF CF SF PF OF\n");
            printf("        %02x %02x %02x %02x %02x %02x\n", context.real_context.flags._zf,
                context.real_context.flags._af,
                context.real_context.flags._cf,
                context.real_context.flags._sf,
                context.real_context.flags._pf,
                context.real_context.flags._of
                );
            printf("        %02x %02x %02x %02x %02x %02x\n", r_fl._zf,
                r_fl._af,
                r_fl._cf,
                r_fl._sf,
                r_fl._pf,
                r_fl._of
            );
        }
        else {
            printf("sub success %08x %08x %08x  R: %08x  E: %08x\n", op_1, op_2, fl, context.real_context.d_flag, r_fl);
        }
       

        Sleep(50);
    }
}//*/