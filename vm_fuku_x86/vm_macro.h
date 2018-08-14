#pragma once


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

inline  uint32_t * get_src_operand(vm_context& context , vm_ops_ex_code ex_code) {
    uint32_t * operand;
    
    if (context.operands.size() >= 2) {
        operand = &context.operands[context.operands.size() - 2];      
    }
    else {
        operand = &context.operands.back();
    }   

    if (ex_code.info.src_is_ptr) {
        operand = (uint32_t *)*operand;
    }
    
    return operand;
}

inline uint32_t * get_dst_operand(vm_context& context , vm_ops_ex_code ex_code) {
    uint32_t * operand = &context.operands.back();

    if (ex_code.info.dst_is_ptr) {
        operand = (uint32_t *)*operand;
    }

    return operand;
}

inline  void free_operand(vm_context& context, uint32_t number_of_operand) {
    for (uint32_t i = 0; i < number_of_operand; i++) {
        context.operands.pop_back();
    }
}