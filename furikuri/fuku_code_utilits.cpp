#include "stdafx.h"
#include "fuku_code_utilits.h"


uint64_t CONVERT_FUKU_REGISTER_TO_FLAG[] = {
    0,

    //x86-x32 registers
    X86_REGISTER_RAX,
    X86_REGISTER_EAX,
    X86_REGISTER_AX,
    X86_REGISTER_AX, X86_REGISTER_AL,

    X86_REGISTER_RCX,
    X86_REGISTER_ECX,
    X86_REGISTER_CX,
    X86_REGISTER_CX, X86_REGISTER_CL,

    X86_REGISTER_RDX,
    X86_REGISTER_EDX,
    X86_REGISTER_DX,
    X86_REGISTER_DX, X86_REGISTER_DL,

    X86_REGISTER_RBX,
    X86_REGISTER_EBX,
    X86_REGISTER_BX,
    X86_REGISTER_BX, X86_REGISTER_BL,

    X86_REGISTER_RSP,
    X86_REGISTER_ESP,
    X86_REGISTER_SP,
    X86_REGISTER_SPL,

    X86_REGISTER_RBP,
    X86_REGISTER_EBP,
    X86_REGISTER_BP,
    X86_REGISTER_BPL,

    X86_REGISTER_RSI,
    X86_REGISTER_ESI,
    X86_REGISTER_SI,
    X86_REGISTER_SIL,

    X86_REGISTER_RDI,
    X86_REGISTER_EDI,
    X86_REGISTER_DI,
    X86_REGISTER_DIL,

    //x86-x64 registers
    X86_REGISTER_R8,
    X86_REGISTER_R8D,
    X86_REGISTER_R8W,
    X86_REGISTER_R8B,
    X86_REGISTER_R9,
    X86_REGISTER_R9D,
    X86_REGISTER_R9W,
    X86_REGISTER_R9B,

    X86_REGISTER_R10,
    X86_REGISTER_R10D,
    X86_REGISTER_R10W,
    X86_REGISTER_R10B,

    X86_REGISTER_R11,
    X86_REGISTER_R11D,
    X86_REGISTER_R11W,
    X86_REGISTER_R11B,

    X86_REGISTER_R12,
    X86_REGISTER_R12D,
    X86_REGISTER_R12W,
    X86_REGISTER_R12B,

    X86_REGISTER_R13,
    X86_REGISTER_R13D,
    X86_REGISTER_R13W,
    X86_REGISTER_R13B,

    X86_REGISTER_R14,
    X86_REGISTER_R14D,
    X86_REGISTER_R14W,
    X86_REGISTER_R14B,

    X86_REGISTER_R15,
    X86_REGISTER_R15D,
    X86_REGISTER_R15W,
    X86_REGISTER_R15B,
};

fuku_register_enum CONVERT_FLAG_REGISTER_TO_FUKU[] = {
    FUKU_REG_AL,
    FUKU_REG_CL,
    FUKU_REG_DL,
    FUKU_REG_BL,
    FUKU_REG_SPL,
    FUKU_REG_BPL,
    FUKU_REG_SIL,
    FUKU_REG_DIL,
    FUKU_REG_R8B ,
    FUKU_REG_R9B ,
    FUKU_REG_R10B,
    FUKU_REG_R11B,
    FUKU_REG_R12B,
    FUKU_REG_R13B,
    FUKU_REG_R14B,
    FUKU_REG_R15B,
    //word
    FUKU_REG_AX,
    FUKU_REG_CX,
    FUKU_REG_DX,
    FUKU_REG_BX,
    FUKU_REG_SP,
    FUKU_REG_BP,
    FUKU_REG_SI,
    FUKU_REG_DI,
    FUKU_REG_R8W ,
    FUKU_REG_R9W ,
    FUKU_REG_R10W,
    FUKU_REG_R11W,
    FUKU_REG_R12W,
    FUKU_REG_R13W,
    FUKU_REG_R14W,
    FUKU_REG_R15W,
    //dword
    FUKU_REG_EAX,
    FUKU_REG_ECX,
    FUKU_REG_EDX,
    FUKU_REG_EBX,
    FUKU_REG_ESP,
    FUKU_REG_EBP,
    FUKU_REG_ESI,
    FUKU_REG_EDI,
    FUKU_REG_R8D ,
    FUKU_REG_R9D ,
    FUKU_REG_R10D,
    FUKU_REG_R11D,
    FUKU_REG_R12D,
    FUKU_REG_R13D,
    FUKU_REG_R14D,
    FUKU_REG_R15D,
    //qword
    FUKU_REG_RAX,
    FUKU_REG_RCX,
    FUKU_REG_RDX,
    FUKU_REG_RBX,
    FUKU_REG_RSP,
    FUKU_REG_RBP,
    FUKU_REG_RSI,
    FUKU_REG_RDI,
    FUKU_REG_R8 ,
    FUKU_REG_R9 ,
    FUKU_REG_R10,
    FUKU_REG_R11,
    FUKU_REG_R12,
    FUKU_REG_R13,
    FUKU_REG_R14,
    FUKU_REG_R15
};

uint64_t FULL_INCLUDE_FLAGS_TABLE[] = {

    X86_REGISTER_RAX | X86_REGISTER_EAX | X86_REGISTER_AX | X86_REGISTER_AL,
    X86_REGISTER_RCX | X86_REGISTER_ECX | X86_REGISTER_CX | X86_REGISTER_CL,
    X86_REGISTER_RDX | X86_REGISTER_EDX | X86_REGISTER_DX | X86_REGISTER_DL,
    X86_REGISTER_RBX | X86_REGISTER_EBX | X86_REGISTER_BX | X86_REGISTER_BL,
    X86_REGISTER_RSP | X86_REGISTER_ESP | X86_REGISTER_SP | X86_REGISTER_SPL,
    X86_REGISTER_RBP | X86_REGISTER_EBP | X86_REGISTER_BP | X86_REGISTER_BPL,
    X86_REGISTER_RSI | X86_REGISTER_ESI | X86_REGISTER_SI | X86_REGISTER_SIL,
    X86_REGISTER_RDI | X86_REGISTER_EDI | X86_REGISTER_DI | X86_REGISTER_DIL,
    X86_REGISTER_R8  | X86_REGISTER_R8D | X86_REGISTER_R8W | X86_REGISTER_R8B,
    X86_REGISTER_R9  | X86_REGISTER_R9D | X86_REGISTER_R9W | X86_REGISTER_R9B,
    X86_REGISTER_R10 | X86_REGISTER_R10D | X86_REGISTER_R10W | X86_REGISTER_R10B,
    X86_REGISTER_R11 | X86_REGISTER_R11D | X86_REGISTER_R11W | X86_REGISTER_R11B,
    X86_REGISTER_R12 | X86_REGISTER_R12D | X86_REGISTER_R12W | X86_REGISTER_R12B,
    X86_REGISTER_R13 | X86_REGISTER_R13D | X86_REGISTER_R13W | X86_REGISTER_R13B,
    X86_REGISTER_R14 | X86_REGISTER_R14D | X86_REGISTER_R14W | X86_REGISTER_R14B,
    X86_REGISTER_R15 | X86_REGISTER_R15D | X86_REGISTER_R15W | X86_REGISTER_R15B,

    X86_REGISTER_RAX | X86_REGISTER_EAX | X86_REGISTER_AX,
    X86_REGISTER_RCX | X86_REGISTER_ECX | X86_REGISTER_CX ,
    X86_REGISTER_RDX | X86_REGISTER_EDX | X86_REGISTER_DX ,
    X86_REGISTER_RBX | X86_REGISTER_EBX | X86_REGISTER_BX,
    X86_REGISTER_RSP | X86_REGISTER_ESP | X86_REGISTER_SP ,
    X86_REGISTER_RBP | X86_REGISTER_EBP | X86_REGISTER_BP,
    X86_REGISTER_RSI | X86_REGISTER_ESI | X86_REGISTER_SI ,
    X86_REGISTER_RDI | X86_REGISTER_EDI | X86_REGISTER_DI ,
    X86_REGISTER_R8  | X86_REGISTER_R8D | X86_REGISTER_R8W ,
    X86_REGISTER_R9  | X86_REGISTER_R9D | X86_REGISTER_R9W ,
    X86_REGISTER_R10 | X86_REGISTER_R10D | X86_REGISTER_R10W ,
    X86_REGISTER_R11 | X86_REGISTER_R11D | X86_REGISTER_R11W ,
    X86_REGISTER_R12 | X86_REGISTER_R12D | X86_REGISTER_R12W ,
    X86_REGISTER_R13 | X86_REGISTER_R13D | X86_REGISTER_R13W ,
    X86_REGISTER_R14 | X86_REGISTER_R14D | X86_REGISTER_R14W ,
    X86_REGISTER_R15 | X86_REGISTER_R15D | X86_REGISTER_R15W ,

    X86_REGISTER_RAX | X86_REGISTER_EAX ,
    X86_REGISTER_RCX | X86_REGISTER_ECX ,
    X86_REGISTER_RDX | X86_REGISTER_EDX ,
    X86_REGISTER_RBX | X86_REGISTER_EBX ,
    X86_REGISTER_RSP | X86_REGISTER_ESP ,
    X86_REGISTER_RBP | X86_REGISTER_EBP ,
    X86_REGISTER_RSI | X86_REGISTER_ESI ,
    X86_REGISTER_RDI | X86_REGISTER_EDI ,
    X86_REGISTER_R8  | X86_REGISTER_R8D ,
    X86_REGISTER_R9  | X86_REGISTER_R9D ,
    X86_REGISTER_R10 | X86_REGISTER_R10D ,
    X86_REGISTER_R11 | X86_REGISTER_R11D ,
    X86_REGISTER_R12 | X86_REGISTER_R12D ,
    X86_REGISTER_R13 | X86_REGISTER_R13D ,
    X86_REGISTER_R14 | X86_REGISTER_R14D ,
    X86_REGISTER_R15 | X86_REGISTER_R15D ,

    X86_REGISTER_RAX,
    X86_REGISTER_RCX ,
    X86_REGISTER_RDX ,
    X86_REGISTER_RBX ,
    X86_REGISTER_RSP ,
    X86_REGISTER_RBP ,
    X86_REGISTER_RSI ,
    X86_REGISTER_RDI ,
    X86_REGISTER_R8  ,
    X86_REGISTER_R9  ,
    X86_REGISTER_R10 ,
    X86_REGISTER_R11 ,
    X86_REGISTER_R12 ,
    X86_REGISTER_R13 ,
    X86_REGISTER_R14 ,
    X86_REGISTER_R15 ,
 
};


extern uint64_t CONVERT_CAPSTONE_REGISTER_TO_FLAG[];

bool has_inst_free_register(fuku_instruction& inst, x86_reg reg) {

    if (CONVERT_CAPSTONE_REGISTER_TO_FLAG[reg] != -2) {
        return GET_BITES(inst.get_custom_flags(), CONVERT_CAPSTONE_REGISTER_TO_FLAG[reg]) == CONVERT_CAPSTONE_REGISTER_TO_FLAG[reg];
    }

    return false;
}

bool has_inst_free_eflags(uint64_t inst_eflags, uint64_t flags) {

    if (GET_BITES(flags, X86_EFLAGS_MODIFY_CF)) {
        if (!GET_BITES(inst_eflags, X86_EFLAGS_MOD_CF)) {
            return false;
        }
    }

    if (GET_BITES(flags, X86_EFLAGS_MODIFY_OF)) {
        if (!GET_BITES(inst_eflags, X86_EFLAGS_MOD_OF)) {
            return false;
        }
    }

    if (GET_BITES(flags, X86_EFLAGS_MODIFY_ZF)) {
        if (!GET_BITES(inst_eflags, X86_EFLAGS_MOD_ZF)) {
            return false;
        }
    }

    if (GET_BITES(flags, X86_EFLAGS_MODIFY_DF)) {
        if (!GET_BITES(inst_eflags, X86_EFLAGS_MOD_DF)) {
            return false;
        }
    }

    if (GET_BITES(flags, X86_EFLAGS_MODIFY_SF)) {
        if (!GET_BITES(inst_eflags, X86_EFLAGS_MOD_SF)) {
            return false;
        }
    }

    if (GET_BITES(flags, X86_EFLAGS_MODIFY_PF)) {
        if (!GET_BITES(inst_eflags, X86_EFLAGS_MOD_PF)) {
            return false;
        }
    }
    if (GET_BITES(flags, X86_EFLAGS_MODIFY_AF)) {
        if (!GET_BITES(inst_eflags, X86_EFLAGS_MOD_AF)) {
            return false;
        }
    }


    return true;
}

uint64_t convert_fuku_reg_to_flag_reg(fuku_register_enum reg) {
   return CONVERT_FUKU_REGISTER_TO_FLAG[reg];
}



inline bool bit_scan_forward(uint32_t& index, uint64_t mask) {
    for (; index < 64; index++) {
        if (mask & ((uint64_t)1 << index)) {
            return true;
        }
    }
    return false;
}

inline bool bit_scan_backward(uint32_t& index, uint64_t mask) {
    for (; index != -1; index--) {
        if (mask & ((uint64_t)1 << index)) {
            return true;
        }
    }
    return false;
}

fuku_register_enum convert_flag_reg_to_fuku_reg(uint64_t reg) {

    uint32_t index = 0;
    if (bit_scan_forward(index, reg)) {
        return CONVERT_FLAG_REGISTER_TO_FUKU[index];
    }
    else {
        return FUKU_REG_NONE;
    }
}



uint32_t get_rand_free_reg_(uint64_t inst_regs, uint32_t min_idx, uint32_t max_idx) {

    uint32_t index = min_idx;

    if (bit_scan_forward(index, inst_regs)) {
        if (index > max_idx) {

            if (max_idx + 16 < 63) {
                uint32_t idx = get_rand_free_reg_(inst_regs, min_idx + 16, max_idx + 16);

                if (idx == -1) {
                    return -1;
                }

                return idx - 16;
            }

            return -1;
        }

        uint32_t rand_idx = FUKU_GET_RAND(min_idx, max_idx);

        index = rand_idx;
        if (rand_idx == min_idx) {
            bit_scan_forward(index, inst_regs);
            return index;
        }
        else if (rand_idx == max_idx) {
            bit_scan_backward(index, inst_regs);
            return index;
        }
        else {
            if (!bit_scan_forward(index, inst_regs)) {
                index = rand_idx;
                bit_scan_backward(index, inst_regs);
            }
        }

        return index;
    }

    return -1;
}

void exclude_reg_flag(uint64_t& reg_flags, uint32_t reg_flag_idx) {

    for (; reg_flag_idx < 63; reg_flag_idx += 16) {
        reg_flags &= ~((uint64_t)1 << reg_flag_idx);
    }
}

fuku_register_enum get_random_reg(uint32_t reg_size, bool x86_only, fuku_register_enum exclude_reg) {

    switch (reg_size) {

    case 1: {
        return get_random_free_flag_reg(0xFFFFFFFFFFFFFFFF, 1, x86_only, exclude_reg);
    }
    case 2: {
        return get_random_free_flag_reg(0xFFFFFFFFFFFF0000, 2, x86_only, exclude_reg);
    }
    case 4: {
        return get_random_free_flag_reg(0xFFFFFFFF00000000, 4, x86_only, exclude_reg);
    }
    case 8: {
        return get_random_free_flag_reg(0xFFFF000000000000, 8, x86_only, exclude_reg);
    }
    }

    return FUKU_REG_NONE;
}

fuku_register_enum get_random_free_flag_reg(fuku_instruction& inst, uint32_t reg_size, bool x86_only, fuku_register_enum exclude_reg) {
    return get_random_free_flag_reg(inst.get_custom_flags(), reg_size, x86_only, exclude_reg);
}

fuku_register_enum get_random_free_flag_reg(uint64_t reg_flags, uint32_t reg_size, bool x86_only, fuku_register_enum exclude_reg) {

    if (exclude_reg != FUKU_REG_NONE) {
        uint64_t ex_inst_reg = convert_fuku_reg_to_flag_reg(exclude_reg);
        if (ex_inst_reg != -2) {

            uint32_t index = 0;
            if (bit_scan_forward(index, ex_inst_reg)) {
                exclude_reg_flag(reg_flags, index);
            }
        }
    }

    uint32_t returned_idx = -1;

    if (reg_flags) {

        switch (reg_size) {

        case 1: {

            if (x86_only) {
                returned_idx = get_rand_free_reg_(reg_flags, 0, 3);
            }
            else {
                returned_idx = get_rand_free_reg_(reg_flags, 0, 15);
            }
            break;
        }
        case 2: {

            if (x86_only) {
                returned_idx = get_rand_free_reg_(reg_flags, 16, 23);
            }
            else {
                returned_idx = get_rand_free_reg_(reg_flags, 16, 31);
            }
            break;
        }
        case 4: {

            if (x86_only) {
                returned_idx = get_rand_free_reg_(reg_flags, 32, 39);
            }
            else {
                returned_idx = get_rand_free_reg_(reg_flags, 32, 47);
            }
            break;
        }
        case 8: {

            if (x86_only) {
                returned_idx = get_rand_free_reg_(reg_flags, 48, 55);
            }
            else {
                returned_idx = get_rand_free_reg_(reg_flags, 48, 63);
            }
            break;
        }
        }
    }

    if (returned_idx != -1) {
        return CONVERT_FLAG_REGISTER_TO_FUKU[returned_idx];
    }

    return FUKU_REG_NONE;
}
