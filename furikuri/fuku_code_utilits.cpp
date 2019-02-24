#include "stdafx.h"
#include "fuku_code_utilits.h"
#include "fuku_code_utilits_conv_tables.h"

uint64_t FULL_INCLUDE_FLAGS_TABLE[] = {
    FLAG_REGISTER_RAX | FLAG_REGISTER_EAX  | FLAG_REGISTER_AX   | FLAG_REGISTER_AL,
    FLAG_REGISTER_RCX | FLAG_REGISTER_ECX  | FLAG_REGISTER_CX   | FLAG_REGISTER_CL,
    FLAG_REGISTER_RDX | FLAG_REGISTER_EDX  | FLAG_REGISTER_DX   | FLAG_REGISTER_DL,
    FLAG_REGISTER_RBX | FLAG_REGISTER_EBX  | FLAG_REGISTER_BX   | FLAG_REGISTER_BL,
    FLAG_REGISTER_RSP | FLAG_REGISTER_ESP  | FLAG_REGISTER_SP   | FLAG_REGISTER_SPL,
    FLAG_REGISTER_RBP | FLAG_REGISTER_EBP  | FLAG_REGISTER_BP   | FLAG_REGISTER_BPL,
    FLAG_REGISTER_RSI | FLAG_REGISTER_ESI  | FLAG_REGISTER_SI   | FLAG_REGISTER_SIL,
    FLAG_REGISTER_RDI | FLAG_REGISTER_EDI  | FLAG_REGISTER_DI   | FLAG_REGISTER_DIL,
    FLAG_REGISTER_R8  | FLAG_REGISTER_R8D  | FLAG_REGISTER_R8W  | FLAG_REGISTER_R8B,
    FLAG_REGISTER_R9  | FLAG_REGISTER_R9D  | FLAG_REGISTER_R9W  | FLAG_REGISTER_R9B,
    FLAG_REGISTER_R10 | FLAG_REGISTER_R10D | FLAG_REGISTER_R10W | FLAG_REGISTER_R10B,
    FLAG_REGISTER_R11 | FLAG_REGISTER_R11D | FLAG_REGISTER_R11W | FLAG_REGISTER_R11B,
    FLAG_REGISTER_R12 | FLAG_REGISTER_R12D | FLAG_REGISTER_R12W | FLAG_REGISTER_R12B,
    FLAG_REGISTER_R13 | FLAG_REGISTER_R13D | FLAG_REGISTER_R13W | FLAG_REGISTER_R13B,
    FLAG_REGISTER_R14 | FLAG_REGISTER_R14D | FLAG_REGISTER_R14W | FLAG_REGISTER_R14B,
    FLAG_REGISTER_R15 | FLAG_REGISTER_R15D | FLAG_REGISTER_R15W | FLAG_REGISTER_R15B,
};

uint8_t index_to_size[] = {
    1,
    2,
    4,
    8
};

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


bool has_free_flag_register(uint64_t regs_flags, uint64_t reg) {
    return GET_BITES(regs_flags, reg) == reg;
}

bool has_inst_free_register(const fuku_instruction& inst, x86_reg reg) {

    if (CONVERT_CAPSTONE_REGISTER_TO_FLAG[reg] != -2) {
        return has_free_flag_register(inst.get_custom_flags(), CONVERT_CAPSTONE_REGISTER_TO_FLAG[reg]);
    }

    return false;
}

bool has_inst_free_eflags(uint64_t inst_eflags, uint64_t flags) {

    if (GET_BITES(flags, X86_EFLAGS_MODIFY_CF)) {
        if (!GET_BITES(inst_eflags, EFLAGS_MOD_CF)) {
            return false;
        }
    }

    if (GET_BITES(flags, X86_EFLAGS_MODIFY_OF)) {
        if (!GET_BITES(inst_eflags, EFLAGS_MOD_OF)) {
            return false;
        }
    }

    if (GET_BITES(flags, X86_EFLAGS_MODIFY_ZF)) {
        if (!GET_BITES(inst_eflags, EFLAGS_MOD_ZF)) {
            return false;
        }
    }

    if (GET_BITES(flags, X86_EFLAGS_MODIFY_DF)) {
        if (!GET_BITES(inst_eflags, EFLAGS_MOD_DF)) {
            return false;
        }
    }

    if (GET_BITES(flags, X86_EFLAGS_MODIFY_SF)) {
        if (!GET_BITES(inst_eflags, EFLAGS_MOD_SF)) {
            return false;
        }
    }

    if (GET_BITES(flags, X86_EFLAGS_MODIFY_PF)) {
        if (!GET_BITES(inst_eflags, EFLAGS_MOD_PF)) {
            return false;
        }
    }
    if (GET_BITES(flags, X86_EFLAGS_MODIFY_AF)) {
        if (!GET_BITES(inst_eflags, EFLAGS_MOD_AF)) {
            return false;
        }
    }


    return true;
}


uint64_t fuku_reg_to_flag_reg(fuku_register_enum reg) {
   return (uint64_t)1 << CONVERT_FUKU_REGISTER_TO_FLAG[reg];
}

uint64_t fuku_reg_to_complex_flag_reg(const fuku_register& reg, uint8_t size) {

    switch (size) {

    case 1: {
        return FULL_INCLUDE_FLAGS_TABLE[reg.get_index() + (reg.is_ext64() ? 8 : 0)] & 0xFFFF;
    }
    case 2: {
        return FULL_INCLUDE_FLAGS_TABLE[reg.get_index() + (reg.is_ext64() ? 8 : 0)] & 0xFFFFFFFF;
    }
    case 4: {
        return FULL_INCLUDE_FLAGS_TABLE[reg.get_index() + (reg.is_ext64() ? 8 : 0)] & 0xFFFFFFFFFFFF;
    }
    case 8: {
        return FULL_INCLUDE_FLAGS_TABLE[reg.get_index() + (reg.is_ext64() ? 8 : 0)] & 0xFFFFFFFFFFFFFFFF;
    }
    }

    return FULL_INCLUDE_FLAGS_TABLE[reg.get_index() + (reg.is_ext64() ? 8 : 0) ];
}

uint64_t flag_reg_to_complex_flag_reg(uint64_t flag_reg) {

    uint32_t index = 0;
    if (!bit_scan_forward(index, flag_reg)) {
        return 0;
    }

    uint8_t size = ((index) / 16)+1;
    uint8_t reg_index = (index) % 16;

    return FULL_INCLUDE_FLAGS_TABLE[reg_index];
}

uint64_t flag_reg_to_complex_flag_reg_by_size(uint64_t flag_reg) {

    uint32_t index = 0;
    if (!bit_scan_forward(index, flag_reg)) {
        return 0;
    }

    uint8_t size = ((index) / 16) + 1;
    uint8_t reg_index = (index) % 16;


    switch (size) {
    case 1: {
        return FULL_INCLUDE_FLAGS_TABLE[reg_index] & 0xFFFF;
    }
    case 2: {
        return FULL_INCLUDE_FLAGS_TABLE[reg_index] & 0xFFFFFFFF;
    }
    case 3: {
        return FULL_INCLUDE_FLAGS_TABLE[reg_index] & 0xFFFFFFFFFFFF;
    }
    case 4: {
        return FULL_INCLUDE_FLAGS_TABLE[reg_index] & 0xFFFFFFFFFFFFFFFF;
    }
    }

    return FULL_INCLUDE_FLAGS_TABLE[reg_index];
}

uint8_t get_random_bit_by_mask(uint64_t mask, uint8_t min_index, uint8_t max_index) {

    uint32_t index = min_index;

    uint32_t rand_idx = FUKU_GET_RAND(min_index, max_index);

    index = rand_idx;
    if (rand_idx == min_index) {
        bit_scan_forward(index, mask);

        return index;
    }
    else if (rand_idx == max_index) {
        bit_scan_backward(index, mask);

        return index;
    }
    else {
        if (!bit_scan_forward(index, mask) || index > max_index) {
            index = rand_idx;
            bit_scan_backward(index, mask);
        }
    }

    return index;
}

fuku_register_enum flag_reg_to_fuku_reg(uint64_t reg) {

    uint32_t index = 0;
    if (bit_scan_forward(index, reg)) {
        return CONVERT_FLAG_REGISTER_TO_FUKU[index];
    }
    else {
        return FUKU_REG_NONE;
    }
}


uint8_t flag_reg_get_size(uint64_t reg) {

    uint32_t index = 0;
    if (!bit_scan_forward(index, reg)) {
        return 0;
    }

    return index_to_size[((index) / 16) + 1];
}

uint8_t flag_reg_get_index(uint64_t reg) {

    uint32_t index = 0;
    if (!bit_scan_forward(index, reg)) {
        return 0;
    }

    return (index) % 8;
}

uint8_t is_flag_reg_ext64(uint64_t reg) {

    uint32_t index = 0;
    if (!bit_scan_forward(index, reg)) {
        return 0;
    }

    return (((index) / 16) > 7) ? 1 : 0;
}

fuku_register_enum fuku_reg_set_grade(fuku_register_enum reg, uint8_t needed_size) {
    return flag_reg_to_fuku_reg( ((uint64_t)1 << (CONVERT_FUKU_REGISTER_TO_FLAG[reg] - 16)) );
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
     
        return get_random_bit_by_mask(inst_regs, min_idx, max_idx);
    }

    return -1;
}

void exclude_reg_flag(uint64_t& reg_flags, uint32_t reg_flag_idx) {

    for (; reg_flag_idx < 63; reg_flag_idx += 16) {
        reg_flags &= ~((uint64_t)1 << reg_flag_idx);
    }
}

fuku_register_enum get_random_reg(uint32_t reg_size, bool x86_only, uint64_t exclude_regs) {

    switch (reg_size) {

    case 1: {
        return get_random_free_flag_reg(0xFFFFFFFFFFFFFFFF, 1, x86_only, exclude_regs);
    }
    case 2: {
        return get_random_free_flag_reg(0xFFFFFFFFFFFF0000, 2, x86_only, exclude_regs);
    }
    case 4: {
        return get_random_free_flag_reg(0xFFFFFFFF00000000, 4, x86_only, exclude_regs);
    }
    case 8: {
        return get_random_free_flag_reg(0xFFFF000000000000, 8, x86_only, exclude_regs);
    }
    }

    return FUKU_REG_NONE;
}

fuku_register_enum get_random_free_flag_reg(const fuku_instruction& inst, uint32_t reg_size, bool x86_only, uint64_t exclude_regs) {
    return get_random_free_flag_reg(inst.get_custom_flags(), reg_size, x86_only, exclude_regs);
}

fuku_register_enum get_random_free_flag_reg(uint64_t reg_flags, uint32_t reg_size, bool x86_only, uint64_t exclude_regs) {


    reg_flags &= ~(exclude_regs);

    uint32_t returned_idx = -1;

    if (reg_flags) {

        switch (reg_size) {

        case 1: {

            if (x86_only) {
                returned_idx = get_rand_free_reg_(reg_flags, FLAG_REGISTER_IDX_AL, FLAG_REGISTER_IDX_BL);
            }
            else {
                returned_idx = get_rand_free_reg_(reg_flags, FLAG_REGISTER_IDX_AL, FLAG_REGISTER_IDX_R15B);
            }
            break;
        }
        case 2: {

            if (x86_only) {
                returned_idx = get_rand_free_reg_(reg_flags, FLAG_REGISTER_IDX_AX, FLAG_REGISTER_IDX_DI);
            }
            else {
                returned_idx = get_rand_free_reg_(reg_flags, FLAG_REGISTER_IDX_AX, FLAG_REGISTER_IDX_R15W);
            }
            break;
        }
        case 4: {

            if (x86_only) {
                returned_idx = get_rand_free_reg_(reg_flags, FLAG_REGISTER_IDX_EAX, FLAG_REGISTER_IDX_EDI);
            }
            else {
                returned_idx = get_rand_free_reg_(reg_flags, FLAG_REGISTER_IDX_EAX, FLAG_REGISTER_IDX_R15D);
            }
            break;
        }
        case 8: {

            if (x86_only) {
                returned_idx = get_rand_free_reg_(reg_flags, FLAG_REGISTER_IDX_RAX, FLAG_REGISTER_IDX_RDI);
            }
            else {
                returned_idx = get_rand_free_reg_(reg_flags, FLAG_REGISTER_IDX_RAX, FLAG_REGISTER_IDX_R15);
            }
            break;
        }
        }
    }

    if (returned_idx != -1) {
        return fuku_register_enum(CONVERT_FLAG_REGISTER_TO_FUKU[returned_idx]);
    }

    return FUKU_REG_NONE;
}
