#include "stdafx.h"
#include "fuku_code_profiler.h"


#define GET_BITES_INCLUDED(src, include_mask, exclude_mask) ((src & include_mask) & (~exclude_mask))

#define CF_EXCLUDE (X86_EFLAGS_MODIFY_CF | X86_EFLAGS_UNDEFINED_CF | X86_EFLAGS_RESET_CF | X86_EFLAGS_SET_CF)
#define DF_EXCLUDE (X86_EFLAGS_MODIFY_DF | X86_EFLAGS_RESET_DF     | X86_EFLAGS_SET_DF)
#define OF_EXCLUDE (X86_EFLAGS_MODIFY_OF | X86_EFLAGS_UNDEFINED_OF | X86_EFLAGS_RESET_OF | X86_EFLAGS_SET_OF)
#define SF_EXCLUDE (X86_EFLAGS_MODIFY_SF | X86_EFLAGS_UNDEFINED_SF | X86_EFLAGS_RESET_SF | X86_EFLAGS_SET_SF)
#define ZF_EXCLUDE (X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_UNDEFINED_ZF | X86_EFLAGS_RESET_ZF | X86_EFLAGS_SET_ZF)
#define AF_EXCLUDE (X86_EFLAGS_MODIFY_AF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_RESET_AF | X86_EFLAGS_SET_AF)
#define PF_EXCLUDE (X86_EFLAGS_MODIFY_PF | X86_EFLAGS_UNDEFINED_PF | X86_EFLAGS_RESET_PF | X86_EFLAGS_SET_PF)


uint64_t TESTED_FLAGS_TABLE[] = {
    X86_EFLAGS_TEST_OF,
    X86_EFLAGS_TEST_SF,
    X86_EFLAGS_TEST_ZF,
    X86_EFLAGS_TEST_PF,
    X86_EFLAGS_TEST_CF,
    X86_EFLAGS_TEST_DF,
    X86_EFLAGS_TEST_AF
};

uint64_t EXCLUDED_FLAGS_TABLE[] = {
    OF_EXCLUDE,
    SF_EXCLUDE,
    ZF_EXCLUDE,
    PF_EXCLUDE,
    CF_EXCLUDE,
    DF_EXCLUDE,
    AF_EXCLUDE
};


uint64_t CONVERT_REGISTER_TABLE[] = {
    -2,
    -2, X86_REGISTER_AL, X86_REGISTER_AX, -2, X86_REGISTER_BL,
    X86_REGISTER_BP, X86_REGISTER_BPL, X86_REGISTER_BX, -2, X86_REGISTER_CL,
    -2, X86_REGISTER_CX, -2, X86_REGISTER_DI, X86_REGISTER_DIL,
    X86_REGISTER_DL, -2, X86_REGISTER_DX, X86_REGISTER_EAX, X86_REGISTER_EBP,
    X86_REGISTER_EBX, X86_REGISTER_ECX, X86_REGISTER_EDI, X86_REGISTER_EDX, -2,
    -2, -2, -2, X86_REGISTER_ESI, X86_REGISTER_ESP,
    -2, -2, -2, -2, X86_REGISTER_RAX,
    X86_REGISTER_RBP, X86_REGISTER_RBX, X86_REGISTER_RCX, X86_REGISTER_RDI, X86_REGISTER_RDX,
    -2, -2, X86_REGISTER_RSI, X86_REGISTER_RSP, X86_REGISTER_SI,
    X86_REGISTER_SIL, X86_REGISTER_SP, X86_REGISTER_SPL, -2, -2,
    -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2,
    -2, -2, -2, -2,
    -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2,
    -2, X86_REGISTER_R8, X86_REGISTER_R9, X86_REGISTER_R10, X86_REGISTER_R11,
    X86_REGISTER_R12, X86_REGISTER_R13, X86_REGISTER_R14, X86_REGISTER_R15,
    -2, -2, -2, -2,
    -2, -2, -2, -2,
    -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2,
    -2, X86_REGISTER_R8B, X86_REGISTER_R9B, X86_REGISTER_R10B, X86_REGISTER_R11B,
    X86_REGISTER_R12B, X86_REGISTER_R13B, X86_REGISTER_R14B, X86_REGISTER_R15B, X86_REGISTER_R8D,
    X86_REGISTER_R9D, X86_REGISTER_R10D, X86_REGISTER_R11D, X86_REGISTER_R12D, X86_REGISTER_R13D,
    X86_REGISTER_R14D, X86_REGISTER_R15D, X86_REGISTER_R8W, X86_REGISTER_R9W, X86_REGISTER_R10W,
    X86_REGISTER_R11W, X86_REGISTER_R12W, X86_REGISTER_R13W, X86_REGISTER_R14W, X86_REGISTER_R15W,
    -2
};

fuku_code_profiler::fuku_code_profiler(fuku_assambler_arch arch)
    :arch(arch){

    cs_open(CS_ARCH_X86, arch == FUKU_ASSAMBLER_ARCH_X86 ? CS_MODE_32 : CS_MODE_64, &cap_handle);
    cs_option(cap_handle, CS_OPT_DETAIL, CS_OPT_ON);
}

fuku_code_profiler::~fuku_code_profiler() {
    cs_close(&cap_handle);
}



uint64_t fuku_code_profiler::profile_graph_registers(fuku_code_holder& code, linestorage::iterator lines_iter) {
    uint64_t included_registers = 0;
    uint64_t excluded_registers = 0;

    cs_insn *instruction;


    for (; lines_iter != code.get_lines().end(); lines_iter++) {
        auto& current_inst = *lines_iter;

        cs_disasm(cap_handle, current_inst.get_op_code(), current_inst.get_op_length(), 0, 1, &instruction);
        if (!instruction) { FUKU_DEBUG; }

        uint16_t current_id = current_inst.get_id();






        //need check on xchg for except swaping of registers

        switch (current_id) {

        case X86_INS_JMP: case X86_INS_RET: case X86_INS_CALL: {
            cs_free(instruction, 1);
            return included_registers;
        }

        default: {
            break;
        }
        }

        cs_free(instruction, 1);
    }

    return included_registers;
}

uint64_t fuku_code_profiler::profile_graph_eflags(fuku_code_holder& code, linestorage::iterator lines_iter) {
    uint64_t included_flags = 0;
    uint64_t excluded_flags = 0;


    for (; lines_iter != code.get_lines().end(); lines_iter++) {
        auto& current_inst = *lines_iter;

        uint16_t current_id = current_inst.get_id();
        uint64_t current_eflags = current_inst.get_eflags();


        if (current_eflags & X86_EFLAGS_GROUP_TEST) {
            
            for (uint8_t flag_idx = 0; flag_idx < (sizeof(TESTED_FLAGS_TABLE) / sizeof(TESTED_FLAGS_TABLE[0])); flag_idx++) {
                if (current_eflags & TESTED_FLAGS_TABLE[flag_idx]) {
                    excluded_flags |= EXCLUDED_FLAGS_TABLE[flag_idx];
                }
            }
        }

        if (excluded_flags == (X86_EFLAGS_GROUP_MODIFY | X86_EFLAGS_GROUP_SET | X86_EFLAGS_GROUP_RESET | X86_EFLAGS_GROUP_UNDEFINED)) {
            return included_flags;
        }      

        switch (current_id) {

            case X86_INS_JMP: case X86_INS_RET: case X86_INS_CALL: {
                return included_flags;
            }

            default: {
                break;
            }
        }

        included_flags |=
            GET_BITES_INCLUDED(
                current_eflags,
                X86_EFLAGS_GROUP_MODIFY | X86_EFLAGS_GROUP_SET | X86_EFLAGS_GROUP_RESET | X86_EFLAGS_GROUP_UNDEFINED,
                excluded_flags
            );

        if (included_flags == (X86_EFLAGS_GROUP_MODIFY | X86_EFLAGS_GROUP_SET | X86_EFLAGS_GROUP_RESET | X86_EFLAGS_GROUP_UNDEFINED)) {
            return included_flags;
        }
    }

    return included_flags;
}

bool fuku_code_profiler::profile_code(fuku_code_holder& code) {

    if (arch != code.get_arch()) {
        return false;
    }

    for (auto line_iter = code.get_lines().begin(); line_iter != code.get_lines().end(); line_iter++) {

        (*line_iter).set_eflags(profile_graph_eflags(code, line_iter));
        (*line_iter).set_custom_flags(profile_graph_registers(code, line_iter));
    }

    return true;
}