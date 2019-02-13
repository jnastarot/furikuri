#pragma once

#define X86_EFLAGS_GROUP_TEST (X86_EFLAGS_TEST_OF | X86_EFLAGS_TEST_SF | X86_EFLAGS_TEST_ZF | X86_EFLAGS_TEST_PF | X86_EFLAGS_TEST_CF | X86_EFLAGS_TEST_DF | X86_EFLAGS_TEST_AF)
#define X86_EFLAGS_GROUP_MODIFY (X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_CF | X86_EFLAGS_MODIFY_DF | X86_EFLAGS_MODIFY_AF)
#define X86_EFLAGS_GROUP_SET (X86_EFLAGS_SET_CF | X86_EFLAGS_SET_DF | X86_EFLAGS_SET_OF | X86_EFLAGS_SET_SF | X86_EFLAGS_SET_ZF | X86_EFLAGS_SET_AF | X86_EFLAGS_SET_PF)
#define X86_EFLAGS_GROUP_RESET (X86_EFLAGS_RESET_OF | X86_EFLAGS_RESET_CF | X86_EFLAGS_RESET_DF | X86_EFLAGS_RESET_SF | X86_EFLAGS_RESET_AF | X86_EFLAGS_RESET_ZF)
#define X86_EFLAGS_GROUP_UNDEFINED (X86_EFLAGS_UNDEFINED_OF | X86_EFLAGS_UNDEFINED_SF | X86_EFLAGS_UNDEFINED_ZF | X86_EFLAGS_UNDEFINED_PF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_UNDEFINED_CF)

#define X86_EFLAGS_MOD_CF (X86_EFLAGS_SET_CF | X86_EFLAGS_UNDEFINED_CF | X86_EFLAGS_RESET_OF | X86_EFLAGS_MODIFY_CF) 
#define X86_EFLAGS_MOD_OF (X86_EFLAGS_SET_OF | X86_EFLAGS_UNDEFINED_OF | X86_EFLAGS_RESET_OF | X86_EFLAGS_MODIFY_OF) 
#define X86_EFLAGS_MOD_ZF (X86_EFLAGS_SET_ZF | X86_EFLAGS_UNDEFINED_ZF | X86_EFLAGS_RESET_ZF | X86_EFLAGS_MODIFY_ZF) 
#define X86_EFLAGS_MOD_DF (X86_EFLAGS_SET_DF | X86_EFLAGS_RESET_DF | X86_EFLAGS_MODIFY_DF) 
#define X86_EFLAGS_MOD_SF (X86_EFLAGS_SET_SF | X86_EFLAGS_UNDEFINED_SF | X86_EFLAGS_RESET_SF | X86_EFLAGS_MODIFY_SF) 
#define X86_EFLAGS_MOD_PF (X86_EFLAGS_SET_PF | X86_EFLAGS_UNDEFINED_PF | X86_EFLAGS_RESET_PF | X86_EFLAGS_MODIFY_PF) 
#define X86_EFLAGS_MOD_AF (X86_EFLAGS_SET_AF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_RESET_AF | X86_EFLAGS_MODIFY_AF) 


//byte
#define X86_REGISTER_AL ((uint64_t)1 << 0)
#define X86_REGISTER_CL ((uint64_t)1 << 1)
#define X86_REGISTER_DL ((uint64_t)1 << 2)
#define X86_REGISTER_BL ((uint64_t)1 << 3)
#define X86_REGISTER_SPL ((uint64_t)1 << 4)
#define X86_REGISTER_BPL ((uint64_t)1 << 5)
#define X86_REGISTER_SIL ((uint64_t)1 << 6)
#define X86_REGISTER_DIL ((uint64_t)1 << 7)
#define X86_REGISTER_R8B  ((uint64_t)1 << 8)
#define X86_REGISTER_R9B  ((uint64_t)1 << 9)
#define X86_REGISTER_R10B ((uint64_t)1 << 10)
#define X86_REGISTER_R11B ((uint64_t)1 << 11)
#define X86_REGISTER_R12B ((uint64_t)1 << 12)
#define X86_REGISTER_R13B ((uint64_t)1 << 13)
#define X86_REGISTER_R14B ((uint64_t)1 << 14)
#define X86_REGISTER_R15B ((uint64_t)1 << 15)
//word
#define X86_REGISTER_AX ((uint64_t)1 << 16)
#define X86_REGISTER_CX ((uint64_t)1 << 17)
#define X86_REGISTER_DX ((uint64_t)1 << 18)
#define X86_REGISTER_BX ((uint64_t)1 << 19)
#define X86_REGISTER_SP ((uint64_t)1 << 20)
#define X86_REGISTER_BP ((uint64_t)1 << 21)
#define X86_REGISTER_SI ((uint64_t)1 << 22)
#define X86_REGISTER_DI ((uint64_t)1 << 23)
#define X86_REGISTER_R8W  ((uint64_t)1 << 24)
#define X86_REGISTER_R9W  ((uint64_t)1 << 25)
#define X86_REGISTER_R10W ((uint64_t)1 << 26)
#define X86_REGISTER_R11W ((uint64_t)1 << 27)
#define X86_REGISTER_R12W ((uint64_t)1 << 28)
#define X86_REGISTER_R13W ((uint64_t)1 << 29)
#define X86_REGISTER_R14W ((uint64_t)1 << 30)
#define X86_REGISTER_R15W ((uint64_t)1 << 31)
//dword
#define X86_REGISTER_EAX ((uint64_t)1 << 32)
#define X86_REGISTER_ECX ((uint64_t)1 << 33)
#define X86_REGISTER_EDX ((uint64_t)1 << 34)
#define X86_REGISTER_EBX ((uint64_t)1 << 35)
#define X86_REGISTER_ESP ((uint64_t)1 << 36)
#define X86_REGISTER_EBP ((uint64_t)1 << 37)
#define X86_REGISTER_ESI ((uint64_t)1 << 38)
#define X86_REGISTER_EDI ((uint64_t)1 << 39)
#define X86_REGISTER_R8D  ((uint64_t)1 << 40)
#define X86_REGISTER_R9D  ((uint64_t)1 << 41)
#define X86_REGISTER_R10D ((uint64_t)1 << 42)
#define X86_REGISTER_R11D ((uint64_t)1 << 43)
#define X86_REGISTER_R12D ((uint64_t)1 << 44)
#define X86_REGISTER_R13D ((uint64_t)1 << 45)
#define X86_REGISTER_R14D ((uint64_t)1 << 46)
#define X86_REGISTER_R15D ((uint64_t)1 << 47)
//qword
#define X86_REGISTER_RAX ((uint64_t)1 << 48)
#define X86_REGISTER_RCX ((uint64_t)1 << 49)
#define X86_REGISTER_RDX ((uint64_t)1 << 50)
#define X86_REGISTER_RBX ((uint64_t)1 << 51)
#define X86_REGISTER_RSP ((uint64_t)1 << 52)
#define X86_REGISTER_RBP ((uint64_t)1 << 53)
#define X86_REGISTER_RSI ((uint64_t)1 << 54)
#define X86_REGISTER_RDI ((uint64_t)1 << 55)
#define X86_REGISTER_R8  ((uint64_t)1 << 56)
#define X86_REGISTER_R9  ((uint64_t)1 << 57)
#define X86_REGISTER_R10 ((uint64_t)1 << 58)
#define X86_REGISTER_R11 ((uint64_t)1 << 59)
#define X86_REGISTER_R12 ((uint64_t)1 << 60)
#define X86_REGISTER_R13 ((uint64_t)1 << 61)
#define X86_REGISTER_R14 ((uint64_t)1 << 62)
#define X86_REGISTER_R15 ((uint64_t)1 << 63)


#define REGISTER_ACCESS_READ  (1 << 0)
#define REGISTER_ACCESS_WRITE (1 << 1)

struct reg_access {
    uint64_t reg;
    uint8_t access;
};

class fuku_code_profiler {  
    csh cap_handle;
    fuku_assambler_arch arch;

    uint64_t registers_table[X86_REG_ENDING];
    bool dirty_registers_table;


    uint64_t profile_graph_registers(fuku_code_holder& code, linestorage::iterator lines_iter);
    uint64_t profile_graph_eflags(fuku_code_holder& code, linestorage::iterator lines_iter);
public:
    fuku_code_profiler(fuku_assambler_arch arch);
    ~fuku_code_profiler();

    bool get_instruction_operands_access(cs_insn *instruction, uint8_t& reg_idx, reg_access op_access[]);
    bool get_instruction_operands_access(fuku_instruction& inst, uint8_t& reg_idx, reg_access op_access[]);

public:
    bool profile_code(fuku_code_holder& code);

};
