#pragma once

#define X86_EFLAGS_GROUP_TEST (X86_EFLAGS_TEST_OF | X86_EFLAGS_TEST_SF | X86_EFLAGS_TEST_ZF | X86_EFLAGS_TEST_PF | X86_EFLAGS_TEST_CF | X86_EFLAGS_TEST_DF | X86_EFLAGS_TEST_AF)
#define X86_EFLAGS_GROUP_MODIFY (X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_CF | X86_EFLAGS_MODIFY_DF | X86_EFLAGS_MODIFY_AF)
#define X86_EFLAGS_GROUP_SET (X86_EFLAGS_SET_CF | X86_EFLAGS_SET_DF | X86_EFLAGS_SET_OF | X86_EFLAGS_SET_SF | X86_EFLAGS_SET_ZF | X86_EFLAGS_SET_AF | X86_EFLAGS_SET_PF)
#define X86_EFLAGS_GROUP_RESET (X86_EFLAGS_RESET_OF | X86_EFLAGS_RESET_CF | X86_EFLAGS_RESET_DF | X86_EFLAGS_RESET_SF | X86_EFLAGS_RESET_AF | X86_EFLAGS_RESET_ZF)
#define X86_EFLAGS_GROUP_UNDEFINED (X86_EFLAGS_UNDEFINED_OF | X86_EFLAGS_UNDEFINED_SF | X86_EFLAGS_UNDEFINED_ZF | X86_EFLAGS_UNDEFINED_PF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_UNDEFINED_CF)


//byte
#define X86_REGISTER_AL (1 << 0)
#define X86_REGISTER_CL (1 << 1)
#define X86_REGISTER_DL (1 << 2)
#define X86_REGISTER_BL (1 << 3)
#define X86_REGISTER_SPL (1 << 4)
#define X86_REGISTER_BPL (1 << 5)
#define X86_REGISTER_SIL (1 << 6)
#define X86_REGISTER_DIL (1 << 7)
#define X86_REGISTER_R8B  (1 << 8)
#define X86_REGISTER_R9B  (1 << 9)
#define X86_REGISTER_R10B (1 << 10)
#define X86_REGISTER_R11B (1 << 11)
#define X86_REGISTER_R12B (1 << 12)
#define X86_REGISTER_R13B (1 << 13)
#define X86_REGISTER_R14B (1 << 14)
#define X86_REGISTER_R15B (1 << 15)
//word
#define X86_REGISTER_AX (1 << 16)
#define X86_REGISTER_CX (1 << 17)
#define X86_REGISTER_DX (1 << 18)
#define X86_REGISTER_BX (1 << 19)
#define X86_REGISTER_SP (1 << 20)
#define X86_REGISTER_BP (1 << 21)
#define X86_REGISTER_SI (1 << 22)
#define X86_REGISTER_DI (1 << 23)
#define X86_REGISTER_R8W  (1 << 24)
#define X86_REGISTER_R9W  (1 << 25)
#define X86_REGISTER_R10W (1 << 26)
#define X86_REGISTER_R11W (1 << 27)
#define X86_REGISTER_R12W (1 << 28)
#define X86_REGISTER_R13W (1 << 29)
#define X86_REGISTER_R14W (1 << 30)
#define X86_REGISTER_R15W (1 << 31)
//dword
#define X86_REGISTER_EAX (1 << 32)
#define X86_REGISTER_ECX (1 << 33)
#define X86_REGISTER_EDX (1 << 34)
#define X86_REGISTER_EBX (1 << 35)
#define X86_REGISTER_ESP (1 << 36)
#define X86_REGISTER_EBP (1 << 37)
#define X86_REGISTER_ESI (1 << 38)
#define X86_REGISTER_EDI (1 << 39)
#define X86_REGISTER_R8D  (1 << 40)
#define X86_REGISTER_R9D  (1 << 41)
#define X86_REGISTER_R10D (1 << 42)
#define X86_REGISTER_R11D (1 << 43)
#define X86_REGISTER_R12D (1 << 44)
#define X86_REGISTER_R13D (1 << 45)
#define X86_REGISTER_R14D (1 << 46)
#define X86_REGISTER_R15D (1 << 47)
//qword
#define X86_REGISTER_RAX (1 << 48)
#define X86_REGISTER_RCX (1 << 49)
#define X86_REGISTER_RDX (1 << 50)
#define X86_REGISTER_RBX (1 << 51)
#define X86_REGISTER_RSP (1 << 52)
#define X86_REGISTER_RBP (1 << 53)
#define X86_REGISTER_RSI (1 << 54)
#define X86_REGISTER_RDI (1 << 55)
#define X86_REGISTER_R8  (1 << 56)
#define X86_REGISTER_R9  (1 << 57)
#define X86_REGISTER_R10 (1 << 58)
#define X86_REGISTER_R11 (1 << 59)
#define X86_REGISTER_R12 (1 << 60)
#define X86_REGISTER_R13 (1 << 61)
#define X86_REGISTER_R14 (1 << 62)
#define X86_REGISTER_R15 (1 << 63)

class fuku_code_profiler {  
    csh cap_handle;
    fuku_assambler_arch arch;

public:
    fuku_code_profiler(fuku_assambler_arch arch);
    ~fuku_code_profiler();

    uint64_t profile_graph_registers(fuku_code_holder& code, linestorage::iterator lines_iter);
    uint64_t profile_graph_eflags(fuku_code_holder& code, linestorage::iterator lines_iter);

public:
    bool profile_code(fuku_code_holder& code);

};

