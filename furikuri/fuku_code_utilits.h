#pragma once

#define EFLAGS_GROUP_TEST (X86_EFLAGS_TEST_OF | X86_EFLAGS_TEST_SF | X86_EFLAGS_TEST_ZF | X86_EFLAGS_TEST_PF | X86_EFLAGS_TEST_CF | X86_EFLAGS_TEST_DF | X86_EFLAGS_TEST_AF)
#define EFLAGS_GROUP_MODIFY (X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_CF | X86_EFLAGS_MODIFY_DF | X86_EFLAGS_MODIFY_AF)
#define EFLAGS_GROUP_SET (X86_EFLAGS_SET_CF | X86_EFLAGS_SET_DF | X86_EFLAGS_SET_OF | X86_EFLAGS_SET_SF | X86_EFLAGS_SET_ZF | X86_EFLAGS_SET_AF | X86_EFLAGS_SET_PF)
#define EFLAGS_GROUP_RESET (X86_EFLAGS_RESET_OF | X86_EFLAGS_RESET_CF | X86_EFLAGS_RESET_DF | X86_EFLAGS_RESET_SF | X86_EFLAGS_RESET_AF | X86_EFLAGS_RESET_ZF)
#define EFLAGS_GROUP_UNDEFINED (X86_EFLAGS_UNDEFINED_OF | X86_EFLAGS_UNDEFINED_SF | X86_EFLAGS_UNDEFINED_ZF | X86_EFLAGS_UNDEFINED_PF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_UNDEFINED_CF)

#define EFLAGS_MOD_CF (X86_EFLAGS_SET_CF | X86_EFLAGS_UNDEFINED_CF | X86_EFLAGS_RESET_OF | X86_EFLAGS_MODIFY_CF) 
#define EFLAGS_MOD_OF (X86_EFLAGS_SET_OF | X86_EFLAGS_UNDEFINED_OF | X86_EFLAGS_RESET_OF | X86_EFLAGS_MODIFY_OF) 
#define EFLAGS_MOD_ZF (X86_EFLAGS_SET_ZF | X86_EFLAGS_UNDEFINED_ZF | X86_EFLAGS_RESET_ZF | X86_EFLAGS_MODIFY_ZF) 
#define EFLAGS_MOD_DF (X86_EFLAGS_SET_DF | X86_EFLAGS_RESET_DF | X86_EFLAGS_MODIFY_DF) 
#define EFLAGS_MOD_SF (X86_EFLAGS_SET_SF | X86_EFLAGS_UNDEFINED_SF | X86_EFLAGS_RESET_SF | X86_EFLAGS_MODIFY_SF) 
#define EFLAGS_MOD_PF (X86_EFLAGS_SET_PF | X86_EFLAGS_UNDEFINED_PF | X86_EFLAGS_RESET_PF | X86_EFLAGS_MODIFY_PF) 
#define EFLAGS_MOD_AF (X86_EFLAGS_SET_AF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_RESET_AF | X86_EFLAGS_MODIFY_AF) 


enum flag_register_index{
     //byte
     FLAG_REGISTER_IDX_AL = 0,
     FLAG_REGISTER_IDX_CL,
     FLAG_REGISTER_IDX_DL,
     FLAG_REGISTER_IDX_BL,
     FLAG_REGISTER_IDX_SPL,
     FLAG_REGISTER_IDX_BPL,
     FLAG_REGISTER_IDX_SIL,
     FLAG_REGISTER_IDX_DIL,
     FLAG_REGISTER_IDX_R8B,
     FLAG_REGISTER_IDX_R9B,
     FLAG_REGISTER_IDX_R10B,
     FLAG_REGISTER_IDX_R11B,
     FLAG_REGISTER_IDX_R12B,
     FLAG_REGISTER_IDX_R13B,
     FLAG_REGISTER_IDX_R14B,
     FLAG_REGISTER_IDX_R15B,
    //word
     FLAG_REGISTER_IDX_AX,
     FLAG_REGISTER_IDX_CX,
     FLAG_REGISTER_IDX_DX,
     FLAG_REGISTER_IDX_BX,
     FLAG_REGISTER_IDX_SP,
     FLAG_REGISTER_IDX_BP,
     FLAG_REGISTER_IDX_SI,
     FLAG_REGISTER_IDX_DI,
     FLAG_REGISTER_IDX_R8W,
     FLAG_REGISTER_IDX_R9W,
     FLAG_REGISTER_IDX_R10W,
     FLAG_REGISTER_IDX_R11W,
     FLAG_REGISTER_IDX_R12W,
     FLAG_REGISTER_IDX_R13W,
     FLAG_REGISTER_IDX_R14W,
     FLAG_REGISTER_IDX_R15W,
    //dword
     FLAG_REGISTER_IDX_EAX,
     FLAG_REGISTER_IDX_ECX,
     FLAG_REGISTER_IDX_EDX,
     FLAG_REGISTER_IDX_EBX,
     FLAG_REGISTER_IDX_ESP,
     FLAG_REGISTER_IDX_EBP,
     FLAG_REGISTER_IDX_ESI,
     FLAG_REGISTER_IDX_EDI,
     FLAG_REGISTER_IDX_R8D,
     FLAG_REGISTER_IDX_R9D,
     FLAG_REGISTER_IDX_R10D,
     FLAG_REGISTER_IDX_R11D,
     FLAG_REGISTER_IDX_R12D,
     FLAG_REGISTER_IDX_R13D,
     FLAG_REGISTER_IDX_R14D,
     FLAG_REGISTER_IDX_R15D,
    //qword
     FLAG_REGISTER_IDX_RAX,
     FLAG_REGISTER_IDX_RCX,
     FLAG_REGISTER_IDX_RDX,
     FLAG_REGISTER_IDX_RBX,
     FLAG_REGISTER_IDX_RSP,
     FLAG_REGISTER_IDX_RBP,
     FLAG_REGISTER_IDX_RSI,
     FLAG_REGISTER_IDX_RDI,
     FLAG_REGISTER_IDX_R8,
     FLAG_REGISTER_IDX_R9,
     FLAG_REGISTER_IDX_R10,
     FLAG_REGISTER_IDX_R11,
     FLAG_REGISTER_IDX_R12,
     FLAG_REGISTER_IDX_R13,
     FLAG_REGISTER_IDX_R14,
     FLAG_REGISTER_IDX_R15,
};


//byte
#define FLAG_REGISTER_AL ((uint64_t)1 << FLAG_REGISTER_IDX_AL)
#define FLAG_REGISTER_CL ((uint64_t)1 << FLAG_REGISTER_IDX_CL)
#define FLAG_REGISTER_DL ((uint64_t)1 << FLAG_REGISTER_IDX_DL)
#define FLAG_REGISTER_BL ((uint64_t)1 << FLAG_REGISTER_IDX_BL)
#define FLAG_REGISTER_SPL ((uint64_t)1 << FLAG_REGISTER_IDX_SPL)
#define FLAG_REGISTER_BPL ((uint64_t)1 << FLAG_REGISTER_IDX_BPL)
#define FLAG_REGISTER_SIL ((uint64_t)1 << FLAG_REGISTER_IDX_SIL)
#define FLAG_REGISTER_DIL ((uint64_t)1 << FLAG_REGISTER_IDX_DIL)
#define FLAG_REGISTER_R8B  ((uint64_t)1 << FLAG_REGISTER_IDX_R8B)
#define FLAG_REGISTER_R9B  ((uint64_t)1 << FLAG_REGISTER_IDX_R9B)
#define FLAG_REGISTER_R10B ((uint64_t)1 << FLAG_REGISTER_IDX_R10B)
#define FLAG_REGISTER_R11B ((uint64_t)1 << FLAG_REGISTER_IDX_R11B)
#define FLAG_REGISTER_R12B ((uint64_t)1 << FLAG_REGISTER_IDX_R12B)
#define FLAG_REGISTER_R13B ((uint64_t)1 << FLAG_REGISTER_IDX_R13B)
#define FLAG_REGISTER_R14B ((uint64_t)1 << FLAG_REGISTER_IDX_R14B)
#define FLAG_REGISTER_R15B ((uint64_t)1 << FLAG_REGISTER_IDX_R15B)
//word
#define FLAG_REGISTER_AX ((uint64_t)1 << FLAG_REGISTER_IDX_AX)
#define FLAG_REGISTER_CX ((uint64_t)1 << FLAG_REGISTER_IDX_CX)
#define FLAG_REGISTER_DX ((uint64_t)1 << FLAG_REGISTER_IDX_DX)
#define FLAG_REGISTER_BX ((uint64_t)1 << FLAG_REGISTER_IDX_BX)
#define FLAG_REGISTER_SP ((uint64_t)1 << FLAG_REGISTER_IDX_SP)
#define FLAG_REGISTER_BP ((uint64_t)1 << FLAG_REGISTER_IDX_BP)
#define FLAG_REGISTER_SI ((uint64_t)1 << FLAG_REGISTER_IDX_SI)
#define FLAG_REGISTER_DI ((uint64_t)1 << FLAG_REGISTER_IDX_DI)
#define FLAG_REGISTER_R8W  ((uint64_t)1 << FLAG_REGISTER_IDX_R8W)
#define FLAG_REGISTER_R9W  ((uint64_t)1 << FLAG_REGISTER_IDX_R9W)
#define FLAG_REGISTER_R10W ((uint64_t)1 << FLAG_REGISTER_IDX_R10W)
#define FLAG_REGISTER_R11W ((uint64_t)1 << FLAG_REGISTER_IDX_R11W)
#define FLAG_REGISTER_R12W ((uint64_t)1 << FLAG_REGISTER_IDX_R12W)
#define FLAG_REGISTER_R13W ((uint64_t)1 << FLAG_REGISTER_IDX_R13W)
#define FLAG_REGISTER_R14W ((uint64_t)1 << FLAG_REGISTER_IDX_R14W)
#define FLAG_REGISTER_R15W ((uint64_t)1 << FLAG_REGISTER_IDX_R15W)
//dword
#define FLAG_REGISTER_EAX ((uint64_t)1 << FLAG_REGISTER_IDX_EAX)
#define FLAG_REGISTER_ECX ((uint64_t)1 << FLAG_REGISTER_IDX_ECX)
#define FLAG_REGISTER_EDX ((uint64_t)1 << FLAG_REGISTER_IDX_EDX)
#define FLAG_REGISTER_EBX ((uint64_t)1 << FLAG_REGISTER_IDX_EBX)
#define FLAG_REGISTER_ESP ((uint64_t)1 << FLAG_REGISTER_IDX_ESP)
#define FLAG_REGISTER_EBP ((uint64_t)1 << FLAG_REGISTER_IDX_EBP)
#define FLAG_REGISTER_ESI ((uint64_t)1 << FLAG_REGISTER_IDX_ESI)
#define FLAG_REGISTER_EDI ((uint64_t)1 << FLAG_REGISTER_IDX_EDI)
#define FLAG_REGISTER_R8D  ((uint64_t)1 << FLAG_REGISTER_IDX_R8D)
#define FLAG_REGISTER_R9D  ((uint64_t)1 << FLAG_REGISTER_IDX_R9D)
#define FLAG_REGISTER_R10D ((uint64_t)1 << FLAG_REGISTER_IDX_R10D)
#define FLAG_REGISTER_R11D ((uint64_t)1 << FLAG_REGISTER_IDX_R11D)
#define FLAG_REGISTER_R12D ((uint64_t)1 << FLAG_REGISTER_IDX_R12D)
#define FLAG_REGISTER_R13D ((uint64_t)1 << FLAG_REGISTER_IDX_R13D)
#define FLAG_REGISTER_R14D ((uint64_t)1 << FLAG_REGISTER_IDX_R14D)
#define FLAG_REGISTER_R15D ((uint64_t)1 << FLAG_REGISTER_IDX_R15D)
//qword
#define FLAG_REGISTER_RAX ((uint64_t)1 << FLAG_REGISTER_IDX_RAX)
#define FLAG_REGISTER_RCX ((uint64_t)1 << FLAG_REGISTER_IDX_RCX)
#define FLAG_REGISTER_RDX ((uint64_t)1 << FLAG_REGISTER_IDX_RDX)
#define FLAG_REGISTER_RBX ((uint64_t)1 << FLAG_REGISTER_IDX_RBX)
#define FLAG_REGISTER_RSP ((uint64_t)1 << FLAG_REGISTER_IDX_RSP)
#define FLAG_REGISTER_RBP ((uint64_t)1 << FLAG_REGISTER_IDX_RBP)
#define FLAG_REGISTER_RSI ((uint64_t)1 << FLAG_REGISTER_IDX_RSI)
#define FLAG_REGISTER_RDI ((uint64_t)1 << FLAG_REGISTER_IDX_RDI)
#define FLAG_REGISTER_R8  ((uint64_t)1 << FLAG_REGISTER_IDX_R8)
#define FLAG_REGISTER_R9  ((uint64_t)1 << FLAG_REGISTER_IDX_R9)
#define FLAG_REGISTER_R10 ((uint64_t)1 << FLAG_REGISTER_IDX_R10)
#define FLAG_REGISTER_R11 ((uint64_t)1 << FLAG_REGISTER_IDX_R11)
#define FLAG_REGISTER_R12 ((uint64_t)1 << FLAG_REGISTER_IDX_R12)
#define FLAG_REGISTER_R13 ((uint64_t)1 << FLAG_REGISTER_IDX_R13)
#define FLAG_REGISTER_R14 ((uint64_t)1 << FLAG_REGISTER_IDX_R14)
#define FLAG_REGISTER_R15 ((uint64_t)1 << FLAG_REGISTER_IDX_R15)

#define REGISTER_ACCESS_READ  (1 << 0)
#define REGISTER_ACCESS_WRITE (1 << 1)


bool has_free_flag_register(uint64_t regs_flags, uint64_t reg);
bool has_inst_free_register(const fuku_instruction& inst, x86_reg reg);
bool has_inst_free_eflags(uint64_t inst_eflags, uint64_t flags); //uint64_t flags used only with MODIFY prefix

uint8_t get_random_bit_by_mask(uint64_t mask, uint8_t min_index, uint8_t max_index);

fuku_register_enum flag_reg_to_fuku_reg(uint64_t reg);
uint64_t fuku_reg_to_flag_reg(fuku_register_enum reg);

uint8_t get_flag_reg_size(uint64_t reg);
uint8_t get_flag_reg_index(uint64_t reg);
uint8_t is_flag_reg_ext64(uint64_t reg);

fuku_register_enum set_fuku_reg_grade(fuku_register_enum reg, uint8_t needed_size);


uint64_t fuku_reg_to_complex_flag_reg(const fuku_register& reg, uint8_t size = 0);
uint64_t flag_reg_to_complex_flag_reg(uint64_t flag_reg);
uint64_t flag_reg_to_complex_flag_reg_by_size(uint64_t flag_reg);

fuku_register_enum get_random_reg(uint32_t reg_size, bool x86_only, uint64_t exclude_regs = 0);
fuku_register_enum get_random_free_flag_reg(uint64_t reg_flags, uint32_t reg_size, bool x86_only, uint64_t exclude_regs = FUKU_REG_NONE);
fuku_register_enum get_random_free_flag_reg(const fuku_instruction& inst, uint32_t reg_size, bool x86_only, uint64_t exclude_regs = FUKU_REG_NONE);
fuku_register_enum get_random_x64_free_flag_reg(uint64_t reg_flags, uint8_t reg_size, uint64_t exclude_regs = FUKU_REG_NONE);


uint64_t get_operand_mask_register(const fuku_type& op);
uint64_t get_operand_mask_register(const fuku_type& op1, const fuku_type& op2);



#define INST_ALLOW_REGISTER   1
#define INST_ALLOW_OPERAND    2
#define INST_ALLOW_IMMEDIATE  4

fuku_immediate generate_86_immediate(uint8_t size);
bool generate_86_operand_src(mutation_context & ctx, fuku_type& op, uint8_t allow_inst, uint8_t size, uint64_t disallow_regs);
bool generate_86_operand_dst(mutation_context & ctx, fuku_type& op, uint8_t allow_inst, uint8_t size, uint64_t allow_regs, uint64_t disallow_regs);

fuku_immediate generate_64_immediate(uint8_t size);
bool generate_64_operand_src(mutation_context & ctx, fuku_type& op, uint8_t allow_inst, uint8_t size, uint64_t disallow_regs);
bool generate_64_operand_dst(mutation_context & ctx, fuku_type& op, uint8_t allow_inst, uint8_t size, uint64_t allow_regs, uint64_t disallow_regs);