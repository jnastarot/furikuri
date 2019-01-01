#pragma once

/* 
    rewrited from 
        https://github.com/v8/v8
*/

enum fuku_register {
    FUKU_REG_NONE,

 /*|_____64bit____|*/
 /*     |___LOW32bit___|*/
 /*          |___LOW16bit___|*/
 /*    |___HIGH8bit___||___LOW8bit___|*/

 //x86-x32 registers
    FUKU_REG_RAX,
        FUKU_REG_EAX,
                FUKU_REG_AX,
            FUKU_REG_AH, FUKU_REG_AL,
  
    FUKU_REG_RCX,
          FUKU_REG_ECX,
                FUKU_REG_CX,
            FUKU_REG_CH, FUKU_REG_CL,

    FUKU_REG_RDX,
          FUKU_REG_EDX,
                FUKU_REG_DX,
            FUKU_REG_DH, FUKU_REG_DL,

    FUKU_REG_RBX,
         FUKU_REG_EBX, 
                FUKU_REG_BX,
            FUKU_REG_BH, FUKU_REG_BL,

    FUKU_REG_RSP,
           FUKU_REG_ESP,
                FUKU_REG_SP,
                         FUKU_REG_SPL,

    FUKU_REG_RBP,
          FUKU_REG_EBP,
                FUKU_REG_BP, 
                         FUKU_REG_BPL,

    FUKU_REG_RSI,
          FUKU_REG_ESI,
                FUKU_REG_SI,
                         FUKU_REG_SIL,

    FUKU_REG_RDI,
          FUKU_REG_EDI,
                FUKU_REG_DI, 
                         FUKU_REG_DIL,



 //x86-x64 registers
    FUKU_REG_R8,
           FUKU_REG_R8D,
                 FUKU_REG_R8W,
                          FUKU_REG_R8B,
    FUKU_REG_R9,
           FUKU_REG_R9D,
                 FUKU_REG_R9W,
                          FUKU_REG_R9B,

    FUKU_REG_R10,
           FUKU_REG_R10D,
                 FUKU_REG_R10W,
                          FUKU_REG_R10B,

    FUKU_REG_R11,
           FUKU_REG_R11D,
                 FUKU_REG_R11W,
                          FUKU_REG_R11B,

    FUKU_REG_R12,
           FUKU_REG_R12D,
                 FUKU_REG_R12W,
                          FUKU_REG_R12B,

    FUKU_REG_R13,
           FUKU_REG_R13D,
                 FUKU_REG_R13W,
                          FUKU_REG_R13B,

    FUKU_REG_R14,
           FUKU_REG_R14D,
                 FUKU_REG_R14W,
                          FUKU_REG_R14B,

    FUKU_REG_R15,
           FUKU_REG_R15D,
                 FUKU_REG_R15W,
                          FUKU_REG_R15B,

    FUKU_REG_MAX,
};

enum fuku_register_index {
    FUKU_REG_INDEX_AX = 0, FUKU_REG_INDEX_R8 = 0,
    FUKU_REG_INDEX_CX = 1, FUKU_REG_INDEX_R9 = 1,
    FUKU_REG_INDEX_DX = 2, FUKU_REG_INDEX_R10 = 2,
    FUKU_REG_INDEX_BX = 3, FUKU_REG_INDEX_R11 = 3,
    FUKU_REG_INDEX_SP = 4, FUKU_REG_INDEX_R12 = 4,
    FUKU_REG_INDEX_BP = 5, FUKU_REG_INDEX_R13 = 5,
    FUKU_REG_INDEX_SI = 6, FUKU_REG_INDEX_R14 = 6,
    FUKU_REG_INDEX_DI = 7, FUKU_REG_INDEX_R15 = 7,

    FUKU_REG_INDEX_INVALID = -1
};

enum fuku_condition {
    FUKU_NO_CONDITION = -1,                jmp = -1,

    FUKU_CONDITION_OVERFLOW        = 0,    jo   = 0,             //(OF == 1)
    FUKU_CONDITION_NO_OVERFLOW     = 1,    jno  = 1,             //(OF != 1)
    FUKU_CONDITION_BELOW           = 2,    jb   = 2,             //(CF == 1)
    FUKU_CONDITION_ABOVE_EQUAL     = 3,    jae  = 3,    jnc = 3, //(CF != 1)
    FUKU_CONDITION_EQUAL           = 4,    je   = 4,    jz  = 4, //(ZF == 1)
    FUKU_CONDITION_NOT_EQUAL       = 5,    jne  = 5,    jnz = 5, //(ZF != 1)
    FUKU_CONDITION_BELOW_EQUAL     = 6,    jbe  = 6,    jna = 6, //(CF == 1 || ZF == 1)
    FUKU_CONDITION_ABOVE           = 7,    jnbe = 7,    ja  = 7, //(CF != 1 && ZF != 1)
    FUKU_CONDITION_NEGATIVE        = 8,    js   = 8,             //(SF == 1)
    FUKU_CONDITION_POSITIVE        = 9,    jns  = 9,             //(SF != 1)
    FUKU_CONDITION_PARITY_EVEN     = 10,   jp   = 10,            //(PF == 1)
    FUKU_CONDITION_PARITY_ODD      = 11,   jnp  = 11,   jpo = 11,//(PF != 1)
    FUKU_CONDITION_LESS            = 12,   jnge = 12,   jl  = 12,//(SF != OF)
    FUKU_CONDITION_GREATER_EQUAL   = 13,   jge  = 13,   jnl = 13,//(SF == OF)
    FUKU_CONDITION_LESS_EQUAL      = 14,   jng  = 14,   jle = 14,//(ZF == 1 || (SF != OF) )
    FUKU_CONDITION_GREATER         = 15,   jnle = 15,   jg  = 15,//(ZF != 1 && (SF == OF) )

    FUKU_CONDITION_MAX
};

enum fuku_operand_scale {
    FUKU_OPERAND_SCALE_1 = 0,  //[index * 1]
    FUKU_OPERAND_SCALE_2 = 1,  //[index * 2]
    FUKU_OPERAND_SCALE_4 = 2,  //[index * 4]
    FUKU_OPERAND_SCALE_8 = 3,  //[index * 8]
};

enum fukU_prefix {
    FUKU_PREFIX_LOCK             = 0xF0,
    FUKU_PREFIX_REPE             = 0xF3,
    FUKU_PREFIX_REPNE            = 0xF2,
    FUKU_PREFIX_CS               = 0x2E,
    FUKU_PREFIX_SS               = 0x36,
    FUKU_PREFIX_DS               = 0x3E,
    FUKU_PREFIX_ES               = 0x26,
    FUKU_PREFIX_FS               = 0x64,
    FUKU_PREFIX_GS               = 0x65,
    FUKU_PREFIX_OVERRIDE_DATA    = 0x66,
    FUKU_PREFIX_OVERRIDE_ADDRESS = 0x67,
};

enum fuku_operand_size {
    FUKU_OPERAND_SIZE_0  = 0, //none
    FUKU_OPERAND_SIZE_8  = 1,
    FUKU_OPERAND_SIZE_16 = 2,
    FUKU_OPERAND_SIZE_32 = 4,
    FUKU_OPERAND_SIZE_64 = 8,
};


/*
    EAX = 0 ECX = 1 r_EDX = 2 
    R8 = 0 R9 = 1 R10 = 2 
    and them lowest parts etc
*/
fuku_register_index fuku_get_index_reg(fuku_register reg);
fuku_register fuku_get_reg_by_index(uint8_t idx,bool x64ext, fuku_operand_size size);

//  returns true for R8 - R15
bool is_fuku_x64arch_reg(fuku_register reg);
//  returns true for EAX - EDI
bool is_fuku_x32arch_reg(fuku_register reg);

//  returns true for RAX - RDI and R8 - R15 
bool is_fuku_64bit_reg(fuku_register reg);
//  returns true for EAX - EDI
bool is_fuku_32bit_reg(fuku_register reg);
//  returns true for AX - DI
bool is_fuku_16bit_reg(fuku_register reg);
//  returns true for AH,AL - Dl and R8B - R15B 
bool is_fuku_8bit_reg(fuku_register reg);


fuku_operand_size get_register_size(fuku_register reg);


uint8_t fuku_to_capstone_reg(fuku_register reg);
uint8_t capstone_to_fuku_reg(fuku_register reg);

x86_insn fuku_to_capstone_jcc(fuku_condition cond);
fuku_condition capstone_to_fuku_jcc(x86_insn cond);



class fuku_immediate {
    bool relocate;

    uint64_t immediate_value;
public:
    fuku_immediate();
    fuku_immediate(uint64_t immediate);
    fuku_immediate(uint64_t immediate, bool is_rel);
    ~fuku_immediate();

    fuku_immediate& operator=(const fuku_immediate& imm);
public:
    fuku_immediate& set_relocate(bool is_rel);
    fuku_immediate& set_immediate(uint64_t immediate);
public:
    bool is_8() const;
    bool is_16() const;
    bool is_32() const;
    bool is_64() const;

    bool is_relocate() const;

    uint8_t get_immediate8() const;
    uint16_t get_immediate16() const;
    uint32_t get_immediate32() const;
    uint64_t get_immediate64() const;

    int8_t get_signed_value8() const;
    int16_t get_signed_value16() const;
    int32_t get_signed_value32() const;
    int64_t get_signed_value64() const;
};

enum fuku_mem_opernad_type {
    FUKU_MEM_OPERAND_BASE_ONLY,
    FUKU_MEM_OPERAND_DISP_ONLY,
    FUKU_MEM_OPERAND_BASE_DISP,
    FUKU_MEM_OPERAND_INDEX_DISP,
    FUKU_MEM_OPERAND_BASE_INDEX,
    FUKU_MEM_OPERAND_BASE_INDEX_DISP,
};

class fuku_operand {
    fuku_register base;
    fuku_register index;
    fuku_operand_scale scale;
    fuku_immediate disp;
public:
    fuku_operand(const fuku_immediate& disp);                  // [disp/r]
    fuku_operand(fuku_register base, const fuku_immediate& disp);  // [base + disp/r]
    fuku_operand(fuku_register base, fuku_register index, fuku_operand_scale scale, const fuku_immediate& disp);// [base + index*scale + disp/r]
    fuku_operand(fuku_register index, fuku_operand_scale scale, const fuku_immediate& disp);// [index*scale + disp/r]
    ~fuku_operand();

public:
    void set_base(fuku_register base);
    void set_index(fuku_register index);
    void set_scale(fuku_operand_scale scale);
    void set_disp(const fuku_immediate& disp);

public:
    fuku_register get_base() const;
    fuku_register get_index() const;
    fuku_operand_scale get_scale() const;
    const fuku_immediate& get_disp() const;

    fuku_mem_opernad_type get_type() const;
};

enum fuku_asm_short_cfg {
    FUKU_ASM_SHORT_CFG_USE_EAX_SHORT  = 1,
    FUKU_ASM_SHORT_CFG_USE_DISP_SHORT = 2,
    FUKU_ASM_SHORT_CFG_USE_IMM_SHORT  = 4,

};

#include "fuku_asm_x86.h"
#include "fuku_asm_x64.h"
