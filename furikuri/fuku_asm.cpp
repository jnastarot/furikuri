#include "stdafx.h"
#include "fuku_asm.h"


int fuku_pattern_x86_rr(uint8_t * dst, uint8_t opcode, fuku_reg86 reg1, fuku_reg86 reg2) {
    if (FUKU_GET_CHANCE(50.f)) {
        dst[0] = (opcode | 2);
        dst[1] = 0xC0 + (8 * reg1) + reg2;
    }
    else {
        dst[0] = opcode;
        dst[1] = 0xC0 + (8 * reg2) + reg1;
    }
    return 2;
}

int fuku_pattern_x86_rm(uint8_t * dst, uint8_t opcode, uint8_t opcode2, fuku_reg86 reg1,uint32_t arg1, uint8_t * imm_offset) {
    
    dst[0] = opcode;
    dst[1] = opcode2 + reg1;
    *(uint32_t*)&dst[2] = arg1;

    if (imm_offset) { *imm_offset = 2; }

    return 6;
}

int fuku_pattern_x86_r_pr(uint8_t * dst, uint8_t opcode,
    uint8_t opcode2, fuku_reg86 reg1, fuku_reg86 reg2) {

    dst[0] = opcode;
    if (reg2 == fuku_reg86::r_ESP) {
        dst[1] = opcode2 + 4 + reg1 * 8;
        dst[2] = 0x24;
        return 3;
    }
    else {
        dst[1] = opcode2 + reg1 * 8 + reg2;
        return 2;
    }
}

int fuku_pattern_x86_r_pr_b(uint8_t * dst, uint8_t opcode,
    uint8_t opcode2, fuku_reg86 reg1, fuku_reg86 reg2, uint8_t offset) {

    dst[0] = opcode;
    if (reg2 == fuku_reg86::r_ESP) {
        dst[1] = opcode2 + 0x40 + 4 + reg1 * 8;
        dst[2] = 0x24;
        dst[3] = offset;
        return 4;
    }
    else {
        dst[1] = opcode2 + 0x40 + reg1 * 8 + reg2;
        dst[2] = offset;
        return 3;
    }
}

int fuku_pattern_x86_r_pr_dw(uint8_t * dst, uint8_t opcode,
    uint8_t opcode2, fuku_reg86 reg1, fuku_reg86 reg2, uint32_t offset) {

    dst[0] = opcode;
    if (reg2 == fuku_reg86::r_ESP) {
        dst[1] = opcode2 + 0x80 + 4 + reg1 * 8;
        dst[2] = 0x24;
        *(uint32_t*)&dst[3] = offset;
        return 7;
    }
    else {
        dst[1] = opcode2 + 0x80 + reg1 * 8 + reg2;
        *(uint32_t*)&dst[2] = offset;
        return 6;
    }
}

int fuku_pattern_x86_pr_m(uint8_t * dst, uint8_t opcode, uint8_t opcode2, fuku_reg86 reg1, uint32_t arg1, uint8_t * imm_offset) {

    dst[0] = opcode;
    if (reg1 == fuku_reg86::r_ESP) {
        dst[1] = opcode2 + 4;
        dst[2] = 0x24;
        *(uint32_t*)&dst[3] = arg1;

        if (imm_offset) { *imm_offset = 3; }
        return 7;
    }
    else {
        dst[1] = opcode2 + reg1;
        *(uint32_t*)&dst[2] = arg1;

        if (imm_offset) { *imm_offset = 2; }
        return 6;
    }
}

int fuku_pattern_x86_pr_m_b(uint8_t * dst, uint8_t opcode, uint8_t opcode2, fuku_reg86 reg1, uint8_t offset, uint32_t arg1, uint8_t * imm_offset) {

    dst[0] = opcode;
    if (reg1 == fuku_reg86::r_ESP) {
        dst[1] = opcode2 + 0x40 + 4;
        dst[2] = 0x24;      
        dst[3] = offset;
        *(uint32_t*)&dst[4] = arg1;

        if (imm_offset) { *imm_offset = 4; }
        return 8;       
    }
    else {
        dst[1] = opcode2 + 0x40 + reg1;
        *(uint8_t*)&dst[2] = offset;
        *(uint32_t*)&dst[3] = arg1;

        if (imm_offset) { *imm_offset = 3; }
        return 7;
    }
}

int fuku_pattern_x86_pr_m_dw(uint8_t * dst, uint8_t opcode, uint8_t opcode2, fuku_reg86 reg1, uint32_t offset, uint32_t arg1, uint8_t * imm_offset) {

    dst[0] = opcode;
    if (reg1 == fuku_reg86::r_ESP) {
        dst[1] = opcode2 + 0x80 + 4;
        dst[2] = 0x24;
        *(uint32_t*)&dst[3] = offset;
        *(uint32_t*)&dst[7] = arg1;

        if (imm_offset) { *imm_offset = 7; }
        return 11;

    }
    else {
        dst[1] = opcode2 + 0x80 + reg1;
        *(uint32_t*)&dst[2] = offset;
        *(uint32_t*)&dst[6] = arg1;

        if (imm_offset) { *imm_offset = 6; }
        return 10;
    }
}


#define FUKU_MACRO_CREATE_RR(name,opcode,type,test,mod) \
void name(fuku_instruction& line, fuku_reg86 reg1, fuku_reg86 reg2) { \
   uint8_t bytecode[16] = { 0 }; \
   int op_len = fuku_pattern_x86_rr(bytecode, opcode, reg1, reg2); \
   line = fuku_instruction().set_op_code(bytecode, op_len).set_type(type).set_tested_flags(test).set_modified_flags(mod); \
}
#define FUKU_MACRO_CREATE_RM(name,opcode,opcode2,type,test,mod) \
void name(fuku_instruction& line, fuku_reg86 reg1, uint32_t arg1, uint8_t * imm_offset) { \
   uint8_t bytecode[16] = { 0 }; \
   int op_len = fuku_pattern_x86_rm(bytecode, opcode,opcode2, reg1, arg1, imm_offset); \
   line = fuku_instruction().set_op_code(bytecode, op_len).set_type(type).set_tested_flags(test).set_modified_flags(mod); \
}
#define FUKU_MACRO_CREATE_PR_M(name,opcode,opcode2,type,test,mod) \
void name(fuku_instruction& line, fuku_reg86 reg1, uint32_t arg1, uint8_t * imm_offset) { \
   uint8_t bytecode[16] = { 0 }; \
   int op_len = fuku_pattern_x86_pr_m(bytecode, opcode,opcode2, reg1, arg1, imm_offset); \
   line = fuku_instruction().set_op_code(bytecode, op_len).set_type(type).set_tested_flags(test).set_modified_flags(mod); \
}
#define FUKU_MACRO_CREATE_PR_M_b(name,opcode,opcode2,type,test,mod) \
void name(fuku_instruction& line, fuku_reg86 reg1, uint8_t offset, uint32_t arg1, uint8_t * imm_offset) { \
   uint8_t bytecode[16] = { 0 }; \
   int op_len = fuku_pattern_x86_pr_m_b(bytecode, opcode, opcode2, reg1, offset, arg1, imm_offset); \
   line = fuku_instruction().set_op_code(bytecode, op_len).set_type(type).set_tested_flags(test).set_modified_flags(mod); \
}
#define FUKU_MACRO_CREATE_PR_M_dw(name,opcode,opcode2,type,test,mod) \
void name(fuku_instruction& line, fuku_reg86 reg1, uint32_t offset, uint32_t arg1, uint8_t * imm_offset) { \
   uint8_t bytecode[16] = { 0 }; \
   int op_len = fuku_pattern_x86_pr_m_dw(bytecode, opcode, opcode2, reg1, offset, arg1, imm_offset); \
   line = fuku_instruction().set_op_code(bytecode, op_len).set_type(type).set_tested_flags(test).set_modified_flags(mod); \
}
#define FUKU_MACRO_CREATE_R_PR(name,opcode,opcode2,type,test,mod) \
void name(fuku_instruction& line, fuku_reg86 reg1, fuku_reg86 reg2) { \
   uint8_t bytecode[16] = { 0 }; \
   int op_len = fuku_pattern_x86_r_pr(bytecode, opcode, opcode2, reg1, reg2); \
   line = fuku_instruction().set_op_code(bytecode, op_len).set_type(type).set_tested_flags(test).set_modified_flags(mod); \
}
#define FUKU_MACRO_CREATE_R_PR_b(name,opcode,opcode2,type,test,mod) \
void name(fuku_instruction& line, fuku_reg86 reg1, fuku_reg86 reg2, uint8_t offset) { \
   uint8_t bytecode[16] = { 0 }; \
   int op_len = fuku_pattern_x86_r_pr_b(bytecode, opcode, opcode2, reg1, reg2, offset); \
   line = fuku_instruction().set_op_code(bytecode, op_len).set_type(type).set_tested_flags(test).set_modified_flags(mod); \
}
#define FUKU_MACRO_CREATE_R_PR_dw(name,opcode,opcode2,type,test,mod) \
void name(fuku_instruction& line, fuku_reg86 reg1, fuku_reg86 reg2, uint32_t offset) { \
   uint8_t bytecode[16] = { 0 }; \
   int op_len = fuku_pattern_x86_r_pr_dw(bytecode, opcode, opcode2, reg1, reg2, offset); \
   line = fuku_instruction().set_op_code(bytecode, op_len).set_type(type).set_tested_flags(test).set_modified_flags(mod); \
}


FUKU_MACRO_CREATE_RR(fuku_asm_x86_mov_rr,  0x89, I_MOV, 0, 0);
FUKU_MACRO_CREATE_RR(fuku_asm_x86_add_rr,  0x01, I_ADD, 0, D_OF | D_SF | D_ZF | D_AF | D_PF | D_CF);
FUKU_MACRO_CREATE_RR(fuku_asm_x86_add_rr,  0x29, I_SUB, 0, D_OF | D_SF | D_ZF | D_AF | D_PF | D_CF);
FUKU_MACRO_CREATE_RR(fuku_asm_x86_xchg_rr, 0x87, I_XCHG, 0, 0);

void fuku_asm_x86_mov_rm(fuku_instruction& line, fuku_reg86 reg1, uint32_t arg1) {
    
    uint8_t bytecode[5] = { 0 };
    bytecode[0] = 0xB8 + reg1;
    *(uint32_t*)&bytecode[1] = arg1;

    line = fuku_instruction().set_op_code(bytecode, 5).set_type(I_MOV).set_tested_flags(0).set_modified_flags(0);
}

FUKU_MACRO_CREATE_PR_M(fuku_asm_x86_mov_pr_m,       0xC7, 0 ,I_MOV ,0 ,0);
FUKU_MACRO_CREATE_PR_M_b(fuku_asm_x86_mov_pr_m_b,   0xC7, 0, I_MOV, 0, 0);
FUKU_MACRO_CREATE_PR_M_dw(fuku_asm_x86_mov_pr_m_dw, 0xC7, 0, I_MOV, 0, 0);
FUKU_MACRO_CREATE_PR_M(fuku_asm_x86_add_pr_m,       0x81, 0, I_ADD, 0, D_OF | D_SF | D_ZF | D_AF | D_PF | D_CF);
FUKU_MACRO_CREATE_PR_M_b(fuku_asm_x86_add_pr_m_b,   0x81, 0, I_ADD, 0, D_OF | D_SF | D_ZF | D_AF | D_PF | D_CF);
FUKU_MACRO_CREATE_PR_M_dw(fuku_asm_x86_add_pr_m_dw, 0x81, 0, I_ADD, 0, D_OF | D_SF | D_ZF | D_AF | D_PF | D_CF);
FUKU_MACRO_CREATE_PR_M(fuku_asm_x86_sub_pr_m,       0x81, 0x28, I_SUB, 0, D_OF | D_SF | D_ZF | D_AF | D_PF | D_CF);
FUKU_MACRO_CREATE_PR_M_b(fuku_asm_x86_sub_pr_m_b,   0x81, 0x28, I_SUB, 0, D_OF | D_SF | D_ZF | D_AF | D_PF | D_CF);
FUKU_MACRO_CREATE_PR_M_dw(fuku_asm_x86_sub_pr_m_dw, 0x81, 0x28, I_SUB, 0, D_OF | D_SF | D_ZF | D_AF | D_PF | D_CF);

FUKU_MACRO_CREATE_R_PR(fuku_asm_x86_mov_r_pr,       0x8B, 0, I_MOV, 0, 0);
FUKU_MACRO_CREATE_R_PR_b(fuku_asm_x86_mov_r_pr_b,   0x8B, 0, I_MOV, 0, 0);
FUKU_MACRO_CREATE_R_PR_dw(fuku_asm_x86_mov_r_pr_dw, 0x8B, 0, I_MOV, 0, 0);
FUKU_MACRO_CREATE_R_PR(fuku_asm_x86_add_r_pr,       0x03, 0, I_ADD, 0, D_OF | D_SF | D_ZF | D_AF | D_PF | D_CF);
FUKU_MACRO_CREATE_R_PR_b(fuku_asm_x86_add_r_pr_b,   0x03, 0, I_ADD, 0, D_OF | D_SF | D_ZF | D_AF | D_PF | D_CF);
FUKU_MACRO_CREATE_R_PR_dw(fuku_asm_x86_add_r_pr_dw, 0x03, 0, I_ADD, 0, D_OF | D_SF | D_ZF | D_AF | D_PF | D_CF);
FUKU_MACRO_CREATE_R_PR(fuku_asm_x86_sub_r_pr,       0x2B, 0, I_SUB, 0, D_OF | D_SF | D_ZF | D_AF | D_PF | D_CF);
FUKU_MACRO_CREATE_R_PR_b(fuku_asm_x86_sub_r_pr_b,   0x2B, 0, I_SUB, 0, D_OF | D_SF | D_ZF | D_AF | D_PF | D_CF);
FUKU_MACRO_CREATE_R_PR_dw(fuku_asm_x86_sub_r_pr_dw, 0x2B, 0, I_SUB, 0, D_OF | D_SF | D_ZF | D_AF | D_PF | D_CF);

FUKU_MACRO_CREATE_R_PR(fuku_asm_x86_mov_pr_r,       0x8B | 2, 0, I_MOV, 0, 0);
FUKU_MACRO_CREATE_R_PR_b(fuku_asm_x86_mov_pr_r_b,   0x8B | 2, 0, I_MOV, 0, 0);
FUKU_MACRO_CREATE_R_PR_dw(fuku_asm_x86_mov_pr_r_dw, 0x8B | 2, 0, I_MOV, 0, 0);
FUKU_MACRO_CREATE_R_PR(fuku_asm_x86_add_pr_r,       0x03, 0, I_ADD, 0, D_OF | D_SF | D_ZF | D_AF | D_PF | D_CF);
FUKU_MACRO_CREATE_R_PR_b(fuku_asm_x86_add_pr_r_b,   0x03, 0, I_ADD, 0, D_OF | D_SF | D_ZF | D_AF | D_PF | D_CF);
FUKU_MACRO_CREATE_R_PR_dw(fuku_asm_x86_add_pr_r_dw, 0x03, 0, I_ADD, 0, D_OF | D_SF | D_ZF | D_AF | D_PF | D_CF);
FUKU_MACRO_CREATE_R_PR(fuku_asm_x86_sub_pr_r,       0x29, 0, I_SUB, 0, D_OF | D_SF | D_ZF | D_AF | D_PF | D_CF);
FUKU_MACRO_CREATE_R_PR_b(fuku_asm_x86_sub_pr_r_b,   0x29, 0, I_SUB, 0, D_OF | D_SF | D_ZF | D_AF | D_PF | D_CF);
FUKU_MACRO_CREATE_R_PR_dw(fuku_asm_x86_sub_pr_r_dw, 0x29, 0, I_SUB, 0, D_OF | D_SF | D_ZF | D_AF | D_PF | D_CF);

void fuku_asm_x86_jmp(fuku_instruction& line, uint32_t offset) {
    uint8_t opcode[5];
    opcode[0] = 0xE9;
    *(uint32_t*)&opcode[1] = offset;

    line = fuku_instruction().set_op_code(opcode, 5).set_type(I_JMP).set_tested_flags(0).set_modified_flags(0);
}