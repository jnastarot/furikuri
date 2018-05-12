#pragma once


enum fuku_reg86 {
    r_EAX,
    r_ECX,
    r_EDX,
    r_EBX,
    r_ESP,
    r_EBP,
    r_ESI,
    r_EDI
};

enum fuku_reg64 {
    r_RAX,
    r_RCX,
    r_RDX,
    r_RBX,
    r_RSP,
    r_RBP,
    r_RSI,
    r_RDI,
    r_R8,
    r_R9,
    r_R10,
    r_R11,
    r_R12,
    r_R13,
    r_R14,
    r_R15
};


void fuku_asm_x86_mov_rr(fuku_instruction& line, fuku_reg86 reg1, fuku_reg86 reg2);
void fuku_asm_x86_mov_rm(fuku_instruction& line, fuku_reg86 reg1, uint32_t arg1);

void fuku_asm_x86_mov_pr_m(fuku_instruction& line, fuku_reg86 reg1, uint32_t arg1, uint8_t * imm_offset);
void fuku_asm_x86_mov_pr_m_b(fuku_instruction& line, fuku_reg86 reg1, uint8_t offset, uint32_t arg1, uint8_t * imm_offset);
void fuku_asm_x86_mov_pr_m_dw(fuku_instruction& line, fuku_reg86 reg1, uint32_t offset, uint32_t arg1, uint8_t * imm_offset);

void fuku_asm_x86_mov_r_pr(fuku_instruction& line, fuku_reg86 reg1, fuku_reg86 reg2);
void fuku_asm_x86_mov_r_pr_b(fuku_instruction& line, fuku_reg86 reg1, fuku_reg86 reg2, uint8_t offset);
void fuku_asm_x86_mov_r_pr_dw(fuku_instruction& line, fuku_reg86 reg1, fuku_reg86 reg2, uint32_t offset);

void fuku_asm_x86_mov_pr_r(fuku_instruction& line, fuku_reg86 reg1, fuku_reg86 reg2);
void fuku_asm_x86_mov_pr_r_b(fuku_instruction& line, fuku_reg86 reg1, fuku_reg86 reg2, uint8_t offset);
void fuku_asm_x86_mov_pr_r_dw(fuku_instruction& line, fuku_reg86 reg1, fuku_reg86 reg2, uint32_t offset);





void fuku_asm_x86_jmp(fuku_instruction& line, uint32_t offset); //jmp offset