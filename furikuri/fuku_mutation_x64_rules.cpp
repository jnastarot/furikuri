#include "stdafx.h"
#include "fuku_mutation_x64_rules.h"

//graph
bool fukutate_jcc(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator lines_iter) {
    return false;
}
bool fukutate_jmp(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {
    return false;
}
bool fukutate_call(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {
    return false;
}
bool fukutate_ret(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {
    return false;
}

//stack
bool fukutate_push(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {
    return false;
}
bool fukutate_pop(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {
    return false;
}

//data transfer
bool fukutate_mov(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {
    return false;
}
bool fukutate_xchg(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {
    return false;
}
bool fukutate_lea(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {
    return false;
}

//aritch
bool fukutate_add(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {
    return false;
}
bool fukutate_or(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {
    return false;
}
bool fukutate_adc(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {
    return false;
}
bool fukutate_sbb(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {
    return false;
}
bool fukutate_and(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {
    return false;
}
bool fukutate_sub(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {
    return false;
}
bool fukutate_xor(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {
    return false;
}
bool fukutate_cmp(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {
    return false;
}
bool fukutate_inc(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {
    return false;
}
bool fukutate_dec(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {
    return false;
}
bool fukutate_test(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {
    return false;
}
bool fukutate_not(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {
    return false;
}
bool fukutate_neg(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {
    return false;
}
bool fukutate_mul(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {
    return false;
}
bool fukutate_imul(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {
    return false;
}
bool fukutate_div(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {
    return false;
}
bool fukutate_idiv(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {
    return false;
}

//shift
bool fukutate_rol(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {
    return false;
}
bool fukutate_ror(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {
    return false;
}
bool fukutate_rcl(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {
    return false;
}
bool fukutate_rcr(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {
    return false;
}
bool fukutate_shl(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {
    return false;
}
bool fukutate_shr(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {
    return false;
}
bool fukutate_sar(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {
    return false;
}

//bittest
bool fukutate_bt(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {
    return false;
}
bool fukutate_bts(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {
    return false;
}
bool fukutate_btr(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {
    return false;
}
bool fukutate_btc(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {
    return false;
}
bool fukutate_bsf(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {
    return false;
}
bool fukutate_bsr(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {
    return false;
}

