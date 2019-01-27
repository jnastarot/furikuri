#pragma once


//graph     JCC/JMP/RET
bool fukutate_jcc(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter);
bool fukutate_jmp(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter);
bool fukutate_ret(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter);

//arith     ADD/SUB/INC/DEC/CMP
bool fukutate_add(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter);
bool fukutate_sub(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter);
bool fukutate_inc(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter);
bool fukutate_dec(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter);
bool fukutate_cmp(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter);

//logical   AND/OR/XOR/TEST
bool fukutate_and(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter);
bool fukutate_or(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter);
bool fukutate_xor(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter);
bool fukutate_test(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter);

//stack     PUSH/POP
bool fukutate_push(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter);
bool fukutate_pop(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter);

//junk generation
void fuku_junk_1b(fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator lines_iter);
void fuku_junk_2b(fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator lines_iter);
void fuku_junk_3b(fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator lines_iter);
void fuku_junk_4b(fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator lines_iter);
void fuku_junk_5b(fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator lines_iter);
void fuku_junk_6b(fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator lines_iter);
void fuku_junk_7b(fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator lines_iter);