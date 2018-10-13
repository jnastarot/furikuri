#pragma once

//graph     JCC/JMP/RET
bool fukutate_jcc(fuku_asm_x86& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter);
bool fukutate_jmp(fuku_asm_x86& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter);
bool fukutate_ret(fuku_asm_x86& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter);

//arith     ADD/SUB/INC/DEC/CMP
bool fukutate_add(fuku_asm_x86& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter);
bool fukutate_sub(fuku_asm_x86& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter);
bool fukutate_inc(fuku_asm_x86& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter);
bool fukutate_dec(fuku_asm_x86& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter);
bool fukutate_cmp(fuku_asm_x86& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter);

//logical   AND/OR/XOR/TEST
bool fukutate_and(fuku_asm_x86& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter);
bool fukutate_or(fuku_asm_x86& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter);
bool fukutate_xor(fuku_asm_x86& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter);
bool fukutate_test(fuku_asm_x86& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter);

//stack     PUSH/POP
bool fukutate_push(fuku_asm_x86& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter);
bool fukutate_pop(fuku_asm_x86& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter);

//junk generation
void fuku_junk_1b(fuku_asm_x86& f_asm, fuku_code_holder& code_holder, linestorage::iterator lines_iter);
void fuku_junk_2b(fuku_asm_x86& f_asm, fuku_code_holder& code_holder, linestorage::iterator lines_iter);
void fuku_junk_3b(fuku_asm_x86& f_asm, fuku_code_holder& code_holder, linestorage::iterator lines_iter);
void fuku_junk_4b(fuku_asm_x86& f_asm, fuku_code_holder& code_holder, linestorage::iterator lines_iter);
void fuku_junk_5b(fuku_asm_x86& f_asm, fuku_code_holder& code_holder, linestorage::iterator lines_iter);
void fuku_junk_6b(fuku_asm_x86& f_asm, fuku_code_holder& code_holder, linestorage::iterator lines_iter);
void fuku_junk_7b(fuku_asm_x86& f_asm, fuku_code_holder& code_holder, linestorage::iterator lines_iter);
