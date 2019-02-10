#pragma once


//junk generation
void fuku_junk_generic(fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator lines_iter, 
    bool unstable_stack, uint64_t eflags_changes, uint64_t regs_changes);

void fuku_junk_1b(fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator lines_iter, 
    bool unstable_stack, uint64_t eflags_changes, uint64_t regs_changes);
void fuku_junk_2b(fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator lines_iter, 
    bool unstable_stack, uint64_t eflags_changes, uint64_t regs_changes);
void fuku_junk_3b(fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator lines_iter,
    bool unstable_stack, uint64_t eflags_changes, uint64_t regs_changes);
void fuku_junk_4b(fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator lines_iter, 
    bool unstable_stack, uint64_t eflags_changes, uint64_t regs_changes);
void fuku_junk_5b(fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator lines_iter,
    bool unstable_stack, uint64_t eflags_changes, uint64_t regs_changes);
void fuku_junk_6b(fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator lines_iter, 
    bool unstable_stack, uint64_t eflags_changes, uint64_t regs_changes);
void fuku_junk_7b(fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator lines_iter, 
    bool unstable_stack, uint64_t eflags_changes, uint64_t regs_changes);