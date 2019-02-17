#pragma once

class fuku_mutation {
public:
    virtual fuku_mutation::~fuku_mutation() {};

    virtual void fuku_mutation::obfuscate(fuku_code_holder& code_holder) {};
    virtual void fuku_mutation::generate_junk(std::vector<uint8_t>& junk, size_t junk_size) {};
};


struct mutation_context {
    fuku_assambler *f_asm;
    fuku_code_holder* code_holder;

    cs_insn *instruction;
    linestorage::iterator first_junk_line_iter;
    linestorage::iterator first_line_iter;
    linestorage::iterator current_line_iter;
    linestorage::iterator next_line_iter;

    bool has_unstable_stack;
    bool is_first_line_begin;
    bool is_next_line_end;
    bool was_mutated;
    bool was_junked;

    size_t   label_idx;
    uint64_t source_virtual_address;

    uint32_t instruction_flags;
    uint64_t eflags_changes;
    uint64_t regs_changes;

    bool swap_junk_label;
    size_t junk_label_idx;
};


#include "fuku_mutation_x86.h"
#include "fuku_mutation_x64.h"

