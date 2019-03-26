#pragma once


class fuku_mutation_x86 : 
    public fuku_mutation {

    csh cap_handle;
    fuku_assambler f_asm;
    fuku_settings_obfuscation settings;

    void fuku_junk(mutation_context& ctx);

    void fukutation(fuku_code_holder& code_holder, linestorage::iterator lines_iter);
    void obfuscate_lines(fuku_code_holder& code_holder, linestorage::iterator lines_iter_begin, linestorage::iterator lines_iter_end, unsigned int recurse_idx);

public:
    fuku_mutation_x86(const fuku_settings_obfuscation& settings);
    ~fuku_mutation_x86();

    void obfuscate(fuku_code_holder& code_holder);

    void get_junk(fuku_code_holder& code_holder, size_t junk_size, bool unstable_stack, 
        uint64_t eflags_changes, uint64_t regs_changes);
};



