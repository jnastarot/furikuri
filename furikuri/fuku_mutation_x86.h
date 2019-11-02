#pragma once

class fuku_mutation_x86 : 
    public fuku_mutation {

    void* inst_changers;

    csh cap_handle;
    fuku_assambler f_asm;
    fuku_settings_obfuscation settings;

    bool fuku_junk(mutation_context& ctx);

    void fukutation(mutation_context& ctx, inststorage::iterator lines_iter);
    void obfuscate_lines(mutation_context& ctx, inststorage::iterator lines_iter_begin, inststorage::iterator lines_iter_end, unsigned int recurse_idx);

public:
    fuku_mutation_x86(const fuku_settings_obfuscation& settings);
    ~fuku_mutation_x86();

    void obfuscate(fuku_code_holder& code_holder);

    void get_junk(fuku_code_holder& code_holder, size_t junk_size, bool unstable_stack, 
        uint64_t eflags_changes, uint64_t regs_changes);
};