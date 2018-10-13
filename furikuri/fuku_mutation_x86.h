#pragma once


class fuku_mutation_x86 : 
    public fuku_mutation {

    fuku_asm_x86 f_asm;
    fuku_ob_settings settings;


    void fuku_mutation_x86::generate_junk(fuku_code_holder& code_holder,
        linestorage::iterator lines_iter, uint32_t max_size, size_t junk_size);


    void fuku_mutation_x86::fuku_junk(fuku_code_holder& code_holder, linestorage::iterator& lines_iter);

    void fuku_mutation_x86::fukutation(fuku_code_holder& code_holder, linestorage::iterator lines_iter);
    void fuku_mutation_x86::obfuscate_lines(fuku_code_holder& code_holder, linestorage::iterator lines_iter_begin, linestorage::iterator lines_iter_end, unsigned int recurse_idx);

public:
    fuku_mutation_x86::fuku_mutation_x86(const fuku_ob_settings& settings);
    fuku_mutation_x86::~fuku_mutation_x86();

    void fuku_mutation_x86::obfuscate(fuku_code_holder& code_holder);

    void fuku_mutation_x86::get_junk(std::vector<uint8_t>& junk, size_t junk_size, bool unstable_stack, uint16_t allow_flags_changes);
};



