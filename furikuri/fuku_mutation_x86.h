#pragma once


class fuku_mutation_x86 : 
    public fuku_mutation {

    fuku_asm_x86 f_asm;
    fuku_ob_settings settings;

    void fuku_mutation_x86::fuku_junk_1b(linestorage& out_lines, fuku_instruction* next_line, bool unstable_stack, uint16_t allow_flags_changes);
    void fuku_mutation_x86::fuku_junk_2b(linestorage& out_lines, fuku_instruction* next_line, bool unstable_stack, uint16_t allow_flags_changes);
    void fuku_mutation_x86::fuku_junk_3b(linestorage& out_lines, fuku_instruction* next_line, bool unstable_stack, uint16_t allow_flags_changes);
    void fuku_mutation_x86::fuku_junk_4b(linestorage& out_lines, fuku_instruction* next_line, bool unstable_stack, uint16_t allow_flags_changes);
    void fuku_mutation_x86::fuku_junk_5b(linestorage& out_lines, fuku_instruction* next_line, bool unstable_stack, uint16_t allow_flags_changes);
    void fuku_mutation_x86::fuku_junk_6b(linestorage& out_lines, fuku_instruction* next_line, bool unstable_stack, uint16_t allow_flags_changes);
    void fuku_mutation_x86::fuku_junk_7b(linestorage& out_lines, fuku_instruction* next_line, bool unstable_stack, uint16_t allow_flags_changes);

    void fuku_mutation_x86::generate_junk(linestorage& junk,
        fuku_instruction* next_line, uint32_t max_size, size_t junk_size, bool unstable_stack, uint16_t allow_flags_changes);


    void fuku_mutation_x86::fuku_junk(linestorage& lines, unsigned int current_line_idx,linestorage& out_lines);

    bool fuku_mutation_x86::fukutate_push(linestorage& lines, unsigned int current_line_idx, linestorage& out_lines);
    bool fuku_mutation_x86::fukutate_pop(linestorage& lines, unsigned int current_line_idx, linestorage& out_lines);
    bool fuku_mutation_x86::fukutate_add(linestorage& lines, unsigned int current_line_idx, linestorage& out_lines);
    bool fuku_mutation_x86::fukutate_sub(linestorage& lines, unsigned int current_line_idx, linestorage& out_lines);
    bool fuku_mutation_x86::fukutate_and(linestorage& lines, unsigned int current_line_idx, linestorage& out_lines);
    bool fuku_mutation_x86::fukutate_inc(linestorage& lines, unsigned int current_line_idx, linestorage& out_lines);
    bool fuku_mutation_x86::fukutate_dec(linestorage& lines, unsigned int current_line_idx, linestorage& out_lines);
    bool fuku_mutation_x86::fukutate_test(linestorage& lines, unsigned int current_line_idx, linestorage& out_lines);
    bool fuku_mutation_x86::fukutate_cmp(linestorage& lines, unsigned int current_line_idx, linestorage& out_lines);
    bool fuku_mutation_x86::fukutate_jcc(linestorage& lines, unsigned int current_line_idx, linestorage& out_lines);
    bool fuku_mutation_x86::fukutate_jmp(linestorage& lines, unsigned int current_line_idx, linestorage& out_lines);
    bool fuku_mutation_x86::fukutate_ret(linestorage& lines, unsigned int current_line_idx, linestorage& out_lines);

    void fuku_mutation_x86::fukutation(linestorage& lines, unsigned int current_line_idx, linestorage& out_lines);
    void fuku_mutation_x86::obfuscate_lines(linestorage& lines, unsigned int recurse_idx);

    uint32_t fuku_mutation_x86::set_label(fuku_instruction& line);
    uint32_t fuku_mutation_x86::get_maxlabel();
public:
    fuku_mutation_x86::fuku_mutation_x86(const fuku_ob_settings& settings);
    fuku_mutation_x86::~fuku_mutation_x86();

    void fuku_mutation_x86::obfuscate(const fuku_code_holder& code_holder);

    void fuku_mutation_x86::get_junk(std::vector<uint8_t>& junk, size_t junk_size, bool unstable_stack, uint16_t allow_flags_changes);
};



