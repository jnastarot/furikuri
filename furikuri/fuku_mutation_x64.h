#pragma once

#pragma once

class fuku_mutation_x64 :
    public fuku_mutation {

    unsigned int complexity;
    fuku_obfuscator * obfuscator;

    void fuku_mutation_x64::fuku_junk(std::vector<fuku_instruction>& lines, unsigned int current_line_idx, std::vector<fuku_instruction>& out_lines);

    bool fuku_mutation_x64::fukutate_push(std::vector<fuku_instruction>& lines, unsigned int current_line_idx, std::vector<fuku_instruction>& out_lines);
    bool fuku_mutation_x64::fukutate_pop(std::vector<fuku_instruction>& lines, unsigned int current_line_idx, std::vector<fuku_instruction>& out_lines);
    bool fuku_mutation_x64::fukutate_add(std::vector<fuku_instruction>& lines, unsigned int current_line_idx, std::vector<fuku_instruction>& out_lines);
    bool fuku_mutation_x64::fukutate_sub(std::vector<fuku_instruction>& lines, unsigned int current_line_idx, std::vector<fuku_instruction>& out_lines);
    bool fuku_mutation_x64::fukutate_xor(std::vector<fuku_instruction>& lines, unsigned int current_line_idx, std::vector<fuku_instruction>& out_lines);
    bool fuku_mutation_x64::fukutate_and(std::vector<fuku_instruction>& lines, unsigned int current_line_idx, std::vector<fuku_instruction>& out_lines);
    bool fuku_mutation_x64::fukutate_inc(std::vector<fuku_instruction>& lines, unsigned int current_line_idx, std::vector<fuku_instruction>& out_lines);
    bool fuku_mutation_x64::fukutate_dec(std::vector<fuku_instruction>& lines, unsigned int current_line_idx, std::vector<fuku_instruction>& out_lines);
    bool fuku_mutation_x64::fukutate_test(std::vector<fuku_instruction>& lines,unsigned int current_line_idx, std::vector<fuku_instruction>& out_lines);
    bool fuku_mutation_x64::fukutate_cmp(std::vector<fuku_instruction>& lines, unsigned int current_line_idx, std::vector<fuku_instruction>& out_lines);
    bool fuku_mutation_x64::fukutate_jcc(std::vector<fuku_instruction>& lines, unsigned int current_line_idx, std::vector<fuku_instruction>& out_lines);
    bool fuku_mutation_x64::fukutate_jmp(std::vector<fuku_instruction>& lines, unsigned int current_line_idx, std::vector<fuku_instruction>& out_lines);
    bool fuku_mutation_x64::fukutate_ret(std::vector<fuku_instruction>& lines, unsigned int current_line_idx, std::vector<fuku_instruction>& out_lines);

    void fuku_mutation_x64::fukutation(std::vector<fuku_instruction>& lines, unsigned int current_line_idx,std::vector<fuku_instruction>& out_lines);
    void fuku_mutation_x64::obfuscate_lines(std::vector<fuku_instruction>& lines, unsigned int recurse_idx);
public:
    fuku_mutation_x64::fuku_mutation_x64();
    fuku_mutation_x64::fuku_mutation_x64(unsigned int complexity, fuku_obfuscator * obfuscator);
    fuku_mutation_x64::~fuku_mutation_x64();

    void fuku_mutation_x64::obfuscate(std::vector<fuku_instruction>& lines);

    void fuku_mutation_x64::generate_junk(std::vector<uint8_t>& junk, size_t junk_size);
};
