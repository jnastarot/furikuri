#pragma once

#pragma once

class fuku_mutation_x64 :
    public fuku_mutation {

    unsigned int complexity;
    fuku_obfuscator * obfuscator;

    void fuku_mutation_x64::obfuscate_lines(std::vector<fuku_instruction>& lines, unsigned int recurse_idx);
public:
    fuku_mutation_x64::fuku_mutation_x64();
    fuku_mutation_x64::fuku_mutation_x64(unsigned int complexity, fuku_obfuscator * obfuscator);
    fuku_mutation_x64::~fuku_mutation_x64();

    void fuku_mutation_x64::obfuscate(std::vector<fuku_instruction>& lines);

    void fuku_mutation_x64::generate_junk(std::vector<uint8_t>& junk, size_t junk_size);
};
