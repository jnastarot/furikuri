#include "stdafx.h"
#include "fuku_mutation_x86.h"


void fuku_x86_junk(std::vector<fuku_instruction>& lines, unsigned int current_line_idx,std::vector<fuku_instruction>& out_lines);
void obfurikuritation_x86(std::vector<fuku_instruction>& lines, unsigned int current_line_idx, std::vector<fuku_instruction>& out_lines);

bool fukutate_add_x86(std::vector<fuku_instruction>& lines, unsigned int current_line_idx, std::vector<fuku_instruction>& out_lines);
bool fukutate_sub_x86(std::vector<fuku_instruction>& lines, unsigned int current_line_idx, std::vector<fuku_instruction>& out_lines);


fuku_mutation_x86::fuku_mutation_x86()
:complexity(1), obfuscator(0){}

fuku_mutation_x86::fuku_mutation_x86(unsigned int complexity, fuku_obfuscator * obfuscator)
: complexity(complexity), obfuscator(obfuscator){}

fuku_mutation_x86::~fuku_mutation_x86() {

}

void fuku_mutation_x86::obfuscate_lines(std::vector<fuku_instruction>& lines, unsigned int recurse_idx) {

    std::vector<fuku_instruction> obf_lines;

    //obfuscate
    for (size_t line_idx = 0; line_idx < lines.size(); line_idx++) {
        std::vector<fuku_instruction> single_line;
    
        obfurikuritation_x86(lines, line_idx, single_line);

        unsigned int recurse_idx_up = 0;
        if (recurse_idx == -1) {
            recurse_idx_up = rand() % complexity + 1;
        }
        else {
            recurse_idx_up = recurse_idx - 1;
        }

        if (recurse_idx_up) {
            obfuscate_lines(single_line, recurse_idx_up);
        }

        if (recurse_idx == -1) {
            single_line[0].set_label_id(lines[line_idx].get_label_id());
            single_line[0].set_source_virtual_address(lines[line_idx].get_source_virtual_address());
        }


        obf_lines.insert(obf_lines.end(), single_line.begin(), single_line.end());
    }

    lines = obf_lines;
}

void fuku_mutation_x86::obfuscate(std::vector<fuku_instruction>& lines) {
    obfuscate_lines(lines, -1);
}

void fuku_mutation_x86::generate_junk(std::vector<uint8_t>& junk, size_t junk_size) {

    
}




void obfurikuritation_x86(std::vector<fuku_instruction>& lines, unsigned int current_line_idx,
    std::vector<fuku_instruction>& out_lines) {


    if (FUKU_GET_CHANCE(FUKU_GENERATE_JUNK_CHANCE)) {
        fuku_x86_junk(lines, current_line_idx, out_lines);
    }

    if (FUKU_GET_CHANCE(FUKU_MUTATE_LINE_CHANCE)) {
        switch (lines[current_line_idx].get_type()) {

        case I_ADD: {
            if (!fukutate_add_x86(lines, current_line_idx, out_lines)) {
                out_lines.push_back(lines[current_line_idx]);
            }
            break;
        }

        case I_SUB: {
            if (!fukutate_sub_x86(lines, current_line_idx, out_lines)) {
                out_lines.push_back(lines[current_line_idx]);
            }
            break;
        }

        default: {
            out_lines.push_back(lines[current_line_idx]);
            break;
        }
        }
    }
    else {
        out_lines.push_back(lines[current_line_idx]);
    }
}

bool fukutate_add_x86(std::vector<fuku_instruction>& lines, unsigned int current_line_idx,
    std::vector<fuku_instruction>& out_lines) {


    return false;
}
bool fukutate_sub_x86(std::vector<fuku_instruction>& lines, unsigned int current_line_idx,
    std::vector<fuku_instruction>& out_lines) {

    return false;
}

void fuku_x86_junk(std::vector<fuku_instruction>& lines, unsigned int current_line_idx,
    std::vector<fuku_instruction>& out_lines) {



}