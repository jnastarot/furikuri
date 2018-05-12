#include "stdafx.h"
#include "fuku_mutation_x64.h"


fuku_mutation_x64::fuku_mutation_x64()
:complexity(1), obfuscator(0){}

fuku_mutation_x64::fuku_mutation_x64(unsigned int complexity, fuku_obfuscator * obfuscator)
: complexity(complexity), obfuscator(obfuscator){}

fuku_mutation_x64::~fuku_mutation_x64() {

}

void fuku_mutation_x64::obfuscate_lines(std::vector<fuku_instruction>& lines, unsigned int recurse_idx) {

    std::vector<fuku_instruction> obf_lines;

    //obfuscate
    for (size_t line_idx = 0; line_idx < lines.size(); line_idx++) {
        std::vector<fuku_instruction> single_line;

        fukutation(lines, line_idx, single_line);

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

void fuku_mutation_x64::obfuscate(std::vector<fuku_instruction>& lines) {
    obfuscate_lines(lines, -1);
}

void fuku_mutation_x64::generate_junk(std::vector<uint8_t>& junk, size_t junk_size) {

    
}




void fuku_mutation_x64::fukutation(std::vector<fuku_instruction>& lines, unsigned int current_line_idx,
    std::vector<fuku_instruction>& out_lines) {

    if (FUKU_GET_CHANCE(FUKU_GENERATE_JUNK_CHANCE)) {
        fuku_junk(lines, current_line_idx, out_lines);
    }

    if (FUKU_GET_CHANCE(FUKU_MUTATE_LINE_CHANCE)) {
        switch (lines[current_line_idx].get_type()) {

        case I_PUSH: {
            if (!fukutate_push(lines, current_line_idx, out_lines)) {
                out_lines.push_back(lines[current_line_idx]);
            }
            break;
        }

        case I_POP: {
            if (!fukutate_pop(lines, current_line_idx, out_lines)) {
                out_lines.push_back(lines[current_line_idx]);
            }
            break;
        }


        case I_ADD: {
            if (!fukutate_add(lines, current_line_idx, out_lines)) {
                out_lines.push_back(lines[current_line_idx]);
            }
            break;
        }

        case I_SUB: {
            if (!fukutate_sub(lines, current_line_idx, out_lines)) {
                out_lines.push_back(lines[current_line_idx]);
            }
            break;
        }

        case I_XOR: {
            if (!fukutate_xor(lines, current_line_idx, out_lines)) {
                out_lines.push_back(lines[current_line_idx]);
            }
            break;
        }

        case I_AND: {
            if (!fukutate_and(lines, current_line_idx, out_lines)) {
                out_lines.push_back(lines[current_line_idx]);
            }
            break;
        }


        case I_INC: {
            if (!fukutate_inc(lines, current_line_idx, out_lines)) {
                out_lines.push_back(lines[current_line_idx]);
            }
            break;
        }

        case I_DEC: {
            if (!fukutate_dec(lines, current_line_idx, out_lines)) {
                out_lines.push_back(lines[current_line_idx]);
            }
            break;
        }

        case I_TEST: {
            if (!fukutate_test(lines, current_line_idx, out_lines)) {
                out_lines.push_back(lines[current_line_idx]);
            }
            break;
        }
        case I_CMP: {
            if (!fukutate_cmp(lines, current_line_idx, out_lines)) {
                out_lines.push_back(lines[current_line_idx]);
            }
            break;
        }

        case I_JMP: {
            if (!fukutate_jmp(lines, current_line_idx, out_lines)) {
                out_lines.push_back(lines[current_line_idx]);
            }
            break;
        }

        case I_RET: {
            if (!fukutate_ret(lines, current_line_idx, out_lines)) {
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



bool fuku_mutation_x64::fukutate_push(std::vector<fuku_instruction>& lines, unsigned int current_line_idx, std::vector<fuku_instruction>& out_lines) {

    return false;
}
bool fuku_mutation_x64::fukutate_pop(std::vector<fuku_instruction>& lines, unsigned int current_line_idx, std::vector<fuku_instruction>& out_lines) {

    return false;
}
bool fuku_mutation_x64::fukutate_add(std::vector<fuku_instruction>& lines, unsigned int current_line_idx, std::vector<fuku_instruction>& out_lines) {

    return false;
}
bool fuku_mutation_x64::fukutate_sub(std::vector<fuku_instruction>& lines, unsigned int current_line_idx, std::vector<fuku_instruction>& out_lines) {

    return false;
}
bool fuku_mutation_x64::fukutate_xor(std::vector<fuku_instruction>& lines, unsigned int current_line_idx, std::vector<fuku_instruction>& out_lines) {

    return false;
}
bool fuku_mutation_x64::fukutate_and(std::vector<fuku_instruction>& lines, unsigned int current_line_idx, std::vector<fuku_instruction>& out_lines) {

    return false;
}
bool fuku_mutation_x64::fukutate_inc(std::vector<fuku_instruction>& lines, unsigned int current_line_idx, std::vector<fuku_instruction>& out_lines) {

    return false;
}
bool fuku_mutation_x64::fukutate_dec(std::vector<fuku_instruction>& lines, unsigned int current_line_idx, std::vector<fuku_instruction>& out_lines) {

    return false;
}
bool fuku_mutation_x64::fukutate_test(std::vector<fuku_instruction>& lines, unsigned int current_line_idx, std::vector<fuku_instruction>& out_lines) {

    return false;
}
bool fuku_mutation_x64::fukutate_cmp(std::vector<fuku_instruction>& lines, unsigned int current_line_idx, std::vector<fuku_instruction>& out_lines) {

    return false;
}
bool fuku_mutation_x64::fukutate_jcc(std::vector<fuku_instruction>& lines, unsigned int current_line_idx, std::vector<fuku_instruction>& out_lines) {

    return false;
}
bool fuku_mutation_x64::fukutate_jmp(std::vector<fuku_instruction>& lines, unsigned int current_line_idx, std::vector<fuku_instruction>& out_lines) {

    return false;
}
bool fuku_mutation_x64::fukutate_ret(std::vector<fuku_instruction>& lines, unsigned int current_line_idx, std::vector<fuku_instruction>& out_lines) {

    return false;
}

void fuku_mutation_x64::fuku_junk(std::vector<fuku_instruction>& lines, unsigned int current_line_idx,
    std::vector<fuku_instruction>& out_lines) {



}