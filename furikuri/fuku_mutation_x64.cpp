#include "stdafx.h"
#include "fuku_mutation_x64.h"


fuku_mutation_x64::fuku_mutation_x64(const ob_fuku_sensitivity& settings, fuku_obfuscator * obfuscator)
: settings(settings), obfuscator(obfuscator){}

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
            recurse_idx_up = rand() % settings.complexity + 1;
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

void fuku_mutation_x64::generate_junk(std::vector<uint8_t>& junk, size_t junk_size, bool unstable_stack, uint16_t allow_flags_changes) {

    size_t current_size = 0;
    std::vector<fuku_instruction> lines;

    while (junk_size != current_size) {

        switch (FUKU_GET_RAND(1, min(junk_size - current_size, 7))) {
        case 1: {
            fuku_junk_1b(lines, 0, unstable_stack, allow_flags_changes); current_size += 1;
            break;
        }
        case 2: {
            fuku_junk_2b(lines, 0, unstable_stack, allow_flags_changes); current_size += 2;
            break;
        }
        case 3: {
            fuku_junk_3b(lines, 0, unstable_stack, allow_flags_changes); current_size += 3;
            break;
        }
        case 4: {
            fuku_junk_4b(lines, 0, unstable_stack, allow_flags_changes); current_size += 4;
            break;
        }
        case 5: {
            fuku_junk_5b(lines, 0, unstable_stack, allow_flags_changes); current_size += 5;
            break;
        }
        case 6: {
            fuku_junk_6b(lines, 0, unstable_stack, allow_flags_changes); current_size += 6;
            break;
        }
        case 7: {
            fuku_junk_7b(lines, 0, unstable_stack, allow_flags_changes); current_size += 7;
            break;
        }
        }
    }

    junk.resize(current_size);
    for (size_t line_idx = 0, caret_pos = 0; line_idx < lines.size(); line_idx++) {
        auto& line = lines[line_idx];
        memcpy(&junk[caret_pos], line.get_op_code(), line.get_op_length());
        caret_pos += line.get_op_length();
    }
}




void fuku_mutation_x64::fukutation(std::vector<fuku_instruction>& lines, unsigned int current_line_idx,
    std::vector<fuku_instruction>& out_lines) {

    if (FUKU_GET_CHANCE(settings.junk_chance)) {
        fuku_junk(lines, current_line_idx, out_lines);
    }

    if (FUKU_GET_CHANCE(settings.mutate_chance)) {
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


    bool unstable_stack = (lines[current_line_idx].get_flags()&ob_fuku_instruction_bad_stack);

    switch (FUKU_GET_RAND(0, 6)) {
    case 0: {
        fuku_junk_1b(out_lines, &lines[current_line_idx], unstable_stack, lines[current_line_idx].get_useless_flags());
        break;
    }
    case 1: {
        fuku_junk_2b(out_lines, &lines[current_line_idx], unstable_stack, lines[current_line_idx].get_useless_flags());
        break;
    }
    case 2: {
        fuku_junk_3b(out_lines, &lines[current_line_idx], unstable_stack, lines[current_line_idx].get_useless_flags());
        break;
    }
    case 3: {
        fuku_junk_4b(out_lines, &lines[current_line_idx], unstable_stack, lines[current_line_idx].get_useless_flags());
        break;
    }
    case 4: {
        fuku_junk_5b(out_lines, &lines[current_line_idx], unstable_stack, lines[current_line_idx].get_useless_flags());
        break;
    }
    case 5: {
        fuku_junk_6b(out_lines, &lines[current_line_idx], unstable_stack, lines[current_line_idx].get_useless_flags());
        break;
    }
    case 6: {
        fuku_junk_7b(out_lines, &lines[current_line_idx], unstable_stack, lines[current_line_idx].get_useless_flags());
        break;
    }
    }
}

void fuku_mutation_x64::fuku_junk_1b(std::vector<fuku_instruction>& out_lines, fuku_instruction* next_line, bool unstable_stack, uint16_t allow_flags_changes) {


}
void fuku_mutation_x64::fuku_junk_2b(std::vector<fuku_instruction>& out_lines, fuku_instruction* next_line, bool unstable_stack, uint16_t allow_flags_changes) {


}
void fuku_mutation_x64::fuku_junk_3b(std::vector<fuku_instruction>& out_lines, fuku_instruction* next_line, bool unstable_stack, uint16_t allow_flags_changes) {


}
void fuku_mutation_x64::fuku_junk_4b(std::vector<fuku_instruction>& out_lines, fuku_instruction* next_line, bool unstable_stack, uint16_t allow_flags_changes) {


}
void fuku_mutation_x64::fuku_junk_5b(std::vector<fuku_instruction>& out_lines, fuku_instruction* next_line, bool unstable_stack, uint16_t allow_flags_changes) {


}
void fuku_mutation_x64::fuku_junk_6b(std::vector<fuku_instruction>& out_lines, fuku_instruction* next_line, bool unstable_stack, uint16_t allow_flags_changes) {


}
void fuku_mutation_x64::fuku_junk_7b(std::vector<fuku_instruction>& out_lines, fuku_instruction* next_line, bool unstable_stack, uint16_t allow_flags_changes) {


}