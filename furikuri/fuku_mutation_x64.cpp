#include "stdafx.h"
#include "fuku_mutation_x64.h"

#define ISNT_LAST (lines.size() > current_line_idx+1)

fuku_mutation_x64::fuku_mutation_x64(const fuku_ob_settings& settings, unsigned int * label_seed)
: settings(settings), label_seed(label_seed){}

fuku_mutation_x64::~fuku_mutation_x64() {

}

void fuku_mutation_x64::obfuscate_lines(linestorage& lines, unsigned int recurse_idx) {

    linestorage obf_lines;

    //obfuscate
    for (size_t line_idx = 0; line_idx < lines.size(); line_idx++) {
        linestorage single_line;

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

void fuku_mutation_x64::obfuscate(linestorage& lines) {
    obfuscate_lines(lines, -1);
}

uint32_t fuku_mutation_x64::set_label(fuku_instruction& line) {
    if (label_seed) {
        if (!line.get_label_id()) {
            line.set_label_id(*label_seed);
            (*label_seed)++;
        }
        return line.get_label_id();
    }
    return 0;
}

uint32_t fuku_mutation_x64::get_maxlabel() {
    if (label_seed) {
        return *label_seed;
    }
    return 0;
}


void fuku_mutation_x64::get_junk(std::vector<uint8_t>& junk, size_t junk_size, bool unstable_stack, uint16_t allow_flags_changes) {

    size_t current_size = 0;
    linestorage lines;

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




void fuku_mutation_x64::fukutation(linestorage& lines, unsigned int current_line_idx,
    linestorage& out_lines) {

    bool unstable_stack = lines[current_line_idx].get_flags() & fuku_instruction_bad_stack;

    if (FUKU_GET_CHANCE(settings.junk_chance)) {
        fuku_junk(lines, current_line_idx, out_lines);
    }

    if (FUKU_GET_CHANCE(settings.mutate_chance)) {
        switch (lines[current_line_idx].get_type()) {

            //todo

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

        case  I_JO: case  I_JNO:
        case  I_JB: case  I_JAE:
        case  I_JZ: case  I_JNZ:
        case  I_JBE:case  I_JA:
        case  I_JS: case  I_JNS:
        case  I_JP: case  I_JNP:
        case  I_JL: case  I_JGE:
        case  I_JLE:case  I_JG: {
            if (!fukutate_jcc(lines, current_line_idx, out_lines)) {
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


    for (auto& line : out_lines) {
        if (unstable_stack) {
            line.set_flags(line.get_flags() | fuku_instruction_bad_stack);
        }

        line.set_label_id(0);

        line.set_source_virtual_address(-1);
    }

    out_lines[0].set_source_virtual_address(lines[current_line_idx].get_source_virtual_address());
    out_lines[0].set_label_id(lines[current_line_idx].get_label_id());
}



bool fuku_mutation_x64::fukutate_push(linestorage& lines, unsigned int current_line_idx, linestorage& out_lines) {

    return false;
}
bool fuku_mutation_x64::fukutate_pop(linestorage& lines, unsigned int current_line_idx, linestorage& out_lines) {

    return false;
}
bool fuku_mutation_x64::fukutate_add(linestorage& lines, unsigned int current_line_idx, linestorage& out_lines) {

    return false;
}
bool fuku_mutation_x64::fukutate_sub(linestorage& lines, unsigned int current_line_idx, linestorage& out_lines) {

    return false;
}
bool fuku_mutation_x64::fukutate_and(linestorage& lines, unsigned int current_line_idx, linestorage& out_lines) {

    return false;
}
bool fuku_mutation_x64::fukutate_inc(linestorage& lines, unsigned int current_line_idx, linestorage& out_lines) {

    return false;
}
bool fuku_mutation_x64::fukutate_dec(linestorage& lines, unsigned int current_line_idx, linestorage& out_lines) {

    return false;
}
bool fuku_mutation_x64::fukutate_test(linestorage& lines, unsigned int current_line_idx, linestorage& out_lines) {

    return false;
}
bool fuku_mutation_x64::fukutate_cmp(linestorage& lines, unsigned int current_line_idx, linestorage& out_lines) {

    return false;
}
bool fuku_mutation_x64::fukutate_jcc(linestorage& lines, unsigned int current_line_idx, linestorage& out_lines) {

    auto& target_line = lines[current_line_idx];

    if (label_seed && ISNT_LAST) {
        const uint8_t* code = &target_line.get_op_code()[target_line.get_op_pref_size()];

        fuku_instruction l_jmp = f_asm.jmp(0);
        l_jmp.set_ip_relocation_destination(target_line.get_ip_relocation_destination());
        l_jmp.set_link_label_id(target_line.get_link_label_id());

        uint8_t cond;

        if (code[0] == 0x0F) {
            cond = code[1] & 0xF;
        }
        else {
            cond = code[0] & 0xF;
        }

        fuku_instruction l_jcc = f_asm.jcc(fuku_condition(cond ^ 1), 0).set_useless_flags(target_line.get_useless_flags());
        l_jcc.set_link_label_id(set_label(lines[current_line_idx + 1]));
        l_jcc.set_flags(l_jcc.get_flags() | fuku_instruction_full_mutated);

        out_lines.push_back(l_jcc);
        out_lines.push_back(l_jmp);
        return true;
    }


    return false;
}
bool fuku_mutation_x64::fukutate_jmp(linestorage& lines, unsigned int current_line_idx, linestorage& out_lines) {

    return false;
}
bool fuku_mutation_x64::fukutate_ret(linestorage& lines, unsigned int current_line_idx, linestorage& out_lines) {

    auto& target_line = lines[current_line_idx];

    if (((target_line.get_flags() & fuku_instruction_bad_stack) == 0)) {
        if (target_line.get_op_code()[0] == 0xC3) { //ret

            out_lines.push_back(f_asm.lea(fuku_reg64::r_RSP, fuku_operand64(fuku_reg64::r_RSP, 8),fuku_asm64_size::asm64_size_64));//lea rsp,[rsp + (8 + stack_offset)]
            out_lines.push_back(f_asm.jmp(fuku_operand64(r_RSP, -8)).set_flags(fuku_instruction_bad_stack));                        //jmp [rsp - (8 + stack_offset)] 

            return true;

        }
        else if (target_line.get_op_code()[0] == 0xC2) { //ret 0x0000
            uint16_t ret_stack = *(uint16_t*)&target_line.get_op_code()[1];
            out_lines.push_back(f_asm.add(fuku_reg64::r_RSP, fuku_operand64(fuku_reg64::r_RSP, 8 + ret_stack), fuku_asm64_size::asm64_size_64));//lea rsp,[rsp + (8 + stack_offset)]
            out_lines.push_back(f_asm.jmp(fuku_operand64(r_RSP, -8 - ret_stack)).set_flags(fuku_instruction_bad_stack));                        //jmp [rsp - (8 + stack_offset)] 

            return true;
        }
    }

    return false;
}


void fuku_mutation_x64::generate_junk(linestorage& junk,
    fuku_instruction* next_line, uint32_t max_size, size_t junk_size, bool unstable_stack, uint16_t allow_flags_changes) {


    size_t current_size = 0;

    while (junk_size != current_size) {

        switch (FUKU_GET_RAND(1, min(min(junk_size - current_size, max_size), 7))) {
        case 1: {
            fuku_junk_1b(junk, next_line, unstable_stack, allow_flags_changes); current_size += 1;
            break;
        }
        case 2: {
            fuku_junk_2b(junk, next_line, unstable_stack, allow_flags_changes); current_size += 2;
            break;
        }
        case 3: {
            fuku_junk_3b(junk, next_line, unstable_stack, allow_flags_changes); current_size += 3;
            break;
        }
        case 4: {
            fuku_junk_4b(junk, next_line, unstable_stack, allow_flags_changes); current_size += 4;
            break;
        }
        case 5: {
            fuku_junk_5b(junk, next_line, unstable_stack, allow_flags_changes); current_size += 5;
            break;
        }
        case 6: {
            fuku_junk_6b(junk, next_line, unstable_stack, allow_flags_changes); current_size += 6;
            break;
        }
        case 7: {
            fuku_junk_7b(junk, next_line, unstable_stack, allow_flags_changes); current_size += 7;
            break;
        }
        }
    }
}

void fuku_mutation_x64::fuku_junk(linestorage& lines, unsigned int current_line_idx,
    linestorage& out_lines) {


    bool unstable_stack = (lines[current_line_idx].get_flags() & fuku_instruction_bad_stack);

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

void fuku_mutation_x64::fuku_junk_1b(linestorage& out_lines, 
    fuku_instruction* next_line, bool unstable_stack, uint16_t allow_flags_changes) {

    out_lines.push_back(f_asm.nop(1));
}
void fuku_mutation_x64::fuku_junk_2b(linestorage& out_lines, 
    fuku_instruction* next_line, bool unstable_stack, uint16_t allow_flags_changes) {

    switch (FUKU_GET_RAND(0, 0)) {
    case 0: {
        out_lines.push_back(f_asm.nop(2));
        break;
    }
    }


}
void fuku_mutation_x64::fuku_junk_3b(linestorage& out_lines, 
    fuku_instruction* next_line, bool unstable_stack, uint16_t allow_flags_changes) {

    switch (FUKU_GET_RAND(0, 0)) {
    case 0: {
        out_lines.push_back(f_asm.nop(3));
        break;
    }
    }
}
void fuku_mutation_x64::fuku_junk_4b(linestorage& out_lines, 
    fuku_instruction* next_line, bool unstable_stack, uint16_t allow_flags_changes) {

    switch (FUKU_GET_RAND(0, 0)) {
    case 0: {
        out_lines.push_back(f_asm.nop(4));
        break;
    }
    }
}
void fuku_mutation_x64::fuku_junk_5b(linestorage& out_lines, 
    fuku_instruction* next_line, bool unstable_stack, uint16_t allow_flags_changes) {

    switch (FUKU_GET_RAND(0, 0)) {
    case 0: {
        out_lines.push_back(f_asm.nop(5));
        break;
    }
    }
}
void fuku_mutation_x64::fuku_junk_6b(linestorage& out_lines, 
    fuku_instruction* next_line, bool unstable_stack, uint16_t allow_flags_changes) {

    switch (FUKU_GET_RAND(0, 0)) {
    case 0: {
        out_lines.push_back(f_asm.nop(6));
        break;
    }
    }
}
void fuku_mutation_x64::fuku_junk_7b(linestorage& out_lines, 
    fuku_instruction* next_line, bool unstable_stack, uint16_t allow_flags_changes) {

    switch (FUKU_GET_RAND(0, 0)) {
    case 0: {
        out_lines.push_back(f_asm.nop(7));
        break;
    }
    }
}