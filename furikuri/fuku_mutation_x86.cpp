#include "stdafx.h"
#include "fuku_mutation_x86.h"


fuku_mutation_x86::fuku_mutation_x86(const ob_fuku_sensitivity& settings, fuku_obfuscator * obfuscator)
: settings(settings), obfuscator(obfuscator){}

fuku_mutation_x86::~fuku_mutation_x86() {

}

void fuku_mutation_x86::obfuscate_lines(std::vector<fuku_instruction>& lines, unsigned int recurse_idx) {

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

void fuku_mutation_x86::obfuscate(std::vector<fuku_instruction>& lines) {
    obfuscate_lines(lines, -1);
}

void fuku_mutation_x86::generate_junk(std::vector<uint8_t>& junk, size_t junk_size) {



    
}




void fuku_mutation_x86::fukutation(std::vector<fuku_instruction>& lines, unsigned int current_line_idx,
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


bool fuku_mutation_x86::fukutate_push(std::vector<fuku_instruction>& lines, unsigned int current_line_idx, std::vector<fuku_instruction>& out_lines) {

    return false;
}
bool fuku_mutation_x86::fukutate_pop(std::vector<fuku_instruction>& lines, unsigned int current_line_idx, std::vector<fuku_instruction>& out_lines) {

    return false;
}
bool fuku_mutation_x86::fukutate_add(std::vector<fuku_instruction>& lines, unsigned int current_line_idx, std::vector<fuku_instruction>& out_lines) {

    return false;
}
bool fuku_mutation_x86::fukutate_sub(std::vector<fuku_instruction>& lines, unsigned int current_line_idx, std::vector<fuku_instruction>& out_lines) {

    return false;
}
bool fuku_mutation_x86::fukutate_xor(std::vector<fuku_instruction>& lines, unsigned int current_line_idx, std::vector<fuku_instruction>& out_lines) {

    return false;
}
bool fuku_mutation_x86::fukutate_and(std::vector<fuku_instruction>& lines, unsigned int current_line_idx, std::vector<fuku_instruction>& out_lines) {

    return false;
}
bool fuku_mutation_x86::fukutate_inc(std::vector<fuku_instruction>& lines, unsigned int current_line_idx, std::vector<fuku_instruction>& out_lines) {

    return false;
}
bool fuku_mutation_x86::fukutate_dec(std::vector<fuku_instruction>& lines, unsigned int current_line_idx, std::vector<fuku_instruction>& out_lines) {

    return false;
}
bool fuku_mutation_x86::fukutate_test(std::vector<fuku_instruction>& lines, unsigned int current_line_idx, std::vector<fuku_instruction>& out_lines) {

    return false;
}
bool fuku_mutation_x86::fukutate_cmp(std::vector<fuku_instruction>& lines, unsigned int current_line_idx, std::vector<fuku_instruction>& out_lines) {

    return false;
}
bool fuku_mutation_x86::fukutate_jcc(std::vector<fuku_instruction>& lines, unsigned int current_line_idx, std::vector<fuku_instruction>& out_lines) {

    return false;
}
bool fuku_mutation_x86::fukutate_jmp(std::vector<fuku_instruction>& lines, unsigned int current_line_idx, std::vector<fuku_instruction>& out_lines) {

    auto& target_line = lines[current_line_idx];

    if (target_line.get_op_code()[0] == 0xE9) {

        fuku_instruction l_push = f_asm.push_imm32(0); //push 00000000
        l_push.set_flags(ob_fuku_instruction_has_relocation);

        l_push.set_relocation_f_imm_offset(1);
        l_push.set_relocation_f_id(0);

        if (target_line.get_link_label_id()) { //internal jmp
            l_push.set_relocation_f_label_id(target_line.get_link_label_id());
        }
        else { //external jmp
            l_push.set_relocation_f_destination(target_line.get_ip_relocation_destination());
        }

        out_lines.push_back(l_push);
        out_lines.push_back(f_asm.ret(0));//ret
        return true;
    }

    return false;
}
bool fuku_mutation_x86::fukutate_ret(std::vector<fuku_instruction>& lines, unsigned int current_line_idx, std::vector<fuku_instruction>& out_lines) {

    auto& target_line = lines[current_line_idx];

    if (target_line.get_op_code()[0] == 0xC3) { //ret

        out_lines.push_back(f_asm.lea(fuku_reg86::r_ESP, fuku_operand86(fuku_reg86::r_ESP,4)));//lea esp,[esp + (4 + stack_offset)]
        out_lines.push_back(f_asm.jmp(fuku_operand86(r_ESP,-4)));           //jmp [esp - (4 + stack_offset)] 

        return true;

    } else if (target_line.get_op_code()[0] == 0xC2) { //ret 0x0000
        uint16_t ret_stack = *(uint16_t*)target_line.get_op_code()[1];
        out_lines.push_back(f_asm.add(fuku_reg86::r_ESP, fuku_operand86(fuku_reg86::r_ESP,4 + ret_stack)));//lea esp,[esp + (4 + stack_offset)]
        out_lines.push_back(f_asm.jmp(fuku_operand86(r_ESP, - 4 - ret_stack)));          //jmp [esp - (4 + stack_offset)] 
        
        return true;
    }

    return false;
}

void fuku_mutation_x86::fuku_junk(std::vector<fuku_instruction>& lines, unsigned int current_line_idx,
    std::vector<fuku_instruction>& out_lines) {



}