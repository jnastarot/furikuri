#include "stdafx.h"
#include "fuku_mutation_x86.h"
#include "fuku_mutation_x86_rules.h"

fuku_mutation_x86::fuku_mutation_x86(const fuku_ob_settings& settings)
: settings(settings){

    cs_open(CS_ARCH_X86, CS_MODE_32, &cap_handle);
    cs_option(cap_handle, CS_OPT_DETAIL, CS_OPT_ON);
}

fuku_mutation_x86::~fuku_mutation_x86() {
    cs_close(&cap_handle);
}

void fuku_mutation_x86::obfuscate_lines(fuku_code_holder& code_holder, linestorage::iterator lines_iter_begin, linestorage::iterator lines_iter_end, unsigned int recurse_idx) {

    for (linestorage::iterator lines_iter = lines_iter_begin; lines_iter != lines_iter_end; lines_iter++) {

        fukutation(code_holder, lines_iter);

        unsigned int recurse_idx_up = 0;
        if (recurse_idx == -1) {
            recurse_idx_up = rand() % settings.complexity + 1;
        }
        else {
            recurse_idx_up = recurse_idx - 1;
        }

        if (recurse_idx_up) {
            auto next_iter = lines_iter; next_iter++;
            obfuscate_lines(code_holder, lines_iter, next_iter, recurse_idx_up);
        }
    }
}

void fuku_mutation_x86::obfuscate(fuku_code_holder& code_holder) {
    obfuscate_lines(code_holder, code_holder.get_lines().begin(), code_holder.get_lines().end(), -1);
}

void fuku_mutation_x86::get_junk(std::vector<uint8_t>& junk, size_t junk_size, bool unstable_stack, uint16_t allow_flags_changes) {

    /*
    size_t current_size = 0;
    linestorage lines;

    while (junk_size != current_size) {

        switch (FUKU_GET_RAND(1, min(junk_size - current_size,7))) {
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
    */

}




void fuku_mutation_x86::fukutation(fuku_code_holder& code_holder, linestorage::iterator lines_iter) {

    cs_insn *instruction;
    bool unstable_stack = lines_iter->get_instruction_flags() & fuku_instruction_bad_stack_pointer;
    bool is_first_line = lines_iter == code_holder.get_lines().begin();
    linestorage::iterator begin_lines_iter;
    linestorage::iterator end_lines_iter = lines_iter; end_lines_iter++;

    if (!is_first_line) {
        begin_lines_iter = lines_iter;
        begin_lines_iter--;
    }


    cs_disasm(cap_handle, lines_iter->get_op_code(), lines_iter->get_op_length(), 0, 1, &instruction);

    if (FUKU_GET_CHANCE(settings.junk_chance)) {
        fuku_junk(code_holder, lines_iter);
    }


    if ( (lines_iter->get_instruction_flags() & fuku_instruction_full_mutated) == 0 &&
        FUKU_GET_CHANCE(settings.mutate_chance)) {

        switch (lines_iter->get_id()) {

        case X86_INS_PUSH: {
            fukutate_push(instruction, f_asm, code_holder, lines_iter);
            break;
        }
                     
        case X86_INS_POP: {
            fukutate_pop(instruction, f_asm, code_holder, lines_iter);
            break;
        }


        case X86_INS_ADD: {
            fukutate_add(instruction, f_asm, code_holder, lines_iter);
            break;
        }

        case X86_INS_SUB: {
            fukutate_sub(instruction, f_asm, code_holder, lines_iter);
            break;
        }

        case X86_INS_INC: {
            fukutate_inc(instruction, f_asm, code_holder, lines_iter);
            break;
        }

        case X86_INS_DEC: {
            fukutate_dec(instruction, f_asm, code_holder, lines_iter);
            break;
        }
                 
        case X86_INS_CMP: {
            fukutate_cmp(instruction, f_asm, code_holder, lines_iter);
            break;
        }


        case X86_INS_AND: {
            fukutate_and(instruction, f_asm, code_holder, lines_iter);
            break;
        }

        case X86_INS_OR: {
            fukutate_or(instruction, f_asm, code_holder, lines_iter);
            break;
        }

        case X86_INS_XOR: {
            fukutate_xor(instruction, f_asm, code_holder, lines_iter);
            break;
        }

        case X86_INS_TEST: {
            fukutate_test(instruction, f_asm, code_holder, lines_iter);
            break;
        }

        
        case X86_INS_JMP: {
            fukutate_jmp(instruction, f_asm, code_holder, lines_iter);
            break;
        }
                               
        case  X86_INS_JO: case  X86_INS_JNO:
        case  X86_INS_JB: case  X86_INS_JAE:
        case  X86_INS_JE: case  X86_INS_JNE:
        case  X86_INS_JBE:case  X86_INS_JA:
        case  X86_INS_JS: case  X86_INS_JNS:
        case  X86_INS_JP: case  X86_INS_JNP:
        case  X86_INS_JL: case  X86_INS_JGE:
        case  X86_INS_JLE:case  X86_INS_JG: {
            fukutate_jcc(f_asm, code_holder, lines_iter);
            break;
        }

                    
        case X86_INS_RET: {
            fukutate_ret(instruction, f_asm, code_holder, lines_iter);
            break;
        }
        
        }
    }

    cs_free(instruction, 1);

    { //move label_idx and source_address to start of instruction's array 

        if (is_first_line) {
            begin_lines_iter = code_holder.get_lines().begin();
        }
        else {
            begin_lines_iter++;
        }

        if (begin_lines_iter != lines_iter) {

            if (lines_iter->get_label_idx() != -1) {
                code_holder.get_labels()[lines_iter->get_label_idx()].instruction = &(*begin_lines_iter);
                begin_lines_iter->set_label_idx(lines_iter->get_label_idx());
                lines_iter->set_label_idx(-1);
            }

            begin_lines_iter->set_source_virtual_address(lines_iter->get_source_virtual_address());
            lines_iter->set_source_virtual_address(-1);
        }

        if (unstable_stack) {
            for (auto current_line = begin_lines_iter; current_line != end_lines_iter; current_line++) {
                current_line->set_instruction_flags(current_line->get_instruction_flags() | fuku_instruction_bad_stack_pointer);
            }
        }

    }
}


void fuku_mutation_x86::generate_junk(fuku_code_holder& code_holder,
    linestorage::iterator lines_iter, uint32_t max_size, size_t junk_size) {

    return;

    size_t current_size = 0;
    
    while (junk_size != current_size) {

        switch (FUKU_GET_RAND(1, min(min(junk_size - current_size, max_size),7))) {
        case 1: {
            fuku_junk_1b(f_asm, code_holder, lines_iter); current_size += 1;
            break;
        }
        case 2: {
            fuku_junk_2b(f_asm, code_holder, lines_iter); current_size += 2;
            break;
        }
        case 3: {
            fuku_junk_3b(f_asm, code_holder, lines_iter); current_size += 3;
            break;
        }
        case 4: {
            fuku_junk_4b(f_asm, code_holder, lines_iter); current_size += 4;
            break;
        }
        case 5: {
            fuku_junk_5b(f_asm, code_holder, lines_iter); current_size += 5;
            break;
        }
        case 6: {
            fuku_junk_6b(f_asm, code_holder, lines_iter); current_size += 6;
            break;
        }
        case 7: {
            fuku_junk_7b(f_asm, code_holder, lines_iter); current_size += 7;
            break;
        }
        }
    }
}

void fuku_mutation_x86::fuku_junk(fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {

    switch (FUKU_GET_RAND(0, 6)) {
    case 0: {
        fuku_junk_1b(f_asm, code_holder, lines_iter);
        break;
    }
    case 1: {
        fuku_junk_2b(f_asm, code_holder, lines_iter);
        break;
    }
    case 2: {
        fuku_junk_3b(f_asm, code_holder, lines_iter);
        break;
    }
    case 3: {
        fuku_junk_4b(f_asm, code_holder, lines_iter);
        break;
    }
    case 4: {
        fuku_junk_5b(f_asm, code_holder, lines_iter);
        break;
    }
    case 5: {
        fuku_junk_6b(f_asm, code_holder, lines_iter);
        break;
    }
    case 6: {
        fuku_junk_7b(f_asm, code_holder, lines_iter);
        break;
    }
    }
}
