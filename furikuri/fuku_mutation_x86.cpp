#include "stdafx.h"
#include "fuku_mutation_x86.h"

#include "fuku_mutation_x86_stack.h"
#include "fuku_mutation_x86_arith.h"
#include "fuku_mutation_x86_logical.h"
#include "fuku_mutation_x86_graph.h"
#include "fuku_mutation_x86_junk.h"

fuku_mutation_x86::fuku_mutation_x86(const fuku_ob_settings& settings)
: settings(settings){}

fuku_mutation_x86::~fuku_mutation_x86() {}

void fuku_mutation_x86::obfuscate_lines(fuku_code_holder& code_holder, unsigned int recurse_idx) {

    for (linestorage::iterator lines_iter = code_holder.get_lines().begin(); lines_iter != code_holder.get_lines().end(); lines_iter++) {

        fukutation(code_holder, lines_iter);

        unsigned int recurse_idx_up = 0;
        if (recurse_idx == -1) {
            recurse_idx_up = rand() % settings.complexity + 1;
        }
        else {
            recurse_idx_up = recurse_idx - 1;
        }

        if (recurse_idx_up) {
            //obfuscate_lines(code_holder, recurse_idx_up);
        }
    }
}

void fuku_mutation_x86::obfuscate(fuku_code_holder& code_holder) {
    obfuscate_lines(code_holder, -1);
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




void fuku_mutation_x86::fukutation(fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {

    bool unstable_stack = lines_iter->get_instruction_flags() & fuku_instruction_bad_stack;

    if (FUKU_GET_CHANCE(settings.junk_chance)) {
        fuku_junk(code_holder, lines_iter);
    }

    if ( (lines_iter->get_instruction_flags() & fuku_instruction_full_mutated) == 0 &&
        FUKU_GET_CHANCE(settings.mutate_chance)) {

        switch (lines_iter->get_id()) {

        case X86_INS_PUSH: {
            fukutate_push(code_holder, lines_iter);
            break;
        }
                     
        case X86_INS_POP: {
            fukutate_pop(code_holder, lines_iter);
            break;
        }


        case X86_INS_ADD: {
            fukutate_add(code_holder, lines_iter);
            break;
        }

        case X86_INS_SUB: {
            fukutate_sub(code_holder, lines_iter);
            break;
        }

        case X86_INS_AND: {
            fukutate_and(code_holder, lines_iter);
            break;
        }


        case X86_INS_INC: {
            fukutate_inc(code_holder, lines_iter);
            break;
        }

        case X86_INS_DEC: {
            fukutate_dec(code_holder, lines_iter);
            break;
        }
                   
        case X86_INS_TEST: {
            fukutate_test(code_holder, lines_iter);
            break;
        }
        case X86_INS_CMP: {
            fukutate_cmp(code_holder, lines_iter);
            break;
        }
        
        case X86_INS_JMP: {
            fukutate_jmp(code_holder, lines_iter);
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
            fukutate_jcc(code_holder, lines_iter);
            break;
        }

                    
        case X86_INS_RET: {
            fukutate_ret(code_holder, lines_iter);
            break;
        }
        
        }
    }


   /*
    for (auto& line : out_lines) {
        if (unstable_stack) {
            line.set_flags(line.get_flags() | fuku_instruction_bad_stack);
        }


        line.set_label_id(0);

        line.set_source_virtual_address(-1);
    }

    out_lines[0].set_source_virtual_address(lines[current_line_idx].get_source_virtual_address());

    out_lines[0].set_label_id(lines[current_line_idx].get_label_id());
    */
}


void fuku_mutation_x86::generate_junk(fuku_code_holder& code_holder,
    linestorage::iterator lines_iter, uint32_t max_size, size_t junk_size) {

    size_t current_size = 0;
    
    while (junk_size != current_size) {

        switch (FUKU_GET_RAND(1, min(min(junk_size - current_size, max_size),7))) {
        case 1: {
            fuku_junk_1b(code_holder, lines_iter); current_size += 1;
            break;
        }
        case 2: {
            fuku_junk_2b(code_holder, lines_iter); current_size += 2;
            break;
        }
        case 3: {
            fuku_junk_3b(code_holder, lines_iter); current_size += 3;
            break;
        }
        case 4: {
            fuku_junk_4b(code_holder, lines_iter); current_size += 4;
            break;
        }
        case 5: {
            fuku_junk_5b(code_holder, lines_iter); current_size += 5;
            break;
        }
        case 6: {
            fuku_junk_6b(code_holder, lines_iter); current_size += 6;
            break;
        }
        case 7: {
            fuku_junk_7b(code_holder, lines_iter); current_size += 7;
            break;
        }
        }
    }
}

