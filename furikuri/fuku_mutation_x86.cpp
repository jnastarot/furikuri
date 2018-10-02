#include "stdafx.h"
#include "fuku_mutation_x86.h"

#define ISNT_LAST (lines.size() > current_line_idx+1)

fuku_mutation_x86::fuku_mutation_x86(const fuku_ob_settings& settings)
: settings(settings){}

fuku_mutation_x86::~fuku_mutation_x86() {

}

void fuku_mutation_x86::obfuscate_lines(linestorage& lines, unsigned int recurse_idx) {

    linestorage obf_lines;


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

        obf_lines.insert(obf_lines.end(), single_line.begin(), single_line.end());
    }

    lines = obf_lines;
}

void fuku_mutation_x86::obfuscate(fuku_code_holder& code_holder) {
    obfuscate_lines(code.lines, -1);
}

uint32_t fuku_mutation_x86::set_label(fuku_instruction& line) {
    if (label_seed) {
        if (!line.get_label_id()) {
            line.set_label_id(*label_seed);
            (*label_seed)++;
        }
        return line.get_label_id();
    }
    return 0;
}

uint32_t fuku_mutation_x86::get_maxlabel() {
    if (label_seed) {
        return *label_seed;
    }
    return 0;
}


void fuku_mutation_x86::get_junk(std::vector<uint8_t>& junk, size_t junk_size, bool unstable_stack, uint16_t allow_flags_changes) {

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
}




void fuku_mutation_x86::fukutation(linestorage& lines, unsigned int current_line_idx,
    linestorage& out_lines) {

    bool unstable_stack = lines[current_line_idx].get_flags() & fuku_instruction_bad_stack;

    if (FUKU_GET_CHANCE(settings.junk_chance)) {
        fuku_junk(lines, current_line_idx, out_lines);
    }

    if ( (lines[current_line_idx].get_flags() & fuku_instruction_full_mutated) == 0 &&
        FUKU_GET_CHANCE(settings.mutate_chance)) {

        switch (lines[current_line_idx].get_type()) {

        case X86_INS_PUSH: {
            if (!fukutate_push(lines, current_line_idx, out_lines)) {
                out_lines.push_back(lines[current_line_idx]);
            }
            break;
        }
                     
        case X86_INS_POP: {
            if (!fukutate_pop(lines, current_line_idx, out_lines)) {
                out_lines.push_back(lines[current_line_idx]);
            }
            break;
        }


        case X86_INS_ADD: {
            if (!fukutate_add(lines, current_line_idx, out_lines)) {
                out_lines.push_back(lines[current_line_idx]);
            }
            break;
        }

        case X86_INS_SUB: {
            if (!fukutate_sub(lines, current_line_idx, out_lines)) {
                out_lines.push_back(lines[current_line_idx]);
            }
            break;
        }

        case X86_INS_AND: {
            if (!fukutate_and(lines, current_line_idx, out_lines)) {
                out_lines.push_back(lines[current_line_idx]);
            }
            break;
        }


        case X86_INS_INC: {
            if (!fukutate_inc(lines, current_line_idx, out_lines)) {
                out_lines.push_back(lines[current_line_idx]);
            }
            break;
        }

        case X86_INS_DEC: {
            if (!fukutate_dec(lines, current_line_idx, out_lines)) {
                out_lines.push_back(lines[current_line_idx]);
            }
            break;
        }
                   
        case X86_INS_TEST: {
            if (!fukutate_test(lines, current_line_idx, out_lines)) {
                out_lines.push_back(lines[current_line_idx]);
            }
            break;
        }
        case X86_INS_CMP: {
            if (!fukutate_cmp(lines, current_line_idx, out_lines)) {
                out_lines.push_back(lines[current_line_idx]);
            }
            break;
        }
        
        case X86_INS_JMP: {
            if (!fukutate_jmp(lines, current_line_idx, out_lines)) {
                out_lines.push_back(lines[current_line_idx]);
            }
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
            if (!fukutate_jcc(lines, current_line_idx, out_lines)) {
                out_lines.push_back(lines[current_line_idx]);
            }
            break;
        }

                    
        case X86_INS_RET: {
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


bool fuku_mutation_x86::fukutate_push(linestorage& lines, unsigned int current_line_idx, linestorage& out_lines) {

    auto& target_line = lines[current_line_idx];
    const uint8_t* code = &target_line.get_op_code()[target_line.get_op_pref_size()];

    if (code[0] == 0x6A || 
        code[0] == 0x68 ) {

        uint32_t val;

        if (code[0] == 0x6A) {
            val = *(uint8_t*)&code[1];
        }
        else {
            val = *(uint32_t*)&code[1];
        }

        
        uint32_t needed = (X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_CF | X86_EFLAGS_MODIFY_PF);

        if ((needed & lines[current_line_idx].get_useless_flags()) == needed) {
            out_lines.push_back(f_asm.sub(fuku_reg86::r_ESP, fuku_immediate86(4)).set_useless_flags(target_line.get_useless_flags()).set_flags(fuku_instruction_bad_stack));
        }
        else {
            out_lines.push_back(f_asm.lea(fuku_reg86::r_ESP, fuku_operand86(fuku_reg86::r_ESP, -4)).set_flags(fuku_instruction_bad_stack));
        }
               
        out_lines.push_back(f_asm.mov(fuku_operand86(fuku_reg86::r_ESP,operand_scale::operand_scale_1),fuku_immediate86(val)).set_useless_flags(target_line.get_useless_flags()).set_flags(fuku_instruction_bad_stack));
        
        if (target_line.get_relocation_f_imm_offset()) {

            out_lines[out_lines.size() - 1].set_relocation_f_id(target_line.get_relocation_f_id());
            out_lines[out_lines.size() - 1].set_relocation_f_label_id(target_line.get_relocation_f_label_id());
            out_lines[out_lines.size() - 1].set_relocation_f_destination(target_line.get_relocation_f_destination());
            out_lines[out_lines.size() - 1].set_relocation_f_imm_offset(3);

            out_lines[out_lines.size() - 1].set_flags(fuku_instruction_has_relocation | fuku_instruction_bad_stack);
            
        }

        /*
        //sub esp,4
        //mov [esp],value
       */
        return true;
    } else if ((code[0] & 0xF0) == 0x50) {
        fuku_reg86 reg = fuku_reg86( code[0] & 0x0F);

        uint32_t needed = (X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_CF | X86_EFLAGS_MODIFY_PF);


        if ((needed & lines[current_line_idx].get_useless_flags()) == needed) {
            out_lines.push_back(f_asm.sub(fuku_reg86::r_ESP, fuku_immediate86(4)).set_useless_flags(target_line.get_useless_flags()).set_flags(fuku_instruction_bad_stack));
        }
        else {
            out_lines.push_back(f_asm.lea(fuku_reg86::r_ESP, fuku_operand86(fuku_reg86::r_ESP, -4)).set_flags(fuku_instruction_bad_stack));
        }

        out_lines.push_back(f_asm.mov(fuku_operand86(fuku_reg86::r_ESP, 0), reg).set_useless_flags(target_line.get_useless_flags()).set_flags(fuku_instruction_bad_stack));
        


        /*
        //sub esp,4
        //mov [esp],reg
       */
        return true;
    }
   

    return false;
}
bool fuku_mutation_x86::fukutate_pop(linestorage& lines, unsigned int current_line_idx, linestorage& out_lines) {


    auto& target_line = lines[current_line_idx];
    const uint8_t* code = &target_line.get_op_code()[target_line.get_op_pref_size()];

     if ((code[0] & 0xF0) == 0x50) {
        fuku_reg86 reg = fuku_reg86(code[0] % 8);

        uint32_t needed = (X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_CF | X86_EFLAGS_MODIFY_PF);

        if (FUKU_GET_RAND(0, 10) < 5) {

            out_lines.push_back(f_asm.mov(reg, fuku_operand86(fuku_reg86::r_ESP, operand_scale::operand_scale_1)).set_useless_flags(target_line.get_useless_flags()));

            if ((needed & lines[current_line_idx].get_useless_flags()) == needed) {
                out_lines.push_back(f_asm.add(fuku_reg86::r_ESP, fuku_immediate86(4)).set_useless_flags(target_line.get_useless_flags()));
            }
            else {
                out_lines.push_back(f_asm.lea(fuku_reg86::r_ESP, fuku_operand86(fuku_reg86::r_ESP, 4)));
            }

            /*
            //mov reg,[esp]
            //add esp,4
            */
        }
        else {

            if ((needed & lines[current_line_idx].get_useless_flags()) == needed) {
                out_lines.push_back(f_asm.add(fuku_reg86::r_ESP, fuku_immediate86(4)).set_useless_flags(target_line.get_useless_flags()));
            }
            else {
                out_lines.push_back(f_asm.lea(fuku_reg86::r_ESP, fuku_operand86(fuku_reg86::r_ESP, 4)));
            }

            out_lines.push_back(f_asm.mov(reg, fuku_operand86(fuku_reg86::r_ESP, -4)).set_useless_flags(target_line.get_useless_flags()).set_flags(fuku_instruction_bad_stack));


            /*
            //add esp,4
            //mov reg,[esp - 4]
            */
        }

        

        return true;
    }

    return false;
}
bool fuku_mutation_x86::fukutate_add(linestorage& lines, unsigned int current_line_idx, linestorage& out_lines) {


    auto& target_line = lines[current_line_idx];
    
    if (((target_line.get_flags() & fuku_instruction_bad_stack) == 0) &&
        (target_line.get_modified_flags() & target_line.get_useless_flags()) == target_line.get_modified_flags() &&
        !target_line.get_relocation_f_imm_offset()) {

        const uint8_t* code = &target_line.get_op_code()[target_line.get_op_pref_size()];

        if (code[0] == 0x05 ||  //add reg,imm
            ((code[0] == 0x81 || code[0] == 0x83) && (code[1] >= 0xC0 && code[1] < 0xC8)) ) {

            fuku_reg86 reg1;
            uint32_t val;

            if (code[0] == 0x05) {
                reg1 = fuku_reg86::r_EAX;
                val = *(uint32_t*)&code[1];
            }
            else {
                reg1 = fuku_reg86(code[1] - 0xC0);
                if (code[0] == 0x81) {
                    val = *(uint32_t*)&code[2];
                }
                else {
                    val = *(int8_t*)&code[2];
                }
            }

            if (reg1 == fuku_reg86::r_ESP) { return false; }

            switch (FUKU_GET_RAND(1, 2)) {
            case 1: {
                unsigned int passes_number = FUKU_GET_RAND(2, 4);
                uint32_t current_val = 0;

                for (unsigned int pass = 0; pass < passes_number; pass++ ) {

                    switch (FUKU_GET_RAND(1, 2)) {

                    case 1: {
                        if (pass + 1 < passes_number) {
                            uint32_t rand_val = FUKU_GET_RAND(0, 0xFFFFFFFF);
                            out_lines.push_back(f_asm.sub(reg1, fuku_immediate86(rand_val)).set_useless_flags(target_line.get_useless_flags()));
                            current_val -= rand_val;
                        }
                        else {
                            out_lines.push_back(f_asm.sub(reg1, fuku_immediate86(current_val - val)).set_useless_flags(target_line.get_useless_flags()));
                            current_val -= (current_val - val);
                        }
                        break;
                    }
                    case 2: {
                        if (pass + 1 < passes_number) {
                            uint32_t rand_val = FUKU_GET_RAND(0, 0xFFFFFFFF);
                            out_lines.push_back(f_asm.add(reg1, fuku_immediate86(rand_val)).set_useless_flags(target_line.get_useless_flags()));
                            current_val += rand_val;
                        }
                        else {
                            out_lines.push_back(f_asm.add(reg1, fuku_immediate86(val - current_val)).set_useless_flags(target_line.get_useless_flags()));
                            current_val += (val - current_val);                       
                        }
                        break;
                    }
                    }
                }
                break;
            }

            case 2: {
                out_lines.push_back(f_asm.sub(reg1, fuku_immediate86((-(int32_t)val))).set_useless_flags(target_line.get_useless_flags()));
                break;
            }
            }
            

            return true;
        }
    }

    return false;
}
bool fuku_mutation_x86::fukutate_sub(linestorage& lines, unsigned int current_line_idx, linestorage& out_lines) {

    auto& target_line = lines[current_line_idx];

    if (((target_line.get_flags() & fuku_instruction_bad_stack) == 0) && 
        (target_line.get_modified_flags() & target_line.get_useless_flags()) == target_line.get_modified_flags() &&
        !target_line.get_relocation_f_imm_offset()) {

        const uint8_t* code = &target_line.get_op_code()[target_line.get_op_pref_size()];

        if (code[0] == 0x2D ||  //sub reg,imm
            ((code[0] == 0x81 || code[0] == 0x83) && (code[1] >= 0xE8 && code[1] < 0xF0))) {

            fuku_reg86 reg1;
            uint32_t val;

            if (code[0] == 0x2D) {
                reg1 = fuku_reg86::r_EAX;
                val = *(uint32_t*)&code[1];
            }
            else {
                reg1 = fuku_reg86(code[1] - 0xE8);
                if (code[0] == 0x81) {
                    val = *(uint32_t*)&code[2];
                }
                else {
                    val = *(int8_t*)&code[2];
                }
            }

            if (reg1 == fuku_reg86::r_ESP) { return false; }

            val = -(int32_t)val;

            switch (FUKU_GET_RAND(1, 2)) {
            case 1: {
                unsigned int passes_number = FUKU_GET_RAND(2, 4);
                uint32_t current_val = 0;

                for (unsigned int pass = 0; pass < passes_number; pass++) {

                    switch (FUKU_GET_RAND(1, 2)) {

                    case 1: {
                        if (pass + 1 < passes_number) {
                            uint32_t rand_val = FUKU_GET_RAND(0, 0xFFFFFFFF);
                            out_lines.push_back(f_asm.sub(reg1, fuku_immediate86(rand_val)).set_useless_flags(target_line.get_useless_flags()));
                            current_val -= rand_val;
                        }
                        else {
                            out_lines.push_back(f_asm.sub(reg1, fuku_immediate86(current_val - val)).set_useless_flags(target_line.get_useless_flags()));
                            current_val -= (current_val - val);
                        }
                        break;
                    }
                    case 2: {
                        if (pass + 1 < passes_number) {
                            uint32_t rand_val = FUKU_GET_RAND(0, 0xFFFFFFFF);
                            out_lines.push_back(f_asm.add(reg1, fuku_immediate86(rand_val)).set_useless_flags(target_line.get_useless_flags()));
                            current_val += rand_val;
                        }
                        else {
                            out_lines.push_back(f_asm.add(reg1, fuku_immediate86(val - current_val)).set_useless_flags(target_line.get_useless_flags()));
                            current_val += (val - current_val);
                        }
                        break;
                    }
                    }
                }
                break;
            }

            case 2: {
                out_lines.push_back(f_asm.sub(reg1, fuku_immediate86((-(int32_t)val))).set_useless_flags(target_line.get_useless_flags()));
                break;
            }
            }


            return true;
        }
    }

    return false;
}

bool fuku_mutation_x86::fukutate_and(linestorage& lines, unsigned int current_line_idx, linestorage& out_lines) {

    //A and B = (A or B) xor A xor B

    auto& target_line = lines[current_line_idx];

    if (((target_line.get_flags() & fuku_instruction_bad_stack) == 0) && 
        (target_line.get_modified_flags() & target_line.get_useless_flags()) == target_line.get_modified_flags() &&
        !target_line.get_relocation_f_imm_offset()) {

        const uint8_t* code = &target_line.get_op_code()[target_line.get_op_pref_size()];

        if (
            (code[0] == 0x21 || code[0] == 0x23) && code[1] >= 0xC0) { //and reg_dw, reg_dw
            fuku_reg86 reg1 = fuku_reg86( (code[1] - 0xC0) % 8);
            fuku_reg86 reg2 = fuku_reg86( (code[1] - 0xC0) / 8);
            fuku_reg86 reg3 = fuku_reg86::r_EAX;

            if (code[0] == 0x23) {  std::swap(reg1, reg2); }

            for (reg3 = fuku_reg86::r_EAX; reg3 < fuku_reg86::r_EBX; reg3 = fuku_reg86(reg3+1)) {}

            out_lines.push_back(f_asm.push(reg3).set_useless_flags(target_line.get_useless_flags()));
            out_lines.push_back(f_asm.mov(reg3, reg1).set_useless_flags(target_line.get_useless_flags()));
            out_lines.push_back(f_asm.or(reg1,reg2).set_useless_flags(target_line.get_useless_flags()));
            out_lines.push_back(f_asm.xor(reg1, reg3).set_useless_flags(target_line.get_useless_flags()));
            out_lines.push_back(f_asm.xor(reg1, reg2).set_useless_flags(target_line.get_useless_flags()));
            out_lines.push_back(f_asm.pop(reg3).set_useless_flags(target_line.get_useless_flags()));

            /*
            push reg3
            mov reg3, reg1
            or  reg1, reg2
            xor reg1, reg3
            xor reg1, reg2
            pop reg3
            */

            return true;
        }
        else if (( (code[0] == 0x81 || code[0] == 0x83) && (code[1] & 0xF0) == 0xE0 && code[1] < 0xE8) || code[1] == 0x25) { //and reg_dw , val //and reg_b , val
            fuku_reg86 reg1;
            fuku_reg86 reg2;
            uint32_t val;

            if (code[1] == 0x25) {
                reg1 = fuku_reg86::r_EAX;
                reg2 = fuku_reg86::r_ECX;
                val = *(uint32_t*)&code[1];
            }
            else {
                reg1 = fuku_reg86((code[1] - 0xE0) & 0x0F);
                reg2 = fuku_reg86::r_ECX;

                if (code[0] == 0x83) {
                    val = *(uint8_t*)&code[2];
                }
                else {
                    val = *(uint32_t*)&code[2];
                }

                for (reg2 = fuku_reg86::r_EAX; reg2 < fuku_reg86::r_EBX; reg2 = fuku_reg86(reg2 + 1)) {}
            }
           
            out_lines.push_back(f_asm.push(reg2).set_useless_flags(target_line.get_useless_flags()));
            out_lines.push_back(f_asm.mov(reg2, reg1).set_useless_flags(target_line.get_useless_flags()));
            out_lines.push_back(f_asm.or(reg1, val).set_useless_flags(target_line.get_useless_flags()));
            out_lines.push_back(f_asm.xor(reg1, reg2).set_useless_flags(target_line.get_useless_flags()));
            out_lines.push_back(f_asm.xor(reg1, val).set_useless_flags(target_line.get_useless_flags()));
            out_lines.push_back(f_asm.pop(reg2).set_useless_flags(target_line.get_useless_flags()));

            /*
            push reg2
            mov reg2, reg1
            or  reg1, val
            xor reg1, reg2
            xor reg1, val
            pop reg2
            */

            return true;
        }

        return false;
    }

    return false;
}

bool fuku_mutation_x86::fukutate_inc(linestorage& lines, unsigned int current_line_idx, linestorage& out_lines) {

    auto& target_line = lines[current_line_idx];

    if (((target_line.get_flags() & fuku_instruction_bad_stack) == 0) && 
        (target_line.get_modified_flags() & target_line.get_useless_flags()) == target_line.get_modified_flags()) {

        const uint8_t* code = &target_line.get_op_code()[target_line.get_op_pref_size()];

        if ((code[0] & 0xF0) == 0x40) { //inc reg_dw 
            fuku_reg86 reg = fuku_reg86(code[0] & 0x0F);
            fuku_instruction l_res;

            if (reg == fuku_reg86::r_ESP) { return false; }

            /*
            (add reg,FFFFFFFF) or (sub reg,1)
            */

            if (FUKU_GET_CHANCE(50.f)) {
                l_res = f_asm.add(reg, fuku_immediate86(1));
            }
            else {
                l_res = f_asm.sub(reg, fuku_immediate86(0xFFFFFFFF));
            }

            l_res.set_useless_flags(target_line.get_useless_flags());

            out_lines.push_back(l_res);

            return true;
        }
        
        return false;
    }

    return false;
}
bool fuku_mutation_x86::fukutate_dec(linestorage& lines, unsigned int current_line_idx, linestorage& out_lines) {

    auto& target_line = lines[current_line_idx];

    if ((target_line.get_modified_flags() & target_line.get_useless_flags()) == target_line.get_modified_flags()) {
        const uint8_t* code = &target_line.get_op_code()[target_line.get_op_pref_size()];

        if ((code[0] & 0xF0) == 0x40) { //dec reg_dw
            fuku_reg86 reg = fuku_reg86((code[0] & 0x0F) - 8);
            fuku_instruction l_res;

            if (reg == fuku_reg86::r_ESP) { return false; }

            /*
            (add reg,1) or (sub reg,FFFFFFFF)
            */

            if (FUKU_GET_CHANCE(50.f)) {
                l_res = f_asm.add(reg, fuku_immediate86(0xFFFFFFFF));
            }
            else {
                l_res = f_asm.sub(reg, fuku_immediate86(1));
            }

            l_res.set_useless_flags(target_line.get_useless_flags());

            out_lines.push_back(l_res);

            return true;
        }

        return false;
    }

    return false;
}
bool fuku_mutation_x86::fukutate_test(linestorage& lines, unsigned int current_line_idx, linestorage& out_lines) {

    auto& target_line = lines[current_line_idx];
    const uint8_t* code = &target_line.get_op_code()[target_line.get_op_pref_size()];

    if (((target_line.get_flags() & fuku_instruction_bad_stack) == 0) &&
        !target_line.get_relocation_f_imm_offset()) {

        if (code[0] == 0x85 && (code[1] >= 0xC0 && code[1] < 0xC8)) { //test reg1,reg2
            fuku_reg86 reg1 = fuku_reg86((code[1] - 0xC0) % 8);
            fuku_reg86 reg2 = fuku_reg86((code[1] - 0xC0) / 8);

            if (reg1 == fuku_reg86::r_ESP) {
                fuku_reg86 reg3;
                for (reg3 = fuku_reg86::r_EAX; reg3 < fuku_reg86::r_EBX; reg3 = fuku_reg86(reg3 + 1)) {}

                out_lines.push_back(f_asm.push(reg3).set_useless_flags(target_line.get_useless_flags()));
                out_lines.push_back(f_asm.mov(reg3, reg1).set_useless_flags(target_line.get_useless_flags()));
                out_lines.push_back(f_asm.lea(reg3, fuku_operand86(reg3, operand_scale::operand_scale_1, 4)).set_useless_flags(target_line.get_useless_flags()));
                out_lines.push_back(f_asm.and(reg3, reg2).set_useless_flags(target_line.get_useless_flags()));
                out_lines.push_back(f_asm.pop(reg3));

                /*
                push reg3
                mov reg3,reg1
                lea reg3, [reg3 + 4]
                and reg3,reg2
                pop reg3
                */
            }
            else {
                out_lines.push_back(f_asm.push(reg1).set_useless_flags(target_line.get_useless_flags()));
                out_lines.push_back(f_asm.and(reg1, reg2).set_useless_flags(target_line.get_useless_flags()));
                out_lines.push_back(f_asm.pop(reg1));
                /*
                push reg1
                and reg1,reg2
                pop reg1
                */
            }

            return true;
        }
        else if (code[0] == 0xA9 || (code[0] == 0xF7 && code[1] >= 0xC0 && code[1] < 0xC8)) { //test reg, imm
            fuku_reg86 reg1;
            uint32_t val;
            if (code[0] == 0xA9) {
                reg1 = fuku_reg86::r_EAX;
                val = *(uint32_t*)&code[1];
            }
            else {
                reg1 = fuku_reg86(code[1] - 0xC0);
                val = *(uint32_t*)&code[2];
            }

            if (reg1 == fuku_reg86::r_ESP) {
                fuku_reg86 reg2;
                for (reg2 = fuku_reg86::r_EAX; reg2 < fuku_reg86::r_EBX; reg2 = fuku_reg86(reg2 + 1)) {}

                out_lines.push_back(f_asm.push(reg2).set_useless_flags(target_line.get_useless_flags()));
                out_lines.push_back(f_asm.mov(reg2, reg1).set_useless_flags(target_line.get_useless_flags()));
                out_lines.push_back(f_asm.lea(reg2, fuku_operand86(reg2, operand_scale::operand_scale_1, 4)).set_useless_flags(target_line.get_useless_flags()));
                out_lines.push_back(f_asm.and(reg2, fuku_immediate86(val)).set_useless_flags(target_line.get_useless_flags()));
                out_lines.push_back(f_asm.pop(reg2));

                /*
                push reg2
                mov reg2,reg1
                lea reg2, [reg2 + 4]
                sub reg2,imm
                pop reg3
                */
            }
            else {
                out_lines.push_back(f_asm.push(reg1).set_useless_flags(target_line.get_useless_flags()));
                out_lines.push_back(f_asm.and(reg1, fuku_immediate86(val)).set_useless_flags(target_line.get_useless_flags()));
                out_lines.push_back(f_asm.pop(reg1));

                /*
                push reg
                and reg, imm
                pop reg
                */
            }
            return true;
        }
    }


    return false;
}
bool fuku_mutation_x86::fukutate_cmp(linestorage& lines, unsigned int current_line_idx, linestorage& out_lines) {

    auto& target_line = lines[current_line_idx];
    const uint8_t* code = &target_line.get_op_code()[target_line.get_op_pref_size()];

    if (((target_line.get_flags() & fuku_instruction_bad_stack) == 0) &&
        !target_line.get_relocation_f_imm_offset()) {

        if ((code[0] == 0x39 || code[0] == 0x3B) && (code[1] >= 0xC0 && code[1] < 0xC8)) { //cmp reg1,reg2
            fuku_reg86 reg1 = fuku_reg86((code[1] - 0xC0) % 8);
            fuku_reg86 reg2 = fuku_reg86((code[1] - 0xC0) / 8);

            if (code[0] == 0x3B) {
                std::swap(reg1, reg2);
            }


            if (reg1 == fuku_reg86::r_ESP) {
                fuku_reg86 reg3;
                for (reg3 = fuku_reg86::r_EAX; reg3 < fuku_reg86::r_EBX; reg3 = fuku_reg86(reg3 + 1)) {}


                out_lines.push_back(f_asm.push(reg3).set_useless_flags(target_line.get_useless_flags()));
                out_lines.push_back(f_asm.mov(reg3, reg1).set_useless_flags(target_line.get_useless_flags()));
                out_lines.push_back(f_asm.lea(reg3, fuku_operand86(reg3, operand_scale::operand_scale_1, 4)).set_useless_flags(target_line.get_useless_flags()));
                out_lines.push_back(f_asm.sub(reg3, reg2).set_useless_flags(target_line.get_useless_flags()));
                out_lines.push_back(f_asm.pop(reg3));

                /*
                push reg3
                mov reg3,reg1
                lea reg3, [reg3 + 4]
                sub reg3,reg2
                pop reg3
                */
            }
            else {
                out_lines.push_back(f_asm.push(reg1).set_useless_flags(target_line.get_useless_flags()));
                out_lines.push_back(f_asm.sub(reg1, reg2).set_useless_flags(target_line.get_useless_flags()));
                out_lines.push_back(f_asm.pop(reg1));

                /*
                push reg1
                sub reg1,reg2
                pop reg1
                */
            }

            return true;
        }
        else if (code[0] == 0x39 || (code[0] == 0x81 && code[1] >= 0xF8)) { //cmp reg, imm
            fuku_reg86 reg1;
            uint32_t val;
            if (code[0] == 0x39) {
                reg1 = fuku_reg86::r_EAX;
                val = *(uint32_t*)&code[1];
            }
            else {
                reg1 = fuku_reg86(code[1] - 0xF8);
                val = *(uint32_t*)&code[2];
            }

            if (reg1 == fuku_reg86::r_ESP) {
                fuku_reg86 reg2;
                for (reg2 = fuku_reg86::r_EAX; reg2 < fuku_reg86::r_EBX; reg2 = fuku_reg86(reg2 + 1)) {}

                out_lines.push_back(f_asm.push(reg2).set_useless_flags(target_line.get_useless_flags()));
                out_lines.push_back(f_asm.mov(reg2, reg1).set_useless_flags(target_line.get_useless_flags()));
                out_lines.push_back(f_asm.lea(reg2, fuku_operand86(reg2, operand_scale::operand_scale_1, 4)).set_useless_flags(target_line.get_useless_flags()));
                out_lines.push_back(f_asm.sub(reg2, fuku_immediate86(val)).set_useless_flags(target_line.get_useless_flags()));
                out_lines.push_back(f_asm.pop(reg2));

                /*
                push reg2
                mov reg2,reg1
                lea reg2, [reg2 + 4]
                sub reg2,imm
                pop reg3
                */
            }
            else {
                out_lines.push_back(f_asm.push(reg1).set_useless_flags(target_line.get_useless_flags()));
                out_lines.push_back(f_asm.sub(reg1, fuku_immediate86(val)).set_useless_flags(target_line.get_useless_flags()));
                out_lines.push_back(f_asm.pop(reg1));

                /*
                push reg
                sub reg, imm
                pop reg
                */
            }


            return true;
        }
    }

    return false;
}
bool fuku_mutation_x86::fukutate_jcc(linestorage& lines, unsigned int current_line_idx, linestorage& out_lines) {

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

        fuku_instruction l_jcc = f_asm.jcc(fuku_condition(cond^1),0).set_useless_flags(target_line.get_useless_flags());
        l_jcc.set_link_label_id(set_label(lines[current_line_idx+1]));
        l_jcc.set_flags(l_jcc.get_flags() | fuku_instruction_full_mutated);

        out_lines.push_back(l_jcc);
        out_lines.push_back(l_jmp);
        return true;
    }


    return false;
}

bool fuku_mutation_x86::fukutate_jmp(linestorage& lines, unsigned int current_line_idx, linestorage& out_lines) {
  
    auto& target_line = lines[current_line_idx];

    if (((target_line.get_flags() & fuku_instruction_bad_stack) == 0)) {
        if (target_line.get_op_code()[0] == 0xE9) {

            fuku_instruction l_push = f_asm.push_imm32(0).set_useless_flags(target_line.get_useless_flags()); //push 00000000

            l_push.set_flags(fuku_instruction_has_relocation);
            l_push.set_relocation_f_imm_offset(1);
            l_push.set_relocation_f_id(0);
            l_push.set_relocation_f_label_id(target_line.get_link_label_id());      
            l_push.set_relocation_f_destination(target_line.get_ip_relocation_destination());

            out_lines.push_back(l_push);
            out_lines.push_back(f_asm.ret(0).set_useless_flags(target_line.get_useless_flags()));//ret
            return true;
        }
    }

    return false;
}

bool fuku_mutation_x86::fukutate_ret(linestorage& lines, unsigned int current_line_idx, linestorage& out_lines) {

    auto& target_line = lines[current_line_idx];

    if (((target_line.get_flags() & fuku_instruction_bad_stack) == 0)) {
        if (target_line.get_op_code()[0] == 0xC3) { //ret

            out_lines.push_back(f_asm.lea(fuku_reg86::r_ESP, fuku_operand86(fuku_reg86::r_ESP, 4)));                   //lea esp,[esp + 4]
            out_lines.push_back(f_asm.jmp(fuku_operand86(r_ESP, -4)).set_flags(fuku_instruction_bad_stack));           //jmp [esp - 4] 

            return true;

        }
        else if (target_line.get_op_code()[0] == 0xC2) { //ret 0x0000
            uint16_t ret_stack = *(uint16_t*)&target_line.get_op_code()[1];
            out_lines.push_back(f_asm.lea(fuku_reg86::r_ESP, fuku_operand86(fuku_reg86::r_ESP, 4 + ret_stack)).set_useless_flags(target_line.get_useless_flags()));     //lea esp,[esp + (4 + stack_offset)]
            out_lines.push_back(f_asm.jmp(fuku_operand86(r_ESP, -4 - ret_stack)).set_flags(fuku_instruction_bad_stack).set_useless_flags(target_line.get_useless_flags()));         //jmp [esp - 4 - stack_offset] 

            return true;
        }
        
    }

    return false;
}

void fuku_mutation_x86::generate_junk(linestorage& junk,
    fuku_instruction* next_line, uint32_t max_size, size_t junk_size, bool unstable_stack, uint16_t allow_flags_changes) {

    size_t current_size = 0;

    while (junk_size != current_size) {

        switch (FUKU_GET_RAND(1, min(min(junk_size - current_size, max_size),7))) {
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

void fuku_mutation_x86::fuku_junk(linestorage& lines, unsigned int current_line_idx,
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
        fuku_junk_6b(out_lines,  &lines[current_line_idx], unstable_stack, lines[current_line_idx].get_useless_flags());
        break;
    }
    case 6: {
        fuku_junk_7b(out_lines, &lines[current_line_idx], unstable_stack, lines[current_line_idx].get_useless_flags());
        break;
    }
    }
}


void fuku_mutation_x86::fuku_junk_1b(linestorage& out_lines, 
    fuku_instruction* next_line, bool unstable_stack, uint16_t allow_flags_changes) {
    out_lines.push_back(f_asm.nop());
}

void fuku_mutation_x86::fuku_junk_2b(linestorage& out_lines, 
    fuku_instruction* next_line, bool unstable_stack, uint16_t allow_flags_changes) {


    switch (FUKU_GET_RAND(0, 4)) {
    
    case 0: {

        fuku_reg86 reg1 = fuku_reg86(FUKU_GET_RAND(fuku_reg86::r_EAX, fuku_reg86::r_EBX));
        out_lines.push_back(f_asm.mov(reg1,reg1).set_useless_flags(allow_flags_changes));
        break;
    }
    case 1: {
    jk_2s:

        fuku_reg86 reg1 = fuku_reg86::r_EAX;
        fuku_reg86 reg2 = fuku_reg86(FUKU_GET_RAND(fuku_reg86::r_EAX, fuku_reg86::r_EDI));
        
        if (FUKU_GET_RAND(0, 1)) {
            out_lines.push_back(f_asm.xchg(reg1, reg2).set_useless_flags(allow_flags_changes));
        }
        else {
            out_lines.push_back(f_asm.xchg(reg2, reg1).set_useless_flags(allow_flags_changes));
        }

        if (FUKU_GET_RAND(0, 1)) {
            out_lines.push_back(f_asm.xchg(reg1, reg2).set_useless_flags(allow_flags_changes));
        }
        else {
            out_lines.push_back(f_asm.xchg(reg2, reg1).set_useless_flags(allow_flags_changes));
        }

        if (reg1 == fuku_reg86::r_ESP || reg2 == fuku_reg86::r_ESP) {
            out_lines[out_lines.size() - 1].set_flags(fuku_instruction_bad_stack);
        }

        break;
    }
    case 2: {
    jk_3s:

        fuku_reg86 reg1 = fuku_reg86(FUKU_GET_RAND(fuku_reg86::r_EAX, fuku_reg86::r_EBX));

        if (!unstable_stack ) {
            out_lines.push_back(f_asm.push(reg1));
            out_lines.push_back(f_asm.pop(reg1));
        }
        else {
            out_lines.push_back(f_asm.lea(reg1, fuku_operand86(reg1, operand_scale::operand_scale_1, 0)).set_useless_flags(allow_flags_changes));
        }

        break;
    }

    case 3: {
        uint32_t needed = (X86_EFLAGS_MODIFY_CF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_AF);

        if ((needed & allow_flags_changes) == needed) {
            fuku_reg86 reg1 = fuku_reg86(FUKU_GET_RAND(fuku_reg86::r_EAX, fuku_reg86::r_EDI));
            fuku_reg86 reg2 = fuku_reg86(FUKU_GET_RAND(fuku_reg86::r_EAX, fuku_reg86::r_EDI));
            out_lines.push_back(f_asm.cmp(reg1, reg2).set_useless_flags(allow_flags_changes));
        }
        else {
            goto jk_2s;
        }
        break;
    }
    case 4: {
        uint32_t needed = (X86_EFLAGS_MODIFY_CF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_AF);

        if ((needed & allow_flags_changes) == needed) {
            fuku_reg86 reg1 = fuku_reg86(FUKU_GET_RAND(fuku_reg86::r_EAX, fuku_reg86::r_EDI));
            fuku_reg86 reg2 = fuku_reg86(FUKU_GET_RAND(fuku_reg86::r_EAX, fuku_reg86::r_EDI));
            out_lines.push_back(f_asm.test(reg1, reg2).set_useless_flags(allow_flags_changes));
        }
        else {
            goto jk_3s;
        }

        break;
    }

    }
}

void fuku_mutation_x86::fuku_junk_3b(linestorage& out_lines,
    fuku_instruction* next_line, bool unstable_stack, uint16_t allow_flags_changes) {

    switch (FUKU_GET_RAND(0, 3)) {
    case 0: {
        uint32_t needed = (X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_CF);

        if ((needed & allow_flags_changes) == needed) {
            fuku_reg86 reg1 = fuku_reg86(FUKU_GET_RAND(fuku_reg86::r_EAX, fuku_reg86::r_EDI));
            out_lines.push_back(f_asm.ror(reg1, 0).set_useless_flags(allow_flags_changes));
        }
        else {
            generate_junk(out_lines, next_line, 2, 3, unstable_stack, allow_flags_changes);
        }
   
        break;
    }
    case 1: {
        uint32_t needed = (X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_CF);

        if ((needed & allow_flags_changes) == needed) {
            fuku_reg86 reg1 = fuku_reg86(FUKU_GET_RAND(fuku_reg86::r_EAX, fuku_reg86::r_EDI));
            out_lines.push_back(f_asm.rol(reg1, 0).set_useless_flags(allow_flags_changes));
        }
        else {
            generate_junk(out_lines, next_line, 2, 3, unstable_stack, allow_flags_changes);
        }
        break;
    }
    case 2: {
        uint32_t needed = (X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_CF | X86_EFLAGS_MODIFY_PF);

        if ((needed & allow_flags_changes) == needed) {
            out_lines.push_back(f_asm.sub(fuku_reg86::r_EAX, fuku_immediate86(0)).set_useless_flags(allow_flags_changes));
        }
        else {
            generate_junk(out_lines, next_line, 2, 3, unstable_stack, allow_flags_changes);
        }
        break;
    }
    case 3: {
        uint32_t needed = (X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_CF | X86_EFLAGS_MODIFY_PF);

        if ((needed & allow_flags_changes) == needed) {
            out_lines.push_back(f_asm.add(fuku_reg86::r_EAX, fuku_immediate86(0)).set_useless_flags(allow_flags_changes));
        }
        else {
            generate_junk(out_lines, next_line, 2, 3, unstable_stack, allow_flags_changes);
        }
        break;
    }
    }
}

void fuku_mutation_x86::fuku_junk_4b(linestorage& out_lines,
    fuku_instruction* next_line, bool unstable_stack, uint16_t allow_flags_changes) {

    switch (FUKU_GET_RAND(0, 1)) {
    case 0: {
        fuku_reg86 reg1 = fuku_reg86(FUKU_GET_RAND(fuku_reg86::r_EAX, fuku_reg86::r_EDI));

        out_lines.push_back(f_asm.not(reg1).set_useless_flags(allow_flags_changes));
        out_lines.push_back(f_asm.not(reg1).set_useless_flags(allow_flags_changes));

        if (reg1 == fuku_reg86::r_ESP) {
            out_lines[out_lines.size() - 1].set_flags(fuku_instruction_bad_stack);
        }
        break;
    }
    case 1: {
        fuku_reg86 reg1 = fuku_reg86(FUKU_GET_RAND(fuku_reg86::r_ECX, fuku_reg86::r_EDI));
        fuku_reg86 reg2 = fuku_reg86(FUKU_GET_RAND(fuku_reg86::r_ECX, fuku_reg86::r_EDI));

        if (FUKU_GET_RAND(0, 1)) {
            out_lines.push_back(f_asm.xchg(reg1, reg2).set_useless_flags(allow_flags_changes));
        }
        else {
            out_lines.push_back(f_asm.xchg(reg2, reg1).set_useless_flags(allow_flags_changes));
        }

        if (FUKU_GET_RAND(0, 1)) {
            out_lines.push_back(f_asm.xchg(reg1, reg2).set_useless_flags(allow_flags_changes));
        }
        else {
            out_lines.push_back(f_asm.xchg(reg2, reg1).set_useless_flags(allow_flags_changes));
        }

        if (reg1 == fuku_reg86::r_ESP || reg2 == fuku_reg86::r_ESP) {
            out_lines[out_lines.size() - 1].set_flags(fuku_instruction_bad_stack);
        }

        break;
    }

    }

}

void fuku_mutation_x86::fuku_junk_5b(linestorage& out_lines,
    fuku_instruction* next_line, bool unstable_stack, uint16_t allow_flags_changes) {

    
    switch (FUKU_GET_RAND(0, 1)) {
    case 0: {
        uint32_t needed = (X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_CF | X86_EFLAGS_MODIFY_PF);

        if ((needed & allow_flags_changes) == needed) {
            out_lines.push_back(f_asm.sub(fuku_reg86::r_EAX, fuku_immediate86(0)).set_useless_flags(allow_flags_changes));
        }
        else {
            generate_junk(out_lines, next_line, 4, 5, unstable_stack, allow_flags_changes);
        }
        break;
    }
    case 1: {
        uint32_t needed = (X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_CF | X86_EFLAGS_MODIFY_PF);

        if ((needed & allow_flags_changes) == needed) {
            out_lines.push_back(f_asm.add(fuku_reg86::r_EAX, fuku_immediate86(0)).set_useless_flags(allow_flags_changes));
        }
        else {
            generate_junk(out_lines, next_line, 4, 5, unstable_stack, allow_flags_changes);
        }
        break;
    }
    }
}

void fuku_mutation_x86::fuku_junk_6b(linestorage& out_lines,
    fuku_instruction* next_line, bool unstable_stack, uint16_t allow_flags_changes) {

    switch (FUKU_GET_RAND(0, 1)) {
    case 0: {
        uint32_t needed = (X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_CF | X86_EFLAGS_MODIFY_PF);

        if ((needed & allow_flags_changes) == needed) {
            fuku_reg86 reg1 = fuku_reg86(FUKU_GET_RAND(fuku_reg86::r_ECX, fuku_reg86::r_EDI));
            out_lines.push_back(f_asm.sub(reg1, fuku_immediate86(0)).set_useless_flags(allow_flags_changes));
        }
        else {
            generate_junk(out_lines, next_line, 5, 6, unstable_stack, allow_flags_changes);
        }
        break;
    }
    case 1: {
        uint32_t needed = (X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_CF | X86_EFLAGS_MODIFY_PF);
        
        if ((needed & allow_flags_changes) == needed) {
            fuku_reg86 reg1 = fuku_reg86(FUKU_GET_RAND(fuku_reg86::r_ECX, fuku_reg86::r_EDI));
            out_lines.push_back(f_asm.add(reg1, fuku_immediate86(0)).set_useless_flags(allow_flags_changes));
        }
        else {
            generate_junk(out_lines, next_line, 5, 6, unstable_stack, allow_flags_changes);
        }
        break;
    }
    }
}


void fuku_mutation_x86::fuku_junk_7b(linestorage& out_lines,
    fuku_instruction* next_line, bool unstable_stack, uint16_t allow_flags_changes) {


    if (!unstable_stack) {
        fuku_reg86 reg1 = fuku_reg86(FUKU_GET_RAND(fuku_reg86::r_EAX, fuku_reg86::r_EBX));
        fuku_immediate86 imm = fuku_immediate86(FUKU_GET_RAND(0x10000000, 0xFFFFFFFF));
        out_lines.push_back(f_asm.push(reg1));
        out_lines.push_back(f_asm.mov(reg1, imm).set_useless_flags(allow_flags_changes));

        if (FUKU_GET_RAND(0, 1)) {
            auto& line = out_lines[out_lines.size() - 1];
            line.set_relocation_f_id(0);
            line.set_relocation_f_destination(imm.get_imm());
            line.set_relocation_f_imm_offset(1);

            if (label_seed) {
                line.set_relocation_f_label_id(FUKU_GET_RAND(1, get_maxlabel() - 1));
            }

            line.set_flags(fuku_instruction_has_relocation);
        }

        out_lines.push_back(f_asm.pop(reg1).set_useless_flags(allow_flags_changes));
    }
    else {
        generate_junk(out_lines, next_line, 6, 7, unstable_stack, allow_flags_changes);
    }

}