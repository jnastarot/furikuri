#pragma once

bool fuku_mutation_x86::fukutate_add(fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {

    /*
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
    */
    return false;
}
bool fuku_mutation_x86::fukutate_sub(fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {
    /*
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
    */
    return false;
}

bool fuku_mutation_x86::fukutate_inc(fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {
    /*
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
    */
    return false;
}

bool fuku_mutation_x86::fukutate_dec(fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {
    /*
    auto& target_line = lines[current_line_idx];

    if ((target_line.get_modified_flags() & target_line.get_useless_flags()) == target_line.get_modified_flags()) {
        const uint8_t* code = &target_line.get_op_code()[target_line.get_op_pref_size()];

        if ((code[0] & 0xF0) == 0x40) { //dec reg_dw
            fuku_reg86 reg = fuku_reg86((code[0] & 0x0F) - 8);
            fuku_instruction l_res;

            if (reg == fuku_reg86::r_ESP) { return false; }

            /*
            (add reg,1) or (sub reg,FFFFFFFF)
            

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
    */
    return false;
}

bool fuku_mutation_x86::fukutate_cmp(fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {
    /*
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
                
            }
            else {
                out_lines.push_back(f_asm.push(reg1).set_useless_flags(target_line.get_useless_flags()));
                out_lines.push_back(f_asm.sub(reg1, reg2).set_useless_flags(target_line.get_useless_flags()));
                out_lines.push_back(f_asm.pop(reg1));

                /*
                push reg1
                sub reg1,reg2
                pop reg1
                
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
                
            }
            else {
                out_lines.push_back(f_asm.push(reg1).set_useless_flags(target_line.get_useless_flags()));
                out_lines.push_back(f_asm.sub(reg1, fuku_immediate86(val)).set_useless_flags(target_line.get_useless_flags()));
                out_lines.push_back(f_asm.pop(reg1));

                /*
                push reg
                sub reg, imm
                pop reg
                
            }


            return true;
        }
    }
    */
    return false;
}