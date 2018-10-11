#pragma once

bool fuku_mutation_x86::fukutate_and(fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {

    //A and B = (A or B) xor A xor B
    /*
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
            

            return true;
        }

        return false;
    }
    */
    return false;
}

bool fuku_mutation_x86::fukutate_test(fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {
    /*
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
                
            }
            else {
                out_lines.push_back(f_asm.push(reg1).set_useless_flags(target_line.get_useless_flags()));
                out_lines.push_back(f_asm.and(reg1, reg2).set_useless_flags(target_line.get_useless_flags()));
                out_lines.push_back(f_asm.pop(reg1));
                /*
                push reg1
                and reg1,reg2
                pop reg1
                
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
                
            }
            else {
                out_lines.push_back(f_asm.push(reg1).set_useless_flags(target_line.get_useless_flags()));
                out_lines.push_back(f_asm.and(reg1, fuku_immediate86(val)).set_useless_flags(target_line.get_useless_flags()));
                out_lines.push_back(f_asm.pop(reg1));

                /*
                push reg
                and reg, imm
                pop reg
                
            }
            return true;
        }
    }

    */
    return false;
}