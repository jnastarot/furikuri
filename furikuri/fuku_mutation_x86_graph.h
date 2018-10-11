#pragma once

bool fuku_mutation_x86::fukutate_jcc(fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {
    /*
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
    */

    return false;
}

bool fuku_mutation_x86::fukutate_jmp(fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {
  /*
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
    */
    return false;
}

bool fuku_mutation_x86::fukutate_ret(fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {
    /*
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
    */
    return false;
}