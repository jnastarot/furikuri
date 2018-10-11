#pragma once

bool fuku_mutation_x86::fukutate_push(fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {

    /*
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
       
        return true;
    }
   */

    return false;
}
bool fuku_mutation_x86::fukutate_pop(fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {

    /*
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
            
        }

        

        return true;
    }
    */
    return false;
}