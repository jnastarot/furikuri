#include "stdafx.h"
#include "fuku_mutation_x64_rules.h"

/*
//graph     JCC/JMP/RET
bool fukutate_jcc(cs_insn *instruction, fuku_asm_x64& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {
     /*
    auto& target_line = *lines_iter;
    
    if (lines_iter++ != code_holder.get_lines().end()) {
        lines_iter--;

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
bool fukutate_jmp(cs_insn *instruction, fuku_asm_x64& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {

    return false;
}
bool fukutate_ret(cs_insn *instruction, fuku_asm_x64& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {
    /*
    auto& target_line = *lines_iter;

    if ( (target_line.get_instruction_flags() & fuku_instruction_bad_stack) == 0) {
        if (target_line.get_op_code()[target_line.get_op_pref_size()] == 0xC3) { //ret



            out_lines.push_back(f_asm.lea(fuku_reg64::r_RSP, fuku_operand64(fuku_reg64::r_RSP, 8),fuku_asm64_size::asm64_size_64));//lea rsp,[rsp + (8 + stack_offset)]
            out_lines.push_back(f_asm.jmp(fuku_operand64(r_RSP, -8)).set_instruction_flags(fuku_instruction_bad_stack));           //jmp [rsp - (8 + stack_offset)] 

            return true;

        }
        else if (target_line.get_op_code()[target_line.get_op_pref_size()] == 0xC2) { //ret 0x0000

            uint16_t ret_stack = *(uint16_t*)&target_line.get_op_code()[1];
            out_lines.push_back(f_asm.add(fuku_reg64::r_RSP, fuku_operand64(fuku_reg64::r_RSP, 8 + ret_stack), fuku_asm64_size::asm64_size_64));//lea rsp,[rsp + (8 + stack_offset)]
            out_lines.push_back(f_asm.jmp(fuku_operand64(r_RSP, -8 - ret_stack)).set_instruction_flags(fuku_instruction_bad_stack));                        //jmp [rsp - (8 + stack_offset)] 

            return true;
        }
    }
    
    return false;
}

//arith     ADD/SUB/INC/DEC/CMP
bool fukutate_add(cs_insn *instruction, fuku_asm_x64& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {

    return false;
}
bool fukutate_sub(cs_insn *instruction, fuku_asm_x64& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {

    return false;
}
bool fukutate_inc(cs_insn *instruction, fuku_asm_x64& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {

    return false;
}
bool fukutate_dec(cs_insn *instruction, fuku_asm_x64& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {

    return false;
}
bool fukutate_cmp(cs_insn *instruction, fuku_asm_x64& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {

    return false;
}

//logical   AND/OR/XOR/TEST
bool fukutate_and(cs_insn *instruction, fuku_asm_x64& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {

    return false;
}
bool fukutate_or(cs_insn *instruction, fuku_asm_x64& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {

    return false;
}
bool fukutate_xor(cs_insn *instruction, fuku_asm_x64& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {

    return false;
}
bool fukutate_test(cs_insn *instruction, fuku_asm_x64& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {

    return false;
}

//stack     PUSH/POP
bool fukutate_push(cs_insn *instruction, fuku_asm_x64& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {

    return false;
}
bool fukutate_pop(cs_insn *instruction, fuku_asm_x64& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {

    return false;
}

*/