#include "stdafx.h"
#include "fuku_mutation_x86_rules.h"

uint8_t convert_regtable[] = {
    X86_REG_INVALID,
    X86_REG_AH, X86_REG_AL, X86_REG_AX, X86_REG_BH, X86_REG_BL,
    X86_REG_BP, X86_REG_BPL, X86_REG_BX, X86_REG_CH, X86_REG_CL,
    X86_REG_CS, X86_REG_CX, X86_REG_DH, X86_REG_DI, X86_REG_DIL,
    X86_REG_DL, X86_REG_DS, X86_REG_DX, 

    r_EAX /*X86_REG_EAX*/, 
    r_EBP /*X86_REG_EBP*/ ,
    r_EBX /*X86_REG_EBX*/,
    r_ECX /*X86_REG_ECX*/,
    r_EDI /*X86_REG_EDI*/,
    r_EDX /*X86_REG_EDX*/, 
    X86_REG_EFLAGS, X86_REG_EIP, X86_REG_EIZ, X86_REG_ES,
    r_ESI /*X86_REG_ESI*/,
    r_ESP /*X86_REG_ESP*/,

    X86_REG_FPSW, X86_REG_FS, X86_REG_GS, X86_REG_IP, X86_REG_RAX,
    X86_REG_RBP, X86_REG_RBX, X86_REG_RCX, X86_REG_RDI, X86_REG_RDX,
    X86_REG_RIP, X86_REG_RIZ, X86_REG_RSI, X86_REG_RSP, X86_REG_SI,
    X86_REG_SIL, X86_REG_SP, X86_REG_SPL, X86_REG_SS, X86_REG_CR0,
    X86_REG_CR1, X86_REG_CR2, X86_REG_CR3, X86_REG_CR4, X86_REG_CR5,
    X86_REG_CR6, X86_REG_CR7, X86_REG_CR8, X86_REG_CR9, X86_REG_CR10,
    X86_REG_CR11, X86_REG_CR12, X86_REG_CR13, X86_REG_CR14, X86_REG_CR15,
    X86_REG_DR0, X86_REG_DR1, X86_REG_DR2, X86_REG_DR3, X86_REG_DR4,
    X86_REG_DR5, X86_REG_DR6, X86_REG_DR7, X86_REG_DR8, X86_REG_DR9,
    X86_REG_DR10, X86_REG_DR11, X86_REG_DR12, X86_REG_DR13, X86_REG_DR14,
    X86_REG_DR15, X86_REG_FP0, X86_REG_FP1, X86_REG_FP2, X86_REG_FP3,
    X86_REG_FP4, X86_REG_FP5, X86_REG_FP6, X86_REG_FP7,
    X86_REG_K0, X86_REG_K1, X86_REG_K2, X86_REG_K3, X86_REG_K4,
    X86_REG_K5, X86_REG_K6, X86_REG_K7, X86_REG_MM0, X86_REG_MM1,
    X86_REG_MM2, X86_REG_MM3, X86_REG_MM4, X86_REG_MM5, X86_REG_MM6,
    X86_REG_MM7, X86_REG_R8, X86_REG_R9, X86_REG_R10, X86_REG_R11,
    X86_REG_R12, X86_REG_R13, X86_REG_R14, X86_REG_R15,
    X86_REG_ST0, X86_REG_ST1, X86_REG_ST2, X86_REG_ST3,
    X86_REG_ST4, X86_REG_ST5, X86_REG_ST6, X86_REG_ST7,
    X86_REG_XMM0, X86_REG_XMM1, X86_REG_XMM2, X86_REG_XMM3, X86_REG_XMM4,
    X86_REG_XMM5, X86_REG_XMM6, X86_REG_XMM7, X86_REG_XMM8, X86_REG_XMM9,
    X86_REG_XMM10, X86_REG_XMM11, X86_REG_XMM12, X86_REG_XMM13, X86_REG_XMM14,
    X86_REG_XMM15, X86_REG_XMM16, X86_REG_XMM17, X86_REG_XMM18, X86_REG_XMM19,
    X86_REG_XMM20, X86_REG_XMM21, X86_REG_XMM22, X86_REG_XMM23, X86_REG_XMM24,
    X86_REG_XMM25, X86_REG_XMM26, X86_REG_XMM27, X86_REG_XMM28, X86_REG_XMM29,
    X86_REG_XMM30, X86_REG_XMM31, X86_REG_YMM0, X86_REG_YMM1, X86_REG_YMM2,
    X86_REG_YMM3, X86_REG_YMM4, X86_REG_YMM5, X86_REG_YMM6, X86_REG_YMM7,
    X86_REG_YMM8, X86_REG_YMM9, X86_REG_YMM10, X86_REG_YMM11, X86_REG_YMM12,
    X86_REG_YMM13, X86_REG_YMM14, X86_REG_YMM15, X86_REG_YMM16, X86_REG_YMM17,
    X86_REG_YMM18, X86_REG_YMM19, X86_REG_YMM20, X86_REG_YMM21, X86_REG_YMM22,
    X86_REG_YMM23, X86_REG_YMM24, X86_REG_YMM25, X86_REG_YMM26, X86_REG_YMM27,
    X86_REG_YMM28, X86_REG_YMM29, X86_REG_YMM30, X86_REG_YMM31, X86_REG_ZMM0,
    X86_REG_ZMM1, X86_REG_ZMM2, X86_REG_ZMM3, X86_REG_ZMM4, X86_REG_ZMM5,
    X86_REG_ZMM6, X86_REG_ZMM7, X86_REG_ZMM8, X86_REG_ZMM9, X86_REG_ZMM10,
    X86_REG_ZMM11, X86_REG_ZMM12, X86_REG_ZMM13, X86_REG_ZMM14, X86_REG_ZMM15,
    X86_REG_ZMM16, X86_REG_ZMM17, X86_REG_ZMM18, X86_REG_ZMM19, X86_REG_ZMM20,
    X86_REG_ZMM21, X86_REG_ZMM22, X86_REG_ZMM23, X86_REG_ZMM24, X86_REG_ZMM25,
    X86_REG_ZMM26, X86_REG_ZMM27, X86_REG_ZMM28, X86_REG_ZMM29, X86_REG_ZMM30,
    X86_REG_ZMM31, X86_REG_R8B, X86_REG_R9B, X86_REG_R10B, X86_REG_R11B,
    X86_REG_R12B, X86_REG_R13B, X86_REG_R14B, X86_REG_R15B, X86_REG_R8D,
    X86_REG_R9D, X86_REG_R10D, X86_REG_R11D, X86_REG_R12D, X86_REG_R13D,
    X86_REG_R14D, X86_REG_R15D, X86_REG_R8W, X86_REG_R9W, X86_REG_R10W,
    X86_REG_R11W, X86_REG_R12W, X86_REG_R13W, X86_REG_R14W, X86_REG_R15W,

    X86_REG_ENDING		// <-- mark the end of the list of registers
};




bool fukutate_jcc(cs_insn *instruction, fuku_asm_x86& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {
    
    auto next_line = lines_iter; next_line++;

    if (next_line != code_holder.get_lines().begin()) { //if not last instruction
        //inverted jcc to next_inst_after real jcc
        //jmp jcc_dst
        
        const uint8_t* code = &lines_iter->get_op_code()[lines_iter->get_op_pref_size()];

        uint8_t cond;

        if (code[0] == 0x0F) {
            cond = code[1] & 0xF;
        }
        else {
            cond = code[0] & 0xF;
        }

        fuku_instruction line[2];

        line[0] = f_asm.jcc(fuku_condition(cond ^ 1), 0)
            .set_custom_flags(lines_iter->get_custom_flags())
            .set_rip_relocation_idx(code_holder.create_rip_relocation(2, &(*next_line)))
            .set_instruction_flags(fuku_instruction_full_mutated);

        line[1] = f_asm.jmp(0)
            .set_custom_flags(lines_iter->get_custom_flags())
            .set_rip_relocation_idx(lines_iter->get_rip_relocation_idx())
            .set_label_idx(lines_iter->get_label_idx())
            .set_source_virtual_address(lines_iter->get_source_virtual_address());

        code_holder.get_rip_relocations()[line[0].get_rip_relocation_idx()].offset = 2;
        code_holder.get_rip_relocations()[line[1].get_rip_relocation_idx()].offset = 1;

        code_holder.get_lines().insert(lines_iter, line[0]);
        *lines_iter = line[1];

        return true;
    }

    return false;
}

bool fukutate_jmp(cs_insn *instruction, fuku_asm_x86& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {
  

    auto detail = instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_REG) { //jmp reg32


    }
    else if (detail.operands[0].type == X86_OP_MEM) { //jmp [op]


    }
    else if (detail.operands[0].type == X86_OP_IMM) { //jmp imm

        if (!IS_HAS_FULL_BITES(lines_iter->get_instruction_flags(), fuku_instruction_bad_stack_pointer)) {

            if (FUKU_GET_RAND(0, 1)) {
                //push jmpdst
                //ret

                
                fuku_instruction line[2];

                line[0] = f_asm.push_imm32(0)
                    .set_custom_flags(lines_iter->get_custom_flags())
                    .set_relocation_first_idx(code_holder.create_relocation_lb(1, code_holder.get_rip_relocations()[lines_iter->get_rip_relocation_idx()].label_idx, 0));

                line[1] = f_asm.ret(0)
                    .set_custom_flags(lines_iter->get_custom_flags())
                    .set_label_idx(lines_iter->get_label_idx())
                    .set_source_virtual_address(lines_iter->get_source_virtual_address());

                code_holder.delete_rip_relocation(lines_iter->get_rip_relocation_idx());


                code_holder.get_lines().insert(lines_iter, line[0]);
                *lines_iter = line[1];
            }
            else {
                //je(jcc) jmpdst
                //jne(jcc) jmpdst

                fuku_instruction line[2];
                uint8_t cond = FUKU_GET_RAND(0, 15);

                line[0] = f_asm.jcc(fuku_condition(cond), 0)
                    .set_custom_flags(lines_iter->get_custom_flags())
                    .set_rip_relocation_idx(code_holder.create_rip_relocation(code_holder.get_rip_relocations()[lines_iter->get_rip_relocation_idx()]));

                line[1] = f_asm.jcc(fuku_condition(cond ^ 1), 0)
                    //.set_custom_flags(lines_iter->get_custom_flags()) //else can be changed flags for jcc
                    .set_label_idx(lines_iter->get_label_idx())
                    .set_rip_relocation_idx(lines_iter->get_rip_relocation_idx())
                    .set_source_virtual_address(lines_iter->get_source_virtual_address());

                code_holder.get_rip_relocations()[line[0].get_rip_relocation_idx()].offset = 2;
                code_holder.get_rip_relocations()[line[1].get_rip_relocation_idx()].offset = 2;

                code_holder.get_lines().insert(lines_iter, line[0]);
                *lines_iter = line[1];
            }

            return true;
        }
    }

    return false;
}

bool fukutate_ret(cs_insn *instruction, fuku_asm_x86& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {

    auto detail = instruction->detail->x86;
    
    if (detail.op_count) { //ret 0x0000

        //lea esp,[esp + (4 + stack_offset)]
        //jmp [esp - 4 - stack_offset]
      
        uint16_t ret_stack = (uint16_t)detail.operands[0].imm;

        fuku_instruction line[2];

        line[0] = f_asm.lea(fuku_reg86::r_ESP, fuku_operand86(fuku_reg86::r_ESP, 4 + ret_stack))
            .set_custom_flags(lines_iter->get_custom_flags());

        line[1] = f_asm.jmp(fuku_operand86(r_ESP, -4 - ret_stack))
            .set_instruction_flags(fuku_instruction_bad_stack_pointer)
            .set_custom_flags(lines_iter->get_custom_flags())
            .set_label_idx(lines_iter->get_label_idx())
            .set_source_virtual_address(lines_iter->get_source_virtual_address());


        
        code_holder.get_lines().insert(lines_iter, line[0]);
        *lines_iter = line[1];
        
        return true;
    }
    else { //ret

        //lea esp,[esp + 4]
        //jmp [esp - 4]

        
        fuku_instruction line[2];

        line[0] = f_asm.lea(fuku_reg86::r_ESP, fuku_operand86(fuku_reg86::r_ESP, 4))
            .set_custom_flags(lines_iter->get_custom_flags());

        line[1] = f_asm.jmp(fuku_operand86(r_ESP, -4))
            .set_instruction_flags(fuku_instruction_bad_stack_pointer)
            .set_custom_flags(lines_iter->get_custom_flags())
            .set_label_idx(lines_iter->get_label_idx())
            .set_source_virtual_address(lines_iter->get_source_virtual_address());
        

        code_holder.get_lines().insert(lines_iter, line[0]);
        *lines_iter = line[1];
        
        return true;
    }

    return false;
}

bool fukutate_add(cs_insn *instruction, fuku_asm_x86& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {

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

bool fukutate_sub(cs_insn *instruction, fuku_asm_x86& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {
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

bool fukutate_inc(cs_insn *instruction, fuku_asm_x86& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {
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

bool fukutate_dec(cs_insn *instruction, fuku_asm_x86& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {
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

bool fukutate_cmp(cs_insn *instruction, fuku_asm_x86& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {
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

bool fukutate_and(cs_insn *instruction, fuku_asm_x86& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {

    auto detail = instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_MEM || detail.operands[1].type == X86_OP_IMM) { //and [op],imm

        if (detail.operands[1].size == 4) { //and [op],imm32

        }
        else if (detail.operands[1].size == 2) { //and [op],imm16

        }
        else if (detail.operands[1].size == 1) { //and [op],imm8

        }


    }
    else if ((detail.operands[0].type == X86_OP_MEM || detail.operands[1].type == X86_OP_REG) ||//and [op],reg
        (detail.operands[0].type == X86_OP_REG || detail.operands[1].type == X86_OP_MEM)) {//and reg,[op]

        cs_x86_op * reg_op = 0;

        if (detail.operands[0].type == X86_OP_REG) {
            reg_op = &detail.operands[0];
        }
        else {
            reg_op = &detail.operands[1];
        }


        if (reg_op->size == 4) { //and [op],reg32


        }
        else if (reg_op->size == 2) { //and [op],reg16


        }
        else if (reg_op->size == 1) { //and [op],imm8

        }


    }
    else if (detail.operands[0].type == X86_OP_REG || detail.operands[1].type == X86_OP_REG) {//and reg,reg

        if (detail.operands[0].size == 4) { //and reg32 ,reg32

        }
        else if (detail.operands[0].size == 2) { //and reg16 , reg16

        }
        else if (detail.operands[0].size == 1) { //and reg8 , reg8

        }
    }
    else if (detail.operands[0].type == X86_OP_REG || detail.operands[1].type == X86_OP_IMM) {//and reg,imm

        if (detail.operands[0].size == 4) { //and reg32 ,imm32

        }
        else if (detail.operands[0].size == 2) { //and reg16 , imm16

        }
        else if (detail.operands[0].size == 1) { //and reg8 , imm8

        }
    }

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

bool fukutate_or(cs_insn *instruction, fuku_asm_x86& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {

    auto detail = instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_MEM || detail.operands[1].type == X86_OP_IMM) { //or [op],imm

        if (detail.operands[1].size == 4) { //or [op],imm32

        }
        else if (detail.operands[1].size == 2) { //or [op],imm16

        }
        else if (detail.operands[1].size == 1) { //or [op],imm8

        }


    }
    else if ((detail.operands[0].type == X86_OP_MEM || detail.operands[1].type == X86_OP_REG) ||//or [op],reg
        (detail.operands[0].type == X86_OP_REG || detail.operands[1].type == X86_OP_MEM)) {//or reg,[op]

        cs_x86_op * reg_op = 0;

        if (detail.operands[0].type == X86_OP_REG) {
            reg_op = &detail.operands[0];
        }
        else {
            reg_op = &detail.operands[1];
        }


        if (reg_op->size == 4) { //or [op],reg32


        }
        else if (reg_op->size == 2) { //or [op],reg16


        }
        else if (reg_op->size == 1) { //or [op],imm8

        }


    }
    else if (detail.operands[0].type == X86_OP_REG || detail.operands[1].type == X86_OP_REG) {//or reg,reg

        if (detail.operands[0].size == 4) { //or reg32 ,reg32

        }
        else if (detail.operands[0].size == 2) { //or reg16 , reg16

        }
        else if (detail.operands[0].size == 1) { //or reg8 , reg8

        }
    }
    else if (detail.operands[0].type == X86_OP_REG || detail.operands[1].type == X86_OP_IMM) {//or reg,imm

        if (detail.operands[0].size == 4) { //or reg32 ,imm32

        }
        else if (detail.operands[0].size == 2) { //or reg16 , imm16

        }
        else if (detail.operands[0].size == 1) { //or reg8 , imm8

        }
    }

    return false;
}

bool fukutate_xor(cs_insn *instruction, fuku_asm_x86& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {


    auto detail = instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_MEM || detail.operands[1].type == X86_OP_IMM) { //xor [op],imm

        if (detail.operands[1].size == 4) { //xor [op],imm32

        }
        else if (detail.operands[1].size == 2) { //xor [op],imm16

        }
        else if (detail.operands[1].size == 1) { //xor [op],imm8

        }


    }
    else if ((detail.operands[0].type == X86_OP_MEM || detail.operands[1].type == X86_OP_REG) ||//xor [op],reg
        (detail.operands[0].type == X86_OP_REG || detail.operands[1].type == X86_OP_MEM)) {//xor reg,[op]

        cs_x86_op * reg_op = 0;

        if (detail.operands[0].type == X86_OP_REG) {
            reg_op = &detail.operands[0];
        }
        else {
            reg_op = &detail.operands[1];
        }


        if (reg_op->size == 4) { //xor [op],reg32


        }
        else if (reg_op->size == 2) { //xor [op],reg16


        }
        else if (reg_op->size == 1) { //xor [op],imm8

        }


    }
    else if (detail.operands[0].type == X86_OP_REG || detail.operands[1].type == X86_OP_REG) {//xor reg,reg

        if (detail.operands[0].size == 4) { //xor reg32 ,reg32

        }
        else if (detail.operands[0].size == 2) { //xor reg16 , reg16

        }
        else if (detail.operands[0].size == 1) { //xor reg8 , reg8

        }
    }
    else if (detail.operands[0].type == X86_OP_REG || detail.operands[1].type == X86_OP_IMM) {//xor reg,imm

        if (detail.operands[0].size == 4) { //xor reg32 ,imm32

        }
        else if (detail.operands[0].size == 2) { //xor reg16 , imm16

        }
        else if (detail.operands[0].size == 1) { //xor reg8 , imm8

        }
    }

    return false;
}

bool fukutate_test(cs_insn *instruction, fuku_asm_x86& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {
    

    auto detail = instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_MEM || detail.operands[1].type == X86_OP_IMM) { //test [op],imm

        if (detail.operands[1].size == 4) { //test [op],imm32

        }
        else if (detail.operands[1].size == 2) { //test [op],imm16

        }
        else if (detail.operands[1].size == 1) { //test [op],imm8

        }


    }
    else if( (detail.operands[0].type == X86_OP_MEM || detail.operands[1].type == X86_OP_REG) ||//test [op],reg
             (detail.operands[0].type == X86_OP_REG || detail.operands[1].type == X86_OP_MEM)) {//test reg,[op]

        cs_x86_op * reg_op = 0;

        if (detail.operands[0].type == X86_OP_REG) {
            reg_op = &detail.operands[0];
        }
        else {
            reg_op = &detail.operands[1];
        }


        if (reg_op->size == 4) { //test [op],reg32


        }
        else if (reg_op->size == 2) { //test [op],reg16


        }
        else if (reg_op->size == 1) { //test [op],imm8

        }


    }
    else if (detail.operands[0].type == X86_OP_REG || detail.operands[1].type == X86_OP_REG) {//test reg,reg

        if (detail.operands[0].size == 4) { //test reg32 ,reg32

        }
        else if (detail.operands[0].size == 2) { //test reg16 , reg16

        }
        else if (detail.operands[0].size == 1) { //test reg8 , reg8

        }
    }
    else if (detail.operands[0].type == X86_OP_REG || detail.operands[1].type == X86_OP_IMM) {//test reg,imm

        if (detail.operands[0].size == 4) { //test reg32 ,imm32

        }
        else if (detail.operands[0].size == 2) { //test reg16 , imm16

        }
        else if (detail.operands[0].size == 1) { //test reg8 , imm8

        }
    }


    /*
    if (((target_line.get_flags() & fuku_instruction_bad_stack) == 0) &&
        !target_line.get_relocation_f_imm_offset()) {

        if (code[0] == 0x85 && (code[1] >= 0xC0 && code[1] < 0xC8)) { //test reg32_1,reg32_2

            //push reg3
            //mov reg3, reg1
            //lea reg3, [reg3 + 4]
            //and reg3, reg2
            //pop reg3

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

            }
            else {

                //push reg1
                //and reg1,reg2
                //pop reg1
                

                out_lines.push_back(f_asm.push(reg1).set_useless_flags(target_line.get_useless_flags()));
                out_lines.push_back(f_asm.and(reg1, reg2).set_useless_flags(target_line.get_useless_flags()));
                out_lines.push_back(f_asm.pop(reg1));

            }

            return true;
        }
        else if (code[0] == 0xA9 || (code[0] == 0xF7 && code[1] >= 0xC0 && code[1] < 0xC8)) { //test reg32, imm
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

                //push reg2
                //mov reg2,reg1
                //lea reg2, [reg2 + 4]
                //sub reg2,imm
                //pop reg3
                

                fuku_reg86 reg2;
                for (reg2 = fuku_reg86::r_EAX; reg2 < fuku_reg86::r_EBX; reg2 = fuku_reg86(reg2 + 1)) {}

                out_lines.push_back(f_asm.push(reg2).set_useless_flags(target_line.get_useless_flags()));
                out_lines.push_back(f_asm.mov(reg2, reg1).set_useless_flags(target_line.get_useless_flags()));
                out_lines.push_back(f_asm.lea(reg2, fuku_operand86(reg2, operand_scale::operand_scale_1, 4)).set_useless_flags(target_line.get_useless_flags()));
                out_lines.push_back(f_asm.and(reg2, fuku_immediate86(val)).set_useless_flags(target_line.get_useless_flags()));
                out_lines.push_back(f_asm.pop(reg2));

                
            }
            else {
                
                //push reg
                //and reg, imm
                //pop reg
                

                out_lines.push_back(f_asm.push(reg1).set_useless_flags(target_line.get_useless_flags()));
                out_lines.push_back(f_asm.and(reg1, fuku_immediate86(val)).set_useless_flags(target_line.get_useless_flags()));
                out_lines.push_back(f_asm.pop(reg1));

                
            }
            return true;
        }
    }
    */
    
    return false;
}

bool fukutate_push(cs_insn *instruction, fuku_asm_x86& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {

    auto detail = instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_REG) { 

        if (detail.operands[0].size == 4) { //push reg32

            //(sub esp,4) or (lea esp,[esp - 4]) 
            //mov [esp],reg
            
            fuku_reg86 reg = fuku_reg86(convert_regtable[detail.operands[0].reg]);

            fuku_instruction line[2];

            uint32_t needed = (X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_CF | X86_EFLAGS_MODIFY_PF);

            if (IS_HAS_FULL_BITES(lines_iter->get_custom_flags(), needed)) {
                line[0] = f_asm.sub(fuku_reg86::r_ESP, fuku_immediate86(4))
                    .set_custom_flags(lines_iter->get_custom_flags());
            }
            else {
                line[0] = f_asm.lea(fuku_reg86::r_ESP, fuku_operand86(fuku_reg86::r_ESP, -4))
                    .set_custom_flags(lines_iter->get_custom_flags());
            }


            line[1] = f_asm.mov(fuku_operand86(fuku_reg86::r_ESP, operand_scale::operand_scale_1), reg)
                .set_custom_flags(lines_iter->get_custom_flags())
                .set_instruction_flags(fuku_instruction_bad_stack_pointer)
                .set_label_idx(lines_iter->get_label_idx())
                .set_source_virtual_address(lines_iter->get_source_virtual_address());


            code_holder.get_lines().insert(lines_iter, line[0]);
            *lines_iter = line[1];

            return true;
        }
        else if (detail.operands[0].size == 2) { //push reg16

      
        }
        else if(detail.operands[0].size == 1){ //push reg8

        }
    }
    else if (detail.operands[0].type == X86_OP_MEM) { //push [op]

    }
    else if (detail.operands[0].type == X86_OP_IMM) { //push imm8/imm32
    
        //(sub esp,4) or (lea esp,[esp - 4]) 
        //mov [esp],value

        uint32_t val = (uint32_t)detail.operands[0].imm;

        fuku_instruction line[2];

        uint32_t needed = (X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_CF | X86_EFLAGS_MODIFY_PF);

        if (IS_HAS_FULL_BITES(lines_iter->get_custom_flags(), needed)) {
            line[0] = f_asm.sub(fuku_reg86::r_ESP, fuku_immediate86(4))
                .set_custom_flags(lines_iter->get_custom_flags());
        }
        else {
            line[0] = f_asm.lea(fuku_reg86::r_ESP, fuku_operand86(fuku_reg86::r_ESP, -4))
                .set_custom_flags(lines_iter->get_custom_flags());
        }

        line[1] = f_asm.mov(fuku_operand86(fuku_reg86::r_ESP, operand_scale::operand_scale_1), fuku_immediate86(val))
            .set_custom_flags(lines_iter->get_custom_flags())
            .set_instruction_flags(fuku_instruction_bad_stack_pointer)
            .set_label_idx(lines_iter->get_label_idx())
            .set_source_virtual_address(lines_iter->get_source_virtual_address());

        if (lines_iter->get_relocation_first_idx() != -1) {
            line[1].set_relocation_first_idx(lines_iter->get_relocation_first_idx());
            code_holder.get_relocations()[lines_iter->get_relocation_first_idx()].offset = 3;
        }

        code_holder.get_lines().insert(lines_iter, line[0]);
        *lines_iter = line[1];

        return true;
    }

    return false;
}

bool fukutate_pop(cs_insn *instruction, fuku_asm_x86& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {

    
    auto detail = instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_REG) { //pop reg


        if (detail.operands[0].size == 4) {      //pop reg32
             //add esp,4
             //mov reg,[esp - 4]
             //     or
             //mov reg,[esp]
             //add esp,4

            fuku_reg86 reg = fuku_reg86(convert_regtable[detail.operands[0].reg]);

            fuku_instruction line[2];

            uint32_t needed = (X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_CF | X86_EFLAGS_MODIFY_PF);

            if (FUKU_GET_RAND(0, 10) < 5) {

                line[0] = f_asm.mov(reg, fuku_operand86(fuku_reg86::r_ESP, operand_scale::operand_scale_1))
                    .set_custom_flags(lines_iter->get_custom_flags());


                if (IS_HAS_FULL_BITES(lines_iter->get_custom_flags(), needed)) {
                    line[1] = f_asm.add(fuku_reg86::r_ESP, fuku_immediate86(4))
                        .set_custom_flags(lines_iter->get_custom_flags());
                }
                else {
                    line[1] = f_asm.lea(fuku_reg86::r_ESP, fuku_operand86(fuku_reg86::r_ESP, 4))
                        .set_custom_flags(lines_iter->get_custom_flags());
                }
            }
            else {

                if (IS_HAS_FULL_BITES(lines_iter->get_custom_flags(), needed)) {
                    line[0] = f_asm.add(fuku_reg86::r_ESP, fuku_immediate86(4))
                        .set_custom_flags(lines_iter->get_custom_flags());

                }
                else {
                    line[0] = f_asm.lea(fuku_reg86::r_ESP, fuku_operand86(fuku_reg86::r_ESP, 4))
                        .set_custom_flags(lines_iter->get_custom_flags());
                }

                line[1] = f_asm.mov(reg, fuku_operand86(fuku_reg86::r_ESP, -4))
                    .set_custom_flags(lines_iter->get_custom_flags())
                    .set_instruction_flags(fuku_instruction_bad_stack_pointer);
            }

            line[1].set_label_idx(lines_iter->get_label_idx())
                .set_source_virtual_address(lines_iter->get_source_virtual_address());


            code_holder.get_lines().insert(lines_iter, line[0]);
            *lines_iter = line[1];

            return true;
        }
        else if (detail.operands[0].size == 2) { //pop reg16


        }
        else if (detail.operands[0].size == 1) { //pop reg8

        }

    }
    else if (detail.operands[0].type == X86_OP_MEM) { //pop [op]

    }

    
    return false;
}

void generate_junk(fuku_asm_x86& f_asm, fuku_code_holder& code_holder,
    linestorage::iterator lines_iter, uint32_t max_size, size_t junk_size) {


    size_t current_size = 0;

    while (junk_size != current_size) {

        switch (FUKU_GET_RAND(1, min(min(junk_size - current_size, max_size), 7))) {
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


void fuku_junk_1b(fuku_asm_x86& f_asm, fuku_code_holder& code_holder, linestorage::iterator lines_iter) {

    //nop
    code_holder.get_lines().insert(lines_iter, f_asm.nop()); 
}

void fuku_junk_2b(fuku_asm_x86& f_asm, fuku_code_holder& code_holder, linestorage::iterator lines_iter) {

    switch (FUKU_GET_RAND(0, 4)) {

    case 0: { 
        //mov reg1, reg1

        fuku_reg86 reg1 = fuku_reg86(FUKU_GET_RAND(fuku_reg86::r_EAX, fuku_reg86::r_EBX));

        code_holder.get_lines().insert(lines_iter, f_asm.mov(reg1, reg1).set_custom_flags(lines_iter->get_custom_flags()));
        break;
    }
    case 1: { 
        //xchg eax, reg2
        //xchg reg2, eax

    jk_2s:

        fuku_reg86 reg1 = fuku_reg86::r_EAX;
        fuku_reg86 reg2 = fuku_reg86(FUKU_GET_RAND(fuku_reg86::r_EAX, fuku_reg86::r_EDI));

        fuku_instruction line[2];

        if (FUKU_GET_RAND(0, 1)) {
            line[0] = f_asm.xchg(reg1, reg2).set_custom_flags(lines_iter->get_custom_flags());
        }
        else {
            line[0] = f_asm.xchg(reg2, reg1).set_custom_flags(lines_iter->get_custom_flags());
        }

        if (FUKU_GET_RAND(0, 1)) {
            line[1] = f_asm.xchg(reg1, reg2).set_custom_flags(lines_iter->get_custom_flags());
        }
        else {
            line[1] = f_asm.xchg(reg2, reg1).set_custom_flags(lines_iter->get_custom_flags());
        }

        if (reg2 == fuku_reg86::r_ESP) {
            line[1].set_instruction_flags(fuku_instruction_bad_stack_pointer);
        }

        code_holder.get_lines().insert(lines_iter, &line[0], &line[2]);

        break;
    }
    case 2: {
    jk_3s:
        //push reg1
        //pop reg1

        fuku_reg86 reg1 = fuku_reg86(FUKU_GET_RAND(fuku_reg86::r_EAX, fuku_reg86::r_EBX));

        if (!IS_HAS_FULL_BITES(lines_iter->get_instruction_flags(), fuku_instruction_bad_stack_pointer)) {

            fuku_instruction line[2];

            line[0] = f_asm.push(reg1).set_custom_flags(lines_iter->get_custom_flags());
            line[1] = f_asm.pop(reg1).set_custom_flags(lines_iter->get_custom_flags());

            code_holder.get_lines().insert(lines_iter, &line[0], &line[2]);
        }
        else {
            //lea reg1, [reg1]

            code_holder.get_lines().insert(lines_iter, f_asm.lea(reg1, fuku_operand86(reg1, operand_scale::operand_scale_1, 0)).set_custom_flags(lines_iter->get_custom_flags()));
        }
        
        break;
    }

    case 3: {
        //cmp reg1, reg2

        uint32_t needed = (X86_EFLAGS_MODIFY_CF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_AF);

        if (IS_HAS_FULL_BITES(lines_iter->get_custom_flags(), needed)) {
            fuku_reg86 reg1 = fuku_reg86(FUKU_GET_RAND(fuku_reg86::r_EAX, fuku_reg86::r_EDI));
            fuku_reg86 reg2 = fuku_reg86(FUKU_GET_RAND(fuku_reg86::r_EAX, fuku_reg86::r_EDI));

            code_holder.get_lines().insert(lines_iter, f_asm.cmp(reg1, reg2).set_custom_flags(lines_iter->get_custom_flags()));
        }
        else {
            goto jk_2s;
        }

        break;
    }
    case 4: {
        //test reg1, reg2

        uint32_t needed = (X86_EFLAGS_MODIFY_CF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_AF);

        if (IS_HAS_FULL_BITES(lines_iter->get_custom_flags(), needed)) {
            fuku_reg86 reg1 = fuku_reg86(FUKU_GET_RAND(fuku_reg86::r_EAX, fuku_reg86::r_EDI));
            fuku_reg86 reg2 = fuku_reg86(FUKU_GET_RAND(fuku_reg86::r_EAX, fuku_reg86::r_EDI));

            code_holder.get_lines().insert(lines_iter, f_asm.test(reg1, reg2).set_custom_flags(lines_iter->get_custom_flags()));
        }
        else {
            goto jk_3s;
        }

        break;
    }

    }
}

void fuku_junk_3b(fuku_asm_x86& f_asm, fuku_code_holder& code_holder, linestorage::iterator lines_iter) {

    switch (FUKU_GET_RAND(0, 3)) {
    case 0: {
        //ror reg1, 0

        fuku_reg86 reg1 = fuku_reg86(FUKU_GET_RAND(fuku_reg86::r_EAX, fuku_reg86::r_EDI));
        code_holder.get_lines().insert(lines_iter, f_asm.ror(reg1, 0).set_custom_flags(lines_iter->get_custom_flags()));

        break;
    }
    case 1: {
        //rol reg1, 0

        fuku_reg86 reg1 = fuku_reg86(FUKU_GET_RAND(fuku_reg86::r_EAX, fuku_reg86::r_EDI));
        code_holder.get_lines().insert(lines_iter, f_asm.rol(reg1, 0).set_custom_flags(lines_iter->get_custom_flags()));

        break;
    }
    case 2: {
        //sub reg1, 0

        uint32_t needed = (X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_CF);

        if (IS_HAS_FULL_BITES(lines_iter->get_custom_flags(), needed)) {
            code_holder.get_lines().insert(lines_iter, f_asm.sub(fuku_reg86::r_EAX, fuku_immediate86(0)).set_custom_flags(lines_iter->get_custom_flags()));
        }
        else {
            generate_junk(f_asm, code_holder, lines_iter, 2, 3);
        }
        break;
    }
    case 3: {
        //add reg1, 0

        uint32_t needed = (X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_CF);

        if (IS_HAS_FULL_BITES(lines_iter->get_custom_flags(), needed)) {
            code_holder.get_lines().insert(lines_iter, f_asm.add(fuku_reg86::r_EAX, fuku_immediate86(0)).set_custom_flags(lines_iter->get_custom_flags()));
        }
        else {
            generate_junk(f_asm, code_holder, lines_iter, 2, 3);
        }
        break;
    }
    }
}

void fuku_junk_4b(fuku_asm_x86& f_asm, fuku_code_holder& code_holder, linestorage::iterator lines_iter) {

    switch (FUKU_GET_RAND(0, 1)) {
    case 0: {
        //not reg1
        //not reg1

        fuku_reg86 reg1 = fuku_reg86(FUKU_GET_RAND(fuku_reg86::r_EAX, fuku_reg86::r_EBX));

        fuku_instruction line[2];

        line[0] = f_asm.not(reg1).set_custom_flags(lines_iter->get_custom_flags());
        line[1] = f_asm.not(reg1).set_custom_flags(lines_iter->get_custom_flags());


        if (reg1 == fuku_reg86::r_ESP) {
            line[1].set_instruction_flags(fuku_instruction_bad_stack_pointer);
        }

        code_holder.get_lines().insert(lines_iter, &line[0], &line[2]);

        break;
    }
    case 1: {
        //xchg reg1, reg2
        //xchg reg2, reg1

        fuku_reg86 reg1 = fuku_reg86(FUKU_GET_RAND(fuku_reg86::r_ECX, fuku_reg86::r_EBX));
        fuku_reg86 reg2 = fuku_reg86(FUKU_GET_RAND(fuku_reg86::r_EAX, fuku_reg86::r_EBX));

        fuku_instruction line[2];

        if (FUKU_GET_RAND(0, 1)) {
            line[0] = f_asm.xchg(reg1, reg2).set_custom_flags(lines_iter->get_custom_flags());
        }
        else {
            line[0] = f_asm.xchg(reg2, reg1).set_custom_flags(lines_iter->get_custom_flags());
        }

        if (FUKU_GET_RAND(0, 1)) {
            line[1] = f_asm.xchg(reg1, reg2).set_custom_flags(lines_iter->get_custom_flags());
        }
        else {
            line[1] = f_asm.xchg(reg2, reg1).set_custom_flags(lines_iter->get_custom_flags());
        }

        if (reg1 == fuku_reg86::r_ESP || reg2 == fuku_reg86::r_ESP) {
            line[1].set_instruction_flags(fuku_instruction_bad_stack_pointer);
        }

        code_holder.get_lines().insert(lines_iter, &line[0], &line[2]);

        break;
    }

    }
}

void fuku_junk_5b(fuku_asm_x86& f_asm, fuku_code_holder& code_holder, linestorage::iterator lines_iter) {


    switch (FUKU_GET_RAND(0, 1)) {
    case 0: {
        //push reg1
        //ror reg1, rand
        //pop reg1

        uint32_t needed = (X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_CF);

        if (IS_HAS_FULL_BITES(lines_iter->get_custom_flags(), needed) &&
            !IS_HAS_FULL_BITES(lines_iter->get_instruction_flags(), fuku_instruction_bad_stack_pointer)) {

            fuku_reg86 reg1 = fuku_reg86(FUKU_GET_RAND(fuku_reg86::r_EAX, fuku_reg86::r_EDI));
            if (reg1 == fuku_reg86::r_ESP) { reg1 = fuku_reg86::r_EAX; }

            fuku_instruction line[3];

            line[0] = f_asm.push(reg1).set_custom_flags(lines_iter->get_custom_flags());
            line[1] = f_asm.ror(reg1, FUKU_GET_RAND(1, 31)).set_custom_flags(lines_iter->get_custom_flags());
            line[2] = f_asm.pop(reg1).set_custom_flags(lines_iter->get_custom_flags());

            code_holder.get_lines().insert(lines_iter, &line[0], &line[3]);
        }
        else {
            generate_junk(f_asm, code_holder, lines_iter, 4, 5);
        }
        break;
    }
    case 1: {
        //push reg1
        //rol reg1, rand
        //pop reg1

        uint32_t needed = (X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_CF);

        if (IS_HAS_FULL_BITES(lines_iter->get_custom_flags(), needed) &&
            !IS_HAS_FULL_BITES(lines_iter->get_instruction_flags(), fuku_instruction_bad_stack_pointer)) {

            fuku_reg86 reg1 = fuku_reg86(FUKU_GET_RAND(fuku_reg86::r_EAX, fuku_reg86::r_EDI));
            if (reg1 == fuku_reg86::r_ESP) { reg1 = fuku_reg86::r_EAX; }


            fuku_instruction line[3];

            line[0] = f_asm.push(reg1).set_custom_flags(lines_iter->get_custom_flags());
            line[1] = f_asm.rol(reg1, FUKU_GET_RAND(1, 31)).set_custom_flags(lines_iter->get_custom_flags());
            line[2] = f_asm.pop(reg1).set_custom_flags(lines_iter->get_custom_flags());

            code_holder.get_lines().insert(lines_iter, &line[0], &line[3]);
        }
        else {
            generate_junk(f_asm, code_holder, lines_iter, 4, 5);
        }
        break;
    }
    }
}

void fuku_junk_6b(fuku_asm_x86& f_asm, fuku_code_holder& code_holder, linestorage::iterator lines_iter) {


    switch (FUKU_GET_RAND(0, 2)) {
    case 0: {
        //sub reg1(not eax), 0

        uint32_t needed = (X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_CF | X86_EFLAGS_MODIFY_PF);

        if (IS_HAS_FULL_BITES(lines_iter->get_custom_flags(), needed)) {
            fuku_reg86 reg1 = fuku_reg86(FUKU_GET_RAND(fuku_reg86::r_ECX, fuku_reg86::r_EDI));

            code_holder.get_lines().insert(lines_iter, f_asm.sub(reg1, fuku_immediate86(0)).set_custom_flags(lines_iter->get_custom_flags()));
        }
        else {
            generate_junk(f_asm, code_holder, lines_iter, 5, 6);
        }
        break;
    }
    case 1: {
        //add reg1(not eax), 0

        uint32_t needed = (X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_CF | X86_EFLAGS_MODIFY_PF);

        if (IS_HAS_FULL_BITES(lines_iter->get_custom_flags(), needed)) {
            fuku_reg86 reg1 = fuku_reg86(FUKU_GET_RAND(fuku_reg86::r_ECX, fuku_reg86::r_EDI));

            code_holder.get_lines().insert(lines_iter, f_asm.add(reg1, fuku_immediate86(0)).set_custom_flags(lines_iter->get_custom_flags()));
        }
        else {
            generate_junk(f_asm, code_holder, lines_iter, 5, 6);
        }
        break;
    }
    case 2: {
        //jcc next_inst

        /*
        if (lines_iter != code_holder.get_lines().end()) {
            

            code_holder.get_lines().insert(lines_iter,
                f_asm.jcc((fuku_condition)FUKU_GET_RAND(0, 15), 0)
                .set_custom_flags(lines_iter->get_custom_flags()) 
            );
            
            auto jcc_iter = lines_iter; jcc_iter--;

            if (lines_iter->get_label_idx() != -1) {
                jcc_iter->set_label_idx(lines_iter->get_label_idx());
                code_holder.get_labels()[lines_iter->get_label_idx()].instruction = &(*jcc_iter);
                lines_iter->set_label_idx(-1);    
            }
            
            jcc_iter->set_rip_relocation_idx(code_holder.create_rip_relocation(2, &(*lines_iter)));
        }
        else {
            generate_junk(f_asm, code_holder, lines_iter, 5, 6);
        }*/
        generate_junk(f_asm, code_holder, lines_iter, 5, 6);
        break;
    }
    }
}


void fuku_junk_7b(fuku_asm_x86& f_asm, fuku_code_holder& code_holder, linestorage::iterator lines_iter) {

    //push reg1
    //mov reg1, randval
    //pop reg1

    if (!IS_HAS_FULL_BITES(lines_iter->get_instruction_flags(), fuku_instruction_bad_stack_pointer)) {

        fuku_reg86 reg1 = fuku_reg86(FUKU_GET_RAND(fuku_reg86::r_EAX, fuku_reg86::r_EBX));
        fuku_immediate86 imm = fuku_immediate86(FUKU_GET_RAND(0x10000000, 0xFFFFFFFF));

        fuku_instruction line[3];
        line[0] = f_asm.push(reg1).set_custom_flags(lines_iter->get_custom_flags());
        line[1] = f_asm.mov(reg1, imm).set_custom_flags(lines_iter->get_custom_flags());
        line[2] = f_asm.pop(reg1).set_custom_flags(lines_iter->get_custom_flags());

        if (FUKU_GET_RAND(0, 1)) {
            line[1].set_relocation_first_idx(code_holder.create_relocation(1, imm.get_imm(), 0));
        }

        code_holder.get_lines().insert(lines_iter, &line[0], &line[3]);
    }
    else {
        generate_junk(f_asm, code_holder, lines_iter, 6, 7);
    }

}