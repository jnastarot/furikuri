#pragma once

void fuku_mutation_x86::fuku_junk(fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {

    switch (FUKU_GET_RAND(0, 6)) {
    case 0: {
        fuku_junk_1b(code_holder, lines_iter);
        break;
    }
    case 1: {
        fuku_junk_2b(code_holder, lines_iter);
        break;
    }
    case 2: {
        fuku_junk_3b(code_holder, lines_iter);
        break;
    }
    case 3: {
        fuku_junk_4b(code_holder, lines_iter);
        break;
    }
    case 4: {
        fuku_junk_5b(code_holder, lines_iter);
        break;
    }
    case 5: {
        fuku_junk_6b(code_holder, lines_iter);
        break;
    }
    case 6: {
        fuku_junk_7b(code_holder, lines_iter);
        break;
    }
    }
}


void fuku_mutation_x86::fuku_junk_1b(fuku_code_holder& code_holder, linestorage::iterator lines_iter) {

    code_holder.get_lines().insert(lines_iter, f_asm.nop());
}

void fuku_mutation_x86::fuku_junk_2b(fuku_code_holder& code_holder, linestorage::iterator lines_iter) {

    switch (FUKU_GET_RAND(0, 4)) {
    
    case 0: {

        fuku_reg86 reg1 = fuku_reg86(FUKU_GET_RAND(fuku_reg86::r_EAX, fuku_reg86::r_EBX));

        code_holder.get_lines().insert(lines_iter, f_asm.mov(reg1, reg1).set_custom_flags(lines_iter->get_custom_flags()));
        break;
    }
    case 1: {
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

        fuku_reg86 reg1 = fuku_reg86(FUKU_GET_RAND(fuku_reg86::r_EAX, fuku_reg86::r_EBX));

        if ( !IS_HAS_FULL_BITES(lines_iter->get_instruction_flags(), fuku_instruction_bad_stack_pointer) ) {

            fuku_instruction line[2];

            line[0] = f_asm.push(reg1).set_custom_flags(lines_iter->get_custom_flags());
            line[1] = f_asm.pop(reg1).set_custom_flags(lines_iter->get_custom_flags());

            code_holder.get_lines().insert(lines_iter, &line[0], &line[2]);
        }
        else {

            code_holder.get_lines().insert(lines_iter, f_asm.lea(reg1, fuku_operand86(reg1, operand_scale::operand_scale_1, 0)).set_custom_flags(lines_iter->get_custom_flags()));
        }

        break;
    }

    case 3: {
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

void fuku_mutation_x86::fuku_junk_3b(fuku_code_holder& code_holder, linestorage::iterator lines_iter) {
    
    switch (FUKU_GET_RAND(0, 3)) {
    case 0: {
        uint32_t needed = (X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_CF);

        if (IS_HAS_FULL_BITES(lines_iter->get_custom_flags(), needed)) {
            fuku_reg86 reg1 = fuku_reg86(FUKU_GET_RAND(fuku_reg86::r_EAX, fuku_reg86::r_EDI));
            code_holder.get_lines().insert(lines_iter, f_asm.ror(reg1, 0).set_custom_flags(lines_iter->get_custom_flags()));
        }
        else {
            generate_junk(code_holder, lines_iter, 2, 3);
        }
   
        break;
    }
    case 1: {
        uint32_t needed = (X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_CF);

        if (IS_HAS_FULL_BITES(lines_iter->get_custom_flags(), needed)) {
            fuku_reg86 reg1 = fuku_reg86(FUKU_GET_RAND(fuku_reg86::r_EAX, fuku_reg86::r_EDI));
            code_holder.get_lines().insert(lines_iter, f_asm.rol(reg1, 0).set_custom_flags(lines_iter->get_custom_flags()));
        }
        else {
            generate_junk(code_holder, lines_iter, 2, 3);
        }
        break;
    }
    case 2: {
        uint32_t needed = (X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_CF);

        if (IS_HAS_FULL_BITES(lines_iter->get_custom_flags(), needed)) {
            code_holder.get_lines().insert(lines_iter, f_asm.sub(fuku_reg86::r_EAX, fuku_immediate86(0)).set_custom_flags(lines_iter->get_custom_flags()));
        }
        else {
            generate_junk(code_holder, lines_iter, 2, 3);
        }
        break;
    }
    case 3: {
        uint32_t needed = (X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_CF);

        if (IS_HAS_FULL_BITES(lines_iter->get_custom_flags(), needed)) {
            code_holder.get_lines().insert(lines_iter, f_asm.add(fuku_reg86::r_EAX, fuku_immediate86(0)).set_custom_flags(lines_iter->get_custom_flags()));
        }
        else {
            generate_junk(code_holder, lines_iter, 2, 3);
        }
        break;
    }
    }
}

void fuku_mutation_x86::fuku_junk_4b(fuku_code_holder& code_holder, linestorage::iterator lines_iter) {

    switch (FUKU_GET_RAND(0, 1)) {
    case 0: {
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

void fuku_mutation_x86::fuku_junk_5b(fuku_code_holder& code_holder, linestorage::iterator lines_iter) {

    
    switch (FUKU_GET_RAND(0, 1)) {
    case 0: {
        uint32_t needed = (X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_CF | X86_EFLAGS_MODIFY_PF);

        if (IS_HAS_FULL_BITES(lines_iter->get_custom_flags(), needed)) {
         //   code_holder.get_lines().insert(lines_iter, f_asm.sub(fuku_reg86::r_EAX, fuku_immediate86(FUKU_GET_RAND(0x100, 0xFFFFFFFF))).set_custom_flags(lines_iter->get_custom_flags()));
        }
        else {
            generate_junk(code_holder, lines_iter, 4, 5);
        }
        break;
    }
    case 1: {
        uint32_t needed = (X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_CF | X86_EFLAGS_MODIFY_PF);

        if (IS_HAS_FULL_BITES(lines_iter->get_custom_flags(), needed)) {
         //   code_holder.get_lines().insert(lines_iter, f_asm.add(fuku_reg86::r_EAX, fuku_immediate86(FUKU_GET_RAND(0x100, 0xFFFFFFFF))).set_custom_flags(lines_iter->get_custom_flags()));
        }
        else {
            generate_junk(code_holder, lines_iter, 4, 5);
        }
        break;
    }
    }
}

void fuku_mutation_x86::fuku_junk_6b(fuku_code_holder& code_holder, linestorage::iterator lines_iter) {

    
    switch (FUKU_GET_RAND(0, 1)) {
    case 0: {
        uint32_t needed = (X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_CF | X86_EFLAGS_MODIFY_PF);

        if (IS_HAS_FULL_BITES(lines_iter->get_custom_flags(), needed)) {
            fuku_reg86 reg1 = fuku_reg86(FUKU_GET_RAND(fuku_reg86::r_ECX, fuku_reg86::r_EDI));

            code_holder.get_lines().insert(lines_iter, f_asm.sub(reg1, fuku_immediate86(0)).set_custom_flags(lines_iter->get_custom_flags()));
        }
        else {
            generate_junk(code_holder, lines_iter, 5, 6);
        }
        break;
    }
    case 1: {
        uint32_t needed = (X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_CF | X86_EFLAGS_MODIFY_PF);
        
        if (IS_HAS_FULL_BITES(lines_iter->get_custom_flags(), needed)) {
            fuku_reg86 reg1 = fuku_reg86(FUKU_GET_RAND(fuku_reg86::r_ECX, fuku_reg86::r_EDI));

            code_holder.get_lines().insert(lines_iter, f_asm.add(reg1, fuku_immediate86(0)).set_custom_flags(lines_iter->get_custom_flags()));
        }
        else {
            generate_junk(code_holder, lines_iter, 5, 6);
        }
        break;
    }
    }
}


void fuku_mutation_x86::fuku_junk_7b(fuku_code_holder& code_holder, linestorage::iterator lines_iter) {

    
    if ( !IS_HAS_FULL_BITES(lines_iter->get_instruction_flags(), fuku_instruction_bad_stack_pointer) ) {

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
        generate_junk(code_holder, lines_iter, 6, 7);
    }

}