#include "stdafx.h"
#include "fuku_mutation_x86_junk.h"


//mov reg,reg
void junk_pattern_1(fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator lines_iter, 
    bool unstable_stack, uint64_t eflags_changes, uint64_t regs_changes) {

    
}

//inc reg
//neg reg
//inc reg
//neg reg
void junk_pattern_2(fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator lines_iter, 
    bool unstable_stack, uint64_t eflags_changes, uint64_t regs_changes) {


}


void junk_pattern_3(fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator lines_iter,
    bool unstable_stack, uint64_t eflags_changes, uint64_t regs_changes) {


}


void fuku_junk_generic(fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator lines_iter,
    bool unstable_stack, uint64_t eflags_changes, uint64_t regs_changes) {


    switch (FUKU_GET_RAND(0, 7)) {
    case 0: {
        fuku_junk_1b(f_asm, code_holder, lines_iter,
            unstable_stack, eflags_changes, regs_changes);

        return;
    }
    case 1: {
        fuku_junk_2b(f_asm, code_holder, lines_iter,
            unstable_stack, eflags_changes, regs_changes);

        return;
    }
    case 2: {
        fuku_junk_3b(f_asm, code_holder, lines_iter,
            unstable_stack, eflags_changes, regs_changes);

        return;
    }
    case 3: {
        fuku_junk_4b(f_asm, code_holder, lines_iter,
            unstable_stack, eflags_changes, regs_changes);

        return;
    }
    case 4: {
        fuku_junk_5b(f_asm, code_holder, lines_iter,
            unstable_stack, eflags_changes, regs_changes);

        return;
    }
    case 5: {
        fuku_junk_6b(f_asm, code_holder, lines_iter,
            unstable_stack, eflags_changes, regs_changes);

        return;
    }
    case 6: {
        fuku_junk_7b(f_asm, code_holder, lines_iter,
            unstable_stack, eflags_changes, regs_changes);

        return;
    }
    case 7: {


    }
    }

}

void fuku_junk_1b(fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator lines_iter,
    bool unstable_stack, uint64_t eflags_changes, uint64_t regs_changes) {

    f_asm.nop(1);
}

void fuku_junk_2b(fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator lines_iter, 
    bool unstable_stack, uint64_t eflags_changes, uint64_t regs_changes) {

    uint32_t instruction_flags = lines_iter->get_instruction_flags();

    if (!HAS_FULL_MASK(instruction_flags, FUKU_INST_BAD_STACK)) {

        f_asm.push(reg_(FUKU_REG_EAX));
        f_asm.get_context().inst->set_eflags(lines_iter->get_eflags());
        f_asm.pop(reg_(FUKU_REG_EAX));
        f_asm.get_context().inst->set_eflags(lines_iter->get_eflags());
    }

    /*
    switch (FUKU_GET_RAND(0, 4)) {

    case 0: {
        //mov reg1, reg1

        fuku_reg86 reg1 = fuku_reg86(FUKU_GET_RAND(fuku_reg86::r_EAX, fuku_reg86::r_EBX));

        code_holder.get_lines().insert(lines_iter, f_asm.mov(reg1, reg1).set_eflags(lines_iter->get_eflags()));
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
            line[0] = f_asm.xchg(reg1, reg2).set_eflags(lines_iter->get_eflags());
        }
        else {
            line[0] = f_asm.xchg(reg2, reg1).set_eflags(lines_iter->get_eflags());
        }

        if (FUKU_GET_RAND(0, 1)) {
            line[1] = f_asm.xchg(reg1, reg2).set_eflags(lines_iter->get_eflags());
        }
        else {
            line[1] = f_asm.xchg(reg2, reg1).set_eflags(lines_iter->get_eflags());
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

        if (!HAS_FULL_MASK(lines_iter->get_instruction_flags(), fuku_instruction_bad_stack_pointer)) {

            fuku_instruction line[2];

            line[0] = f_asm.push(reg1).set_eflags(lines_iter->get_eflags());
            line[1] = f_asm.pop(reg1).set_eflags(lines_iter->get_eflags());

            code_holder.get_lines().insert(lines_iter, &line[0], &line[2]);
        }
        else {
            //lea reg1, [reg1]

            code_holder.get_lines().insert(lines_iter, f_asm.lea(reg1, fuku_operand86(reg1, operand_scale::operand_scale_1, 0)).set_eflags(lines_iter->get_eflags()));
        }

        break;
    }

    case 3: {
        //cmp reg1, reg2

        uint32_t needed = (X86_EFLAGS_MODIFY_CF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_AF);

        if (HAS_FULL_MASK(lines_iter->get_eflags(), needed)) {
            fuku_reg86 reg1 = fuku_reg86(FUKU_GET_RAND(fuku_reg86::r_EAX, fuku_reg86::r_EDI));
            fuku_reg86 reg2 = fuku_reg86(FUKU_GET_RAND(fuku_reg86::r_EAX, fuku_reg86::r_EDI));

            code_holder.get_lines().insert(lines_iter, f_asm.cmp(reg1, reg2).set_eflags(lines_iter->get_eflags()));
        }
        else {
            goto jk_2s;
        }

        break;
    }
    case 4: {
        //test reg1, reg2

        uint32_t needed = (X86_EFLAGS_MODIFY_CF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_AF);

        if (HAS_FULL_MASK(lines_iter->get_eflags(), needed)) {
            fuku_reg86 reg1 = fuku_reg86(FUKU_GET_RAND(fuku_reg86::r_EAX, fuku_reg86::r_EDI));
            fuku_reg86 reg2 = fuku_reg86(FUKU_GET_RAND(fuku_reg86::r_EAX, fuku_reg86::r_EDI));

            code_holder.get_lines().insert(lines_iter, f_asm.test(reg1, reg2).set_eflags(lines_iter->get_eflags()));
        }
        else {
            goto jk_3s;
        }

        break;
    }

    }*/
}

void fuku_junk_3b(fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator lines_iter,
    bool unstable_stack, uint64_t eflags_changes, uint64_t regs_changes) {

}

void fuku_junk_4b(fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator lines_iter,
    bool unstable_stack, uint64_t eflags_changes, uint64_t regs_changes) {

}

void fuku_junk_5b(fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator lines_iter,
    bool unstable_stack, uint64_t eflags_changes, uint64_t regs_changes) {

}

void fuku_junk_6b(fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator lines_iter,
    bool unstable_stack, uint64_t eflags_changes, uint64_t regs_changes) {



}

void fuku_junk_7b(fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator lines_iter,
    bool unstable_stack, uint64_t eflags_changes, uint64_t regs_changes) {


}

/*
void fuku_junk_3b(fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator lines_iter) {

    switch (FUKU_GET_RAND(0, 3)) {
    case 0: {
        //ror reg1, 0

        fuku_reg86 reg1 = fuku_reg86(FUKU_GET_RAND(fuku_reg86::r_EAX, fuku_reg86::r_EDI));
        code_holder.get_lines().insert(lines_iter, f_asm.ror(reg1, 0).set_eflags(lines_iter->get_eflags()));

        break;
    }
    case 1: {
        //rol reg1, 0

        fuku_reg86 reg1 = fuku_reg86(FUKU_GET_RAND(fuku_reg86::r_EAX, fuku_reg86::r_EDI));
        code_holder.get_lines().insert(lines_iter, f_asm.rol(reg1, 0).set_eflags(lines_iter->get_eflags()));

        break;
    }
    case 2: {
        //sub reg1, 0

        uint32_t needed = (X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_CF);

        if (HAS_FULL_MASK(lines_iter->get_eflags(), needed)) {
            code_holder.get_lines().insert(lines_iter, f_asm.sub(fuku_reg86::r_EAX, fuku_immediate86(0)).set_eflags(lines_iter->get_eflags()));
        }
        else {
            generate_junk(f_asm, code_holder, lines_iter, 2, 3);
        }
        break;
    }
    case 3: {
        //add reg1, 0

        uint32_t needed = (X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_CF);

        if (HAS_FULL_MASK(lines_iter->get_eflags(), needed)) {
            code_holder.get_lines().insert(lines_iter, f_asm.add(fuku_reg86::r_EAX, fuku_immediate86(0)).set_eflags(lines_iter->get_eflags()));
        }
        else {
            generate_junk(f_asm, code_holder, lines_iter, 2, 3);
        }
        break;
    }
    }
}

void fuku_junk_4b(fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator lines_iter) {

    switch (FUKU_GET_RAND(0, 1)) {
    case 0: {
        //not reg1
        //not reg1

        fuku_reg86 reg1 = fuku_reg86(FUKU_GET_RAND(fuku_reg86::r_EAX, fuku_reg86::r_EBX));

        fuku_instruction line[2];

        line[0] = f_asm.not(reg1).set_eflags(lines_iter->get_eflags());
        line[1] = f_asm.not(reg1).set_eflags(lines_iter->get_eflags());


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
            line[0] = f_asm.xchg(reg1, reg2).set_eflags(lines_iter->get_eflags());
        }
        else {
            line[0] = f_asm.xchg(reg2, reg1).set_eflags(lines_iter->get_eflags());
        }

        if (FUKU_GET_RAND(0, 1)) {
            line[1] = f_asm.xchg(reg1, reg2).set_eflags(lines_iter->get_eflags());
        }
        else {
            line[1] = f_asm.xchg(reg2, reg1).set_eflags(lines_iter->get_eflags());
        }

        if (reg1 == fuku_reg86::r_ESP || reg2 == fuku_reg86::r_ESP) {
            line[1].set_instruction_flags(fuku_instruction_bad_stack_pointer);
        }

        code_holder.get_lines().insert(lines_iter, &line[0], &line[2]);

        break;
    }

    }
}

void fuku_junk_5b(fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator lines_iter) {


    switch (FUKU_GET_RAND(0, 1)) {
    case 0: {
        //push reg1
        //ror reg1, rand
        //pop reg1

        uint32_t needed = (X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_CF);

        if (HAS_FULL_MASK(lines_iter->get_eflags(), needed) &&
            !HAS_FULL_MASK(lines_iter->get_instruction_flags(), fuku_instruction_bad_stack_pointer)) {

            fuku_reg86 reg1 = fuku_reg86(FUKU_GET_RAND(fuku_reg86::r_EAX, fuku_reg86::r_EDI));
            if (reg1 == fuku_reg86::r_ESP) { reg1 = fuku_reg86::r_EAX; }

            fuku_instruction line[3];

            line[0] = f_asm.push(reg1).set_eflags(lines_iter->get_eflags());
            line[1] = f_asm.ror(reg1, FUKU_GET_RAND(1, 31)).set_eflags(lines_iter->get_eflags());
            line[2] = f_asm.pop(reg1).set_eflags(lines_iter->get_eflags());

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

        if (HAS_FULL_MASK(lines_iter->get_eflags(), needed) &&
            !HAS_FULL_MASK(lines_iter->get_instruction_flags(), fuku_instruction_bad_stack_pointer)) {

            fuku_reg86 reg1 = fuku_reg86(FUKU_GET_RAND(fuku_reg86::r_EAX, fuku_reg86::r_EDI));
            if (reg1 == fuku_reg86::r_ESP) { reg1 = fuku_reg86::r_EAX; }


            fuku_instruction line[3];

            line[0] = f_asm.push(reg1).set_eflags(lines_iter->get_eflags());
            line[1] = f_asm.rol(reg1, FUKU_GET_RAND(1, 31)).set_eflags(lines_iter->get_eflags());
            line[2] = f_asm.pop(reg1).set_eflags(lines_iter->get_eflags());

            code_holder.get_lines().insert(lines_iter, &line[0], &line[3]);
        }
        else {
            generate_junk(f_asm, code_holder, lines_iter, 4, 5);
        }
        break;
    }
    }
}

void fuku_junk_6b(fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator lines_iter) {


    switch (FUKU_GET_RAND(0, 2)) {
    case 0: {
        //sub reg1(not eax), 0

        uint32_t needed = (X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_CF | X86_EFLAGS_MODIFY_PF);

        if (HAS_FULL_MASK(lines_iter->get_eflags(), needed)) {
            fuku_reg86 reg1 = fuku_reg86(FUKU_GET_RAND(fuku_reg86::r_ECX, fuku_reg86::r_EDI));

            code_holder.get_lines().insert(lines_iter, f_asm.sub(reg1, fuku_immediate86(0)).set_eflags(lines_iter->get_eflags()));
        }
        else {
            generate_junk(f_asm, code_holder, lines_iter, 5, 6);
        }
        break;
    }
    case 1: {
        //add reg1(not eax), 0

        uint32_t needed = (X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_CF | X86_EFLAGS_MODIFY_PF);

        if (HAS_FULL_MASK(lines_iter->get_eflags(), needed)) {
            fuku_reg86 reg1 = fuku_reg86(FUKU_GET_RAND(fuku_reg86::r_ECX, fuku_reg86::r_EDI));

            code_holder.get_lines().insert(lines_iter, f_asm.add(reg1, fuku_immediate86(0)).set_eflags(lines_iter->get_eflags()));
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
                .set_eflags(lines_iter->get_eflags())
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
        }//
        generate_junk(f_asm, code_holder, lines_iter, 5, 6);
        break;
    }
    }
}


void fuku_junk_7b(fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator lines_iter) {

    //push reg1
    //mov reg1, randval
    //pop reg1

    if (!HAS_FULL_MASK(lines_iter->get_instruction_flags(), fuku_instruction_bad_stack_pointer)) {

        fuku_reg86 reg1 = fuku_reg86(FUKU_GET_RAND(fuku_reg86::r_EAX, fuku_reg86::r_EBX));
        fuku_immediate86 imm = fuku_immediate86(FUKU_GET_RAND(0x10000000, 0xFFFFFFFF));

        fuku_instruction line[3];
        line[0] = f_asm.push(reg1).set_eflags(lines_iter->get_eflags());
        line[1] = f_asm.mov(reg1, imm).set_eflags(lines_iter->get_eflags());
        line[2] = f_asm.pop(reg1).set_eflags(lines_iter->get_eflags());

        if (FUKU_GET_RAND(0, 1)) {
            line[1].set_relocation_first_idx(code_holder.create_relocation(1, imm.get_imm(), 0));
        }

        code_holder.get_lines().insert(lines_iter, &line[0], &line[3]);
    }
    else {
        generate_junk(f_asm, code_holder, lines_iter, 6, 7);
    }

}
*/

