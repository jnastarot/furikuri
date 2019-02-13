#include "stdafx.h"
#include "fuku_mutation_x86_junk.h"

uint32_t reg_sizes[] = {
    1,
    2,
    4
};


//transfer reg1,reg2
bool junk_pattern_1(fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator lines_iter, 
    bool unstable_stack, uint64_t eflags_changes, uint64_t regs_changes) {

    uint32_t reg_size = reg_sizes[FUKU_GET_RAND(0, 2)];

    fuku_register reg1_ = get_random_free_flag_reg(regs_changes, reg_size, true, FUKU_REG_ESP);

    if (reg1_.get_reg() == FUKU_REG_NONE) {
        return false;
    }
    

    switch (FUKU_GET_RAND(0, 1)) {
        case 0: {
            fuku_register reg2_ = get_random_reg(reg_size, true);

            f_asm.mov(reg1_, reg2_);
            f_asm.get_context().inst->
                set_eflags(eflags_changes)
                .set_custom_flags(regs_changes);


            break;
        }
        case 1: {
            fuku_register reg2_ = get_random_free_flag_reg(regs_changes, reg_size, true, FUKU_REG_ESP);

            f_asm.xchg(reg1_, reg2_);
            f_asm.get_context().inst->
                set_eflags(eflags_changes)
                .set_custom_flags(regs_changes);


            break;
        }
    }
    return true;
}


//logical reg1,reg2
bool junk_pattern_2(fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator lines_iter,
    bool unstable_stack, uint64_t eflags_changes, uint64_t regs_changes) {


    if (!has_inst_free_eflags(eflags_changes,
        X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_CF | X86_EFLAGS_MODIFY_PF)) {

        return false;
    }

    uint32_t reg_size = reg_sizes[FUKU_GET_RAND(0, 2)];


    fuku_register reg1_ = get_random_free_flag_reg(regs_changes, reg_size, true, FUKU_REG_ESP);

    if (reg1_.get_reg() == FUKU_REG_NONE) {
        return false;
    }
    fuku_register reg2_ = get_random_reg(reg_size, true);


    switch (FUKU_GET_RAND(0, 3)) {

    case 0: {
        f_asm.xor_(reg1_, reg2_);
        f_asm.get_context().inst->
            set_eflags(eflags_changes)
            .set_custom_flags(regs_changes);

        break;
    }

    case 1: {
        f_asm.and_(reg1_, reg2_);
        f_asm.get_context().inst->
            set_eflags(eflags_changes)
            .set_custom_flags(regs_changes);

        break;
    }
    case 2: {
        f_asm.or_(reg1_, reg2_);
        f_asm.get_context().inst->
            set_eflags(eflags_changes)
            .set_custom_flags(regs_changes);

        break;
    }
    case 3: {
        f_asm.test(reg1_, reg2_);
        f_asm.get_context().inst->
            set_eflags(eflags_changes)
            .set_custom_flags(regs_changes);

        break;
    }
    }

    return true;
}


//arithmetic reg1,reg2
bool junk_pattern_3(fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator lines_iter,
    bool unstable_stack, uint64_t eflags_changes, uint64_t regs_changes) {


    if (!has_inst_free_eflags(eflags_changes,
        X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_CF | X86_EFLAGS_MODIFY_PF)) {

        return false;
    }

    uint32_t reg_size = reg_sizes[FUKU_GET_RAND(0, 2)];

    fuku_register reg1_ = get_random_free_flag_reg(regs_changes, reg_size, true, FUKU_REG_ESP);

    if (reg1_.get_reg() == FUKU_REG_NONE) {
        return false;
    }
    fuku_register reg2_ = get_random_reg(reg_size, true);


    switch (FUKU_GET_RAND(0, 4)) {

    case 0: {
        f_asm.add(reg1_, reg2_);
        f_asm.get_context().inst->
            set_eflags(eflags_changes)
            .set_custom_flags(regs_changes);

        break;
    }

    case 1: {
        f_asm.adc(reg1_, reg2_);
        f_asm.get_context().inst->
            set_eflags(eflags_changes)
            .set_custom_flags(regs_changes);

        break;
    }
    case 2: {
        f_asm.sub(reg1_, reg2_);
        f_asm.get_context().inst->
            set_eflags(eflags_changes)
            .set_custom_flags(regs_changes);

        break;
    }
    case 3: {
        f_asm.sbb(reg1_, reg2_);
        f_asm.get_context().inst->
            set_eflags(eflags_changes)
            .set_custom_flags(regs_changes);

        break;
    }
    case 4: {
        f_asm.cmp(reg1_, reg2_);
        f_asm.get_context().inst->
            set_eflags(eflags_changes)
            .set_custom_flags(regs_changes);

        break;
    }
    }

    return true;
}


//shift reg1,val
bool junk_pattern_4(fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator lines_iter,
    bool unstable_stack, uint64_t eflags_changes, uint64_t regs_changes) {


    if (!has_inst_free_eflags(eflags_changes,
        X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_CF)) {

        return false;
    }

    uint32_t reg_size = reg_sizes[FUKU_GET_RAND(0, 2)];

    fuku_register reg1_ = get_random_free_flag_reg(regs_changes, reg_size, true, FUKU_REG_ESP);

    if (reg1_.get_reg() == FUKU_REG_NONE) {
        return false;
    }


    fuku_immediate shift_8 = FUKU_GET_RAND(1, 64);

    switch (FUKU_GET_RAND(0, 4)) {

    case 0: {
        f_asm.rol(reg1_, shift_8);
        f_asm.get_context().inst->
            set_eflags(eflags_changes)
            .set_custom_flags(regs_changes);

        break;
    }

    case 1: {
        f_asm.ror(reg1_, shift_8);
        f_asm.get_context().inst->
            set_eflags(eflags_changes)
            .set_custom_flags(regs_changes);

        break;
    }
    case 2: {
        f_asm.rcl(reg1_, shift_8);
        f_asm.get_context().inst->
            set_eflags(eflags_changes)
            .set_custom_flags(regs_changes);

        break;
    }
    case 3: {
        f_asm.rcr(reg1_, shift_8);
        f_asm.get_context().inst->
            set_eflags(eflags_changes)
            .set_custom_flags(regs_changes);

        break;
    }

    }

    return true;
}

//inc reg
//neg reg
//inc reg
//neg reg
bool junk_pattern_5(fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator lines_iter, 
    bool unstable_stack, uint64_t eflags_changes, uint64_t regs_changes) {

    if (!has_inst_free_eflags(eflags_changes,
        X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_CF | X86_EFLAGS_MODIFY_PF)) {

        return false;
    }

    fuku_register reg1_ = get_random_free_flag_reg(regs_changes, 4, true, FUKU_REG_ESP);

    if (reg1_.get_reg() == FUKU_REG_NONE) {
        return false;
    }

    f_asm.inc(reg1_);
    f_asm.get_context().inst->
        set_eflags(eflags_changes)
        .set_custom_flags(regs_changes);
    f_asm.neg(reg1_);
    f_asm.get_context().inst->
        set_eflags(eflags_changes)
        .set_custom_flags(regs_changes);
    f_asm.inc(reg1_);
    f_asm.get_context().inst->
        set_eflags(eflags_changes)
        .set_custom_flags(regs_changes);
    f_asm.neg(reg1_);
    f_asm.get_context().inst->
        set_eflags(eflags_changes)
        .set_custom_flags(regs_changes);

    return true;
}

//push reg
//
//pop reg
void junk_pattern__5(fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator lines_iter,
    bool unstable_stack, uint64_t eflags_changes, uint64_t regs_changes) {


}


void fuku_junk_generic(fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator lines_iter,
    bool unstable_stack, uint64_t eflags_changes, uint64_t regs_changes) {


    switch (FUKU_GET_RAND(0, 4)) {
    case 0: {
        junk_pattern_1(f_asm, code_holder, lines_iter,
            unstable_stack, eflags_changes, regs_changes);

        return;
    }
    case 1: {
        junk_pattern_2(f_asm, code_holder, lines_iter,
            unstable_stack, eflags_changes, regs_changes);

        return;
    }
    case 2: {
        junk_pattern_3(f_asm, code_holder, lines_iter,
            unstable_stack, eflags_changes, regs_changes);

        return;
    }
    case 3: {
        junk_pattern_4(f_asm, code_holder, lines_iter,
            unstable_stack, eflags_changes, regs_changes);

        return;
    }
    case 4: {
        junk_pattern_5(f_asm, code_holder, lines_iter,
            unstable_stack, eflags_changes, regs_changes);

        return;
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

