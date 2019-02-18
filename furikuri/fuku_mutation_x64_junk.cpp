#include "stdafx.h"
#include "fuku_mutation_x64_junk.h"

#define IsAllowedStackOperations (!HAS_FULL_MASK(ctx.instruction_flags, FUKU_INST_BAD_STACK))

uint32_t reg_sizes_64[] = {
    1,
    2,
    4,
    8
};

uint32_t reg_sizes_8_16_64[] = {
    1,
    2,
    8
};

uint32_t reg_sizes_16_64[] = {
    2,
    8
};

fuku_immediate generate_64_immediate(uint8_t size) {

    uint8_t sw_ = FUKU_GET_RAND(0, size * 4);

    switch (sw_) {
    case 0:
        return fuku_immediate(FUKU_GET_RAND(1, size * 0xFF) * 4);
    case 1:
        return fuku_immediate(FUKU_GET_RAND(1, 0xFFFFFFFF));


    case 2:case 3:
    case 4:case 5:
    case 6:case 7:
    case 8:case 9:
    case 10:case 11:
    case 12:case 13:
    case 14:case 15:
    case 16:
        return fuku_immediate(FUKU_GET_RAND(1, 0xF)* (1 << ((sw_ - 2) * 4)));

    default:
        break;
    }

    return fuku_immediate(FUKU_GET_RAND(1, 0xFFFFFFFF));
}


//transfer reg1,reg2
//transfer reg1,val
bool junk_64_low_pattern_1(mutation_context & ctx) {
 //   return false;
    uint32_t reg_size = reg_sizes_64[FUKU_GET_RAND(0, 2)];

    fuku_register reg1_ = get_random_free_flag_reg(ctx.regs_changes, reg_size, false, 
        FLAG_REGISTER_SP | FLAG_REGISTER_ESP | FLAG_REGISTER_RSP |
        FLAG_REGISTER_SPL | FLAG_REGISTER_BPL | FLAG_REGISTER_SIL | FLAG_REGISTER_DIL);

    if (reg1_.get_reg() == FUKU_REG_NONE) {
        return false;
    }


    switch (FUKU_GET_RAND(0, 4)) {
    case 0: {
        fuku_type src = generate_64_immediate(reg_size);

        if (FUKU_GET_RAND(0, 1)) {
            src = reg_(get_random_reg(reg_size, false));
        }

        ctx.f_asm->mov(reg1_, src);
        ctx.f_asm->get_context().inst->
            set_eflags(ctx.eflags_changes)
            .set_custom_flags(ctx.regs_changes);


        break;
    }
    case 1: {return false;
        fuku_register reg1_ = get_random_free_flag_reg(ctx.regs_changes, 1, false, FLAG_REGISTER_SP | FLAG_REGISTER_ESP | FLAG_REGISTER_RSP |
            FLAG_REGISTER_SPL | FLAG_REGISTER_BPL | FLAG_REGISTER_SIL | FLAG_REGISTER_DIL);

        if (reg1_.get_reg() == FUKU_REG_NONE) {
            return false;
        }

        ctx.f_asm->setcc(fuku_condition(FUKU_GET_RAND(0, 15)), reg1_);
        ctx.f_asm->get_context().inst->
            set_eflags(ctx.eflags_changes)
            .set_custom_flags(ctx.regs_changes);
        break;
    }
    case 2: { //todo
      /*  reg_size = reg_sizes_64[FUKU_GET_RAND(1, 2)];
        fuku_type src = generate_immediate(reg_size);

        if (FUKU_GET_RAND(0, 1)) {
            src = reg_(get_random_reg(reg_size, true));
        }

        ctx.f_asm->cmovcc(fuku_condition(FUKU_GET_RAND(0, 15)), reg1_, src);
        ctx.f_asm->get_context().inst->
            set_eflags(ctx.eflags_changes)
            .set_custom_flags(ctx.regs_changes);
        */
        break;
    }
    case 3: {return false;
        fuku_register reg2_ = get_random_free_flag_reg(ctx.regs_changes, reg_size, false, FLAG_REGISTER_SP | FLAG_REGISTER_ESP | FLAG_REGISTER_RSP |
            FLAG_REGISTER_SPL | FLAG_REGISTER_BPL | FLAG_REGISTER_SIL | FLAG_REGISTER_DIL);

        ctx.f_asm->xchg(reg1_, reg2_);
        ctx.f_asm->get_context().inst->
            set_eflags(ctx.eflags_changes)
            .set_custom_flags(ctx.regs_changes);


        break;
    }
    case 4: {return false;
        reg1_ = get_random_free_flag_reg(ctx.regs_changes, reg_sizes_64[FUKU_GET_RAND(1, 2)], false, FLAG_REGISTER_SP | FLAG_REGISTER_ESP | FLAG_REGISTER_RSP |
            FLAG_REGISTER_SPL | FLAG_REGISTER_BPL | FLAG_REGISTER_SIL | FLAG_REGISTER_DIL);

        if (reg1_.get_reg() == FUKU_REG_NONE) {
            return false;
        }

        ctx.f_asm->bswap(reg1_);
        ctx.f_asm->get_context().inst->
            set_eflags(ctx.eflags_changes)
            .set_custom_flags(ctx.regs_changes);

        break;
    }
    }
    return true;
}


//logical reg1,reg2
//logical reg1,val
bool junk_64_low_pattern_2(mutation_context & ctx) {


    if (!has_inst_free_eflags(ctx.eflags_changes,
        X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_CF | X86_EFLAGS_MODIFY_PF)) {

        return false;
    }

    uint32_t reg_size = reg_sizes_64[FUKU_GET_RAND(0, 3)];


    fuku_register reg1_ = get_random_free_flag_reg(ctx.regs_changes, reg_size, false, FLAG_REGISTER_SP | FLAG_REGISTER_ESP | FLAG_REGISTER_RSP |
        FLAG_REGISTER_SPL | FLAG_REGISTER_BPL | FLAG_REGISTER_SIL | FLAG_REGISTER_DIL);

    if (reg1_.get_reg() == FUKU_REG_NONE) {
        return false;
    }


    fuku_type src = generate_64_immediate(reg_size);

    if (FUKU_GET_RAND(0, 1)) {
        src = reg_(get_random_reg(reg_size, false));
    }

    switch (FUKU_GET_RAND(0, 4)) {

    case 0: {
        ctx.f_asm->xor_(reg1_, src);
        ctx.f_asm->get_context().inst->
            set_eflags(ctx.eflags_changes)
            .set_custom_flags(ctx.regs_changes);

        break;
    }

    case 1: {
        ctx.f_asm->and_(reg1_, src);
        ctx.f_asm->get_context().inst->
            set_eflags(ctx.eflags_changes)
            .set_custom_flags(ctx.regs_changes);

        break;
    }
    case 2: {
        ctx.f_asm->or_(reg1_, src);
        ctx.f_asm->get_context().inst->
            set_eflags(ctx.eflags_changes)
            .set_custom_flags(ctx.regs_changes);

        break;
    }
    case 3: {
        ctx.f_asm->test(reg1_, src);
        ctx.f_asm->get_context().inst->
            set_eflags(ctx.eflags_changes)
            .set_custom_flags(ctx.regs_changes);

        break;
    }
    case 4: {
        ctx.f_asm->not_(reg1_);
        ctx.f_asm->get_context().inst->
            set_eflags(ctx.eflags_changes)
            .set_custom_flags(ctx.regs_changes);

        break;
    }
    }

    return true;
}


//arithmetic reg1,reg2
//arithmetic reg1,val
bool junk_64_low_pattern_3(mutation_context & ctx) {


    if (!has_inst_free_eflags(ctx.eflags_changes,
        X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_CF | X86_EFLAGS_MODIFY_PF)) {

        return false;
    }

    uint32_t reg_size = reg_sizes_64[FUKU_GET_RAND(0, 3)];

    fuku_register reg1_ = get_random_free_flag_reg(ctx.regs_changes, reg_size, false, FLAG_REGISTER_SP | FLAG_REGISTER_ESP | FLAG_REGISTER_RSP);

    if (reg1_.get_reg() == FUKU_REG_NONE) {
        return false;
    }


    fuku_type src = generate_64_immediate(reg_size);

    if (FUKU_GET_RAND(0, 1)) {
        src = reg_(get_random_reg(reg_size, false));
    }

    switch (FUKU_GET_RAND(0, 7)) {

    case 0: {
        ctx.f_asm->add(reg1_, src);
        ctx.f_asm->get_context().inst->
            set_eflags(ctx.eflags_changes)
            .set_custom_flags(ctx.regs_changes);

        break;
    }

    case 1: {
        ctx.f_asm->adc(reg1_, src);
        ctx.f_asm->get_context().inst->
            set_eflags(ctx.eflags_changes)
            .set_custom_flags(ctx.regs_changes);

        break;
    }
    case 2: {
        ctx.f_asm->sub(reg1_, src);
        ctx.f_asm->get_context().inst->
            set_eflags(ctx.eflags_changes)
            .set_custom_flags(ctx.regs_changes);

        break;
    }
    case 3: {
        ctx.f_asm->sbb(reg1_, src);
        ctx.f_asm->get_context().inst->
            set_eflags(ctx.eflags_changes)
            .set_custom_flags(ctx.regs_changes);

        break;
    }
    case 4: {
        ctx.f_asm->cmp(reg1_, src);
        ctx.f_asm->get_context().inst->
            set_eflags(ctx.eflags_changes)
            .set_custom_flags(ctx.regs_changes);

        break;
    }
    case 5: {
        ctx.f_asm->inc(reg1_);
        ctx.f_asm->get_context().inst->
            set_eflags(ctx.eflags_changes)
            .set_custom_flags(ctx.regs_changes);

        break;
    }
    case 6: {
        ctx.f_asm->dec(reg1_);
        ctx.f_asm->get_context().inst->
            set_eflags(ctx.eflags_changes)
            .set_custom_flags(ctx.regs_changes);

        break;
    }
    case 7: {
        ctx.f_asm->neg(reg1_);
        ctx.f_asm->get_context().inst->
            set_eflags(ctx.eflags_changes)
            .set_custom_flags(ctx.regs_changes);

        break;
    }
    }

    return true;
}


//rotate reg1,val
//rotate reg1,cl
bool junk_64_low_pattern_4(mutation_context & ctx) {


    if (!has_inst_free_eflags(ctx.eflags_changes,
        X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_CF)) {

        return false;
    }

    uint32_t reg_size = reg_sizes_64[FUKU_GET_RAND(0, 3)];



    fuku_register reg1_ = get_random_free_flag_reg(ctx.regs_changes, reg_size, false, FLAG_REGISTER_SP | FLAG_REGISTER_ESP | FLAG_REGISTER_RSP);

    if (reg1_.get_reg() == FUKU_REG_NONE) {
        return false;
    }

    fuku_type src = fuku_immediate(FUKU_GET_RAND(1, reg_size * 16 - 1));

    if (FUKU_GET_RAND(0, 1)) {
        src = fuku_register(FUKU_REG_CL);
    }

    switch (FUKU_GET_RAND(0, 3)) {

    case 0: {
        ctx.f_asm->rol(reg1_, src);
        ctx.f_asm->get_context().inst->
            set_eflags(ctx.eflags_changes)
            .set_custom_flags(ctx.regs_changes);

        break;
    }

    case 1: {
        ctx.f_asm->ror(reg1_, src);
        ctx.f_asm->get_context().inst->
            set_eflags(ctx.eflags_changes)
            .set_custom_flags(ctx.regs_changes);

        break;
    }
    case 2: {
        ctx.f_asm->rcl(reg1_, src);
        ctx.f_asm->get_context().inst->
            set_eflags(ctx.eflags_changes)
            .set_custom_flags(ctx.regs_changes);

        break;
    }
    case 3: {
        ctx.f_asm->rcr(reg1_, src);
        ctx.f_asm->get_context().inst->
            set_eflags(ctx.eflags_changes)
            .set_custom_flags(ctx.regs_changes);

        break;
    }

    }

    return true;
}


//shift reg1,val
//shift reg1,reg
bool junk_64_low_pattern_5(mutation_context & ctx) {


    if (!has_inst_free_eflags(ctx.eflags_changes,
        X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_CF)) {

        return false;
    }

    uint32_t reg_size = reg_sizes_64[FUKU_GET_RAND(0, 3)];



    fuku_register reg1_ = get_random_free_flag_reg(ctx.regs_changes, reg_size, false, FLAG_REGISTER_SP | FLAG_REGISTER_ESP | FLAG_REGISTER_RSP);

    if (reg1_.get_reg() == FUKU_REG_NONE) {
        return false;
    }

    fuku_type src = fuku_immediate(FUKU_GET_RAND(1, reg_size * 16 - 1));

    if (FUKU_GET_RAND(0, 1)) {
        src = fuku_register(FUKU_REG_CL);
    }

    switch (FUKU_GET_RAND(0, 2)) {

    case 0: {
        ctx.f_asm->sar(reg1_, src);
        ctx.f_asm->get_context().inst->
            set_eflags(ctx.eflags_changes)
            .set_custom_flags(ctx.regs_changes);

        break;
    }

    case 1: {
        ctx.f_asm->shl(reg1_, src);
        ctx.f_asm->get_context().inst->
            set_eflags(ctx.eflags_changes)
            .set_custom_flags(ctx.regs_changes);

        break;
    }
    case 2: {
        ctx.f_asm->shr(reg1_, src);
        ctx.f_asm->get_context().inst->
            set_eflags(ctx.eflags_changes)
            .set_custom_flags(ctx.regs_changes);

        break;
    }

    }

    return true;
}



//bittest reg1,val
//bittest reg1,reg
bool junk_64_low_pattern_6(mutation_context & ctx) {


    if (!has_inst_free_eflags(ctx.eflags_changes,
        X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_CF)) {

        return false;
    }

    uint32_t reg_size = reg_sizes_64[FUKU_GET_RAND(1, 3)];



    fuku_register reg1_ = get_random_free_flag_reg(ctx.regs_changes, reg_size, false);

    if (reg1_.get_reg() == FUKU_REG_NONE) {
        return false;
    }

    fuku_type src = fuku_immediate(FUKU_GET_RAND(1, reg_size * 16 - 1));

    if (FUKU_GET_RAND(0, 1)) {
        src = reg_(get_random_reg(reg_size, false));
    }

    switch (FUKU_GET_RAND(0, 3)) {

    case 0: {
        ctx.f_asm->bt(reg1_, src);
        ctx.f_asm->get_context().inst->
            set_eflags(ctx.eflags_changes)
            .set_custom_flags(ctx.regs_changes);

        break;
    }

    case 1: {
        ctx.f_asm->btc(reg1_, src);
        ctx.f_asm->get_context().inst->
            set_eflags(ctx.eflags_changes)
            .set_custom_flags(ctx.regs_changes);

        break;
    }
    case 2: {
        ctx.f_asm->bts(reg1_, src);
        ctx.f_asm->get_context().inst->
            set_eflags(ctx.eflags_changes)
            .set_custom_flags(ctx.regs_changes);

        break;
    }
    case 3: {
        ctx.f_asm->btr(reg1_, src);
        ctx.f_asm->get_context().inst->
            set_eflags(ctx.eflags_changes)
            .set_custom_flags(ctx.regs_changes);

        break;
    }
    }

    return true;
}


//convert byte\word to word\dword
bool junk_64_low_pattern_7(mutation_context & ctx) {

    uint32_t reg_size = reg_sizes_64[FUKU_GET_RAND(0, 2)];

    fuku_register reg1_ = get_random_free_flag_reg(ctx.regs_changes, reg_size, false,
        FLAG_REGISTER_AL |
        FLAG_REGISTER_RCX | FLAG_REGISTER_ECX | FLAG_REGISTER_CX | FLAG_REGISTER_CL |
        FLAG_REGISTER_DL |
        FLAG_REGISTER_RBX | FLAG_REGISTER_EBX | FLAG_REGISTER_BX | FLAG_REGISTER_BL |
        FLAG_REGISTER_RSP | FLAG_REGISTER_ESP | FLAG_REGISTER_SP | FLAG_REGISTER_SPL |
        FLAG_REGISTER_RBP | FLAG_REGISTER_EBP | FLAG_REGISTER_BP | FLAG_REGISTER_BPL |
        FLAG_REGISTER_RSI | FLAG_REGISTER_ESI | FLAG_REGISTER_SI | FLAG_REGISTER_SIL |
        FLAG_REGISTER_RDI | FLAG_REGISTER_EDI | FLAG_REGISTER_DI | FLAG_REGISTER_DIL);


    if (reg1_.get_reg() == FUKU_REG_NONE) {
        return false;
    }


    switch (reg1_.get_reg()) {
    case FUKU_REG_AX: {
        ctx.f_asm->cbw();
        ctx.f_asm->get_context().inst->
            set_eflags(ctx.eflags_changes)
            .set_custom_flags(ctx.regs_changes);

        return false;
        break;
    }
    case FUKU_REG_EAX: {
        ctx.f_asm->cwde();
        ctx.f_asm->get_context().inst->
            set_eflags(ctx.eflags_changes)
            .set_custom_flags(ctx.regs_changes);
        return false;
        break;
    }
    case FUKU_REG_DX: {
        ctx.f_asm->cwd();
        ctx.f_asm->get_context().inst->
            set_eflags(ctx.eflags_changes)
            .set_custom_flags(ctx.regs_changes);

        break;
    }
    case FUKU_REG_EDX: {
        ctx.f_asm->cdq();
        ctx.f_asm->get_context().inst->
            set_eflags(ctx.eflags_changes)
            .set_custom_flags(ctx.regs_changes);

        break;
    }

    }

    return true;
}


//set / reset flag
bool junk_64_low_pattern_8(mutation_context & ctx) {


    switch (FUKU_GET_RAND(0, 4)) {

    case 0: {
        if (!has_inst_free_eflags(ctx.eflags_changes, X86_EFLAGS_MODIFY_CF)) { return false; }

        ctx.f_asm->stc();
        ctx.f_asm->get_context().inst->
            set_eflags(ctx.eflags_changes)
            .set_custom_flags(ctx.regs_changes);

        break;
    }

    case 1: {
        if (!has_inst_free_eflags(ctx.eflags_changes, X86_EFLAGS_MODIFY_CF)) { return false; }

        ctx.f_asm->clc();
        ctx.f_asm->get_context().inst->
            set_eflags(ctx.eflags_changes)
            .set_custom_flags(ctx.regs_changes);

        break;
    }
    case 2: {
        if (!has_inst_free_eflags(ctx.eflags_changes, X86_EFLAGS_MODIFY_CF)) { return false; }

        ctx.f_asm->cmc();
        ctx.f_asm->get_context().inst->
            set_eflags(ctx.eflags_changes)
            .set_custom_flags(ctx.regs_changes);

        break;
    }
    case 3: {
        if (!has_inst_free_eflags(ctx.eflags_changes, X86_EFLAGS_MODIFY_DF)) { return false; }

        ctx.f_asm->cld();
        ctx.f_asm->get_context().inst->
            set_eflags(ctx.eflags_changes)
            .set_custom_flags(ctx.regs_changes);

        break;
    }
    case 4: {
        if (!has_inst_free_eflags(ctx.eflags_changes, X86_EFLAGS_MODIFY_DF)) { return false; }

        ctx.f_asm->std();
        ctx.f_asm->get_context().inst->
            set_eflags(ctx.eflags_changes)
            .set_custom_flags(ctx.regs_changes);

        break;
    }
    }

    return true;
}

//inc reg
//neg reg
//inc reg
//neg reg
bool junk_64_high_pattern_1(mutation_context & ctx) {

    if (!has_inst_free_eflags(ctx.eflags_changes,
        X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_CF | X86_EFLAGS_MODIFY_PF)) {

        return false;
    }

    uint32_t reg_size = reg_sizes_64[FUKU_GET_RAND(0, 3)];
    fuku_register reg1_ = get_random_free_flag_reg(ctx.regs_changes, reg_size, false, FLAG_REGISTER_SP | FLAG_REGISTER_ESP | FLAG_REGISTER_RSP);

    if (reg1_.get_reg() == FUKU_REG_NONE) {
        return false;
    }

    ctx.f_asm->inc(reg1_);
    ctx.f_asm->get_context().inst->
        set_eflags(ctx.eflags_changes)
        .set_custom_flags(ctx.regs_changes);
    ctx.f_asm->neg(reg1_);
    ctx.f_asm->get_context().inst->
        set_eflags(ctx.eflags_changes)
        .set_custom_flags(ctx.regs_changes);
    ctx.f_asm->inc(reg1_);
    ctx.f_asm->get_context().inst->
        set_eflags(ctx.eflags_changes)
        .set_custom_flags(ctx.regs_changes);
    ctx.f_asm->neg(reg1_);
    ctx.f_asm->get_context().inst->
        set_eflags(ctx.eflags_changes)
        .set_custom_flags(ctx.regs_changes);

    return true;
}

//not reg1
//not reg1
bool junk_64_high_pattern_2(mutation_context & ctx) {//what the hell rex64 "not" clear high 32 bits of 64 bits register all time

    uint32_t reg_size = reg_sizes_8_16_64[FUKU_GET_RAND(0, 2)];
    fuku_register reg1_ = get_random_free_flag_reg(ctx.regs_changes, reg_size, false,
        FLAG_REGISTER_SP | FLAG_REGISTER_ESP | FLAG_REGISTER_RSP |
        FLAG_REGISTER_SPL | FLAG_REGISTER_BPL | FLAG_REGISTER_SIL | FLAG_REGISTER_DIL);

    if (reg1_.get_reg() == FUKU_REG_NONE) {
        return false;
    }

    uint64_t flag_reg = fuku_reg_to_complex_flag_reg(reg1_, reg_size);
    

    ctx.f_asm->not_(reg1_);
    ctx.f_asm->get_context().inst->
        set_eflags(ctx.eflags_changes)
        .set_custom_flags(ctx.regs_changes);
    ctx.f_asm->not_(reg1_);
    ctx.f_asm->get_context().inst->
        set_eflags(ctx.eflags_changes)
        .set_custom_flags(ctx.regs_changes & ~(flag_reg));

    return true;
}



//push reg1
//pop  reg1
bool junk_64_high_pattern_3(mutation_context & ctx) {
    return false;
    if (!IsAllowedStackOperations) {
        return false;
    }

    uint32_t reg_size = reg_sizes_16_64[FUKU_GET_RAND(0, 1)];
    fuku_register reg1_ = get_random_reg(reg_size, false, FLAG_REGISTER_SP | FLAG_REGISTER_ESP | FLAG_REGISTER_RSP);

    uint64_t flag_reg = fuku_reg_to_complex_flag_reg(reg1_, reg_size);

    ctx.f_asm->push(reg1_);
    ctx.f_asm->get_context().inst->
        set_eflags(ctx.eflags_changes)
        .set_custom_flags(ctx.regs_changes);

    ctx.f_asm->pop(reg1_);
    ctx.f_asm->get_context().inst->
        set_eflags(ctx.eflags_changes)
        .set_custom_flags(ctx.regs_changes | flag_reg);

    return true;
}


//jcc next_inst
bool junk_64_high_pattern_4(mutation_context & ctx) {

    if (ctx.current_line_iter == ctx.code_holder->get_lines().end()) {
        return false;
    }

    uint8_t cond = FUKU_GET_RAND(0, 15);

    ctx.f_asm->jcc(fuku_condition(cond), imm(-1));

    ctx.f_asm->get_context().inst->
        set_eflags(ctx.eflags_changes)
        .set_custom_flags(ctx.regs_changes)
        .set_rip_relocation_idx(
            ctx.code_holder->create_rip_relocation(
                ctx.f_asm->get_context().immediate_offset,
                ctx.f_asm->get_context().inst
            )
        );

    ctx.swap_junk_label = true;
    ctx.junk_label_idx = ctx.code_holder->get_rip_relocations()[ctx.f_asm->get_context().inst->get_rip_relocation_idx()].label_idx;

    return true;
}


//jmp next_inst
//some code trash
bool junk_64_high_pattern_5(mutation_context & ctx) {

    if (ctx.current_line_iter == ctx.code_holder->get_lines().end()) {
        return false;
    }

    ctx.f_asm->jmp(imm(-1));
    ctx.f_asm->get_context().inst->
        set_eflags(ctx.eflags_changes)
        .set_custom_flags(ctx.regs_changes)
        .set_rip_relocation_idx(
            ctx.code_holder->create_rip_relocation(
                ctx.f_asm->get_context().immediate_offset,
                ctx.f_asm->get_context().inst
            )
        );

    ctx.swap_junk_label = true;
    ctx.junk_label_idx = ctx.code_holder->get_rip_relocations()[ctx.f_asm->get_context().inst->get_rip_relocation_idx()].label_idx;


    std::vector<uint8_t> trash;

    for (uint8_t t_size = 0; t_size < FUKU_GET_RAND(1, 15); t_size++) {
        trash.push_back(FUKU_GET_RAND(0, 0xFF));
    }

    ctx.f_asm->nop();
    ctx.f_asm->get_context().inst->set_op_code(trash.data(), trash.size())
        .set_instruction_flags(FUKU_INST_JUNK_CODE);

    return true;
}



bool fuku_junk_64_generic_low(mutation_context & ctx) {

    switch (FUKU_GET_RAND(0, 7)) {
    case 0: {
        return junk_64_low_pattern_1(ctx);
    }
    case 1: {
   //     return junk_64_low_pattern_2(ctx);
    }
    case 2: {
  //      return junk_64_low_pattern_3(ctx);
    }
    case 3: {
   //     return junk_64_low_pattern_4(ctx);
    }
    case 4: {
  //      return junk_64_low_pattern_5(ctx);
    }
    case 5: {
  //      return junk_64_low_pattern_6(ctx);
    }
    case 6: {
   //     return junk_64_low_pattern_7(ctx);
    }
    case 7: {
   //     return junk_64_low_pattern_8(ctx);
    }
    }

    return false;
}


bool fuku_junk_64_generic_high(mutation_context & ctx) {

    switch (FUKU_GET_RAND(0, 4)) {
    case 0: {
        return junk_64_high_pattern_1(ctx);
    }
    case 1: {
        return junk_64_high_pattern_2(ctx);
    }
    case 2: {
        return junk_64_high_pattern_3(ctx);
    }
    case 3: {
        return junk_64_high_pattern_4(ctx);
    }
    case 4: {
        return junk_64_high_pattern_5(ctx);
    }
    }

    return false;
}

void fuku_junk_64_generic(mutation_context & ctx) {

    ctx.was_junked = false;

    switch (FUKU_GET_RAND(0, 3)) {
    case 0:
    case 1: {
        ctx.was_junked = fuku_junk_64_generic_low(ctx);
        break;
    }
    case 2:
    case 3: {
        ctx.was_junked = fuku_junk_64_generic_high(ctx);
        break;
    }
    }
}

