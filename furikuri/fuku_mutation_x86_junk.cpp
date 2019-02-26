#include "stdafx.h"
#include "fuku_mutation_x86_junk.h"

#define IsAllowedStackOperations (!HAS_FULL_MASK(ctx.instruction_flags, FUKU_INST_BAD_STACK))

uint8_t reg_sizes[] = {
    1,
    2,
    4
};


//transfer reg1,reg2
//transfer reg1,val
bool junk_86_low_pattern_1(mutation_context & ctx) {

    fuku_type dst;
    fuku_type src;

    switch (FUKU_GET_RAND(0, 7)) {
        case 0: {
            
            uint32_t reg_size = reg_sizes[FUKU_GET_RAND(0, 2)];

            if (!generate_86_operand_dst(ctx, dst, INST_ALLOW_REGISTER | INST_ALLOW_OPERAND,
                reg_size, ctx.regs_changes, FLAG_REGISTER_SP | FLAG_REGISTER_ESP)) {
                return false;
            }

            if (!generate_86_operand_src(ctx, src, INST_ALLOW_REGISTER | INST_ALLOW_IMMEDIATE
                | (dst.get_type() == FUKU_T0_OPERAND ? 0 : INST_ALLOW_OPERAND),
                reg_size, 0)) {
                return false;
            }

            ctx.f_asm->mov(dst, src);
            break;
        }
        case 1: {

            if (!generate_86_operand_dst(ctx, dst, INST_ALLOW_REGISTER | INST_ALLOW_OPERAND,
                1, ctx.regs_changes, FLAG_REGISTER_SP | FLAG_REGISTER_ESP)) {
                return false;
            }

            ctx.f_asm->setcc(fuku_condition(FUKU_GET_RAND(0, 15)), dst);
            break;
        }
        case 2: {
            uint32_t reg_size = reg_sizes[FUKU_GET_RAND(1, 2)];

            if (!generate_86_operand_dst(ctx, dst, INST_ALLOW_REGISTER,
                reg_size, ctx.regs_changes, FLAG_REGISTER_SP | FLAG_REGISTER_ESP)) {
                return false;
            }

            if (!generate_86_operand_src(ctx, src, INST_ALLOW_REGISTER | INST_ALLOW_OPERAND,
                reg_size, 0)) {
                return false;
            }

            ctx.f_asm->cmovcc(fuku_condition(FUKU_GET_RAND(0, 15)), dst, src);
            break;
        }
        case 3: {
            uint32_t reg_size = reg_sizes[FUKU_GET_RAND(0, 2)];

            if (!generate_86_operand_dst(ctx, dst, INST_ALLOW_REGISTER,
                reg_size, ctx.regs_changes, FLAG_REGISTER_SP | FLAG_REGISTER_ESP)) {
                return false;
            }

            if (!generate_86_operand_dst(ctx, src, INST_ALLOW_REGISTER
                | (dst.get_type() == FUKU_T0_OPERAND ? 0 : INST_ALLOW_OPERAND),
                reg_size, ctx.regs_changes, 0)) {
                return false;
            }

            ctx.f_asm->xchg(dst, src);
            break;
        }
        case 4: {

            uint32_t reg_size = reg_sizes[FUKU_GET_RAND(1, 2)];

            if (!generate_86_operand_dst(ctx, dst, INST_ALLOW_REGISTER,
                reg_size, ctx.regs_changes, FLAG_REGISTER_SP | FLAG_REGISTER_ESP)) {
                return false;
            }

            if (reg_size != 2) {
                reg_size = reg_sizes[FUKU_GET_RAND(0, 1)];
            }
            else {
                reg_size = 1;
            }

            if (!generate_86_operand_src(ctx, src, INST_ALLOW_REGISTER | INST_ALLOW_OPERAND,
                reg_size, 0)) {
                return false;
            }

            ctx.f_asm->movzx(dst, src);
            break;
        }
        case 5: {
            uint32_t reg_size = reg_sizes[FUKU_GET_RAND(1, 2)];

            if (!generate_86_operand_dst(ctx, dst, INST_ALLOW_REGISTER,
                reg_size, ctx.regs_changes, FLAG_REGISTER_SP | FLAG_REGISTER_ESP)) {
                return false;
            }

            if (reg_size != 2) {
                reg_size = reg_sizes[FUKU_GET_RAND(0, 1)];
            }
            else {
                reg_size = 1;
            }

            if (!generate_86_operand_src(ctx, src, INST_ALLOW_REGISTER | INST_ALLOW_OPERAND,
                reg_size, 0)) {
                return false;
            }

            ctx.f_asm->movsx(dst, src);
            break;
        }
        case 6: { return false;
            uint32_t reg_size = reg_sizes[FUKU_GET_RAND(1, 2)];

            if (!generate_86_operand_dst(ctx, dst, INST_ALLOW_REGISTER,
                reg_size, ctx.regs_changes, FLAG_REGISTER_SP | FLAG_REGISTER_ESP)) {
                return false;
            }

            if (!generate_86_operand_src(ctx, src, INST_ALLOW_REGISTER
                | (dst.get_type() == FUKU_T0_OPERAND ? 0 : INST_ALLOW_OPERAND),
                reg_size, 0)) {
                return false;
            }

            ctx.f_asm->movsxd(dst, src);
            break;
        }
        case 7: {
            uint32_t reg_size = reg_sizes[FUKU_GET_RAND(2, 3)];

            if (!generate_86_operand_dst(ctx, dst, INST_ALLOW_REGISTER,
                reg_size, ctx.regs_changes, FLAG_REGISTER_SP | FLAG_REGISTER_ESP)) {
                return false;
            }

            ctx.f_asm->bswap(dst);
            break;
        }
    }


    ctx.f_asm->get_context().inst->
        set_eflags(ctx.eflags_changes)
        .set_custom_flags(ctx.regs_changes);

    return true;
}


//logical reg1,reg2
//logical reg1,val
bool junk_86_low_pattern_2(mutation_context & ctx) {


    if (!has_inst_free_eflags(ctx.eflags_changes,
        X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_CF | X86_EFLAGS_MODIFY_PF)) {

        return false;
    }


    fuku_type dst;
    fuku_type src;

    uint32_t reg_size = reg_sizes[FUKU_GET_RAND(0, 2)];

    if (!generate_86_operand_dst(ctx, dst, INST_ALLOW_REGISTER | INST_ALLOW_OPERAND,
        reg_size, ctx.regs_changes, FLAG_REGISTER_SP | FLAG_REGISTER_ESP)) {
        return false;
    }

    bool has_src = generate_86_operand_src(ctx, src, INST_ALLOW_REGISTER | INST_ALLOW_IMMEDIATE
        | (dst.get_type() == FUKU_T0_OPERAND ? 0 : INST_ALLOW_OPERAND),
        reg_size, 0);

    switch (FUKU_GET_RAND(has_src ? 0 : 4, 4)) {

    case 0: {
        ctx.f_asm->xor_(dst, src);
        break;
    }
    case 1: {
        ctx.f_asm->and_(dst, src);
        break;
    }
    case 2: {
        ctx.f_asm->or_(dst, src);
        break;
    }
    case 3: {
        ctx.f_asm->test(dst, src);
        break;
    }
    case 4: {
       ctx.f_asm->not_(dst);
        break;
    }
    default: {return false; }
    }

    ctx.f_asm->get_context().inst->
        set_eflags(ctx.eflags_changes)
        .set_custom_flags(ctx.regs_changes);

    return true;
}


//arithmetic reg1,reg2
//arithmetic reg1,val
bool junk_86_low_pattern_3(mutation_context & ctx) {

    if (!has_inst_free_eflags(ctx.eflags_changes,
        X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_CF | X86_EFLAGS_MODIFY_PF)) {
        return false;
    }

    fuku_type dst;
    fuku_type src;

    uint32_t reg_size = reg_sizes[FUKU_GET_RAND(0, 2)];

    if (!generate_86_operand_dst(ctx, dst, INST_ALLOW_REGISTER | INST_ALLOW_OPERAND,
        reg_size, ctx.regs_changes, FLAG_REGISTER_SP | FLAG_REGISTER_ESP)) {
        return false;
    }

    bool has_src = generate_86_operand_src(ctx, src, INST_ALLOW_REGISTER | INST_ALLOW_IMMEDIATE
        | (dst.get_type() == FUKU_T0_OPERAND ? 0 : INST_ALLOW_OPERAND),
        reg_size, 0);

    switch (FUKU_GET_RAND(has_src ? 0 : 5, 7)) {

    case 0: {
        ctx.f_asm->add(dst, src);
        break;
    }
    case 1: {
        ctx.f_asm->adc(dst, src);
        break;
    }
    case 2: {
        ctx.f_asm->sub(dst, src);
        break;
    }
    case 3: {
        ctx.f_asm->sbb(dst, src);
        break;
    }
    case 4: {
        ctx.f_asm->cmp(dst, src);
        break;
    }
    case 5: {
        ctx.f_asm->inc(dst);
        break;
    }
    case 6: {
        ctx.f_asm->dec(dst);
        break;
    }
    case 7: {
        ctx.f_asm->neg(dst);
        break;
    }
    default: {return false; }
    }

    ctx.f_asm->get_context().inst->
        set_eflags(ctx.eflags_changes)
        .set_custom_flags(ctx.regs_changes);

    return true;
}


//rotate reg1,val
//rotate reg1,cl
bool junk_86_low_pattern_4(mutation_context & ctx) {


    if (!has_inst_free_eflags(ctx.eflags_changes,
        X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_CF)) {

        return false;
    }


    fuku_type dst;
    fuku_type src;

    uint32_t reg_size = reg_sizes[FUKU_GET_RAND(0, 2)];

    if (!generate_86_operand_dst(ctx, dst, INST_ALLOW_REGISTER | INST_ALLOW_OPERAND,
        reg_size, ctx.regs_changes, FLAG_REGISTER_SP | FLAG_REGISTER_ESP)) {
        return false;
    }


    if (FUKU_GET_RAND(0, 1)) {
        src = fuku_register(FUKU_REG_CL);
    }
    else {
        src = fuku_immediate(FUKU_GET_RAND(1, reg_size * 16 - 1));
    }

    switch (FUKU_GET_RAND(0, 3)) {

    case 0: {
       ctx.f_asm->rol(dst, src);
        break;
    }
    case 1: {
        ctx.f_asm->ror(dst, src);
        break;
    }
    case 2: {
        ctx.f_asm->rcl(dst, src);
        break;
    }
    case 3: {
        ctx.f_asm->rcr(dst, src);
        break;
    }
    default: {return false; }
    }


    ctx.f_asm->get_context().inst->
        set_eflags(ctx.eflags_changes)
        .set_custom_flags(ctx.regs_changes);

    return true;
}


//shift reg1,val
//shift reg1,reg
bool junk_86_low_pattern_5(mutation_context & ctx) {


    if (!has_inst_free_eflags(ctx.eflags_changes,
        X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_CF)) {

        return false;
    }

    fuku_type dst;
    fuku_type src;

    uint32_t reg_size = reg_sizes[FUKU_GET_RAND(0, 2)];

    if (!generate_86_operand_dst(ctx, dst, INST_ALLOW_REGISTER | INST_ALLOW_OPERAND,
        reg_size, ctx.regs_changes, FLAG_REGISTER_SP | FLAG_REGISTER_ESP)) {
        return false;
    }

    if (FUKU_GET_RAND(0, 1)) {
        src = fuku_register(FUKU_REG_CL);
    }
    else {
        src = fuku_immediate(FUKU_GET_RAND(1, reg_size * 16 - 1));
    }

    switch (FUKU_GET_RAND(0, 2)) {

    case 0: {
        ctx.f_asm->sar(dst, src);
        break;
    }
    case 1: {
        ctx.f_asm->shl(dst, src);
        break;
    }
    case 2: {
        ctx.f_asm->shr(dst, src);
        break;
    }
    default: {return false; }
    }


    ctx.f_asm->get_context().inst->
        set_eflags(ctx.eflags_changes)
        .set_custom_flags(ctx.regs_changes);

    return true;
}



//bittest reg1,val
//bittest reg1,reg
bool junk_86_low_pattern_6(mutation_context & ctx) {


    if (!has_inst_free_eflags(ctx.eflags_changes,
        X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_CF)) {

        return false;
    }

    fuku_type dst;
    fuku_type src;

    uint32_t reg_size = reg_sizes[FUKU_GET_RAND(1, 2)];

    if (!generate_86_operand_dst(ctx, dst, INST_ALLOW_REGISTER | INST_ALLOW_OPERAND,
        reg_size, ctx.regs_changes, FLAG_REGISTER_SP | FLAG_REGISTER_ESP)) {
        return false;
    }

    if (!generate_86_operand_src(ctx, src, INST_ALLOW_REGISTER | INST_ALLOW_IMMEDIATE,
        1, 0)) {
        return false;
    }


    switch (FUKU_GET_RAND(0, 3)) {

    case 0: {
        ctx.f_asm->bt(dst, src);
        break;
    }
    case 1: {
        ctx.f_asm->btc(dst, src);
        break;
    }
    case 2: {
        ctx.f_asm->bts(dst, src);
        break;
    }
    case 3: {
        ctx.f_asm->btr(dst, src);
        break;
    }
    default: {return false; }
    }


    ctx.f_asm->get_context().inst->
        set_eflags(ctx.eflags_changes)
        .set_custom_flags(ctx.regs_changes);

    return true;
}


//convert byte\word to word\dword
bool junk_86_low_pattern_7(mutation_context & ctx) {

    uint32_t reg_size = reg_sizes[FUKU_GET_RAND(0, 2)];

    fuku_type dst;

    if (!generate_86_operand_dst(ctx, dst, INST_ALLOW_REGISTER,
        reg_size, ctx.regs_changes, 
        FLAG_REGISTER_AL |
        FLAG_REGISTER_RCX | FLAG_REGISTER_ECX | FLAG_REGISTER_CX | FLAG_REGISTER_CL |
        FLAG_REGISTER_DL |
        FLAG_REGISTER_RBX | FLAG_REGISTER_EBX | FLAG_REGISTER_BX | FLAG_REGISTER_BL |
        FLAG_REGISTER_RSP | FLAG_REGISTER_ESP | FLAG_REGISTER_SP | FLAG_REGISTER_SPL |
        FLAG_REGISTER_RBP | FLAG_REGISTER_EBP | FLAG_REGISTER_BP | FLAG_REGISTER_BPL |
        FLAG_REGISTER_RSI | FLAG_REGISTER_ESI | FLAG_REGISTER_SI | FLAG_REGISTER_SIL |
        FLAG_REGISTER_RDI | FLAG_REGISTER_EDI | FLAG_REGISTER_DI | FLAG_REGISTER_DIL)) {
        return false;
    }


    if (dst.get_register().get_reg() == FUKU_REG_NONE) {
        return false;
    }

    switch (dst.get_register().get_reg()) {
    case FUKU_REG_AX: {
        ctx.f_asm->cbw();
        break;
    }
    case FUKU_REG_EAX: {
        ctx.f_asm->cwde();
        break;
    }
    case FUKU_REG_DX: {
        if (!has_free_flag_register(ctx.regs_changes, FLAG_REGISTER_AX)) { return false; }
       ctx.f_asm->cwd();
        break;
    }
    case FUKU_REG_EDX: {
        if (!has_free_flag_register(ctx.regs_changes, FLAG_REGISTER_EAX)) { return false; }
        ctx.f_asm->cdq();
        break;
    }
    default: {return false; }
    }

    ctx.f_asm->get_context().inst->
        set_eflags(ctx.eflags_changes)
        .set_custom_flags(ctx.regs_changes);

    return true;
}


//set / reset flag
bool junk_86_low_pattern_8(mutation_context & ctx) {


    switch (FUKU_GET_RAND(0, 4)) {

    case 0: {
        if (!has_inst_free_eflags(ctx.eflags_changes,X86_EFLAGS_MODIFY_CF)) { return false; }

        ctx.f_asm->stc();
        break;
    }
    case 1: {
        if (!has_inst_free_eflags(ctx.eflags_changes, X86_EFLAGS_MODIFY_CF)) { return false; }

        ctx.f_asm->clc();
        break;
    }
    case 2: {
        if (!has_inst_free_eflags(ctx.eflags_changes, X86_EFLAGS_MODIFY_CF)) { return false; }

        ctx.f_asm->cmc();
        break;
    }
    case 3: {
        if (!has_inst_free_eflags(ctx.eflags_changes, X86_EFLAGS_MODIFY_DF)) { return false; }

        ctx.f_asm->cld();
        break;
    }
    case 4: {
        if (!has_inst_free_eflags(ctx.eflags_changes, X86_EFLAGS_MODIFY_DF)) { return false; }

        ctx.f_asm->std();
        break;
    }
    default: {return false; }
    }

    ctx.f_asm->get_context().inst->
        set_eflags(ctx.eflags_changes)
        .set_custom_flags(ctx.regs_changes);

    return true;
}

//inc reg
//neg reg
//inc reg
//neg reg
bool junk_86_high_pattern_1(mutation_context & ctx) {

    if (!has_inst_free_eflags(ctx.eflags_changes,
        X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_CF | X86_EFLAGS_MODIFY_PF)) {

        return false;
    }

    fuku_type dst;
    
    uint32_t reg_size = reg_sizes[FUKU_GET_RAND(0, 2)];

    if (!generate_86_operand_dst(ctx, dst, INST_ALLOW_REGISTER | INST_ALLOW_OPERAND,
        reg_size, ctx.regs_changes, FLAG_REGISTER_SP | FLAG_REGISTER_ESP)) {
        return false;
    }

    ctx.f_asm->inc(dst);
    ctx.f_asm->get_context().inst->
        set_eflags(ctx.eflags_changes)
        .set_custom_flags(ctx.regs_changes);
    ctx.f_asm->neg(dst);
    ctx.f_asm->get_context().inst->
        set_eflags(ctx.eflags_changes)
        .set_custom_flags(ctx.regs_changes);
    ctx.f_asm->inc(dst);
    ctx.f_asm->get_context().inst->
        set_eflags(ctx.eflags_changes)
        .set_custom_flags(ctx.regs_changes);
    ctx.f_asm->neg(dst);
    ctx.f_asm->get_context().inst->
        set_eflags(ctx.eflags_changes)
        .set_custom_flags(ctx.regs_changes);

    return true;
}

//not reg1
//not reg1
bool junk_86_high_pattern_2(mutation_context & ctx) {

    fuku_type dst;

    uint32_t reg_size = reg_sizes[FUKU_GET_RAND(0, 2)];

    if (!generate_86_operand_dst(ctx, dst, INST_ALLOW_REGISTER | INST_ALLOW_OPERAND,
        reg_size, ctx.regs_changes, FLAG_REGISTER_SP | FLAG_REGISTER_ESP)) {
        return false;
    }

    uint64_t flag_reg = fuku_reg_to_complex_flag_reg(dst.get_register().get_reg(), reg_size);


    ctx.f_asm->not_(dst);
    ctx.f_asm->get_context().inst->
        set_eflags(ctx.eflags_changes)
        .set_custom_flags(ctx.regs_changes);
    ctx.f_asm->not_(dst);
    ctx.f_asm->get_context().inst->
        set_eflags(ctx.eflags_changes)
        .set_custom_flags(ctx.regs_changes & ~(flag_reg));

    return true;
}



//push reg1
//pop  reg1
bool junk_86_high_pattern_3(mutation_context & ctx) {

    if (!IsAllowedStackOperations) {
        return false;
    }


    fuku_type src;

    uint32_t reg_size = reg_sizes[FUKU_GET_RAND(1, 2)];

    if (!generate_86_operand_src(ctx, src, INST_ALLOW_REGISTER,
        reg_size, FLAG_REGISTER_SP | FLAG_REGISTER_ESP)) {
        return false;
    }

    uint64_t flag_reg = fuku_reg_to_complex_flag_reg(src.get_register().get_reg(), reg_size);

    ctx.f_asm->push(src);
    ctx.f_asm->get_context().inst->
        set_eflags(ctx.eflags_changes)
        .set_custom_flags(ctx.regs_changes);

    ctx.f_asm->pop(src);
    ctx.f_asm->get_context().inst->
        set_eflags(ctx.eflags_changes)
        .set_custom_flags(ctx.regs_changes | flag_reg);

    return true;
}


//jcc next_inst
bool junk_86_high_pattern_4(mutation_context & ctx) {

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
bool junk_86_high_pattern_5(mutation_context & ctx) {

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
    ctx.f_asm->get_context().inst->set_op_code(trash.data(), (uint8_t)trash.size())
        .set_instruction_flags(FUKU_INST_JUNK_CODE);

    return true;
}


bool fuku_junk_86_generic_low(mutation_context & ctx) {

    switch (FUKU_GET_RAND(0, 7)) {
    case 0: {
        return junk_86_low_pattern_1(ctx);
    }
    case 1: {
        return junk_86_low_pattern_2(ctx);
    }
    case 2: {
        return junk_86_low_pattern_3(ctx);
    }
    case 3: {
        return junk_86_low_pattern_4(ctx);
    }
    case 4: {
        return junk_86_low_pattern_5(ctx);
    }
    case 5: {
        return junk_86_low_pattern_6(ctx);
    }
    case 6: {
        return junk_86_low_pattern_7(ctx);
    }
    case 7: {
        return junk_86_low_pattern_8(ctx);
    }
    }

    return false;
}


bool fuku_junk_86_generic_high(mutation_context & ctx) {

    switch (FUKU_GET_RAND(0, 4)) {
    case 0: {
        return junk_86_high_pattern_1(ctx);
    }
    case 1: {
        return junk_86_high_pattern_2(ctx);
    }
    case 2: {
        return junk_86_high_pattern_3(ctx);
    }
    case 3: {
        return junk_86_high_pattern_4(ctx);
    }
    case 4: {
        return junk_86_high_pattern_5(ctx);
    }
    }

    return false;
}

void fuku_junk_86_generic(mutation_context & ctx) {

    ctx.was_junked = false;

    switch (FUKU_GET_RAND(0, 3)) {
    case 0:
    case 1: {
        ctx.was_junked = fuku_junk_86_generic_low(ctx);
        break;
    }
    case 2:
    case 3: {
        ctx.was_junked = fuku_junk_86_generic_high(ctx);
        break;
    }
    }
}
