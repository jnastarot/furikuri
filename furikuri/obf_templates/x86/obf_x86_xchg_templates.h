#pragma once


//xor dst_1, dst_2
//xor dst_2, dst_1
//xor dst_1, dst_2
inline bool _xchg_86_multi_tmpl_1(mutation_context& ctx, fuku_type dst_1, fuku_type dst_2, int8_t inst_size) {

    if (has_inst_free_eflags(ctx.eflags_changes,
        X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_CF | X86_EFLAGS_MODIFY_PF)) {

        uint64_t changes_regflags = ctx.regs_changes & ~get_operand_mask_register(dst_1, dst_2);

        ctx.f_asm->xor_(dst_1, dst_2);
        ctx.f_asm->get_context().inst->
            set_eflags(ctx.eflags_changes)
            .set_custom_flags(changes_regflags);
        ctx.f_asm->xor_(dst_2, dst_1);
        ctx.f_asm->get_context().inst->
            set_eflags(ctx.eflags_changes)
            .set_custom_flags(changes_regflags);
        ctx.f_asm->xor_(dst_1, dst_2);
        ctx.f_asm->get_context().inst->
            set_eflags(ctx.eflags_changes)
            .set_custom_flags(changes_regflags);

        return true;
    }

    return false;
}

//mov temp_dst_1, dst_1
//mov temp_dst_2, dst_2
//mov dst_1, temp_dst_2
//mov dst_2, temp_dst_1
inline bool _xchg_86_multi_tmpl_2(mutation_context& ctx, fuku_type dst_1, fuku_type dst_2, int8_t inst_size) {


    fuku_type temp_dst_1;
    fuku_type temp_dst_2;

    uint32_t additation_inst_flag = 0;

    if ((dst_1.get_type() == FUKU_T0_OPERAND ? 
        dst_1.get_operand().get_base().get_index() == FUKU_REG_INDEX_SP || dst_1.get_operand().get_index().get_index() == FUKU_REG_INDEX_SP : 
        dst_1.get_register().get_index() == FUKU_REG_INDEX_SP) ||
        dst_2.get_operand().get_base().get_index() == FUKU_REG_INDEX_SP) {

        additation_inst_flag = FUKU_INST_BAD_STACK;
    }

    uint64_t out_regflags = ctx.regs_changes & ~get_operand_mask_register(dst_1, dst_2);


    if (!generate_86_operand_dst(ctx, temp_dst_1, INST_ALLOW_REGISTER, inst_size, out_regflags,
        FLAG_REGISTER_SP | FLAG_REGISTER_ESP)) {

        return false;
    }

    out_regflags &= ~get_operand_mask_register(temp_dst_1);

    if (!generate_86_operand_dst(ctx, temp_dst_2, INST_ALLOW_REGISTER, inst_size, out_regflags,
        FLAG_REGISTER_SP | FLAG_REGISTER_ESP)) {

        return false;
    }

    out_regflags &= ~get_operand_mask_register(temp_dst_2);

    size_t relocate_disp = ctx.current_line_iter->get_relocation_disp_idx();

    ctx.f_asm->mov(temp_dst_1, dst_1);
    ctx.f_asm->get_context().inst->
        set_eflags(ctx.eflags_changes)
        .set_custom_flags(out_regflags).set_instruction_flags(additation_inst_flag);
    restore_disp_relocate(dst_1);
    ctx.f_asm->mov(temp_dst_2, dst_2);
    ctx.f_asm->get_context().inst->
        set_eflags(ctx.eflags_changes)
        .set_custom_flags(out_regflags).set_instruction_flags(additation_inst_flag);
    ctx.f_asm->mov(dst_1, temp_dst_2);
    ctx.f_asm->get_context().inst->
        set_eflags(ctx.eflags_changes)
        .set_custom_flags(out_regflags).set_instruction_flags(additation_inst_flag);
    restore_disp_relocate(dst_1);
    ctx.f_asm->mov(dst_2, temp_dst_1);
    ctx.f_asm->get_context().inst->
        set_eflags(ctx.eflags_changes)
        .set_custom_flags(out_regflags).set_instruction_flags(additation_inst_flag);

    return true;
}

bool _xchg_86_reg_reg_tmpl(mutation_context& ctx) {

    auto& detail = ctx.instruction->detail->x86;

    fuku_register reg_dst_1 = capstone_to_fuku_reg(detail.operands[0].reg);
    fuku_register reg_dst_2 = capstone_to_fuku_reg(detail.operands[1].reg);

    switch (FUKU_GET_RAND(0, 0)) {

    case 0: {
        return _xchg_86_multi_tmpl_1(ctx, reg_dst_1, reg_dst_2, detail.operands[0].size);
    }
    case 1: {
        return _xchg_86_multi_tmpl_2(ctx, reg_dst_1, reg_dst_2, detail.operands[0].size);
    }
    default: { return false; }
    }

    return true;
}

bool _xchg_86_op_reg_tmpl(mutation_context& ctx) {

    auto& detail = ctx.instruction->detail->x86;

    fuku_operand op_dst(FUKU_REG_NONE, FUKU_OPERAND_SIZE_0);
    fuku_register reg_dst;

    if (ctx.instruction->detail->x86.operands[0].type == X86_OP_MEM) {
        op_dst = capstone_to_fuku_op(detail, 0);
        reg_dst = capstone_to_fuku_reg(detail.operands[1].reg);
    }
    else {
        op_dst = capstone_to_fuku_op(detail, 1);
        reg_dst = capstone_to_fuku_reg(detail.operands[0].reg);
    }


    switch (FUKU_GET_RAND(0, 0)) {

    case 0: {
        return _xchg_86_multi_tmpl_2(ctx, op_dst, reg_dst, detail.operands[0].size);
    }
    default: { return false; }
    }

    return true;
}