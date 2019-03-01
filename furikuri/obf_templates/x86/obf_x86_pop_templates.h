#pragma once

//add esp,4
//mov reg,[esp - 4]
inline bool _pop_86_multi_tmpl_1(mutation_context& ctx, fuku_type dst, int8_t inst_size) {

    size_t relocate_disp = ctx.current_line_iter->get_relocation_disp_idx();

    if (dst.get_type() == FUKU_T0_REGISTER && dst.get_register().get_index() == FUKU_REG_INDEX_SP) { return false; }

    if (has_inst_free_eflags(ctx.eflags_changes,
        X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_CF | X86_EFLAGS_MODIFY_PF)) {

        ctx.f_asm->add(reg_(FUKU_REG_ESP), imm(inst_size));
        ctx.f_asm->get_context().inst->
            set_eflags(ctx.eflags_changes)
            .set_custom_flags(ctx.regs_changes);
    }
    else {
        ctx.f_asm->lea(reg_(FUKU_REG_ESP), dword_ptr(FUKU_REG_ESP, imm(inst_size)));
        ctx.f_asm->get_context().inst->
            set_eflags(ctx.eflags_changes)
            .set_custom_flags(ctx.regs_changes);
    }

    uint64_t out_regflags = ctx.regs_changes & ~get_operand_mask_register(dst);

    ctx.f_asm->mov(dst, fuku_operand(FUKU_REG_ESP, imm(-inst_size), (fuku_operand_size)inst_size));
    ctx.f_asm->get_context().inst->
        set_eflags(ctx.eflags_changes)
        .set_custom_flags(out_regflags)
        .set_instruction_flags(FUKU_INST_BAD_STACK);    

    return true;
}


//mov reg,[esp]
//add esp,4
inline bool _pop_86_multi_tmpl_2(mutation_context& ctx, fuku_type dst, int8_t inst_size) {

    size_t relocate_disp = ctx.current_line_iter->get_relocation_disp_idx();

    if (dst.get_type() == FUKU_T0_REGISTER && dst.get_register().get_index() == FUKU_REG_INDEX_SP) { return false; }

    ctx.f_asm->mov(dst, fuku_operand(FUKU_REG_ESP, (fuku_operand_size)inst_size));
    ctx.f_asm->get_context().inst->
        set_eflags(ctx.eflags_changes)
        .set_custom_flags(ctx.regs_changes);

    uint64_t out_regflags = ctx.regs_changes & ~get_operand_mask_register(dst);


    if (has_inst_free_eflags(ctx.eflags_changes,
        X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_CF | X86_EFLAGS_MODIFY_PF)) {

        ctx.f_asm->add(reg_(FUKU_REG_ESP), imm(inst_size));
        ctx.f_asm->get_context().inst->
            set_eflags(ctx.eflags_changes)
            .set_custom_flags(out_regflags)
            .set_instruction_flags(FUKU_INST_BAD_STACK);
    }
    else {
        ctx.f_asm->lea(reg_(FUKU_REG_ESP), dword_ptr(FUKU_REG_ESP, imm(inst_size)));
        ctx.f_asm->get_context().inst->
            set_eflags(ctx.eflags_changes)
            .set_custom_flags(out_regflags)
            .set_instruction_flags(FUKU_INST_BAD_STACK);
    }

    return true;
}


bool _pop_86_reg_tmpl(mutation_context& ctx) {

    auto& detail = ctx.instruction->detail->x86;
    fuku_register reg_src = capstone_to_fuku_reg(detail.operands[0].reg);

    switch (FUKU_GET_RAND(0, 1)) {

    case 0: {
        return _pop_86_multi_tmpl_1(ctx, reg_src, detail.operands[0].size);
    }
    case 1: {
        return _pop_86_multi_tmpl_2(ctx, reg_src, detail.operands[0].size);
    }

    default: { return false; }
    }

    return true;
}


bool _pop_86_op_tmpl(mutation_context& ctx) {

    return false;
}