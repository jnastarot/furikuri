#pragma once

//push reg
//ret   
inline bool _jmp_86_multi_tmpl_1(mutation_context& ctx, fuku_type src, uint8_t inst_size) {

    if (IsAllowedStackOperations) {
        size_t relocate_rip = ctx.current_line_iter->get_rip_relocation_idx();
        size_t relocate_disp = ctx.current_line_iter->get_relocation_disp_idx();

        if (src.get_type() == FUKU_T0_IMMEDIATE) { //need 4 byte imm
            ctx.f_asm->push(imm(0xFFFFFFFF));
            restore_rip_to_imm_relocate(src);
        }
        else {
            ctx.f_asm->push(src);
            restore_disp_relocate(src);
        }
 
        ctx.f_asm->get_context().inst->
            set_eflags(ctx.eflags_changes)
            .set_custom_flags(ctx.regs_changes);

        ctx.f_asm->ret(imm(0));
        ctx.f_asm->get_context().inst->
            set_eflags(ctx.eflags_changes)
            .set_custom_flags(ctx.regs_changes);
    }
    else {
        return false;
    }

    return true;
}

//je  dst
//jne dst
inline bool _jmp_86_multi_tmpl_2(mutation_context& ctx, fuku_type src, uint8_t inst_size) {

    if (src.get_type() != FUKU_T0_IMMEDIATE) { return false; }

    uint8_t cond = FUKU_GET_RAND(0, 15);

    size_t relocate_rip = ctx.current_line_iter->get_rip_relocation_idx();
    size_t rip_label_idx = ctx.code_holder->get_rip_relocations()[relocate_rip].label_idx;

    ctx.f_asm->jcc(fuku_condition(cond), imm(0xFFFFFFFF));
    ctx.f_asm->get_context().inst->
        set_eflags(ctx.eflags_changes)
        .set_custom_flags(ctx.regs_changes)
        .set_rip_relocation_idx(ctx.code_holder->create_rip_relocation_lb(ctx.f_asm->get_context().immediate_offset, rip_label_idx))
        .set_instruction_flags(ctx.instruction_flags | FUKU_INST_NO_MUTATE);

    ctx.f_asm->jcc(fuku_condition(cond ^ 1), imm(0xFFFFFFFF));
    ctx.f_asm->get_context().inst->
        set_eflags(ctx.eflags_changes & (~di_fl_jcc[fuku_condition(cond ^ 1)]))
        .set_custom_flags(ctx.regs_changes)
        .set_rip_relocation_idx(ctx.code_holder->create_rip_relocation_lb(ctx.f_asm->get_context().immediate_offset, rip_label_idx))
        .set_instruction_flags(ctx.instruction_flags | FUKU_INST_NO_MUTATE);

    ctx.code_holder->delete_rip_relocation(relocate_rip);

    return true;
}


//mov randreg, dst
//jmp randreg
inline bool _jmp_86_multi_tmpl_3(mutation_context& ctx, fuku_type src, uint8_t inst_size) {

    fuku_register rand_reg = get_random_free_flag_reg(ctx.regs_changes, 4, true);

    if (rand_reg.get_reg() != FUKU_REG_NONE) {

        size_t relocate_rip = ctx.current_line_iter->get_rip_relocation_idx();
        size_t relocate_disp = ctx.current_line_iter->get_relocation_disp_idx();

        uint64_t out_regflags = ctx.regs_changes & ~get_operand_mask_register(rand_reg, src);

        if (src.get_type() == FUKU_T0_IMMEDIATE) { //need 4 byte imm
            ctx.f_asm->mov(rand_reg, imm(0xFFFFFFFF));
            restore_rip_to_imm_relocate(src);
        }
        else {
            ctx.f_asm->mov(rand_reg, src);
            restore_disp_relocate(src);
        }

        ctx.f_asm->get_context().inst->
            set_eflags(ctx.eflags_changes)
            .set_custom_flags(out_regflags);      

        ctx.f_asm->jmp(rand_reg);
        ctx.f_asm->get_context().inst->
            set_eflags(ctx.eflags_changes)
            .set_custom_flags(out_regflags);

    }
    else {
        return false;
    }

    return true;
}


bool _jmp_86_imm_tmpl(mutation_context& ctx) {

    auto& detail = ctx.instruction->detail->x86;
    fuku_immediate imm_src = detail.operands[0].imm;

    switch (FUKU_GET_RAND(0, 2)) {

    case 0: {
        return _jmp_86_multi_tmpl_1(ctx, imm_src, detail.operands[0].size);
    }
    case 1: {
        return _jmp_86_multi_tmpl_2(ctx, imm_src, detail.operands[0].size);
    }
    case 2: {
        return _jmp_86_multi_tmpl_3(ctx, imm_src, detail.operands[0].size);
    }
    default: { return false; }
    }

    return true;
}


bool _jmp_86_reg_tmpl(mutation_context& ctx) {

    auto& detail = ctx.instruction->detail->x86;
    fuku_register reg_src = capstone_to_fuku_reg(detail.operands[0].reg);

    switch (FUKU_GET_RAND(0, 1)) {

    case 0: {
        return _jmp_86_multi_tmpl_1(ctx, reg_src, detail.operands[0].size);
    }
    case 1: {
        return _jmp_86_multi_tmpl_3(ctx, reg_src, detail.operands[0].size);
    }

    default: { return false; }
    }

    return true;
}


bool _jmp_86_op_tmpl(mutation_context& ctx) {

    auto& detail = ctx.instruction->detail->x86;
    fuku_operand op_src = capstone_to_fuku_op(detail, 0);

    switch (FUKU_GET_RAND(0, 1)) {

    case 0: {
        return _jmp_86_multi_tmpl_1(ctx, op_src, detail.operands[0].size);
    }
    case 1: {
        return _jmp_86_multi_tmpl_3(ctx, op_src, detail.operands[0].size);
    }

    default: { return false; }
    }

    return true;
}