#pragma once

//mov somereg, src
//xchg dst, somereg
inline bool _mov_86_multi_tmpl_1(mutation_context& ctx, fuku_type dst, fuku_type src, int8_t inst_size) {

    size_t relocate_imm = ctx.current_line_iter->get_relocation_imm_idx();
    size_t relocate_disp = ctx.current_line_iter->get_relocation_disp_idx();

    fuku_type temp_dst;

    uint64_t changes_regflags = ctx.regs_changes & ~get_operand_mask_register(dst, src);

    if (!generate_86_operand_dst(ctx, temp_dst, INST_ALLOW_REGISTER, inst_size, changes_regflags,
        FLAG_REGISTER_SP | FLAG_REGISTER_ESP)) {

        return false;
    }

    uint64_t out_regflags = changes_regflags & ~(fuku_reg_to_complex_flag_reg(temp_dst.get_register().get_reg(), 8));

    ctx.f_asm->mov(temp_dst, src);
    ctx.f_asm->get_context().inst->
        set_eflags(ctx.eflags_changes)
        .set_custom_flags(out_regflags);

    restore_imm_or_disp(src)

    ctx.f_asm->xchg(dst, temp_dst);
    ctx.f_asm->get_context().inst->
        set_eflags(ctx.eflags_changes)
        .set_custom_flags(out_regflags);


    restore_disp_relocate(dst)

    return true;
}


//xor dst,dst 
//add dst, src
inline bool _mov_86_multi_tmpl_2(mutation_context& ctx, fuku_type dst, fuku_type src, int8_t inst_size) {

    size_t relocate_imm = ctx.current_line_iter->get_relocation_imm_idx();
    size_t relocate_disp = ctx.current_line_iter->get_relocation_disp_idx();

    if (has_inst_free_eflags(ctx.eflags_changes,
        X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_CF | X86_EFLAGS_MODIFY_PF)) {

        uint64_t out_regflags = ctx.regs_changes & ~get_operand_mask_register(dst, src);

        ctx.f_asm->xor_(dst, dst);
        ctx.f_asm->get_context().inst->
            set_eflags(ctx.eflags_changes)
            .set_custom_flags(ctx.regs_changes);

        ctx.f_asm->add(dst, src);
        ctx.f_asm->get_context().inst->
            set_eflags(ctx.eflags_changes)
            .set_custom_flags(out_regflags);

        restore_imm_or_disp(src)
    }
    else {
        return false;
    }

    return true;
}

//push src
//pop dst
inline bool _mov_86_multi_tmpl_3(mutation_context& ctx, fuku_type dst, fuku_type src, int8_t inst_size) {

    if (inst_size == 1 || (src.get_type() == FUKU_T0_IMMEDIATE && inst_size != 4) ) { return false; }

    size_t relocate_imm = ctx.current_line_iter->get_relocation_imm_idx();
    size_t relocate_disp = ctx.current_line_iter->get_relocation_disp_idx();

    if (IsAllowedStackOperations &&
        ((dst.get_type() == FUKU_T0_REGISTER) ? dst.get_register().get_index() != FUKU_REG_INDEX_SP : true) &&
        ((src.get_type() == FUKU_T0_REGISTER) ? src.get_register().get_index() != FUKU_REG_INDEX_SP : true)) {

        uint64_t out_regflags = ctx.regs_changes & ~get_operand_mask_register(dst, src);

        ctx.f_asm->push(src);
        ctx.f_asm->get_context().inst->
            set_eflags(ctx.eflags_changes)
            .set_custom_flags(out_regflags);

        restore_imm_or_disp(src)

        ctx.f_asm->pop(dst);
        ctx.f_asm->get_context().inst->
            set_eflags(ctx.eflags_changes)
            .set_custom_flags(out_regflags);

        restore_disp_relocate(dst)

    }
    else {
        return false;
    }

    return true;
}

bool _mov_86_reg_reg_tmpl(mutation_context& ctx) {

    auto& detail = ctx.instruction->detail->x86;

    fuku_register reg_dst = capstone_to_fuku_reg(detail.operands[0].reg);
    fuku_register reg_src = capstone_to_fuku_reg(detail.operands[1].reg);

    switch (FUKU_GET_RAND(0, 2)) {

    case 0: {
        return _mov_86_multi_tmpl_1(ctx, reg_dst, reg_src, detail.operands[0].size);
    }
    case 1: {
        return _mov_86_multi_tmpl_2(ctx, reg_dst, reg_src, detail.operands[0].size);
    }
    case 2: {
        return _mov_86_multi_tmpl_3(ctx, reg_dst, reg_src, detail.operands[0].size);
    }

    default: { return false; }
    }

    return true;
}

bool _mov_86_reg_imm_tmpl(mutation_context& ctx) {

    auto& detail = ctx.instruction->detail->x86;

    fuku_register reg_dst = capstone_to_fuku_reg(detail.operands[0].reg);
    fuku_immediate imm_src = detail.operands[1].imm;

    switch (FUKU_GET_RAND(0, 2)) {

    case 0: {
        return _mov_86_multi_tmpl_1(ctx, reg_dst, imm_src, detail.operands[0].size);
    }
    case 1: {
        return _mov_86_multi_tmpl_2(ctx, reg_dst, imm_src, detail.operands[0].size);
    }
    case 2: {
        return _mov_86_multi_tmpl_3(ctx, reg_dst, imm_src, detail.operands[0].size);
    }

    default: { return false; }
    }

    return true;
}


bool _mov_86_reg_op_tmpl(mutation_context& ctx) {

    auto& detail = ctx.instruction->detail->x86;

    fuku_register reg_dst = capstone_to_fuku_reg(detail.operands[0].reg);
    fuku_operand op_src = capstone_to_fuku_op(detail, 1);

    switch (FUKU_GET_RAND(0, 2)) {

    case 0: {
        return _mov_86_multi_tmpl_1(ctx, reg_dst, op_src, detail.operands[0].size);
    }
    case 1: {
        return _mov_86_multi_tmpl_2(ctx, reg_dst, op_src, detail.operands[0].size);
    }
    case 2: {
        return _mov_86_multi_tmpl_3(ctx, reg_dst, op_src, detail.operands[0].size);
    }

    default: { return false; }
    }

    return true;
}


bool _mov_86_op_reg_tmpl(mutation_context& ctx) {

    auto& detail = ctx.instruction->detail->x86;

    fuku_operand op_dst = capstone_to_fuku_op(detail, 0);
    fuku_register reg_src = capstone_to_fuku_reg(detail.operands[1].reg);


    switch (FUKU_GET_RAND(0, 1)) {

    case 0: {
        return _mov_86_multi_tmpl_1(ctx, op_dst, reg_src, detail.operands[0].size);
    }
    case 1: {
        return _mov_86_multi_tmpl_3(ctx, op_dst, reg_src, detail.operands[0].size);
    }

    default: { return false; }
    }

    return true;
}

bool _mov_86_op_imm_tmpl(mutation_context& ctx) {

    auto& detail = ctx.instruction->detail->x86;

    fuku_operand op_dst = capstone_to_fuku_op(detail, 0);
    fuku_immediate imm_src = detail.operands[1].imm;

    switch (FUKU_GET_RAND(0, 1)) {

    case 0: {
        return _mov_86_multi_tmpl_1(ctx, op_dst, imm_src, detail.operands[0].size);
    }
    case 1: {
        return _mov_86_multi_tmpl_3(ctx, op_dst, imm_src, detail.operands[0].size);
    }

    default: { return false; }
    }

    return true;
}