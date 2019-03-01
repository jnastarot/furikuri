#pragma once


//push next_inst_address
//jmp reg
inline bool _call_86_multi_tmpl_1(mutation_context& ctx, fuku_type src, uint8_t inst_size) {

    if (!ctx.is_next_line_end) { //if not last instruction

        size_t relocate_rip = ctx.current_line_iter->get_rip_relocation_idx();
        size_t relocate_disp = ctx.current_line_iter->get_relocation_disp_idx();

        uint64_t out_regflags = ctx.regs_changes & ~get_operand_mask_register(src);

        ctx.f_asm->push(imm(0xFFFFFFFF));
        ctx.f_asm->get_context().inst->
            set_eflags(ctx.eflags_changes)
            .set_custom_flags(ctx.regs_changes)
            .set_relocation_imm_idx(
                ctx.code_holder->create_relocation(
                    ctx.f_asm->get_context().immediate_offset, &(*ctx.next_line_iter), 0
                )
            );

        ctx.f_asm->jmp(src);
        ctx.f_asm->get_context().inst->
            set_eflags(ctx.eflags_changes)
            .set_custom_flags(out_regflags);
 
        restore_rip_imm_or_disp(src);


        return true;
    }

    return false;
}


bool _call_86_imm_tmpl(mutation_context& ctx) {

    auto& detail = ctx.instruction->detail->x86;
    fuku_immediate imm_src = detail.operands[0].imm;

    switch (FUKU_GET_RAND(0, 0)) {

    case 0: {
        return _call_86_multi_tmpl_1(ctx, imm_src, detail.operands[0].size);
    }

    default: { return false; }
    }

    return true;
}


bool _call_86_reg_tmpl(mutation_context& ctx) {

    auto& detail = ctx.instruction->detail->x86;
    fuku_register reg_src = capstone_to_fuku_reg(detail.operands[0].reg);

    switch (FUKU_GET_RAND(0, 0)) {

    case 0: {
        return _call_86_multi_tmpl_1(ctx, reg_src, detail.operands[0].size);
    }

    default: { return false; }
    }

    return true;
}


bool _call_86_op_tmpl(mutation_context& ctx) {

    auto& detail = ctx.instruction->detail->x86;
    fuku_operand op_src = capstone_to_fuku_op(detail, 0);

    switch (FUKU_GET_RAND(0, 0)) {

    case 0: {
        return _call_86_multi_tmpl_1(ctx, op_src, detail.operands[0].size);
    }

    default: { return false; }
    }

    return true;
}