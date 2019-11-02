#pragma once

//(sub esp,4) or (lea esp,[esp - 4]) 
 //mov [esp],reg
inline bool _push_64_multi_tmpl_1(mutation_context& ctx, fuku_type src, int8_t inst_size) {

    auto reloc_imm = ctx.payload_inst_iter->get_imm_reloc();
    auto reloc_disp = ctx.payload_inst_iter->get_disp_reloc();
    auto reloc_rip = ctx.payload_inst_iter->get_rip_reloc();
    bool used_disp_reloc = ctx.payload_inst_iter->is_used_disp_reloc();

    if (src.get_type() == FUKU_T0_REGISTER && src.get_register().get_index() == FUKU_REG_INDEX_SP) { return false; }

    uint64_t out_regflags = ctx.cpu_registers & ~get_operand_mask_register(src);

    if (has_inst_free_eflags(ctx.cpu_flags,
        X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_CF | X86_EFLAGS_MODIFY_PF)) {

        ctx.f_asm->sub(reg_(FUKU_REG_RSP), imm(inst_size));
        ctx.f_asm->get_context().inst->
            set_cpu_flags(ctx.cpu_flags)
            .set_cpu_registers(ctx.cpu_registers);
    }
    else {
        ctx.f_asm->lea(reg_(FUKU_REG_RSP), qword_ptr(FUKU_REG_RSP, imm(-inst_size)));
        ctx.f_asm->get_context().inst->
            set_cpu_flags(ctx.cpu_flags)
            .set_cpu_registers(ctx.cpu_registers);
    }

    ctx.f_asm->mov(fuku_operand(FUKU_REG_RSP, (fuku_operand_size)inst_size), src);
    ctx.f_asm->get_context().inst->
        set_cpu_flags(ctx.cpu_flags)
        .set_cpu_registers(out_regflags);


    restore_disp_relocate(src)


    return true;
}


//mov [esp - 4],reg
//(sub esp,4) or (lea esp,[esp - 4])
inline bool _push_64_multi_tmpl_2(mutation_context& ctx, fuku_type src, int8_t inst_size) {

    if (ctx.settings->is_not_allowed_unstable_stack()) {
        return false;
    }

    auto reloc_imm = ctx.payload_inst_iter->get_imm_reloc();
    auto reloc_disp = ctx.payload_inst_iter->get_disp_reloc();
    auto reloc_rip = ctx.payload_inst_iter->get_rip_reloc();
    bool used_disp_reloc = ctx.payload_inst_iter->is_used_disp_reloc();

    if (src.get_type() == FUKU_T0_REGISTER && src.get_register().get_index() == FUKU_REG_INDEX_SP) { return false; }

    ctx.f_asm->mov(fuku_operand(FUKU_REG_RSP, imm(-inst_size), (fuku_operand_size)inst_size), src);
    ctx.f_asm->get_context().inst->
        set_cpu_flags(ctx.cpu_flags)
        .set_cpu_registers(ctx.cpu_registers);

    uint64_t out_regflags = ctx.cpu_registers & ~get_operand_mask_register(src);

    restore_disp_relocate(src)

    if (has_inst_free_eflags(ctx.cpu_flags,
            X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_CF | X86_EFLAGS_MODIFY_PF)) {

        ctx.f_asm->sub(reg_(FUKU_REG_RSP), imm(inst_size));
        ctx.f_asm->get_context().inst->
            set_cpu_flags(ctx.cpu_flags)
            .set_cpu_registers(out_regflags)
            .set_inst_flags(FUKU_INST_BAD_STACK);
    }
    else {
        ctx.f_asm->lea(reg_(FUKU_REG_RSP), qword_ptr(FUKU_REG_RSP, imm(-inst_size)));
        ctx.f_asm->get_context().inst->
            set_cpu_flags(ctx.cpu_flags)
            .set_cpu_registers(out_regflags)
            .set_inst_flags(FUKU_INST_BAD_STACK);
    }

    return true;
}


bool _push_64_imm_tmpl(mutation_context& ctx) {

    auto& detail = ctx.instruction->detail->x86;
    fuku_immediate imm_src = detail.operands[0].imm;

    switch (FUKU_GET_RAND(0, 1)) {

    case 0: {
        return _push_64_multi_tmpl_1(ctx, imm_src, detail.operands[0].size);
    }
    case 1: {
        return _push_64_multi_tmpl_2(ctx, imm_src, detail.operands[0].size);
    }

    default: { return false; }
    }

    return true;
}


bool _push_64_reg_tmpl(mutation_context& ctx) {

    auto& detail = ctx.instruction->detail->x86;
    fuku_register reg_src = capstone_to_fuku_reg(detail.operands[0].reg);

    switch (FUKU_GET_RAND(0, 1)) {

    case 0: {
        return _push_64_multi_tmpl_1(ctx, reg_src, detail.operands[0].size);
    }
    case 1: {
        return _push_64_multi_tmpl_2(ctx, reg_src, detail.operands[0].size);
    }

    default: { return false; }
    }

    return true;
}


bool _push_64_op_tmpl(mutation_context& ctx) {

    return false;
}


//stack
bool fukutate_64_push(mutation_context& ctx) {
    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_REG) {  //push reg
        return _push_64_reg_tmpl(ctx);
    }
    else if (detail.operands[0].type == X86_OP_MEM) { //push [op]
        return _push_64_op_tmpl(ctx);
    }
    else if (detail.operands[0].type == X86_OP_IMM) { //push imm8/imm32
        return _push_64_imm_tmpl(ctx);
    }

    return false;
}