#pragma once

#define restore_disp_relocate(op) \
           if (op.get_type() == FUKU_T0_OPERAND && relocate_disp != -1) {\
                ctx.f_asm->get_context().inst->\
                set_relocation_disp_idx(relocate_disp);\
                ctx.code_holder->get_relocations()[relocate_disp].offset = ctx.f_asm->get_context().displacment_offset;\
           }

#define restore_imm_relocate(op) \
           if (inst_size == 4 && op.get_type() == FUKU_T0_IMMEDIATE && relocate_imm != -1) {\
                ctx.f_asm->get_context().inst->\
                set_relocation_imm_idx(relocate_imm);\
                ctx.code_holder->get_relocations()[relocate_imm].offset = ctx.f_asm->get_context().immediate_offset;\
           }

#define restore_imm_or_disp(op) restore_disp_relocate(op) else restore_imm_relocate(op)

//(sub esp,4) or (lea esp,[esp - 4]) 
 //mov [esp],reg
bool _push_86_multi_tmpl_1(mutation_context& ctx, fuku_type src, int8_t inst_size) {

    size_t relocate_imm = ctx.current_line_iter->get_relocation_imm_idx();

    if (src.get_type() == FUKU_T0_REGISTER && src.get_register().get_index() == FUKU_REG_INDEX_SP) { return false; }

    uint64_t out_regflags;

    if (src.get_type() == FUKU_T0_REGISTER) {
        out_regflags = ctx.regs_changes & ~(fuku_reg_to_complex_flag_reg(src.get_register().get_reg(), 8));
    }
    else {
        out_regflags = ctx.regs_changes;
    }


    ctx.f_asm->get_context().short_cfg = 0xFF;

    if (has_inst_free_eflags(ctx.eflags_changes,
        X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_CF | X86_EFLAGS_MODIFY_PF)) {

        ctx.f_asm->sub(reg_(FUKU_REG_ESP), imm(inst_size));
        ctx.f_asm->get_context().inst->
            set_eflags(ctx.eflags_changes)
            .set_custom_flags(ctx.regs_changes);
    }
    else {
        ctx.f_asm->lea(reg_(FUKU_REG_ESP), dword_ptr(FUKU_REG_ESP, imm(-inst_size)));
        ctx.f_asm->get_context().inst->
            set_eflags(ctx.eflags_changes)
            .set_custom_flags(ctx.regs_changes);
    }

    ctx.f_asm->mov(fuku_operand(FUKU_REG_ESP, (fuku_operand_size)inst_size), src);
    ctx.f_asm->get_context().inst->
        set_eflags(ctx.eflags_changes)
        .set_custom_flags(out_regflags)
        .set_instruction_flags(FUKU_INST_BAD_STACK);


    restore_imm_relocate(src)


    return true;
}


//mov [esp - 4],reg
//(sub esp,4) or (lea esp,[esp - 4])
bool _push_86_multi_tmpl_2(mutation_context& ctx, fuku_type src, int8_t inst_size) {

    size_t relocate_imm = ctx.current_line_iter->get_relocation_imm_idx();

    if (src.get_type() == FUKU_T0_REGISTER && src.get_register().get_index() == FUKU_REG_INDEX_SP) { return false; }

    ctx.f_asm->mov(fuku_operand(FUKU_REG_ESP, imm(-inst_size), (fuku_operand_size)inst_size), src);
    ctx.f_asm->get_context().inst->
        set_eflags(ctx.eflags_changes)
        .set_custom_flags(ctx.regs_changes);

    uint64_t out_regflags;
    if (src.get_type() == FUKU_T0_REGISTER) {
        out_regflags = ctx.regs_changes & ~(fuku_reg_to_complex_flag_reg(src.get_register().get_reg(), 8));
    }
    else {
        out_regflags = ctx.regs_changes;
    }

    restore_imm_relocate(src)

        if (has_inst_free_eflags(ctx.eflags_changes,
            X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_CF | X86_EFLAGS_MODIFY_PF)) {

            ctx.f_asm->sub(reg_(FUKU_REG_ESP), imm(inst_size));
            ctx.f_asm->get_context().inst->
                set_eflags(ctx.eflags_changes)
                .set_custom_flags(out_regflags)
                .set_instruction_flags(FUKU_INST_BAD_STACK);
        }
        else {
            ctx.f_asm->lea(reg_(FUKU_REG_ESP), dword_ptr(FUKU_REG_ESP, imm(-inst_size)));
            ctx.f_asm->get_context().inst->
                set_eflags(ctx.eflags_changes)
                .set_custom_flags(out_regflags)
                .set_instruction_flags(FUKU_INST_BAD_STACK);
        }

    return true;
}


bool _push_86_imm_tmpl(mutation_context& ctx, cs_x86& x86) {

    fuku_immediate imm_src = x86.operands[0].imm;

    switch (FUKU_GET_RAND(0, 1)) {

    case 0: {
        return _push_86_multi_tmpl_1(ctx, imm_src, x86.operands[0].size);
    }
    case 1: {
        return _push_86_multi_tmpl_2(ctx, imm_src, x86.operands[0].size);
    }

    default: { return false; }
    }

    return true;
}


bool _push_86_reg_tmpl(mutation_context& ctx, cs_x86& x86) {

    fuku_register reg_src = capstone_to_fuku_reg(x86.operands[0].reg);

    switch (FUKU_GET_RAND(0, 1)) {

    case 0: {
        return _push_86_multi_tmpl_1(ctx, reg_src, x86.operands[0].size);
    }
    case 1: {
        return _push_86_multi_tmpl_2(ctx, reg_src, x86.operands[0].size);
    }

    default: { return false; }
    }

    return true;
}


bool _push_86_op_tmpl(mutation_context& ctx, cs_x86& x86) {

    return false;
}


//mov somereg, src
//xchg dst, somereg
bool _mov_86_multi_tmpl_1(mutation_context& ctx, fuku_type dst, fuku_type src, int8_t inst_size) {

    size_t relocate_imm = ctx.current_line_iter->get_relocation_imm_idx();
    size_t relocate_disp = ctx.current_line_iter->get_relocation_disp_idx();


    fuku_type temp_dst;

    if (!generate_86_operand_dst(ctx, temp_dst, INST_ALLOW_REGISTER, inst_size, ctx.regs_changes, 
        FLAG_REGISTER_SP | FLAG_REGISTER_ESP)) {

        return false;
    }
    
    if (temp_dst.get_register().get_reg() == dst.get_register().get_reg()) {
        return true;
    }

    uint64_t out_regflags = ctx.regs_changes & ~(fuku_reg_to_complex_flag_reg(temp_dst.get_register().get_reg(), 8));

    ctx.f_asm->mov(temp_dst, src);
    ctx.f_asm->get_context().inst->
        set_eflags(ctx.eflags_changes)
        .set_custom_flags(out_regflags);

    restore_imm_relocate(src)

    ctx.f_asm->xchg(dst, temp_dst);
    ctx.f_asm->get_context().inst->
        set_eflags(ctx.eflags_changes)
        .set_custom_flags(out_regflags);


    restore_disp_relocate(dst)

    return true;
}


//xor dst,dst 
//add dst, src
bool _mov_86_multi_tmpl_2(mutation_context& ctx, fuku_type dst, fuku_type src, int8_t inst_size) {

    size_t relocate_imm = ctx.current_line_iter->get_relocation_imm_idx();
    size_t relocate_disp = ctx.current_line_iter->get_relocation_disp_idx();

    if (has_inst_free_eflags(ctx.eflags_changes,
        X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_CF | X86_EFLAGS_MODIFY_PF)) {

        uint64_t out_regflags;

        if (dst.get_type() == FUKU_T0_REGISTER) {
            out_regflags = ctx.regs_changes & ~(fuku_reg_to_complex_flag_reg(dst.get_register(), 8));
        }
        else {
            out_regflags = ctx.eflags_changes;
        }

        ctx.f_asm->xor_(dst, dst);
        ctx.f_asm->get_context().inst->
            set_eflags(ctx.eflags_changes)
            .set_custom_flags(ctx.regs_changes);

        restore_disp_relocate(dst)

        ctx.f_asm->add(dst, src);
        ctx.f_asm->get_context().inst->
            set_eflags(ctx.eflags_changes)
            .set_custom_flags(out_regflags);

        restore_imm_relocate(src)
    }
    else {
        return false;
    }

    return true;
}

//push src
//pop dst
bool _mov_86_multi_tmpl_3(mutation_context& ctx, fuku_type dst, fuku_type src, int8_t inst_size) {
    return false;
    if (inst_size == 1) { return false; }

    size_t relocate_imm = ctx.current_line_iter->get_relocation_imm_idx();
    size_t relocate_disp = ctx.current_line_iter->get_relocation_disp_idx();

    if (IsAllowedStackOperations &&
        ((dst.get_type() == FUKU_T0_REGISTER) ? dst.get_register().get_index() != FUKU_REG_INDEX_SP : true) &&
        ((src.get_type() == FUKU_T0_REGISTER) ? src.get_register().get_index() != FUKU_REG_INDEX_SP : true)) {

        ctx.f_asm->push(src);
        ctx.f_asm->get_context().inst->
            set_eflags(ctx.eflags_changes)
            .set_custom_flags(ctx.regs_changes);

        restore_imm_relocate(src)

        ctx.f_asm->pop(dst);
        ctx.f_asm->get_context().inst->
            set_eflags(ctx.eflags_changes)
            .set_custom_flags(ctx.regs_changes);

        restore_disp_relocate(dst)

    }
    else {
        return false;
    }

    return true;
}

bool _mov_86_reg_reg_tmpl(mutation_context& ctx, cs_x86& x86) {

    fuku_register reg_dst = capstone_to_fuku_reg(x86.operands[0].reg);
    fuku_register reg_src = capstone_to_fuku_reg(x86.operands[1].reg);

    switch (FUKU_GET_RAND(0, 2)) {

    case 0: {
         return _mov_86_multi_tmpl_1(ctx, reg_dst, reg_src, x86.operands[0].size);
    }
    case 1: {
        return _mov_86_multi_tmpl_2(ctx, reg_dst, reg_src, x86.operands[0].size);
    }
    case 2: {
        return _mov_86_multi_tmpl_3(ctx, reg_dst, reg_src, x86.operands[0].size);
    }

    default: { return false; }
    }

    return true;
}

bool _mov_86_reg_imm_tmpl(mutation_context& ctx, cs_x86& x86) {

    fuku_register reg_dst = capstone_to_fuku_reg(x86.operands[0].reg);
    fuku_immediate imm_src = x86.operands[1].imm;

    switch (FUKU_GET_RAND(0, 2)) {

    case 0: {
        return _mov_86_multi_tmpl_1(ctx, reg_dst, imm_src, x86.operands[0].size);
    }
    case 1: {
        return _mov_86_multi_tmpl_2(ctx, reg_dst, imm_src, x86.operands[0].size);
    }
    case 2: {
        return _mov_86_multi_tmpl_3(ctx, reg_dst, imm_src, x86.operands[0].size);
    }

    default: { return false; }
    }

    return true;
}


bool _mov_86_reg_op_tmpl(mutation_context& ctx, cs_x86& x86) {

    fuku_register reg_dst = capstone_to_fuku_reg(x86.operands[0].reg);
    fuku_operand op_src = capstone_to_fuku_op(x86, 1);

    switch (FUKU_GET_RAND(0, 2)) {

    case 0: {
        return _mov_86_multi_tmpl_1(ctx, reg_dst, op_src, x86.operands[0].size);
    }
    case 1: {
        return _mov_86_multi_tmpl_2(ctx, reg_dst, op_src, x86.operands[0].size);
    }
    case 2: {
        return _mov_86_multi_tmpl_3(ctx, reg_dst, op_src, x86.operands[0].size);
    }

    default: { return false; }
    }

    return true;
}


bool _mov_86_op_reg_tmpl(mutation_context& ctx, cs_x86& x86) {

    fuku_operand op_dst = capstone_to_fuku_op(x86, 0);
    fuku_register reg_src = capstone_to_fuku_reg(x86.operands[1].reg);


    switch (FUKU_GET_RAND(0, 1)) {

    case 0: {
        return _mov_86_multi_tmpl_1(ctx, op_dst, reg_src, x86.operands[0].size);
    }
    case 1: {
        return _mov_86_multi_tmpl_3(ctx, op_dst, reg_src, x86.operands[0].size);
    }

    default: { return false; }
    }

    return true;
}

bool _mov_86_op_imm_tmpl(mutation_context& ctx, cs_x86& x86) {

    fuku_operand op_dst = capstone_to_fuku_op(x86, 0);
    fuku_immediate imm_src = x86.operands[1].imm;

    switch (FUKU_GET_RAND(0, 1)) {

    case 0: {
        return _mov_86_multi_tmpl_1(ctx, op_dst, imm_src, x86.operands[0].size);
    }
    case 1: {
        return _mov_86_multi_tmpl_3(ctx, op_dst, imm_src, x86.operands[0].size);
    }

    default: { return false; }
    }

    return true;
}


