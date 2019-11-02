#pragma once

//mov somereg, src
//xchg dst, somereg
inline bool _mov_64_multi_tmpl_1(mutation_context& ctx, fuku_type dst, fuku_type src, int8_t inst_size) {

    auto reloc_imm = ctx.payload_inst_iter->get_imm_reloc();
    auto reloc_disp = ctx.payload_inst_iter->get_disp_reloc();
    auto reloc_rip = ctx.payload_inst_iter->get_rip_reloc();
    bool used_disp_reloc = ctx.payload_inst_iter->is_used_disp_reloc();

    fuku_type temp_dst;

    uint64_t changes_regflags = ctx.cpu_registers & ~get_operand_mask_register(dst, src);

    if (!get_operand_dst_x64( temp_dst, INST_ALLOW_REGISTER, inst_size, changes_regflags,
        FLAG_REGISTER_SP | FLAG_REGISTER_ESP | FLAG_REGISTER_RSP)) {

        return false;
    }

    uint64_t out_regflags = changes_regflags & ~(get_flag_complex_by_fuku_register(temp_dst.get_register().get_reg(), 8));

    ctx.f_asm->mov(temp_dst, src);
    ctx.f_asm->get_context().inst->
        set_cpu_flags(ctx.cpu_flags)
        .set_cpu_registers(out_regflags);

    restore_imm_or_disp(src)

    ctx.f_asm->xchg(dst, temp_dst);
    ctx.f_asm->get_context().inst->
        set_cpu_flags(ctx.cpu_flags)
        .set_cpu_registers(out_regflags);


    restore_disp_relocate(src)

    return true;
}


//xor dst,dst 
//add dst, src
inline bool _mov_64_multi_tmpl_2(mutation_context& ctx, fuku_type dst, fuku_type src, int8_t inst_size) {


    auto reloc_imm = ctx.payload_inst_iter->get_imm_reloc();
    auto reloc_disp = ctx.payload_inst_iter->get_disp_reloc();
    auto reloc_rip = ctx.payload_inst_iter->get_rip_reloc();
    bool used_disp_reloc = ctx.payload_inst_iter->is_used_disp_reloc();

    if (has_inst_free_eflags(ctx.cpu_flags,
        X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_CF | X86_EFLAGS_MODIFY_PF)) {

        uint64_t out_regflags = ctx.cpu_registers & ~get_operand_mask_register(dst, src);

        ctx.f_asm->xor_(dst, dst);
        ctx.f_asm->get_context().inst->
            set_cpu_flags(ctx.cpu_flags)
            .set_cpu_registers(ctx.cpu_registers);

        ctx.f_asm->add(dst, src);
        ctx.f_asm->get_context().inst->
            set_cpu_flags(ctx.cpu_flags)
            .set_cpu_registers(out_regflags);

        restore_disp_relocate(src)
        restore_imm_relocate(src)
    }
    else {
        return false;
    }

    return true;
}

//push src
//pop dst
inline bool _mov_64_multi_tmpl_3(mutation_context& ctx, fuku_type dst, fuku_type src, int8_t inst_size) {

    if (inst_size == 1 || (src.get_type() == FUKU_T0_IMMEDIATE && inst_size != 4) ) { return false; }

    auto reloc_imm = ctx.payload_inst_iter->get_imm_reloc();
    auto reloc_disp = ctx.payload_inst_iter->get_disp_reloc();
    auto reloc_rip = ctx.payload_inst_iter->get_rip_reloc();
    bool used_disp_reloc = ctx.payload_inst_iter->is_used_disp_reloc();

    if (IsAllowedStackOperations &&
        ((dst.get_type() == FUKU_T0_REGISTER) ? dst.get_register().get_index() != FUKU_REG_INDEX_SP : true) &&
        ((src.get_type() == FUKU_T0_REGISTER) ? src.get_register().get_index() != FUKU_REG_INDEX_SP : true)) {

        uint64_t out_regflags = ctx.cpu_registers & ~get_operand_mask_register(dst, src);

        ctx.f_asm->push(src);
        ctx.f_asm->get_context().inst->
            set_cpu_flags(ctx.cpu_flags)
            .set_cpu_registers(out_regflags);

        restore_imm_or_disp(src)

        ctx.f_asm->pop(dst);
        ctx.f_asm->get_context().inst->
            set_cpu_flags(ctx.cpu_flags)
            .set_cpu_registers(out_regflags);

        restore_disp_relocate(dst)

    }
    else {
        return false;
    }

    return true;
}

bool _mov_64_reg_reg_tmpl(mutation_context& ctx) {

    auto& detail = ctx.instruction->detail->x86;

    fuku_register reg_dst = capstone_to_fuku_reg(detail.operands[0].reg);
    fuku_register reg_src = capstone_to_fuku_reg(detail.operands[1].reg);

    switch (FUKU_GET_RAND(0, 2)) {

    case 0: {
        return _mov_64_multi_tmpl_1(ctx, reg_dst, reg_src, detail.operands[0].size);
    }
    case 1: {
        return _mov_64_multi_tmpl_2(ctx, reg_dst, reg_src, detail.operands[0].size);
    }
    case 2: {
        return _mov_64_multi_tmpl_3(ctx, reg_dst, reg_src, detail.operands[0].size);
    }

    default: { return false; }
    }

    return true;
}

bool _mov_64_reg_imm_tmpl(mutation_context& ctx) {

    auto& detail = ctx.instruction->detail->x86;

    fuku_register reg_dst = capstone_to_fuku_reg(detail.operands[0].reg);
    fuku_immediate imm_src = detail.operands[1].imm;

    switch (FUKU_GET_RAND(0, 2)) {

    case 0: {
        return _mov_64_multi_tmpl_1(ctx, reg_dst, imm_src, detail.operands[0].size);
    }
    case 1: {
        return _mov_64_multi_tmpl_2(ctx, reg_dst, imm_src, detail.operands[0].size);
    }
    case 2: {
        return _mov_64_multi_tmpl_3(ctx, reg_dst, imm_src, detail.operands[0].size);
    }

    default: { return false; }
    }

    return true;
}


bool _mov_64_reg_op_tmpl(mutation_context& ctx) {

    auto& detail = ctx.instruction->detail->x86;

    fuku_register reg_dst = capstone_to_fuku_reg(detail.operands[0].reg);
    fuku_operand op_src = capstone_to_fuku_op(detail, 1);

    switch (FUKU_GET_RAND(0, 2)) {

    case 0: {
        return _mov_64_multi_tmpl_1(ctx, reg_dst, op_src, detail.operands[0].size);
    }
    case 1: {
        return _mov_64_multi_tmpl_2(ctx, reg_dst, op_src, detail.operands[0].size);
    }
    case 2: {
        return _mov_64_multi_tmpl_3(ctx, reg_dst, op_src, detail.operands[0].size);
    }

    default: { return false; }
    }

    return true;
}


bool _mov_64_op_reg_tmpl(mutation_context& ctx) {

    auto& detail = ctx.instruction->detail->x86;

    fuku_operand op_dst = capstone_to_fuku_op(detail, 0);
    fuku_register reg_src = capstone_to_fuku_reg(detail.operands[1].reg);


    switch (FUKU_GET_RAND(0, 1)) {

    case 0: {
        return _mov_64_multi_tmpl_1(ctx, op_dst, reg_src, detail.operands[0].size);
    }
    case 1: {
        return _mov_64_multi_tmpl_3(ctx, op_dst, reg_src, detail.operands[0].size);
    }

    default: { return false; }
    }

    return true;
}

bool _mov_64_op_imm_tmpl(mutation_context& ctx) {

    auto& detail = ctx.instruction->detail->x86;

    fuku_operand op_dst = capstone_to_fuku_op(detail, 0);
    fuku_immediate imm_src = detail.operands[1].imm;

    switch (FUKU_GET_RAND(0, 1)) {

    case 0: {
        return _mov_64_multi_tmpl_1(ctx, op_dst, imm_src, detail.operands[0].size);
    }
    case 1: {
        return _mov_64_multi_tmpl_3(ctx, op_dst, imm_src, detail.operands[0].size);
    }

    default: { return false; }
    }

    return true;
}


bool fukutate_64_mov(mutation_context& ctx) {
    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_REG) {

        if (detail.operands[1].type == X86_OP_REG) { //mov reg, reg
            return _mov_64_reg_reg_tmpl(ctx);
        }
        else if (detail.operands[1].type == X86_OP_IMM) {//mov reg, imm
            return _mov_64_reg_imm_tmpl(ctx);
        }
        else if (detail.operands[1].type == X86_OP_MEM) {//mov reg, [op]
            return _mov_64_reg_op_tmpl(ctx);
        }
    }
    else if (detail.operands[0].type == X86_OP_MEM) {

        if (detail.operands[1].type == X86_OP_REG) { //mov [op], reg
            return _mov_64_op_reg_tmpl(ctx);
        }
        else if (detail.operands[1].type == X86_OP_IMM) {//mov [op], imm
            return _mov_64_op_imm_tmpl(ctx);
        }
    }

    return false;
}