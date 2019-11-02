#pragma once

//push reg
//ret   
inline bool _jmp_86_multi_tmpl_1(mutation_context& ctx, fuku_type src, uint8_t inst_size) {

    if (ctx.settings->is_not_allowed_relocations()) {
        return false;
    }

    if (IsAllowedStackOperations) {

        auto reloc_imm = ctx.payload_inst_iter->get_imm_reloc();
        auto reloc_disp = ctx.payload_inst_iter->get_disp_reloc();
        auto reloc_rip = ctx.payload_inst_iter->get_rip_reloc();
        bool used_disp_reloc = ctx.payload_inst_iter->is_used_disp_reloc();


        if (src.get_type() == FUKU_T0_IMMEDIATE) { //need 4 byte imm
            ctx.f_asm->push(imm(0xFFFFFFFF));
            restore_rip_to_imm_relocate(src);
        }
        else {
            ctx.f_asm->push(src);
            restore_disp_relocate(src);
        }
 
        ctx.f_asm->get_context().inst->
            set_cpu_flags(ctx.cpu_flags)
            .set_cpu_registers(ctx.cpu_registers);

        ctx.f_asm->ret(imm(0));
        ctx.f_asm->get_context().inst->
            set_cpu_flags(ctx.cpu_flags)
            .set_cpu_registers(ctx.cpu_registers);
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

    auto reloc_imm = ctx.payload_inst_iter->get_imm_reloc();
    auto reloc_disp = ctx.payload_inst_iter->get_disp_reloc();
    auto reloc_rip = ctx.payload_inst_iter->get_rip_reloc();
    bool used_disp_reloc = ctx.payload_inst_iter->is_used_disp_reloc();

    ctx.f_asm->jcc(fuku_condition(cond), imm(0xFFFFFFFF));
    ctx.f_asm->get_context().inst->
        set_cpu_flags(ctx.cpu_flags)
        .set_cpu_registers(ctx.cpu_registers)
        .set_rip_reloc(ctx.code_holder->create_rip_relocation(fuku_rip_relocation()
            .set_label(reloc_rip->label)
            .set_offset(ctx.f_asm->get_context().immediate_offset)
        ))
        .set_inst_flags(ctx.inst_flags | FUKU_INST_NO_MUTATE);

    ctx.f_asm->jcc(fuku_condition(cond ^ 1), imm(0xFFFFFFFF));
    ctx.f_asm->get_context().inst->
        set_cpu_flags(ctx.cpu_flags & (~di_fl_jcc[fuku_condition(cond ^ 1)]))
        .set_cpu_registers(ctx.cpu_registers)
        .set_rip_reloc(ctx.code_holder->create_rip_relocation(fuku_rip_relocation()
            .set_label(reloc_rip->label)
            .set_offset(ctx.f_asm->get_context().immediate_offset)
        ))
        .set_inst_flags(ctx.inst_flags | FUKU_INST_NO_MUTATE);

    
    ctx.code_holder->release_rip_relocation(reloc_rip);

    return true;
}


//mov randreg, dst
//jmp randreg
inline bool _jmp_86_multi_tmpl_3(mutation_context& ctx, fuku_type src, uint8_t inst_size) {

    if (ctx.settings->is_not_allowed_relocations()) {
        return false;
    }

    fuku_register rand_reg = get_random_free_register(ctx.cpu_registers, 4, true);

    if (rand_reg.get_reg() != FUKU_REG_NONE) {
        
        auto reloc_imm = ctx.payload_inst_iter->get_imm_reloc();
        auto reloc_disp = ctx.payload_inst_iter->get_disp_reloc();
        auto reloc_rip = ctx.payload_inst_iter->get_rip_reloc();
        bool used_disp_reloc = ctx.payload_inst_iter->is_used_disp_reloc();

        uint64_t out_regflags = ctx.cpu_registers & ~get_operand_mask_register(rand_reg, src);

        if (src.get_type() == FUKU_T0_IMMEDIATE) { //need 4 byte imm
            ctx.f_asm->mov(rand_reg, imm(0xFFFFFFFF));
            restore_rip_to_imm_relocate(src);
        }
        else {
            ctx.f_asm->mov(rand_reg, src);
            restore_disp_relocate(src);
        }

        ctx.f_asm->get_context().inst->
            set_cpu_flags(ctx.cpu_flags)
            .set_cpu_registers(out_regflags);      

        ctx.f_asm->jmp(rand_reg);
        ctx.f_asm->get_context().inst->
            set_cpu_flags(ctx.cpu_flags)
            .set_cpu_registers(out_regflags);

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

bool fukutate_86_jmp(mutation_context& ctx) {

    auto& detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_REG) { //jmp reg
        return _jmp_86_reg_tmpl(ctx);
    }
    else if (detail.operands[0].type == X86_OP_MEM) { //jmp [op]
        return _jmp_86_op_tmpl(ctx);
    }
    else if (detail.operands[0].type == X86_OP_IMM) { //jmp imm
        return _jmp_86_imm_tmpl(ctx);
    }

    return false;
}