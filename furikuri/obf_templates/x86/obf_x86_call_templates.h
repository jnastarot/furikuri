#pragma once


//push next_inst_address
//jmp reg
inline bool _call_86_multi_tmpl_1(mutation_context& ctx, fuku_type src, uint8_t inst_size) {
    
    if (ctx.settings->is_not_allowed_relocations()) {
        return false;
    }

    if (!ctx.is_next_last_inst) { //if not last instruction

        auto reloc_imm = ctx.payload_inst_iter->get_imm_reloc();
        auto reloc_disp = ctx.payload_inst_iter->get_disp_reloc();
        auto reloc_rip = ctx.payload_inst_iter->get_rip_reloc();
        bool used_disp_reloc = ctx.payload_inst_iter->is_used_disp_reloc();

        uint64_t out_regflags = ctx.cpu_registers & ~get_operand_mask_register(src);

        ctx.f_asm->push(imm(0xFFFFFFFF));
        ctx.f_asm->get_context().inst->
            set_cpu_flags(ctx.cpu_flags)
            .set_cpu_registers(ctx.cpu_registers)
            .set_imm_reloc(
                ctx.code_holder->create_relocation(fuku_relocation()
                    .set_label(
                        ctx.code_holder->create_label(
                            fuku_code_label().set_inst(&(*ctx.next_inst_iter)
                            )
                        )
                    )
                    .set_offset(ctx.f_asm->get_context().immediate_offset)
                ));

        ctx.f_asm->jmp(src);
        ctx.f_asm->get_context().inst->
            set_cpu_flags(ctx.cpu_flags)
            .set_cpu_registers(out_regflags);
 
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

bool fukutate_86_call(mutation_context& ctx) {

    auto& detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_MEM) { //call [op]
        return _call_86_op_tmpl(ctx);
    }
    else if (detail.operands[0].type == X86_OP_REG) {//call reg
        return _call_86_reg_tmpl(ctx);
    }
    else if (detail.operands[0].type == X86_OP_IMM) {
        return _call_86_imm_tmpl(ctx);
    }


    return false;
}