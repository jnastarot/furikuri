#pragma once

//inverted jcc to next_inst_after real jcc
//jmp jcc_dst
inline bool _jcc_64_multi_tmpl_1(mutation_context& ctx, fuku_type dst, uint8_t inst_size) {

    if (!ctx.is_next_last_inst) { //if not last instruction
         
        auto reloc_imm = ctx.payload_inst_iter->get_imm_reloc();
        auto reloc_disp = ctx.payload_inst_iter->get_disp_reloc();
        auto reloc_rip = ctx.payload_inst_iter->get_rip_reloc();
        bool used_disp_reloc = ctx.payload_inst_iter->is_used_disp_reloc();

        fuku_condition cond = capstone_to_fuku_cond((x86_insn)ctx.instruction->id);

        ctx.f_asm->jcc(fuku_condition(cond ^ 1), imm(0xFFFFFFFF));
        ctx.f_asm->get_context().inst->
            set_cpu_flags(ctx.cpu_flags)
            .set_cpu_registers(ctx.cpu_registers)
            .set_rip_reloc(
                ctx.code_holder->create_rip_relocation(fuku_rip_relocation()
                .set_label(
                        ctx.code_holder->create_label(
                                    fuku_code_label().set_inst(&(*ctx.next_inst_iter)
                                )
                        )
                )
                .set_offset(ctx.f_asm->get_context().immediate_offset)
            ))
            .set_inst_flags(FUKU_INST_NO_MUTATE | ctx.inst_flags);


        ctx.f_asm->jmp(imm(0xFFFFFFFF));
        ctx.f_asm->get_context().inst->
            set_cpu_flags(ctx.cpu_flags)
            .set_cpu_registers(ctx.cpu_registers)
            .set_inst_flags(FUKU_INST_NO_MUTATE | ctx.inst_flags);

        restore_rip_relocate_in_imm(dst);
        
        return true;
    }

    return false;
}

bool _jcc_64_imm_tmpl(mutation_context& ctx) {

    auto& detail = ctx.instruction->detail->x86;
    fuku_immediate imm_src = detail.operands[0].imm;

    switch (FUKU_GET_RAND(0, 0)) {

    case 0: {
        return _jcc_64_multi_tmpl_1(ctx, imm_src, detail.operands[0].size);
    }

    default: { return false; }
    }

    return true;
}

bool fukutate_64_jcc(mutation_context& ctx) {
    return _jcc_64_imm_tmpl(ctx); //jcc imm
}
