#pragma once

//inverted jcc to next_inst_after real jcc
//jmp jcc_dst
inline bool _jcc_64_multi_tmpl_1(mutation_context& ctx, fuku_type dst, uint8_t inst_size) {

    if (!ctx.is_next_line_end) { //if not last instruction
         

        fuku_condition cond = capstone_to_fuku_cond((x86_insn)ctx.instruction->id);
        size_t relocate_rip = ctx.current_line_iter->get_rip_relocation_idx();

        ctx.f_asm->jcc(fuku_condition(cond ^ 1), imm(0xFFFFFFFF));
        ctx.f_asm->get_context().inst->
            set_eflags(ctx.eflags_changes)
            .set_custom_flags(ctx.regs_changes)
            .set_rip_relocation_idx(
                ctx.code_holder->create_rip_relocation(
                    ctx.f_asm->get_context().immediate_offset, &(*ctx.next_line_iter)
                )
            )
            .set_instruction_flags(FUKU_INST_NO_MUTATE | ctx.instruction_flags);

        ctx.f_asm->jmp(imm(0xFFFFFFFF));
        ctx.f_asm->get_context().inst->
            set_eflags(ctx.eflags_changes)
            .set_custom_flags(ctx.regs_changes)
            .set_instruction_flags(FUKU_INST_NO_MUTATE | ctx.instruction_flags);

        restore_rip_relocate_imm(dst);
        
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
