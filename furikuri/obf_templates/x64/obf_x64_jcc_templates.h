#pragma once

//inverted jcc to next_inst_after real jcc
//jmp jcc_dst
inline bool _jcc_86_multi_tmpl_1(mutation_context& ctx) {

    if (!ctx.is_next_line_end) { //if not last instruction
         

        fuku_condition cond = capstone_to_fuku_cond((x86_insn)ctx.instruction->id);
        size_t rel_idx = ctx.current_line_iter->get_rip_relocation_idx();

        ctx.f_asm->jcc(fuku_condition(cond ^ 1), imm(-1));
        ctx.f_asm->get_context().inst->
            set_eflags(ctx.eflags_changes)
            .set_custom_flags(ctx.regs_changes)
            .set_rip_relocation_idx(
                ctx.code_holder->create_rip_relocation(
                    ctx.f_asm->get_context().immediate_offset, &(*ctx.next_line_iter)
                )
            )
            .set_instruction_flags(FUKU_INST_NO_MUTATE | ctx.instruction_flags);

        ctx.f_asm->jmp(imm(-1));
        ctx.f_asm->get_context().inst->
            set_eflags(ctx.eflags_changes)
            .set_custom_flags(ctx.regs_changes)
            .set_rip_relocation_idx(rel_idx)
            .set_instruction_flags(FUKU_INST_NO_MUTATE | ctx.instruction_flags);

        ctx.code_holder->get_rip_relocations()[rel_idx].offset = ctx.f_asm->get_context().immediate_offset;
        
        return true;
    }

    return false;
}

bool _jcc_86_imm_tmpl(mutation_context& ctx) {

    switch (FUKU_GET_RAND(0, 0)) {

    case 0: {
        return _jcc_86_multi_tmpl_1(ctx);
    }

    default: { return false; }
    }

    return true;
}
