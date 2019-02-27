#pragma once

//lea esp,[esp + (4 + stack_offset)]
//jmp [esp - 4 - stack_offset]
inline bool _ret_86_multi_tmpl_1(mutation_context& ctx, uint16_t stack_ret) {

    ctx.f_asm->lea(reg_(FUKU_REG_ESP), dword_ptr(FUKU_REG_ESP, imm(4 + stack_ret)));
    ctx.f_asm->get_context().inst->
        set_eflags(ctx.eflags_changes)
        .set_custom_flags(ctx.regs_changes);

    ctx.f_asm->jmp(dword_ptr(FUKU_REG_ESP, imm(-4 - stack_ret)));
    ctx.f_asm->get_context().inst->
        set_eflags(ctx.eflags_changes)
        .set_custom_flags(ctx.regs_changes)
        .set_instruction_flags(FUKU_INST_BAD_STACK);

    return true;
}


bool _ret_86_imm_tmpl(mutation_context& ctx) {

    auto& detail = ctx.instruction->detail->x86;

    uint16_t ret_stack = 0;

    if (detail.op_count) { //ret 0x0000
        ret_stack = (uint16_t)detail.operands[0].imm;
    }

    switch (FUKU_GET_RAND(0, 0)) {

    case 0: {
        return _ret_86_multi_tmpl_1(ctx, ret_stack);
    }

    default: { return false; }
    }

    return true;
}