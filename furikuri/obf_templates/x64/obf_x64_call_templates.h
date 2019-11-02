#pragma once


bool _call_64_imm_tmpl(mutation_context& ctx) {

    auto& detail = ctx.instruction->detail->x86;
    fuku_immediate imm_src = detail.operands[0].imm;

    switch (FUKU_GET_RAND(0, 0)) {
    case 0: {}
    default: { return false; }
    }

    return true;
}


bool _call_64_reg_tmpl(mutation_context& ctx) {

    auto& detail = ctx.instruction->detail->x86;
    fuku_register reg_src = capstone_to_fuku_reg(detail.operands[0].reg);

    switch (FUKU_GET_RAND(0, 0)) {
    case 0: {}
    default: { return false; }
    }

    return true;
}


bool _call_64_op_tmpl(mutation_context& ctx) {

    auto& detail = ctx.instruction->detail->x86;
    fuku_operand op_src = capstone_to_fuku_op(detail, 0);

    switch (FUKU_GET_RAND(0, 0)) {
    case 0: {}
    default: { return false; }
    }

    return true;
}

bool fukutate_64_call(mutation_context& ctx) {

    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_MEM) { //call [op]
        return _call_64_op_tmpl(ctx);
    }
    else if (detail.operands[0].type == X86_OP_REG) {//call reg
        return _call_64_reg_tmpl(ctx);
    }
    else if (detail.operands[0].type == X86_OP_IMM) {//call imm
        return _call_64_imm_tmpl(ctx);
    }


    return false;
}