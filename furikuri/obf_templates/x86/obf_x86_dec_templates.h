#pragma once

bool _dec_86_reg_tmpl(mutation_context& ctx) {

    auto& detail = ctx.instruction->detail->x86;

    fuku_register reg_src = capstone_to_fuku_reg(detail.operands[0].reg);


    switch (FUKU_GET_RAND(0, 0)) {

    case 0: {

    }

    default: { return false; }
    }

    return true;
}

bool _dec_86_op_tmpl(mutation_context& ctx) {

    auto& detail = ctx.instruction->detail->x86;

    fuku_operand op_dst = capstone_to_fuku_op(detail, 0);

    switch (FUKU_GET_RAND(0, 0)) {

    case 0: {

    }

    default: { return false; }
    }

    return true;
}

bool fukutate_86_dec(mutation_context& ctx) {

    auto& detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_REG) {  //dec reg
        return _dec_86_reg_tmpl(ctx);
    }
    else if (detail.operands[0].type == X86_OP_MEM) { //dec [op]
        return _dec_86_op_tmpl(ctx);
    }

    return false;
}