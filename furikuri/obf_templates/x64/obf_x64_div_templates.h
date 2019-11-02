#pragma once


bool _div_64_reg_tmpl(mutation_context& ctx) {

    auto& detail = ctx.instruction->detail->x86;

    fuku_register reg_src = capstone_to_fuku_reg(detail.operands[0].reg);


    switch (FUKU_GET_RAND(0, 0)) {

    case 0: {

    }

    default: { return false; }
    }

    return true;
}

bool _div_64_op_tmpl(mutation_context& ctx) {

    auto& detail = ctx.instruction->detail->x86;

    fuku_operand op_dst = capstone_to_fuku_op(detail, 0);

    switch (FUKU_GET_RAND(0, 0)) {

    case 0: {

    }

    default: { return false; }
    }

    return true;
}

bool fukutate_64_div(mutation_context& ctx) {

    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_REG) {  //div reg
        return _div_64_reg_tmpl(ctx);
    }
    else if (detail.operands[0].type == X86_OP_MEM) { //div [op]
        return _div_64_op_tmpl(ctx);
    }

    return false;
}