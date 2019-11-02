#pragma once


bool _mul_64_reg_tmpl(mutation_context& ctx) {

    auto& detail = ctx.instruction->detail->x86;

    fuku_register reg_src = capstone_to_fuku_reg(detail.operands[0].reg);


    switch (FUKU_GET_RAND(0, 0)) {

    case 0: {

    }

    default: { return false; }
    }

    return true;
}

bool _mul_64_op_tmpl(mutation_context& ctx) {

    auto& detail = ctx.instruction->detail->x86;

    fuku_operand op_dst = capstone_to_fuku_op(detail, 0);

    switch (FUKU_GET_RAND(0, 0)) {

    case 0: {

    }

    default: { return false; }
    }

    return true;
}

bool fukutate_64_mul(mutation_context& ctx) {

    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_REG) {  //mul reg
        return _mul_64_reg_tmpl(ctx);
    }
    else if (detail.operands[0].type == X86_OP_MEM) { //mul [op]
        return _mul_64_op_tmpl(ctx);
    }

    return false;
}