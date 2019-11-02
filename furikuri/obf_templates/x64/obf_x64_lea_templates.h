#pragma once




bool _lea_64_reg_op_tmpl(mutation_context& ctx) {

    auto& detail = ctx.instruction->detail->x86;

    fuku_register reg_dst = capstone_to_fuku_reg(detail.operands[0].reg);
    fuku_operand op_src = capstone_to_fuku_op(detail, 1);

    switch (FUKU_GET_RAND(0, 0)) {

    case 0: {

    }

    default: { return false; }
    }

    return true;
}

bool fukutate_64_lea(mutation_context& ctx) {

    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_REG) {
        if (detail.operands[1].type == X86_OP_MEM) {//lea reg, [op]
            return _lea_64_reg_op_tmpl(ctx);
        }
    }

    return false;
}