#pragma once


bool _shr_64_reg_reg_tmpl(mutation_context& ctx) {

    auto& detail = ctx.instruction->detail->x86;

    fuku_register reg_dst = capstone_to_fuku_reg(detail.operands[0].reg);
    fuku_register reg_src = capstone_to_fuku_reg(detail.operands[1].reg);

    switch (FUKU_GET_RAND(0, 0)) {

    case 0: {

    }

    default: { return false; }
    }

    return true;
}

bool _shr_64_reg_imm_tmpl(mutation_context& ctx) {

    auto& detail = ctx.instruction->detail->x86;

    fuku_register reg_dst = capstone_to_fuku_reg(detail.operands[0].reg);
    fuku_immediate imm_src = detail.operands[1].imm;

    switch (FUKU_GET_RAND(0, 0)) {

    case 0: {

    }

    default: { return false; }
    }

    return true;
}


bool _shr_64_op_reg_tmpl(mutation_context& ctx) {

    auto& detail = ctx.instruction->detail->x86;

    fuku_operand op_dst = capstone_to_fuku_op(detail, 0);
    fuku_register reg_src = capstone_to_fuku_reg(detail.operands[1].reg);


    switch (FUKU_GET_RAND(0, 0)) {

    case 0: {

    }

    default: { return false; }
    }

    return true;
}

bool _shr_64_op_imm_tmpl(mutation_context& ctx) {

    auto& detail = ctx.instruction->detail->x86;

    fuku_operand op_dst = capstone_to_fuku_op(detail, 0);
    fuku_immediate imm_src = detail.operands[1].imm;

    switch (FUKU_GET_RAND(0, 0)) {

    case 0: {

    }

    default: { return false; }
    }

    return true;
}

bool fukutate_64_shr(mutation_context& ctx) {

    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_REG) {

        if (detail.operands[1].type == X86_OP_REG) { //shr reg, reg
            return _shr_64_reg_reg_tmpl(ctx);
        }
        else if (detail.operands[1].type == X86_OP_IMM) {//shr reg, imm
            return _shr_64_reg_imm_tmpl(ctx);
        }
    }
    else if (detail.operands[0].type == X86_OP_MEM) {

        if (detail.operands[1].type == X86_OP_REG) { //shr [op], reg
            return _shr_64_op_reg_tmpl(ctx);
        }
        else if (detail.operands[1].type == X86_OP_IMM) {//shr [op], imm
            return _shr_64_op_imm_tmpl(ctx);
        }
    }

    return false;
}