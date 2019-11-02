#pragma once



bool _cmp_64_reg_reg_tmpl(mutation_context& ctx) {

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

bool _cmp_64_reg_imm_tmpl(mutation_context& ctx) {

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


bool _cmp_64_reg_op_tmpl(mutation_context& ctx) {

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


bool _cmp_64_op_reg_tmpl(mutation_context& ctx) {

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

bool _cmp_64_op_imm_tmpl(mutation_context& ctx) {

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

bool fukutate_64_cmp(mutation_context& ctx) {

    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_REG) {

        if (detail.operands[1].type == X86_OP_REG) { //cmp reg, reg
            return _cmp_64_reg_reg_tmpl(ctx);
        }
        else if (detail.operands[1].type == X86_OP_IMM) {//cmp reg, imm
            return _cmp_64_reg_imm_tmpl(ctx);
        }
        else if (detail.operands[1].type == X86_OP_MEM) {//cmp reg, [op]
            return _cmp_64_reg_op_tmpl(ctx);
        }
    }
    else if (detail.operands[0].type == X86_OP_MEM) {

        if (detail.operands[1].type == X86_OP_REG) { //cmp [op], reg
            return _cmp_64_op_reg_tmpl(ctx);
        }
        else if (detail.operands[1].type == X86_OP_IMM) {//cmp [op], imm
            return _cmp_64_op_imm_tmpl(ctx);
        }
    }

    return false;
}