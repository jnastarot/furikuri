#include "stdafx.h"
#include "fuku_mutation_x64_rules.h"

#define IsAllowedStackOperations (!HAS_FULL_MASK(ctx.instruction_flags, FUKU_INST_BAD_STACK))

static uint64_t di_fl_jcc[] = {
    EFLAGS_MOD_OF , EFLAGS_MOD_OF, //jo   / jno
    EFLAGS_MOD_CF , EFLAGS_MOD_CF, //jb   / jae
    EFLAGS_MOD_ZF , EFLAGS_MOD_ZF, //je   / jne
    EFLAGS_MOD_ZF | EFLAGS_MOD_CF, EFLAGS_MOD_ZF | EFLAGS_MOD_CF, //jbe / jnbe
    EFLAGS_MOD_SF , EFLAGS_MOD_SF, //js   / jns
    EFLAGS_MOD_PF , EFLAGS_MOD_PF, //jp   / jnp
    EFLAGS_MOD_OF | EFLAGS_MOD_SF, EFLAGS_MOD_OF | EFLAGS_MOD_SF, //jnge / jge
    EFLAGS_MOD_OF | EFLAGS_MOD_SF | EFLAGS_MOD_ZF, EFLAGS_MOD_OF | EFLAGS_MOD_SF | EFLAGS_MOD_ZF //jng / jnle
};

#define restore_disp_relocate(op) \
           if (op.get_type() == FUKU_T0_OPERAND && relocate_disp != -1) {\
                ctx.f_asm->get_context().inst->\
                set_relocation_disp_idx(relocate_disp);\
                ctx.code_holder->get_relocations()[relocate_disp].offset = ctx.f_asm->get_context().displacment_offset;\
           }

#define restore_imm_relocate(op) \
           if (inst_size == 8 && op.get_type() == FUKU_T0_IMMEDIATE && relocate_imm != -1) {\
                ctx.f_asm->get_context().inst->\
                set_relocation_imm_idx(relocate_imm);\
                ctx.code_holder->get_relocations()[relocate_imm].offset = ctx.f_asm->get_context().immediate_offset;\
           }

#define restore_rip_relocate_imm(op) \
           if (inst_size == 8 && op.get_type() == FUKU_T0_IMMEDIATE &&relocate_rip != -1) {\
                ctx.f_asm->get_context().inst->\
                set_rip_relocation_idx(relocate_rip);\
                ctx.code_holder->get_rip_relocations()[relocate_rip].offset = ctx.f_asm->get_context().immediate_offset;\
           }

#define restore_rip_relocate_disp(op) \
           if (inst_size == 8 && op.get_type() == FUKU_T0_OPERAND &&relocate_rip != -1) {\
                ctx.f_asm->get_context().inst->\
                set_rip_relocation_idx(relocate_rip);\
                ctx.code_holder->get_rip_relocations()[relocate_rip].offset = ctx.f_asm->get_context().displacment_offset;\
           }

#define restore_rip_to_imm_relocate(op) \
           if (op.get_type() == FUKU_T0_IMMEDIATE && relocate_rip != -1) {\
                size_t rip_label_idx = ctx.code_holder->get_rip_relocations()[relocate_rip].label_idx;\
                ctx.f_asm->get_context().inst->\
                set_relocation_imm_idx(\
                    ctx.code_holder->create_relocation_lb(\
                        ctx.f_asm->get_context().immediate_offset, rip_label_idx, 0\
                    )\
                );\
                ctx.code_holder->delete_rip_relocation(relocate_rip);\
           }

#define restore_rip_to_disp_relocate(op) \
           if (op.get_type() == FUKU_T0_OPERAND && relocate_rip != -1) {\
                size_t rip_label_idx = ctx.code_holder->get_rip_relocations()[relocate_rip].label_idx;\
                ctx.f_asm->get_context().inst->\
                set_relocation_disp_idx(\
                    ctx.code_holder->create_relocation_lb(\
                        ctx.f_asm->get_context().displacment_offset, rip_label_idx, 0\
                    )\
                );\
                ctx.code_holder->delete_rip_relocation(relocate_rip);\
           }

#define restore_imm_or_disp(op)         restore_disp_relocate(op) else restore_imm_relocate(op)
#define restore_rip_imm_or_disp(op)     restore_rip_relocate_imm(op) else restore_disp_relocate(op)
#define restore_rip_to_imm_or_disp(op)  restore_rip_to_imm_relocate(op) else restore_rip_to_disp_relocate(op)

#include "obf_templates/x64/obf_x64_mov_templates.h"
#include "obf_templates/x64/obf_x64_xchg_templates.h"
#include "obf_templates/x64/obf_x64_push_templates.h"
#include "obf_templates/x64/obf_x64_pop_templates.h"
#include "obf_templates/x64/obf_x64_lea_templates.h"

#include "obf_templates/x64/obf_x64_jcc_templates.h"
#include "obf_templates/x64/obf_x64_jmp_templates.h"
#include "obf_templates/x64/obf_x64_call_templates.h"
#include "obf_templates/x64/obf_x64_ret_templates.h"

#include "obf_templates/x64/obf_x64_add_templates.h"
#include "obf_templates/x64/obf_x64_sub_templates.h"
#include "obf_templates/x64/obf_x64_adc_templates.h"
#include "obf_templates/x64/obf_x64_sbb_templates.h"
#include "obf_templates/x64/obf_x64_cmp_templates.h"
#include "obf_templates/x64/obf_x64_neg_templates.h"
#include "obf_templates/x64/obf_x64_inc_templates.h"
#include "obf_templates/x64/obf_x64_dec_templates.h"
#include "obf_templates/x64/obf_x64_mul_templates.h"
#include "obf_templates/x64/obf_x64_imul_templates.h"
#include "obf_templates/x64/obf_x64_div_templates.h"
#include "obf_templates/x64/obf_x64_idiv_templates.h"

#include "obf_templates/x64/obf_x64_and_templates.h"
#include "obf_templates/x64/obf_x64_or_templates.h"
#include "obf_templates/x64/obf_x64_xor_templates.h"
#include "obf_templates/x64/obf_x64_test_templates.h"
#include "obf_templates/x64/obf_x64_not_templates.h"

#include "obf_templates/x64/obf_x64_ror_templates.h"
#include "obf_templates/x64/obf_x64_rol_templates.h"
#include "obf_templates/x64/obf_x64_rcl_templates.h"
#include "obf_templates/x64/obf_x64_rcr_templates.h"
#include "obf_templates/x64/obf_x64_shl_templates.h"
#include "obf_templates/x64/obf_x64_shr_templates.h"
#include "obf_templates/x64/obf_x64_sar_templates.h"

#include "obf_templates/x64/obf_x64_bt_templates.h"
#include "obf_templates/x64/obf_x64_bts_templates.h"
#include "obf_templates/x64/obf_x64_btr_templates.h"
#include "obf_templates/x64/obf_x64_btc_templates.h"
#include "obf_templates/x64/obf_x64_bsf_templates.h"
#include "obf_templates/x64/obf_x64_bsr_templates.h"


void fukutate_64_jcc(mutation_context & ctx) {
    ctx.was_mutated = _jcc_64_imm_tmpl(ctx); //jcc imm
}

void fukutate_64_jmp(mutation_context & ctx) {

    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_REG) { //jmp reg
        ctx.was_mutated = _jmp_64_reg_tmpl(ctx);
    }
    else if (detail.operands[0].type == X86_OP_MEM) { //jmp [op]
        ctx.was_mutated = _jmp_64_op_tmpl(ctx);
    }
    else if (detail.operands[0].type == X86_OP_IMM) { //jmp imm
        ctx.was_mutated = _jmp_64_imm_tmpl(ctx);
    }
}

void fukutate_64_call(mutation_context & ctx) {

    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_MEM) { //call [op]
        ctx.was_mutated = _call_64_op_tmpl(ctx);
    }
    else if (detail.operands[0].type == X86_OP_REG) {//call reg
        ctx.was_mutated = _call_64_reg_tmpl(ctx);
    }
    else if (detail.operands[0].type == X86_OP_IMM) {//call imm
        ctx.was_mutated = _call_64_imm_tmpl(ctx);
    }

}
void fukutate_64_ret(mutation_context & ctx) {
    ctx.was_mutated = _ret_64_imm_tmpl(ctx); //ret \ ret 0xXXXX
}

//stack
void fukutate_64_push(mutation_context & ctx) {
    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_REG) {  //push reg
        ctx.was_mutated = _push_64_reg_tmpl(ctx);
    }
    else if (detail.operands[0].type == X86_OP_MEM) { //push [op]
        ctx.was_mutated = _push_64_op_tmpl(ctx);
    }
    else if (detail.operands[0].type == X86_OP_IMM) { //push imm8/imm32
        ctx.was_mutated = _push_64_imm_tmpl(ctx);
    }
}

void fukutate_64_pop(mutation_context & ctx) {
    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_REG) { //pop reg
        ctx.was_mutated = _pop_64_reg_tmpl(ctx);
    }
    else if (detail.operands[0].type == X86_OP_MEM) { //pop [op]
        ctx.was_mutated = _pop_64_op_tmpl(ctx);
    }
}

//data transfer
void fukutate_64_mov(mutation_context & ctx) {
    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_REG) {

        if (detail.operands[1].type == X86_OP_REG) { //mov reg, reg
            ctx.was_mutated = _mov_64_reg_reg_tmpl(ctx);
        }
        else if (detail.operands[1].type == X86_OP_IMM) {//mov reg, imm
            ctx.was_mutated = _mov_64_reg_imm_tmpl(ctx);
        }
        else if (detail.operands[1].type == X86_OP_MEM) {//mov reg, [op]
            ctx.was_mutated = _mov_64_reg_op_tmpl(ctx);
        }
    }
    else if (detail.operands[0].type == X86_OP_MEM) {

        if (detail.operands[1].type == X86_OP_REG) { //mov [op], reg
            ctx.was_mutated = _mov_64_op_reg_tmpl(ctx);
        }
        else if (detail.operands[1].type == X86_OP_IMM) {//mov [op], imm
            ctx.was_mutated = _mov_64_op_imm_tmpl(ctx);
        }
    }
}
void fukutate_64_xchg(mutation_context & ctx) {
    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_MEM ||
        detail.operands[1].type == X86_OP_MEM) { //xchg [op], reg
        ctx.was_mutated = _xchg_64_op_reg_tmpl(ctx);
    }
    else { //xchg reg, reg
        ctx.was_mutated = _xchg_64_reg_reg_tmpl(ctx);
    }
}

void fukutate_64_lea(mutation_context& ctx) {

    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_REG) {
        if (detail.operands[1].type == X86_OP_MEM) {//lea reg, [op]
            ctx.was_mutated = _lea_64_reg_op_tmpl(ctx);
        }
    }
}

void fukutate_64_add(mutation_context& ctx) {

    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_REG) {

        if (detail.operands[1].type == X86_OP_REG) { //add reg, reg
            ctx.was_mutated = _add_64_reg_reg_tmpl(ctx);
        }
        else if (detail.operands[1].type == X86_OP_IMM) {//add reg, imm
            ctx.was_mutated = _add_64_reg_imm_tmpl(ctx);
        }
        else if (detail.operands[1].type == X86_OP_MEM) {//add reg, [op]
            ctx.was_mutated = _add_64_reg_op_tmpl(ctx);
        }
    }
    else if (detail.operands[0].type == X86_OP_MEM) {

        if (detail.operands[1].type == X86_OP_REG) { //add [op], reg
            ctx.was_mutated = _add_64_op_reg_tmpl(ctx);
        }
        else if (detail.operands[1].type == X86_OP_IMM) {//add [op], imm
            ctx.was_mutated = _add_64_op_imm_tmpl(ctx);
        }
    }

}
void fukutate_64_or(mutation_context& ctx) {

    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_REG) {

        if (detail.operands[1].type == X86_OP_REG) { //or reg, reg
            ctx.was_mutated = _or_64_reg_reg_tmpl(ctx);
        }
        else if (detail.operands[1].type == X86_OP_IMM) {//or reg, imm
            ctx.was_mutated = _or_64_reg_imm_tmpl(ctx);
        }
        else if (detail.operands[1].type == X86_OP_MEM) {//or reg, [op]
            ctx.was_mutated = _or_64_reg_op_tmpl(ctx);
        }
    }
    else if (detail.operands[0].type == X86_OP_MEM) {

        if (detail.operands[1].type == X86_OP_REG) { //or [op], reg
            ctx.was_mutated = _or_64_op_reg_tmpl(ctx);
        }
        else if (detail.operands[1].type == X86_OP_IMM) {//or [op], imm
            ctx.was_mutated = _or_64_op_imm_tmpl(ctx);
        }
    }

}
void fukutate_64_adc(mutation_context& ctx) {

    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_REG) {

        if (detail.operands[1].type == X86_OP_REG) { //adc reg, reg
            ctx.was_mutated = _adc_64_reg_reg_tmpl(ctx);
        }
        else if (detail.operands[1].type == X86_OP_IMM) {//adc reg, imm
            ctx.was_mutated = _adc_64_reg_imm_tmpl(ctx);
        }
        else if (detail.operands[1].type == X86_OP_MEM) {//adc reg, [op]
            ctx.was_mutated = _adc_64_reg_op_tmpl(ctx);
        }
    }
    else if (detail.operands[0].type == X86_OP_MEM) {

        if (detail.operands[1].type == X86_OP_REG) { //adc [op], reg
            ctx.was_mutated = _adc_64_op_reg_tmpl(ctx);
        }
        else if (detail.operands[1].type == X86_OP_IMM) {//adc [op], imm
            ctx.was_mutated = _adc_64_op_imm_tmpl(ctx);
        }
    }
}
void fukutate_64_sbb(mutation_context& ctx) {

    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_REG) {

        if (detail.operands[1].type == X86_OP_REG) { //sbb reg, reg
            ctx.was_mutated = _sbb_64_reg_reg_tmpl(ctx);
        }
        else if (detail.operands[1].type == X86_OP_IMM) {//sbb reg, imm
            ctx.was_mutated = _sbb_64_reg_imm_tmpl(ctx);
        }
        else if (detail.operands[1].type == X86_OP_MEM) {//sbb reg, [op]
            ctx.was_mutated = _sbb_64_reg_op_tmpl(ctx);
        }
    }
    else if (detail.operands[0].type == X86_OP_MEM) {

        if (detail.operands[1].type == X86_OP_REG) { //sbb [op], reg
            ctx.was_mutated = _sbb_64_op_reg_tmpl(ctx);
        }
        else if (detail.operands[1].type == X86_OP_IMM) {//sbb [op], imm
            ctx.was_mutated = _sbb_64_op_imm_tmpl(ctx);
        }
    }
}

void fukutate_64_and(mutation_context& ctx) {

    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_REG) {

        if (detail.operands[1].type == X86_OP_REG) { //and reg, reg
            ctx.was_mutated = _and_64_reg_reg_tmpl(ctx);
        }
        else if (detail.operands[1].type == X86_OP_IMM) {//and reg, imm
            ctx.was_mutated = _and_64_reg_imm_tmpl(ctx);
        }
        else if (detail.operands[1].type == X86_OP_MEM) {//and reg, [op]
            ctx.was_mutated = _and_64_reg_op_tmpl(ctx);
        }
    }
    else if (detail.operands[0].type == X86_OP_MEM) {

        if (detail.operands[1].type == X86_OP_REG) { //and [op], reg
            ctx.was_mutated = _and_64_op_reg_tmpl(ctx);
        }
        else if (detail.operands[1].type == X86_OP_IMM) {//and [op], imm
            ctx.was_mutated = _and_64_op_imm_tmpl(ctx);
        }
    }

}

void fukutate_64_sub(mutation_context& ctx) {

    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_REG) {

        if (detail.operands[1].type == X86_OP_REG) { //sub reg, reg
            ctx.was_mutated = _sub_64_reg_reg_tmpl(ctx);
        }
        else if (detail.operands[1].type == X86_OP_IMM) {//sub reg, imm
            ctx.was_mutated = _sub_64_reg_imm_tmpl(ctx);
        }
        else if (detail.operands[1].type == X86_OP_MEM) {//sub reg, [op]
            ctx.was_mutated = _sub_64_reg_op_tmpl(ctx);
        }
    }
    else if (detail.operands[0].type == X86_OP_MEM) {

        if (detail.operands[1].type == X86_OP_REG) { //sub [op], reg
            ctx.was_mutated = _sub_64_op_reg_tmpl(ctx);
        }
        else if (detail.operands[1].type == X86_OP_IMM) {//sub [op], imm
            ctx.was_mutated = _sub_64_op_imm_tmpl(ctx);
        }
    }

}
void fukutate_64_xor(mutation_context& ctx) {

    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_REG) {

        if (detail.operands[1].type == X86_OP_REG) { //xor reg, reg
            ctx.was_mutated = _xor_64_reg_reg_tmpl(ctx);
        }
        else if (detail.operands[1].type == X86_OP_IMM) {//xor reg, imm
            ctx.was_mutated = _xor_64_reg_imm_tmpl(ctx);
        }
        else if (detail.operands[1].type == X86_OP_MEM) {//xor reg, [op]
            ctx.was_mutated = _xor_64_reg_op_tmpl(ctx);
        }
    }
    else if (detail.operands[0].type == X86_OP_MEM) {

        if (detail.operands[1].type == X86_OP_REG) { //xor [op], reg
            ctx.was_mutated = _xor_64_op_reg_tmpl(ctx);
        }
        else if (detail.operands[1].type == X86_OP_IMM) {//xor [op], imm
            ctx.was_mutated = _xor_64_op_imm_tmpl(ctx);
        }
    }

}

void fukutate_64_cmp(mutation_context& ctx) {

    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_REG) {

        if (detail.operands[1].type == X86_OP_REG) { //cmp reg, reg
            ctx.was_mutated = _cmp_64_reg_reg_tmpl(ctx);
        }
        else if (detail.operands[1].type == X86_OP_IMM) {//cmp reg, imm
            ctx.was_mutated = _cmp_64_reg_imm_tmpl(ctx);
        }
        else if (detail.operands[1].type == X86_OP_MEM) {//cmp reg, [op]
            ctx.was_mutated = _cmp_64_reg_op_tmpl(ctx);
        }
    }
    else if (detail.operands[0].type == X86_OP_MEM) {

        if (detail.operands[1].type == X86_OP_REG) { //cmp [op], reg
            ctx.was_mutated = _cmp_64_op_reg_tmpl(ctx);
        }
        else if (detail.operands[1].type == X86_OP_IMM) {//cmp [op], imm
            ctx.was_mutated = _cmp_64_op_imm_tmpl(ctx);
        }
    }
}

void fukutate_64_test(mutation_context& ctx) {

    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_REG) {

        if (detail.operands[1].type == X86_OP_REG) { //test reg, reg
            ctx.was_mutated = _test_64_reg_reg_tmpl(ctx);
        }
        else if (detail.operands[1].type == X86_OP_IMM) {//test reg, imm
            ctx.was_mutated = _test_64_reg_imm_tmpl(ctx);
        }
    }
    else if (detail.operands[0].type == X86_OP_MEM) {

        if (detail.operands[1].type == X86_OP_REG) { //test [op], reg
            ctx.was_mutated = _test_64_op_reg_tmpl(ctx);
        }
        else if (detail.operands[1].type == X86_OP_IMM) {//test [op], imm
            ctx.was_mutated = _test_64_op_imm_tmpl(ctx);
        }
    }
}


void fukutate_64_inc(mutation_context& ctx) {

    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_REG) {  //inc reg
        ctx.was_mutated = _inc_64_reg_tmpl(ctx);
    }
    else if (detail.operands[0].type == X86_OP_MEM) { //inc [op]
        ctx.was_mutated = _inc_64_op_tmpl(ctx);
    }
}

void fukutate_64_dec(mutation_context& ctx) {

    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_REG) {  //dec reg
        ctx.was_mutated = _dec_64_reg_tmpl(ctx);
    }
    else if (detail.operands[0].type == X86_OP_MEM) { //dec [op]
        ctx.was_mutated = _dec_64_op_tmpl(ctx);
    }
}

void fukutate_64_not(mutation_context& ctx) {

    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_REG) {  //not reg
        ctx.was_mutated = _not_64_reg_tmpl(ctx);
    }
    else if (detail.operands[0].type == X86_OP_MEM) { //not [op]
        ctx.was_mutated = _not_64_op_tmpl(ctx);
    }
}

void fukutate_64_neg(mutation_context& ctx) {

    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_REG) {  //neg reg
        ctx.was_mutated = _neg_64_reg_tmpl(ctx);
    }
    else if (detail.operands[0].type == X86_OP_MEM) { //neg [op]
        ctx.was_mutated = _neg_64_op_tmpl(ctx);
    }
}

void fukutate_64_mul(mutation_context& ctx) {

    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_REG) {  //mul reg
        ctx.was_mutated = _mul_64_reg_tmpl(ctx);
    }
    else if (detail.operands[0].type == X86_OP_MEM) { //mul [op]
        ctx.was_mutated = _mul_64_op_tmpl(ctx);
    }
}

void fukutate_64_imul(mutation_context& ctx) {

}

void fukutate_64_div(mutation_context& ctx) {

    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_REG) {  //div reg
        ctx.was_mutated = _div_64_reg_tmpl(ctx);
    }
    else if (detail.operands[0].type == X86_OP_MEM) { //div [op]
        ctx.was_mutated = _div_64_op_tmpl(ctx);
    }
}

void fukutate_64_idiv(mutation_context& ctx) {

    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_REG) {  //idiv reg
        ctx.was_mutated = _idiv_64_reg_tmpl(ctx);
    }
    else if (detail.operands[0].type == X86_OP_MEM) { //idiv [op]
        ctx.was_mutated = _idiv_64_op_tmpl(ctx);
    }
}


void fukutate_64_rol(mutation_context& ctx) {

    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_REG) {

        if (detail.operands[1].type == X86_OP_REG) { //rol reg, reg
            ctx.was_mutated = _rol_64_reg_reg_tmpl(ctx);
        }
        else if (detail.operands[1].type == X86_OP_IMM) {//rol reg, imm
            ctx.was_mutated = _rol_64_reg_imm_tmpl(ctx);
        }
    }
    else if (detail.operands[0].type == X86_OP_MEM) {

        if (detail.operands[1].type == X86_OP_REG) { //rol [op], reg
            ctx.was_mutated = _rol_64_op_reg_tmpl(ctx);
        }
        else if (detail.operands[1].type == X86_OP_IMM) {//rol [op], imm
            ctx.was_mutated = _rol_64_op_imm_tmpl(ctx);
        }
    }
}

void fukutate_64_ror(mutation_context& ctx) {

    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_REG) {

        if (detail.operands[1].type == X86_OP_REG) { //ror reg, reg
            ctx.was_mutated = _ror_64_reg_reg_tmpl(ctx);
        }
        else if (detail.operands[1].type == X86_OP_IMM) {//ror reg, imm
            ctx.was_mutated = _ror_64_reg_imm_tmpl(ctx);
        }
    }
    else if (detail.operands[0].type == X86_OP_MEM) {

        if (detail.operands[1].type == X86_OP_REG) { //ror [op], reg
            ctx.was_mutated = _ror_64_op_reg_tmpl(ctx);
        }
        else if (detail.operands[1].type == X86_OP_IMM) {//ror [op], imm
            ctx.was_mutated = _ror_64_op_imm_tmpl(ctx);
        }
    }
}


void fukutate_64_rcl(mutation_context& ctx) {

    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_REG) {

        if (detail.operands[1].type == X86_OP_REG) { //rcl reg, reg
            ctx.was_mutated = _rcl_64_reg_reg_tmpl(ctx);
        }
        else if (detail.operands[1].type == X86_OP_IMM) {//rcl reg, imm
            ctx.was_mutated = _rcl_64_reg_imm_tmpl(ctx);
        }
    }
    else if (detail.operands[0].type == X86_OP_MEM) {

        if (detail.operands[1].type == X86_OP_REG) { //rcl [op], reg
            ctx.was_mutated = _rcl_64_op_reg_tmpl(ctx);
        }
        else if (detail.operands[1].type == X86_OP_IMM) {//rcl [op], imm
            ctx.was_mutated = _rcl_64_op_imm_tmpl(ctx);
        }
    }
}


void fukutate_64_rcr(mutation_context& ctx) {

    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_REG) {

        if (detail.operands[1].type == X86_OP_REG) { //rcr reg, reg
            ctx.was_mutated = _rcr_64_reg_reg_tmpl(ctx);
        }
        else if (detail.operands[1].type == X86_OP_IMM) {//rcr reg, imm
            ctx.was_mutated = _rcr_64_reg_imm_tmpl(ctx);
        }
    }
    else if (detail.operands[0].type == X86_OP_MEM) {

        if (detail.operands[1].type == X86_OP_REG) { //rcr [op], reg
            ctx.was_mutated = _rcr_64_op_reg_tmpl(ctx);
        }
        else if (detail.operands[1].type == X86_OP_IMM) {//rcr [op], imm
            ctx.was_mutated = _rcr_64_op_imm_tmpl(ctx);
        }
    }
}


void fukutate_64_shl(mutation_context& ctx) {

    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_REG) {

        if (detail.operands[1].type == X86_OP_REG) { //shl reg, reg
            ctx.was_mutated = _shl_64_reg_reg_tmpl(ctx);
        }
        else if (detail.operands[1].type == X86_OP_IMM) {//shl reg, imm
            ctx.was_mutated = _shl_64_reg_imm_tmpl(ctx);
        }
    }
    else if (detail.operands[0].type == X86_OP_MEM) {

        if (detail.operands[1].type == X86_OP_REG) { //shl [op], reg
            ctx.was_mutated = _shl_64_op_reg_tmpl(ctx);
        }
        else if (detail.operands[1].type == X86_OP_IMM) {//shl [op], imm
            ctx.was_mutated = _shl_64_op_imm_tmpl(ctx);
        }
    }
}


void fukutate_64_shr(mutation_context& ctx) {

    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_REG) {

        if (detail.operands[1].type == X86_OP_REG) { //shr reg, reg
            ctx.was_mutated = _shr_64_reg_reg_tmpl(ctx);
        }
        else if (detail.operands[1].type == X86_OP_IMM) {//shr reg, imm
            ctx.was_mutated = _shr_64_reg_imm_tmpl(ctx);
        }
    }
    else if (detail.operands[0].type == X86_OP_MEM) {

        if (detail.operands[1].type == X86_OP_REG) { //shr [op], reg
            ctx.was_mutated = _shr_64_op_reg_tmpl(ctx);
        }
        else if (detail.operands[1].type == X86_OP_IMM) {//shr [op], imm
            ctx.was_mutated = _shr_64_op_imm_tmpl(ctx);
        }
    }
}


void fukutate_64_sar(mutation_context& ctx) {

    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_REG) {

        if (detail.operands[1].type == X86_OP_REG) { //sar reg, reg
            ctx.was_mutated = _sar_64_reg_reg_tmpl(ctx);
        }
        else if (detail.operands[1].type == X86_OP_IMM) {//sar reg, imm
            ctx.was_mutated = _sar_64_reg_imm_tmpl(ctx);
        }
    }
    else if (detail.operands[0].type == X86_OP_MEM) {

        if (detail.operands[1].type == X86_OP_REG) { //sar [op], reg
            ctx.was_mutated = _sar_64_op_reg_tmpl(ctx);
        }
        else if (detail.operands[1].type == X86_OP_IMM) {//sar [op], imm
            ctx.was_mutated = _sar_64_op_imm_tmpl(ctx);
        }
    }
}


void fukutate_64_bt(mutation_context& ctx) {

    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_REG) {

        if (detail.operands[1].type == X86_OP_REG) { //bt reg, reg
            ctx.was_mutated = _bt_64_reg_reg_tmpl(ctx);
        }
        else if (detail.operands[1].type == X86_OP_IMM) {//bt reg, imm
            ctx.was_mutated = _bt_64_reg_imm_tmpl(ctx);
        }
    }
    else if (detail.operands[0].type == X86_OP_MEM) {

        if (detail.operands[1].type == X86_OP_REG) { //bt [op], reg
            ctx.was_mutated = _bt_64_op_reg_tmpl(ctx);
        }
        else if (detail.operands[1].type == X86_OP_IMM) {//bt [op], imm
            ctx.was_mutated = _bt_64_op_imm_tmpl(ctx);
        }
    }
}

void fukutate_64_bts(mutation_context& ctx) {

    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_REG) {

        if (detail.operands[1].type == X86_OP_REG) { //bts reg, reg
            ctx.was_mutated = _bts_64_reg_reg_tmpl(ctx);
        }
        else if (detail.operands[1].type == X86_OP_IMM) {//bts reg, imm
            ctx.was_mutated = _bts_64_reg_imm_tmpl(ctx);
        }
    }
    else if (detail.operands[0].type == X86_OP_MEM) {

        if (detail.operands[1].type == X86_OP_REG) { //bts [op], reg
            ctx.was_mutated = _bts_64_op_reg_tmpl(ctx);
        }
        else if (detail.operands[1].type == X86_OP_IMM) {//bts [op], imm
            ctx.was_mutated = _bts_64_op_imm_tmpl(ctx);
        }
    }
}

void fukutate_64_btr(mutation_context& ctx) {

    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_REG) {

        if (detail.operands[1].type == X86_OP_REG) { //btr reg, reg
            ctx.was_mutated = _btr_64_reg_reg_tmpl(ctx);
        }
        else if (detail.operands[1].type == X86_OP_IMM) {//btr reg, imm
            ctx.was_mutated = _btr_64_reg_imm_tmpl(ctx);
        }
    }
    else if (detail.operands[0].type == X86_OP_MEM) {

        if (detail.operands[1].type == X86_OP_REG) { //btr [op], reg
            ctx.was_mutated = _btr_64_op_reg_tmpl(ctx);
        }
        else if (detail.operands[1].type == X86_OP_IMM) {//btr [op], imm
            ctx.was_mutated = _btr_64_op_imm_tmpl(ctx);
        }
    }
}

void fukutate_64_btc(mutation_context& ctx) {

    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_REG) {

        if (detail.operands[1].type == X86_OP_REG) { //btc reg, reg
            ctx.was_mutated = _btc_64_reg_reg_tmpl(ctx);
        }
        else if (detail.operands[1].type == X86_OP_IMM) {//btc reg, imm
            ctx.was_mutated = _btc_64_reg_imm_tmpl(ctx);
        }
    }
    else if (detail.operands[0].type == X86_OP_MEM) {

        if (detail.operands[1].type == X86_OP_REG) { //btc [op], reg
            ctx.was_mutated = _btc_64_op_reg_tmpl(ctx);
        }
        else if (detail.operands[1].type == X86_OP_IMM) {//btc [op], imm
            ctx.was_mutated = _btc_64_op_imm_tmpl(ctx);
        }
    }
}

void fukutate_64_bsf(mutation_context& ctx) {

    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_REG) {

        if (detail.operands[1].type == X86_OP_REG) { //bsf reg, reg
            ctx.was_mutated = _bsf_64_reg_reg_tmpl(ctx);
        }
        else if (detail.operands[1].type == X86_OP_MEM) {//bsf reg, [op]
            ctx.was_mutated = _bsf_64_reg_op_tmpl(ctx);
        }
    }
}

void fukutate_64_bsr(mutation_context& ctx) {

    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_REG) {

        if (detail.operands[1].type == X86_OP_REG) { //bsr reg, reg
            ctx.was_mutated = _bsr_64_reg_reg_tmpl(ctx);
        }
        else if (detail.operands[1].type == X86_OP_MEM) {//bsr reg, [op]
            ctx.was_mutated = _bsr_64_reg_op_tmpl(ctx);
        }
    }
}

