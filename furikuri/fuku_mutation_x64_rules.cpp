#include "stdafx.h"
#include "fuku_mutation_x64_rules.h"

#define IsAllowedStackOperations (!HAS_FULL_MASK(ctx.inst_flags, FUKU_INST_BAD_STACK))

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
           if (op.get_type() == FUKU_T0_OPERAND && reloc_disp && used_disp_reloc) {\
                ctx.f_asm->get_context().inst->\
                set_disp_reloc(reloc_disp);\
                reloc_disp->offset = ctx.f_asm->get_context().displacment_offset;\
           }

#define restore_imm_relocate(op) \
           if (inst_size == 8 && op.get_type() == FUKU_T0_IMMEDIATE && reloc_imm) {\
                ctx.f_asm->get_context().inst->\
                set_imm_reloc(reloc_imm);\
                reloc_imm->offset = ctx.f_asm->get_context().immediate_offset;\
           }

#define restore_rip_relocate_in_imm(op) \
           if (inst_size == 8 && op.get_type() == FUKU_T0_IMMEDIATE && reloc_rip && !used_disp_reloc) {\
                ctx.f_asm->get_context().inst->\
                set_rip_reloc(reloc_rip);\
                reloc_rip->offset = ctx.f_asm->get_context().immediate_offset;\
           }

#define restore_rip_relocate_in_disp(op) \
           if (inst_size == 8 && op.get_type() == FUKU_T0_OPERAND && reloc_rip && !used_disp_reloc) {\
                ctx.f_asm->get_context().inst->\
                set_rip_reloc(reloc_rip);\
                reloc_rip->offset = ctx.f_asm->get_context().displacment_offset;\
           }

#define restore_rip_to_imm_relocate(op) \
           if (op.get_type() == FUKU_T0_IMMEDIATE && reloc_rip && !used_disp_reloc) {\
                ctx.f_asm->get_context().inst->set_imm_reloc(\
                    ctx.code_holder->create_relocation(fuku_relocation()\
                        .set_label(reloc_rip->label)\
                        .set_offset(ctx.f_asm->get_context().immediate_offset)\
                    )\
                );\
                ctx.code_holder->release_rip_relocation(reloc_rip);\
           }

#define restore_rip_to_disp_relocate(op) \
           if (op.get_type() == FUKU_T0_OPERAND && reloc_rip && !used_disp_reloc) {\
                ctx.f_asm->get_context().inst->set_disp_reloc(\
                    ctx.code_holder->create_relocation(fuku_relocation()\
                        .set_label(reloc_rip->label)\
                        .set_offset(ctx.f_asm->get_context().displacment_offset)\
                    )\
                );\
                ctx.code_holder->release_rip_relocation(reloc_rip);\
           }

#define restore_imm_or_disp(op)         restore_disp_relocate(op) else restore_imm_relocate(op)
#define restore_rip_imm_or_disp(op)     restore_rip_relocate_in_imm(op) else restore_disp_relocate(op)
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



void init_x64_rules(_fukutate_instruction* rules) {

    rules[X86_INS_JMP] = fukutate_64_jmp;
    rules[X86_INS_CALL] = fukutate_64_call;
    rules[X86_INS_JO] = fukutate_64_jcc;
    rules[X86_INS_JNO] = fukutate_64_jcc;
    rules[X86_INS_JB] = fukutate_64_jcc;
    rules[X86_INS_JAE] = fukutate_64_jcc;
    rules[X86_INS_JE] = fukutate_64_jcc;
    rules[X86_INS_JNE] = fukutate_64_jcc;
    rules[X86_INS_JBE] = fukutate_64_jcc;
    rules[X86_INS_JA] = fukutate_64_jcc;
    rules[X86_INS_JS] = fukutate_64_jcc;
    rules[X86_INS_JNS] = fukutate_64_jcc;
    rules[X86_INS_JP] = fukutate_64_jcc;
    rules[X86_INS_JNP] = fukutate_64_jcc;
    rules[X86_INS_JL] = fukutate_64_jcc;
    rules[X86_INS_JGE] = fukutate_64_jcc;
    rules[X86_INS_JLE] = fukutate_64_jcc;
    rules[X86_INS_JG] = fukutate_64_jcc;
    rules[X86_INS_RET] = fukutate_64_ret;

    rules[X86_INS_MOV] = fukutate_64_mov;
    rules[X86_INS_XCHG] = fukutate_64_xchg;
    rules[X86_INS_LEA] = fukutate_64_lea;
    rules[X86_INS_PUSH] = fukutate_64_push;
    rules[X86_INS_POP] = fukutate_64_pop;

    //ARITHMETIC
    rules[X86_INS_ADD] = fukutate_64_add;
    rules[X86_INS_OR] = fukutate_64_or;
    rules[X86_INS_ADC] = fukutate_64_adc;
    rules[X86_INS_SBB] = fukutate_64_sbb;
    rules[X86_INS_AND] = fukutate_64_and;
    rules[X86_INS_SUB] = fukutate_64_sub;
    rules[X86_INS_XOR] = fukutate_64_xor;
    rules[X86_INS_CMP] = fukutate_64_cmp;
    rules[X86_INS_INC] = fukutate_64_inc;
    rules[X86_INS_DEC] = fukutate_64_dec;
    rules[X86_INS_TEST] = fukutate_64_test;
    rules[X86_INS_NOT] = fukutate_64_not;
    rules[X86_INS_NEG] = fukutate_64_neg;
    rules[X86_INS_MUL] = fukutate_64_mul;
    rules[X86_INS_IMUL] = fukutate_64_imul;
    rules[X86_INS_DIV] = fukutate_64_div;
    rules[X86_INS_IDIV] = fukutate_64_idiv;

    //SHIFT
    rules[X86_INS_ROL] = fukutate_64_rol;
    rules[X86_INS_ROR] = fukutate_64_ror;
    rules[X86_INS_RCL] = fukutate_64_rcl;
    rules[X86_INS_RCR] = fukutate_64_rcr;
    rules[X86_INS_SAL] = fukutate_64_shl;//SAL is too SHL
    rules[X86_INS_SHL] = fukutate_64_shl;
    rules[X86_INS_SHR] = fukutate_64_shr;
    rules[X86_INS_SAR] = fukutate_64_sar;

    //BITTEST
    rules[X86_INS_BT] = fukutate_64_bt;
    rules[X86_INS_BTS] = fukutate_64_bts;
    rules[X86_INS_BTR] = fukutate_64_btr;
    rules[X86_INS_BTC] = fukutate_64_btc;
    rules[X86_INS_BSF] = fukutate_64_bsf;
    rules[X86_INS_BSR] = fukutate_64_bsr;
}