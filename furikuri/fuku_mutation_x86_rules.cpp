#include "stdafx.h"
#include "fuku_mutation_x86_rules.h"

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
           if (inst_size == 4 && op.get_type() == FUKU_T0_IMMEDIATE && reloc_imm) {\
                ctx.f_asm->get_context().inst->\
                set_imm_reloc(reloc_imm);\
                reloc_imm->offset = ctx.f_asm->get_context().immediate_offset;\
           }

#define restore_rip_relocate_in_imm(op) \
           if (inst_size == 4 && op.get_type() == FUKU_T0_IMMEDIATE && reloc_rip && !used_disp_reloc) {\
                ctx.f_asm->get_context().inst->\
                set_rip_reloc(reloc_rip);\
                reloc_rip->offset = ctx.f_asm->get_context().immediate_offset;\
           }

#define restore_rip_relocate_in_disp(op) \
           if (inst_size == 4 && op.get_type() == FUKU_T0_OPERAND && reloc_rip && !used_disp_reloc) {\
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


#include "obf_templates/x86/obf_x86_mov_templates.h"
#include "obf_templates/x86/obf_x86_xchg_templates.h"
#include "obf_templates/x86/obf_x86_push_templates.h"
#include "obf_templates/x86/obf_x86_pop_templates.h"
#include "obf_templates/x86/obf_x86_lea_templates.h"

#include "obf_templates/x86/obf_x86_jcc_templates.h"
#include "obf_templates/x86/obf_x86_jmp_templates.h"
#include "obf_templates/x86/obf_x86_call_templates.h"
#include "obf_templates/x86/obf_x86_ret_templates.h"

#include "obf_templates/x86/obf_x86_add_templates.h"
#include "obf_templates/x86/obf_x86_sub_templates.h"
#include "obf_templates/x86/obf_x86_adc_templates.h"
#include "obf_templates/x86/obf_x86_sbb_templates.h"
#include "obf_templates/x86/obf_x86_cmp_templates.h"
#include "obf_templates/x86/obf_x86_neg_templates.h"
#include "obf_templates/x86/obf_x86_inc_templates.h"
#include "obf_templates/x86/obf_x86_dec_templates.h"
#include "obf_templates/x86/obf_x86_mul_templates.h"
#include "obf_templates/x86/obf_x86_imul_templates.h"
#include "obf_templates/x86/obf_x86_div_templates.h"
#include "obf_templates/x86/obf_x86_idiv_templates.h"

#include "obf_templates/x86/obf_x86_and_templates.h"
#include "obf_templates/x86/obf_x86_or_templates.h"
#include "obf_templates/x86/obf_x86_xor_templates.h"
#include "obf_templates/x86/obf_x86_test_templates.h"
#include "obf_templates/x86/obf_x86_not_templates.h"

#include "obf_templates/x86/obf_x86_ror_templates.h"
#include "obf_templates/x86/obf_x86_rol_templates.h"
#include "obf_templates/x86/obf_x86_rcl_templates.h"
#include "obf_templates/x86/obf_x86_rcr_templates.h"
#include "obf_templates/x86/obf_x86_shl_templates.h"
#include "obf_templates/x86/obf_x86_shr_templates.h"
#include "obf_templates/x86/obf_x86_sar_templates.h"

#include "obf_templates/x86/obf_x86_bt_templates.h"
#include "obf_templates/x86/obf_x86_bts_templates.h"
#include "obf_templates/x86/obf_x86_btr_templates.h"
#include "obf_templates/x86/obf_x86_btc_templates.h"
#include "obf_templates/x86/obf_x86_bsf_templates.h"
#include "obf_templates/x86/obf_x86_bsr_templates.h"



void init_x86_rules(_fukutate_instruction* rules) {

    rules[X86_INS_JMP] = fukutate_86_jmp;
    rules[X86_INS_CALL] = fukutate_86_call;
    rules[X86_INS_JO] = fukutate_86_jcc;
    rules[X86_INS_JNO] = fukutate_86_jcc;
    rules[X86_INS_JB] = fukutate_86_jcc;
    rules[X86_INS_JAE] = fukutate_86_jcc;
    rules[X86_INS_JE] = fukutate_86_jcc;
    rules[X86_INS_JNE] = fukutate_86_jcc;
    rules[X86_INS_JBE] = fukutate_86_jcc;
    rules[X86_INS_JA] = fukutate_86_jcc;
    rules[X86_INS_JS] = fukutate_86_jcc;
    rules[X86_INS_JNS] = fukutate_86_jcc;
    rules[X86_INS_JP] = fukutate_86_jcc;
    rules[X86_INS_JNP] = fukutate_86_jcc;
    rules[X86_INS_JL] = fukutate_86_jcc;
    rules[X86_INS_JGE] = fukutate_86_jcc;
    rules[X86_INS_JLE] = fukutate_86_jcc;
    rules[X86_INS_JG] = fukutate_86_jcc;
    rules[X86_INS_RET] = fukutate_86_ret;

    rules[X86_INS_MOV] = fukutate_86_mov;
    rules[X86_INS_XCHG] = fukutate_86_xchg;
    rules[X86_INS_LEA] = fukutate_86_lea;
    rules[X86_INS_PUSH] = fukutate_86_push;
    rules[X86_INS_POP] = fukutate_86_pop;

    //ARITHMETIC
    rules[X86_INS_ADD] = fukutate_86_add;
    rules[X86_INS_OR] = fukutate_86_or;
    rules[X86_INS_ADC] = fukutate_86_adc;
    rules[X86_INS_SBB] = fukutate_86_sbb;
    rules[X86_INS_AND] = fukutate_86_and;
    rules[X86_INS_SUB] = fukutate_86_sub;
    rules[X86_INS_XOR] = fukutate_86_xor;
    rules[X86_INS_CMP] = fukutate_86_cmp;
    rules[X86_INS_INC] = fukutate_86_inc;
    rules[X86_INS_DEC] = fukutate_86_dec;
    rules[X86_INS_TEST] = fukutate_86_test;
    rules[X86_INS_NOT] = fukutate_86_not;
    rules[X86_INS_NEG] = fukutate_86_neg;
    rules[X86_INS_MUL] = fukutate_86_mul;
    rules[X86_INS_IMUL] = fukutate_86_imul;
    rules[X86_INS_DIV] = fukutate_86_div;
    rules[X86_INS_IDIV] = fukutate_86_idiv;

    //SHIFT
    rules[X86_INS_ROL] = fukutate_86_rol;
    rules[X86_INS_ROR] = fukutate_86_ror;
    rules[X86_INS_RCL] = fukutate_86_rcl;
    rules[X86_INS_RCR] = fukutate_86_rcr;
    rules[X86_INS_SAL] = fukutate_86_shl;//SAL is too SHL
    rules[X86_INS_SHL] = fukutate_86_shl;
    rules[X86_INS_SHR] = fukutate_86_shr;
    rules[X86_INS_SAR] = fukutate_86_sar;

    //BITTEST
    rules[X86_INS_BT] = fukutate_86_bt;
    rules[X86_INS_BTS] = fukutate_86_bts;
    rules[X86_INS_BTR] = fukutate_86_btr;
    rules[X86_INS_BTC] = fukutate_86_btc;
    rules[X86_INS_BSF] = fukutate_86_bsf;
    rules[X86_INS_BSR] = fukutate_86_bsr;
}