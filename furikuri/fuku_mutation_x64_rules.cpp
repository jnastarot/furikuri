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


/*
JCC MUTATE RULES

1: exmpl for je
    jne inst_after_je
    jmp jccdst

*/
void fukutate_64_jcc(mutation_context & ctx) {
    if (!ctx.is_next_line_end) { //if not last instruction
      //inverted jcc to next_inst_after real jcc
      //jmp jcc_dst

        fuku_condition cond = capstone_to_fuku_cond((x86_insn)ctx.instruction->id);
        size_t rel_idx = ctx.current_line_iter->get_rip_relocation_idx();

        ctx.f_asm->jcc(fuku_condition(cond ^ 1), imm(-1));
        ctx.f_asm->get_context().inst->
            set_eflags(ctx.eflags_changes)
            .set_rip_relocation_idx(
                ctx.code_holder->create_rip_relocation(
                    ctx.f_asm->get_context().immediate_offset, &(*ctx.next_line_iter)
                )
            )
            .set_instruction_flags(FUKU_INST_NO_MUTATE | ctx.instruction_flags);

        ctx.f_asm->jmp(imm(-1));
        ctx.f_asm->get_context().inst->
            set_eflags(ctx.eflags_changes)
            .set_rip_relocation_idx(rel_idx)
            .set_instruction_flags(FUKU_INST_NO_MUTATE | ctx.instruction_flags);

        ctx.code_holder->get_rip_relocations()[rel_idx].offset = ctx.f_asm->get_context().immediate_offset;

        ctx.was_mutated = true;
        return;
    }

    ctx.was_mutated = false;
    return;
}

void fukutate_64_jmp(mutation_context & ctx) {
    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_REG) { //jmp reg32

        switch (FUKU_GET_RAND(0, 0)) {

            //push reg
            //ret   
        case 0: {

            if (IsAllowedStackOperations) {

                ctx.f_asm->push(reg_(capstone_to_fuku_reg(detail.operands[0].reg)));

                ctx.f_asm->get_context().inst->
                    set_eflags(ctx.eflags_changes)
                    .set_custom_flags(ctx.regs_changes);

                ctx.f_asm->ret(imm(0));
                ctx.f_asm->get_context().inst->
                    set_eflags(ctx.eflags_changes)
                    .set_custom_flags(ctx.regs_changes);
            }
            else {
                ctx.was_mutated = false;
                return;
            }

            break;
        }

        default: {ctx.was_mutated = false; return; }
        }

        ctx.was_mutated = true;
        return;
    }
    else if (detail.operands[0].type == X86_OP_MEM) { //jmp [op]

  
    }
    else if (detail.operands[0].type == X86_OP_IMM) { //jmp imm

        size_t rip_label_orig = ctx.current_line_iter->get_rip_relocation_idx();
        size_t rip_label_idx = ctx.code_holder->get_rip_relocations()[rip_label_orig].label_idx;

        switch (FUKU_GET_RAND(0, 1)) {

        case 0: {
            //je  dst
            //jne dst

            uint8_t cond = FUKU_GET_RAND(0, 15);

            ctx.f_asm->jcc(fuku_condition(cond), imm(-1));
            ctx.f_asm->get_context().inst->
                set_eflags(ctx.eflags_changes)
                .set_custom_flags(ctx.regs_changes)
                .set_rip_relocation_idx(ctx.code_holder->create_rip_relocation_lb(ctx.f_asm->get_context().immediate_offset, rip_label_idx))
                .set_instruction_flags(ctx.instruction_flags | FUKU_INST_NO_MUTATE);

            ctx.f_asm->jcc(fuku_condition(cond ^ 1), imm(-1));
            ctx.f_asm->get_context().inst->
                set_eflags(ctx.eflags_changes & (~di_fl_jcc[fuku_condition(cond ^ 1)]))
                .set_custom_flags(ctx.regs_changes)
                .set_rip_relocation_idx(ctx.code_holder->create_rip_relocation_lb(ctx.f_asm->get_context().immediate_offset, rip_label_idx))
                .set_instruction_flags(ctx.instruction_flags | FUKU_INST_NO_MUTATE);

            ctx.code_holder->delete_rip_relocation(rip_label_orig);

            break;
        }
        case 1: {
            //mov randreg, dst
            //jmp randreg

            fuku_register rand_reg = get_random_free_flag_reg(ctx.regs_changes, 8, false);

            if (rand_reg.get_reg() != FUKU_REG_NONE) {

                uint64_t flag_reg = fuku_reg_to_complex_flag_reg(rand_reg);

                ctx.f_asm->mov(rand_reg, imm(0xFFFFFFFFFFFFFFFF));
                ctx.f_asm->get_context().inst->
                    set_eflags(ctx.eflags_changes)
                    .set_custom_flags(ctx.regs_changes)
                    .set_relocation_imm_idx(
                        ctx.code_holder->create_relocation_lb(
                            ctx.f_asm->get_context().immediate_offset, rip_label_idx, 0
                        )
                    );

                ctx.f_asm->jmp(rand_reg);
                ctx.f_asm->get_context().inst->
                    set_eflags(ctx.eflags_changes)
                    .set_custom_flags(ctx.regs_changes & (~flag_reg));

                ctx.code_holder->delete_rip_relocation(rip_label_orig);
            }
            else {
                ctx.was_mutated = false;
                return;
            }

            break;
        }
        default: {ctx.was_mutated = false; return; }
        }

        ctx.was_mutated = true;
        return;
    }

    ctx.was_mutated = false;
    return;
}
void fukutate_64_call(mutation_context & ctx) {
    ctx.was_mutated = false; return;
}
void fukutate_64_ret(mutation_context & ctx) {
    ctx.was_mutated = false; return;
}

//stack
void fukutate_64_push(mutation_context & ctx) {
    ctx.was_mutated = false; return;
}

void fukutate_64_pop(mutation_context & ctx) {
    ctx.was_mutated = false; return;
}

//data transfer
void fukutate_64_mov(mutation_context & ctx) {
    ctx.was_mutated = false; return;
}
void fukutate_64_xchg(mutation_context & ctx) {
    ctx.was_mutated = false; return;
}
void fukutate_64_lea(mutation_context & ctx) {
    ctx.was_mutated = false; return;
}

//aritch
void fukutate_64_add(mutation_context & ctx) {
    ctx.was_mutated = false; return;
}
void fukutate_64_or(mutation_context & ctx) {
    ctx.was_mutated = false; return;
}
void fukutate_64_adc(mutation_context & ctx) {
    ctx.was_mutated = false; return;
}
void fukutate_64_sbb(mutation_context & ctx) {
    ctx.was_mutated = false; return;
}
void fukutate_64_and(mutation_context & ctx) {
    ctx.was_mutated = false; return;
}
void fukutate_64_sub(mutation_context & ctx) {
    ctx.was_mutated = false; return;
}
void fukutate_64_xor(mutation_context & ctx) {
    ctx.was_mutated = false; return;
}
void fukutate_64_cmp(mutation_context & ctx) {
    ctx.was_mutated = false; return;
}
void fukutate_64_inc(mutation_context & ctx) {
    ctx.was_mutated = false; return;
}
void fukutate_64_dec(mutation_context & ctx) {
    ctx.was_mutated = false; return;
}
void fukutate_64_test(mutation_context & ctx) {
    ctx.was_mutated = false; return;
}
void fukutate_64_not(mutation_context & ctx) {
    ctx.was_mutated = false; return;
}
void fukutate_64_neg(mutation_context & ctx) {
    ctx.was_mutated = false; return;
}
void fukutate_64_mul(mutation_context & ctx) {
    ctx.was_mutated = false; return;
}
void fukutate_64_imul(mutation_context & ctx) {
    ctx.was_mutated = false; return;
}
void fukutate_64_div(mutation_context & ctx) {
    ctx.was_mutated = false; return;
}
void fukutate_64_idiv(mutation_context & ctx) {
    ctx.was_mutated = false; return;
}

//shift
void fukutate_64_rol(mutation_context & ctx) {
    ctx.was_mutated = false; return;
}
void fukutate_64_ror(mutation_context & ctx) {
    ctx.was_mutated = false; return;
}
void fukutate_64_rcl(mutation_context & ctx) {
    ctx.was_mutated = false; return;
}
void fukutate_64_rcr(mutation_context & ctx) {
    ctx.was_mutated = false; return;
}
void fukutate_64_shl(mutation_context & ctx) {
    ctx.was_mutated = false; return;
}
void fukutate_64_shr(mutation_context & ctx) {
    ctx.was_mutated = false; return;
}
void fukutate_64_sar(mutation_context & ctx) {
    ctx.was_mutated = false; return;
}

//bittest
void fukutate_64_bt(mutation_context & ctx) {
    ctx.was_mutated = false; return;
}
void fukutate_64_bts(mutation_context & ctx) {
    ctx.was_mutated = false; return;
}
void fukutate_64_btr(mutation_context & ctx) {
    ctx.was_mutated = false; return;
}
void fukutate_64_btc(mutation_context & ctx) {
    ctx.was_mutated = false; return;
}
void fukutate_64_bsf(mutation_context & ctx) {
    ctx.was_mutated = false; return;
}
void fukutate_64_bsr(mutation_context & ctx) {
    ctx.was_mutated = false; return;
}

