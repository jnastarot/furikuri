#include "stdafx.h"
#include "fuku_mutation_x86_rules.h"

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


#include "mutation_86_templates.h"


void fukutate_86_jcc(mutation_context& ctx) {

    if (!ctx.is_next_line_end) { //if not last instruction
        //inverted jcc to next_inst_after real jcc
        //jmp jcc_dst

        fuku_condition cond = capstone_to_fuku_cond((x86_insn)ctx.instruction->id);
        size_t rel_idx = ctx.current_line_iter->get_rip_relocation_idx();

        ctx.f_asm->jcc(fuku_condition(cond ^ 1), imm(-1));
        ctx.f_asm->get_context().inst->
            set_eflags(ctx.eflags_changes)
            .set_custom_flags(ctx.regs_changes)
            .set_rip_relocation_idx(
                ctx.code_holder->create_rip_relocation(
                    ctx.f_asm->get_context().immediate_offset, &(*ctx.next_line_iter)
                )
            )
            .set_instruction_flags(FUKU_INST_NO_MUTATE | ctx.instruction_flags);

        ctx.f_asm->jmp(imm(-1));
        ctx.f_asm->get_context().inst->
            set_eflags(ctx.eflags_changes)
            .set_custom_flags(ctx.regs_changes)
            .set_rip_relocation_idx(rel_idx)
            .set_instruction_flags(FUKU_INST_NO_MUTATE | ctx.instruction_flags);

        ctx.code_holder->get_rip_relocations()[rel_idx].offset = ctx.f_asm->get_context().immediate_offset;

        ctx.was_mutated = true;
    }
}


void fukutate_86_jmp(mutation_context& ctx) {

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
                return;
            }

            break;
        }

        default: { return; }
        }

        ctx.was_mutated = true;
        return;
    }
    else if (detail.operands[0].type == X86_OP_MEM) { //jmp [op]


    }
    else if (detail.operands[0].type == X86_OP_IMM) { //jmp imm

        size_t rip_label_orig = ctx.current_line_iter->get_rip_relocation_idx();
        size_t rip_label_idx = ctx.code_holder->get_rip_relocations()[rip_label_orig].label_idx;

        switch (FUKU_GET_RAND(0, 2)) {
            //push jmpdst
            //ret   
        case 0: {

            if (IsAllowedStackOperations) {


                ctx.f_asm->push(imm(0xFFFFFFFF));
                ctx.f_asm->get_context().inst->
                    set_eflags(ctx.eflags_changes)
                    .set_custom_flags(ctx.regs_changes)
                    .set_relocation_imm_idx(
                        ctx.code_holder->create_relocation_lb(
                            ctx.f_asm->get_context().immediate_offset, rip_label_idx, 0
                        )
                    );

                ctx.f_asm->ret(imm(0));
                ctx.f_asm->get_context().inst->
                    set_eflags(ctx.eflags_changes)
                    .set_custom_flags(ctx.regs_changes);

                ctx.code_holder->delete_rip_relocation(rip_label_orig);
            }
            else {
                return;
            }
            break;
        }

        case 1: {
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
        case 2: {
            //mov randreg, dst
            //jmp randreg

            fuku_register rand_reg = get_random_free_flag_reg(ctx.regs_changes, 4, true);

            if (rand_reg.get_reg() != FUKU_REG_NONE) {

                uint64_t flag_reg = fuku_reg_to_complex_flag_reg(rand_reg);

                ctx.f_asm->mov(rand_reg, imm(0xFFFFFFFF));
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
                return;
            }

            break;
        }
        default: { return; }
        }

        ctx.was_mutated = true;
    }
}


void fukutate_86_call(mutation_context& ctx) {

    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_MEM) { //call [op]

        if (detail.operands[0].size == 4) { //call [op]

        }
        else if (detail.operands[0].size == 2) { //call [op]

        }
        else if (detail.operands[0].size == 1) { //call [op]

        }


    }
    else if (detail.operands[0].type == X86_OP_REG) {//call reg


        cs_x86_op * reg_op = &detail.operands[0];

        fuku_register_enum src_reg = capstone_to_fuku_reg(detail.operands[0].reg);
        if (reg_op->size == 4) { //call reg32

            //push next_inst_address
            //jmp reg
            if (!ctx.is_next_line_end) { //if not last instruction
                uint64_t out_regflags = ctx.regs_changes & ~(fuku_reg_to_complex_flag_reg(src_reg, 8));

                ctx.f_asm->push(imm(0xFFFFFFFF));
                ctx.f_asm->get_context().inst->
                    set_eflags(ctx.eflags_changes)
                    .set_custom_flags(ctx.regs_changes)
                    .set_relocation_imm_idx(
                        ctx.code_holder->create_relocation(
                            ctx.f_asm->get_context().immediate_offset, &(*ctx.next_line_iter), 0
                        )
                    );

                ctx.f_asm->jmp(reg_(src_reg));
                ctx.f_asm->get_context().inst->
                    set_eflags(ctx.eflags_changes)
                    .set_custom_flags(ctx.regs_changes);

                ctx.was_mutated = true;
            }
            
        }
        else if (reg_op->size == 2) { //call reg16


        }
        else if (reg_op->size == 1) { //call reg8

        }


    }
    else if (detail.operands[0].type == X86_OP_IMM) {

        
        //push next_inst_address
        //jmp imm
        if (!ctx.is_next_line_end) { //if not last instruction

            size_t rip_label_orig = ctx.current_line_iter->get_rip_relocation_idx();

            ctx.f_asm->push(imm(0xFFFFFFFF));
            ctx.f_asm->get_context().inst->
                set_eflags(ctx.eflags_changes)
                .set_custom_flags(ctx.regs_changes)
                .set_relocation_imm_idx(
                    ctx.code_holder->create_relocation(
                        ctx.f_asm->get_context().immediate_offset, &(*ctx.next_line_iter), 0
                    )
                );

            ctx.f_asm->jmp(imm(0xFFFFFFFF));
            ctx.f_asm->get_context().inst->
                set_eflags(ctx.eflags_changes)
                .set_custom_flags(ctx.regs_changes)
                .set_rip_relocation_idx(rip_label_orig);

            ctx.code_holder->get_rip_relocations()[rip_label_orig].offset = ctx.f_asm->get_context().immediate_offset;

            ctx.was_mutated = true;
        }
    }

}


void fukutate_86_ret(mutation_context& ctx) {

    auto detail = ctx.instruction->detail->x86;


    //lea esp,[esp + (4 + stack_offset)]
    //jmp [esp - 4 - stack_offset] <- bad esp here
    uint16_t ret_stack = 0;

    if (detail.op_count) { //ret 0x0000
        ret_stack = (uint16_t)detail.operands[0].imm;
    }

    ctx.f_asm->lea(reg_(FUKU_REG_ESP), dword_ptr(FUKU_REG_ESP, imm(4 + ret_stack)));
    ctx.f_asm->get_context().inst->
        set_eflags(ctx.eflags_changes)
        .set_custom_flags(ctx.regs_changes);

    ctx.f_asm->jmp(dword_ptr(FUKU_REG_ESP, imm(-4 - ret_stack)));
    ctx.f_asm->get_context().inst->
        set_eflags(ctx.eflags_changes)
        .set_custom_flags(ctx.regs_changes)
        .set_instruction_flags(FUKU_INST_BAD_STACK);

    ctx.was_mutated = true;
}



void fukutate_86_push(mutation_context& ctx) {
    if (!IsAllowedStackOperations) { return; }
    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_REG) {  //push reg
        ctx.was_mutated = _push_86_reg_tmpl(ctx, detail);
    }
    else if (detail.operands[0].type == X86_OP_MEM) { //push [op]
        ctx.was_mutated = _push_86_op_tmpl(ctx, detail);
    }
    else if (detail.operands[0].type == X86_OP_IMM) { //push imm8/imm32
        ctx.was_mutated = _push_86_imm_tmpl(ctx, detail);
    }
}



void fukutate_86_pop(mutation_context& ctx) {

    auto detail = ctx.instruction->detail->x86;
    uint32_t instruction_flags = ctx.current_line_iter->get_instruction_flags();

    if (detail.operands[0].type == X86_OP_REG) { //pop reg

        fuku_register_enum reg = capstone_to_fuku_reg(detail.operands[0].reg);

        if (reg == FUKU_REG_ESP || reg == FUKU_REG_SP) { return; }

        uint64_t out_regflags = ctx.regs_changes & ~(fuku_reg_to_complex_flag_reg(reg, 8));

        if (detail.operands[0].size == 4) {      //pop reg32

            switch (FUKU_GET_RAND(0, 1)) {


            //mov reg,[esp]
             //add esp,4
            case 0: {
                ctx.f_asm->mov(reg_(reg), dword_ptr(FUKU_REG_ESP));
                ctx.f_asm->get_context().inst->
                    set_eflags(ctx.eflags_changes)
                    .set_custom_flags(ctx.regs_changes);

                if (has_inst_free_eflags(ctx.eflags_changes,
                    X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_CF | X86_EFLAGS_MODIFY_PF)) {

                    ctx.f_asm->add(reg_(FUKU_REG_ESP), imm(4));
                    ctx.f_asm->get_context().inst->
                        set_eflags(ctx.eflags_changes)
                        .set_custom_flags(out_regflags)
                        .set_instruction_flags(FUKU_INST_BAD_STACK);
                }
                else {
                    ctx.f_asm->lea(reg_(FUKU_REG_ESP), dword_ptr(FUKU_REG_ESP, imm(4)));
                    ctx.f_asm->get_context().inst->
                        set_eflags(ctx.eflags_changes)
                        .set_custom_flags(out_regflags)
                        .set_instruction_flags(FUKU_INST_BAD_STACK);
                }

                break;
            }
            case 1: {
                //add esp,4
                //mov reg,[esp - 4]

                if (has_inst_free_eflags(ctx.eflags_changes,
                    X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_CF | X86_EFLAGS_MODIFY_PF)) {

                    ctx.f_asm->add(reg_(FUKU_REG_ESP), imm(4));
                    ctx.f_asm->get_context().inst->
                        set_eflags(ctx.eflags_changes)
                        .set_custom_flags(ctx.regs_changes);
                }
                else {
                    ctx.f_asm->lea(reg_(FUKU_REG_ESP), dword_ptr(FUKU_REG_ESP, imm(4)));
                    ctx.f_asm->get_context().inst->
                        set_eflags(ctx.eflags_changes)
                        .set_custom_flags(ctx.regs_changes);
                }

                ctx.f_asm->mov(reg_(reg), dword_ptr(FUKU_REG_ESP, imm(-4)));
                ctx.f_asm->get_context().inst->
                    set_eflags(ctx.eflags_changes)
                    .set_custom_flags(out_regflags)
                    .set_instruction_flags(FUKU_INST_BAD_STACK);

                break;
            }

            default: { return; }
            }


            ctx.was_mutated = true;
        }
        else if (detail.operands[0].size == 2) { //pop reg16

            switch (FUKU_GET_RAND(0, 1)) {

                //mov reg,[esp]
                //add esp,2
            case 0: {
                ctx.f_asm->mov(reg_(reg), word_ptr(FUKU_REG_ESP));
                ctx.f_asm->get_context().inst->
                    set_eflags(ctx.eflags_changes)
                    .set_custom_flags(ctx.regs_changes);

                if (has_inst_free_eflags(ctx.eflags_changes,
                    X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_CF | X86_EFLAGS_MODIFY_PF)) {

                    ctx.f_asm->add(reg_(FUKU_REG_ESP), imm(2));
                    ctx.f_asm->get_context().inst->
                        set_eflags(ctx.eflags_changes)
                        .set_custom_flags(out_regflags)
                        .set_instruction_flags(FUKU_INST_BAD_STACK);
                }
                else {
                    ctx.f_asm->lea(reg_(FUKU_REG_ESP), dword_ptr(FUKU_REG_ESP, imm(2)));
                    ctx.f_asm->get_context().inst->
                        set_eflags(ctx.eflags_changes)
                        .set_custom_flags(out_regflags)
                        .set_instruction_flags(FUKU_INST_BAD_STACK);
                }

                break;
            }
            case 1: {
                //add esp,2
                //mov reg,[esp - 2]

                if (has_inst_free_eflags(ctx.eflags_changes,
                    X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_CF | X86_EFLAGS_MODIFY_PF)) {

                    ctx.f_asm->add(reg_(FUKU_REG_ESP), imm(2));
                    ctx.f_asm->get_context().inst->
                        set_eflags(ctx.eflags_changes)
                        .set_custom_flags(ctx.regs_changes);
                }
                else {
                    ctx.f_asm->lea(reg_(FUKU_REG_ESP), dword_ptr(FUKU_REG_ESP, imm(2)));
                    ctx.f_asm->get_context().inst->
                        set_eflags(ctx.eflags_changes)
                        .set_custom_flags(ctx.regs_changes);
                }

                ctx.f_asm->mov(reg_(reg), word_ptr(FUKU_REG_ESP, imm(-2)));
                ctx.f_asm->get_context().inst->
                    set_eflags(ctx.eflags_changes)
                    .set_custom_flags(out_regflags)
                    .set_instruction_flags(FUKU_INST_BAD_STACK);

                break;
            }

            default: { return; }
            }


            ctx.was_mutated = true;
        }
        else if (detail.operands[0].size == 1) { //pop reg8

        }

    }
    else if (detail.operands[0].type == X86_OP_MEM) { //pop [op]

    }
}

void fukutate_86_mov(mutation_context& ctx) {

    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_REG) {

        if (detail.operands[1].type == X86_OP_REG) { //mov reg, reg
            ctx.was_mutated = _mov_86_reg_reg_tmpl(ctx, detail);
        }
        else if (detail.operands[1].type == X86_OP_IMM) {//mov reg, imm
            ctx.was_mutated = _mov_86_reg_imm_tmpl(ctx, detail);
        }
        else if (detail.operands[1].type == X86_OP_MEM) {//mov reg, [op]
            ctx.was_mutated = _mov_86_reg_op_tmpl(ctx, detail);
        }
    }
    else if (detail.operands[0].type == X86_OP_MEM) {

        if (detail.operands[1].type == X86_OP_REG) { //mov [op], reg
            ctx.was_mutated = _mov_86_op_reg_tmpl(ctx, detail);
        }
        else if (detail.operands[1].type == X86_OP_IMM) {//mov [op], imm
            ctx.was_mutated = _mov_86_op_imm_tmpl(ctx, detail);
        }
    }
}

void fukutate_86_xchg(mutation_context& ctx) {

    
}
void fukutate_86_lea(mutation_context& ctx) {

    
}

void fukutate_86_add(mutation_context& ctx) {

    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_MEM && detail.operands[1].type == X86_OP_IMM) { //add [op],imm

        if (detail.operands[1].size == 4) { //add [op],imm32

        }
        else if (detail.operands[1].size == 2) { //add [op],imm16

        }
        else if (detail.operands[1].size == 1) { //add [op],imm8

        }


    }
    else if ((detail.operands[0].type == X86_OP_MEM && detail.operands[1].type == X86_OP_REG) ||//add [op],reg
        (detail.operands[0].type == X86_OP_REG && detail.operands[1].type == X86_OP_MEM)) {//add reg,[op]

        cs_x86_op * reg_op = 0;

        if (detail.operands[0].type == X86_OP_REG) {
            reg_op = &detail.operands[0];
        }
        else {
            reg_op = &detail.operands[1];
        }


        if (reg_op->size == 4) { //add [op],reg32


        }
        else if (reg_op->size == 2) { //add [op],reg16


        }
        else if (reg_op->size == 1) { //add [op],imm8

        }


    }
    else if (detail.operands[0].type == X86_OP_REG && detail.operands[1].type == X86_OP_REG) {//add reg,reg

        if (detail.operands[0].size == 4) { //add reg32 ,reg32

        }
        else if (detail.operands[0].size == 2) { //add reg16 , reg16

        }
        else if (detail.operands[0].size == 1) { //add reg8 , reg8

        }
    }
    else if (detail.operands[0].type == X86_OP_REG && detail.operands[1].type == X86_OP_IMM) {//add reg,imm

        if (detail.operands[0].size == 4) { //add reg32 ,imm32

        }
        else if (detail.operands[0].size == 2) { //add reg16 , imm16

        }
        else if (detail.operands[0].size == 1) { //add reg8 , imm8

        }
    }

    
}
void fukutate_86_or(mutation_context& ctx) {

    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_MEM && detail.operands[1].type == X86_OP_IMM) { //or [op],imm

        if (detail.operands[1].size == 4) { //or [op],imm32

        }
        else if (detail.operands[1].size == 2) { //or [op],imm16

        }
        else if (detail.operands[1].size == 1) { //or [op],imm8

        }


    }
    else if ((detail.operands[0].type == X86_OP_MEM && detail.operands[1].type == X86_OP_REG) ||//or [op],reg
        (detail.operands[0].type == X86_OP_REG && detail.operands[1].type == X86_OP_MEM)) {//or reg,[op]

        cs_x86_op * reg_op = 0;

        if (detail.operands[0].type == X86_OP_REG) {
            reg_op = &detail.operands[0];
        }
        else {
            reg_op = &detail.operands[1];
        }


        if (reg_op->size == 4) { //or [op],reg32


        }
        else if (reg_op->size == 2) { //or [op],reg16


        }
        else if (reg_op->size == 1) { //or [op],imm8

        }


    }
    else if (detail.operands[0].type == X86_OP_REG && detail.operands[1].type == X86_OP_REG) {//or reg,reg

        if (detail.operands[0].size == 4) { //or reg32 ,reg32

        }
        else if (detail.operands[0].size == 2) { //or reg16 , reg16

        }
        else if (detail.operands[0].size == 1) { //or reg8 , reg8

        }
    }
    else if (detail.operands[0].type == X86_OP_REG && detail.operands[1].type == X86_OP_IMM) {//or reg,imm

        if (detail.operands[0].size == 4) { //or reg32 ,imm32

        }
        else if (detail.operands[0].size == 2) { //or reg16 , imm16

        }
        else if (detail.operands[0].size == 1) { //or reg8 , imm8

        }
    }

    
}
void fukutate_86_adc(mutation_context& ctx) {

    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_MEM && detail.operands[1].type == X86_OP_IMM) { //adc [op],imm

        if (detail.operands[1].size == 4) { //adc [op],imm32

        }
        else if (detail.operands[1].size == 2) { //adc [op],imm16

        }
        else if (detail.operands[1].size == 1) { //adc [op],imm8

        }


    }
    else if ((detail.operands[0].type == X86_OP_MEM && detail.operands[1].type == X86_OP_REG) ||//adc [op],reg
        (detail.operands[0].type == X86_OP_REG && detail.operands[1].type == X86_OP_MEM)) {//adc reg,[op]

        cs_x86_op * reg_op = 0;

        if (detail.operands[0].type == X86_OP_REG) {
            reg_op = &detail.operands[0];
        }
        else {
            reg_op = &detail.operands[1];
        }


        if (reg_op->size == 4) { //adc [op],reg32


        }
        else if (reg_op->size == 2) { //adc [op],reg16


        }
        else if (reg_op->size == 1) { //adc [op],imm8

        }


    }
    else if (detail.operands[0].type == X86_OP_REG && detail.operands[1].type == X86_OP_REG) {//adc reg,reg

        if (detail.operands[0].size == 4) { //adc reg32 ,reg32

        }
        else if (detail.operands[0].size == 2) { //adc reg16 , reg16

        }
        else if (detail.operands[0].size == 1) { //adc reg8 , reg8

        }
    }
    else if (detail.operands[0].type == X86_OP_REG && detail.operands[1].type == X86_OP_IMM) {//adc reg,imm

        if (detail.operands[0].size == 4) { //adc reg32 ,imm32

        }
        else if (detail.operands[0].size == 2) { //adc reg16 , imm16

        }
        else if (detail.operands[0].size == 1) { //adc reg8 , imm8

        }
    }

    
}
void fukutate_86_sbb(mutation_context& ctx) {

    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_MEM && detail.operands[1].type == X86_OP_IMM) { //sbb [op],imm

        if (detail.operands[1].size == 4) { //sbb [op],imm32

        }
        else if (detail.operands[1].size == 2) { //sbb [op],imm16

        }
        else if (detail.operands[1].size == 1) { //sbb [op],imm8

        }


    }
    else if ((detail.operands[0].type == X86_OP_MEM && detail.operands[1].type == X86_OP_REG) ||//sbb [op],reg
        (detail.operands[0].type == X86_OP_REG && detail.operands[1].type == X86_OP_MEM)) {//sbb reg,[op]

        cs_x86_op * reg_op = 0;

        if (detail.operands[0].type == X86_OP_REG) {
            reg_op = &detail.operands[0];
        }
        else {
            reg_op = &detail.operands[1];
        }


        if (reg_op->size == 4) { //sbb [op],reg32


        }
        else if (reg_op->size == 2) { //sbb [op],reg16


        }
        else if (reg_op->size == 1) { //sbb [op],imm8

        }


    }
    else if (detail.operands[0].type == X86_OP_REG && detail.operands[1].type == X86_OP_REG) {//sbb reg,reg

        if (detail.operands[0].size == 4) { //sbb reg32 ,reg32

        }
        else if (detail.operands[0].size == 2) { //sbb reg16 , reg16

        }
        else if (detail.operands[0].size == 1) { //sbb reg8 , reg8

        }
    }
    else if (detail.operands[0].type == X86_OP_REG && detail.operands[1].type == X86_OP_IMM) {//sbb reg,imm

        if (detail.operands[0].size == 4) { //sbb reg32 ,imm32

        }
        else if (detail.operands[0].size == 2) { //sbb reg16 , imm16

        }
        else if (detail.operands[0].size == 1) { //sbb reg8 , imm8

        }
    }

    
}
void fukutate_86_and(mutation_context& ctx) {

    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_MEM && detail.operands[1].type == X86_OP_IMM) { //and [op],imm

        if (detail.operands[1].size == 4) { //and [op],imm32

        }
        else if (detail.operands[1].size == 2) { //and [op],imm16

        }
        else if (detail.operands[1].size == 1) { //and [op],imm8

        }


    }
    else if ((detail.operands[0].type == X86_OP_MEM && detail.operands[1].type == X86_OP_REG) ||//and [op],reg
        (detail.operands[0].type == X86_OP_REG && detail.operands[1].type == X86_OP_MEM)) {//and reg,[op]

        cs_x86_op * reg_op = 0;

        if (detail.operands[0].type == X86_OP_REG) {
            reg_op = &detail.operands[0];
        }
        else {
            reg_op = &detail.operands[1];
        }


        if (reg_op->size == 4) { //and [op],reg32


        }
        else if (reg_op->size == 2) { //and [op],reg16


        }
        else if (reg_op->size == 1) { //and [op],imm8

        }


    }
    else if (detail.operands[0].type == X86_OP_REG && detail.operands[1].type == X86_OP_REG) {//and reg,reg

        if (detail.operands[0].size == 4) { //and reg32 ,reg32

        }
        else if (detail.operands[0].size == 2) { //and reg16 , reg16

        }
        else if (detail.operands[0].size == 1) { //and reg8 , reg8

        }
    }
    else if (detail.operands[0].type == X86_OP_REG && detail.operands[1].type == X86_OP_IMM) {//and reg,imm

        if (detail.operands[0].size == 4) { //and reg32 ,imm32

        }
        else if (detail.operands[0].size == 2) { //and reg16 , imm16

        }
        else if (detail.operands[0].size == 1) { //and reg8 , imm8

        }
    }

    
}

void fukutate_86_sub(mutation_context& ctx) {

    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_MEM && detail.operands[1].type == X86_OP_IMM) { //sub [op],imm

        if (detail.operands[1].size == 4) { //sub [op],imm32

        }
        else if (detail.operands[1].size == 2) { //sub [op],imm16

        }
        else if (detail.operands[1].size == 1) { //sub [op],imm8

        }


    }
    else if ((detail.operands[0].type == X86_OP_MEM && detail.operands[1].type == X86_OP_REG) ||//sub [op],reg
        (detail.operands[0].type == X86_OP_REG && detail.operands[1].type == X86_OP_MEM)) {//sub reg,[op]

        cs_x86_op * reg_op = 0;

        if (detail.operands[0].type == X86_OP_REG) {
            reg_op = &detail.operands[0];
        }
        else {
            reg_op = &detail.operands[1];
        }


        if (reg_op->size == 4) { //sub [op],reg32


        }
        else if (reg_op->size == 2) { //sub [op],reg16


        }
        else if (reg_op->size == 1) { //sub [op],imm8

        }


    }
    else if (detail.operands[0].type == X86_OP_REG && detail.operands[1].type == X86_OP_REG) {//sub reg,reg

        if (detail.operands[0].size == 4) { //sub reg32 ,reg32

        }
        else if (detail.operands[0].size == 2) { //sub reg16 , reg16

        }
        else if (detail.operands[0].size == 1) { //sub reg8 , reg8

        }
    }
    else if (detail.operands[0].type == X86_OP_REG && detail.operands[1].type == X86_OP_IMM) {//sub reg,imm

        if (detail.operands[0].size == 4) { //sub reg32 ,imm32

        }
        else if (detail.operands[0].size == 2) { //sub reg16 , imm16

        }
        else if (detail.operands[0].size == 1) { //sub reg8 , imm8

        }
    }

    
}
void fukutate_86_xor(mutation_context& ctx) {

    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_MEM && detail.operands[1].type == X86_OP_IMM) { //xor [op],imm

        if (detail.operands[1].size == 4) { //xor [op],imm32

        }
        else if (detail.operands[1].size == 2) { //xor [op],imm16

        }
        else if (detail.operands[1].size == 1) { //xor [op],imm8

        }


    }
    else if ((detail.operands[0].type == X86_OP_MEM && detail.operands[1].type == X86_OP_REG) ||//xor [op],reg
        (detail.operands[0].type == X86_OP_REG && detail.operands[1].type == X86_OP_MEM)) {//xor reg,[op]

        cs_x86_op * reg_op = 0;

        if (detail.operands[0].type == X86_OP_REG) {
            reg_op = &detail.operands[0];
        }
        else {
            reg_op = &detail.operands[1];
        }


        if (reg_op->size == 4) { //xor [op],reg32


        }
        else if (reg_op->size == 2) { //xor [op],reg16


        }
        else if (reg_op->size == 1) { //xor [op],imm8

        }


    }
    else if (detail.operands[0].type == X86_OP_REG && detail.operands[1].type == X86_OP_REG) {//xor reg,reg

        if (detail.operands[0].size == 4) { //xor reg32 ,reg32

        }
        else if (detail.operands[0].size == 2) { //xor reg16 , reg16

        }
        else if (detail.operands[0].size == 1) { //xor reg8 , reg8

        }
    }
    else if (detail.operands[0].type == X86_OP_REG && detail.operands[1].type == X86_OP_IMM) {//xor reg,imm

        if (detail.operands[0].size == 4) { //xor reg32 ,imm32

        }
        else if (detail.operands[0].size == 2) { //xor reg16 , imm16

        }
        else if (detail.operands[0].size == 1) { //xor reg8 , imm8

        }
    }

    
}
void fukutate_86_cmp(mutation_context& ctx) {

    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_MEM && detail.operands[1].type == X86_OP_IMM) { //cmp [op],imm

        if (detail.operands[1].size == 4) { //cmp [op],imm32

        }
        else if (detail.operands[1].size == 2) { //cmp [op],imm16

        }
        else if (detail.operands[1].size == 1) { //cmp [op],imm8

        }


    }
    else if ((detail.operands[0].type == X86_OP_MEM && detail.operands[1].type == X86_OP_REG) ||//cmp [op],reg
        (detail.operands[0].type == X86_OP_REG && detail.operands[1].type == X86_OP_MEM)) {//cmp reg,[op]

        cs_x86_op * reg_op = 0;

        if (detail.operands[0].type == X86_OP_REG) {
            reg_op = &detail.operands[0];
        }
        else {
            reg_op = &detail.operands[1];
        }


        if (reg_op->size == 4) { //cmp [op],reg32


        }
        else if (reg_op->size == 2) { //cmp [op],reg16


        }
        else if (reg_op->size == 1) { //cmp [op],imm8

        }


    }
    else if (detail.operands[0].type == X86_OP_REG && detail.operands[1].type == X86_OP_REG) {//cmp reg,reg

        if (detail.operands[0].size == 4) { //cmp reg32 ,reg32

        }
        else if (detail.operands[0].size == 2) { //cmp reg16 , reg16

        }
        else if (detail.operands[0].size == 1) { //cmp reg8 , reg8

        }
    }
    else if (detail.operands[0].type == X86_OP_REG && detail.operands[1].type == X86_OP_IMM) {//cmp reg,imm

        if (detail.operands[0].size == 4) { //cmp reg32 ,imm32

        }
        else if (detail.operands[0].size == 2) { //cmp reg16 , imm16

        }
        else if (detail.operands[0].size == 1) { //cmp reg8 , imm8

        }
    }

    
}

void fukutate_86_test(mutation_context& ctx) {

    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_MEM && detail.operands[1].type == X86_OP_IMM) { //test [op],imm

        if (detail.operands[1].size == 4) { //test [op],imm32

        }
        else if (detail.operands[1].size == 2) { //test [op],imm16

        }
        else if (detail.operands[1].size == 1) { //test [op],imm8

        }


    }
    else if ((detail.operands[0].type == X86_OP_MEM && detail.operands[1].type == X86_OP_REG) ||//test [op],reg
        (detail.operands[0].type == X86_OP_REG && detail.operands[1].type == X86_OP_MEM)) {//test reg,[op]

        cs_x86_op * reg_op = 0;

        if (detail.operands[0].type == X86_OP_REG) {
            reg_op = &detail.operands[0];
        }
        else {
            reg_op = &detail.operands[1];
        }


        if (reg_op->size == 4) { //test [op],reg32


        }
        else if (reg_op->size == 2) { //test [op],reg16


        }
        else if (reg_op->size == 1) { //test [op],imm8

        }


    }
    else if (detail.operands[0].type == X86_OP_REG && detail.operands[1].type == X86_OP_REG) {//test reg,reg

        if (detail.operands[0].size == 4) { //test reg32 ,reg32

        }
        else if (detail.operands[0].size == 2) { //test reg16 , reg16

        }
        else if (detail.operands[0].size == 1) { //test reg8 , reg8

        }
    }
    else if (detail.operands[0].type == X86_OP_REG && detail.operands[1].type == X86_OP_IMM) {//test reg,imm

        if (detail.operands[0].size == 4) { //test reg32 ,imm32

        }
        else if (detail.operands[0].size == 2) { //test reg16 , imm16

        }
        else if (detail.operands[0].size == 1) { //test reg8 , imm8

        }
    }

    
}


void fukutate_86_inc(mutation_context& ctx) {

    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_MEM) { //inc [op]

        if (detail.operands[0].size == 4) { //inc [op]

        }
        else if (detail.operands[0].size == 2) { //inc [op]

        }
        else if (detail.operands[0].size == 1) { //inc [op]

        }


    }
    else if (detail.operands[0].type == X86_OP_REG) {//inc reg

        cs_x86_op * reg_op = &detail.operands[0];


        if (reg_op->size == 4) { //inc [op]


        }
        else if (reg_op->size == 2) { //inc [op]


        }
        else if (reg_op->size == 1) { //inc [op]

        }


    }

    
}

void fukutate_86_dec(mutation_context& ctx) {

    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_MEM) { //dec [op]

        if (detail.operands[0].size == 4) { //dec [op]

        }
        else if (detail.operands[0].size == 2) { //dec [op]

        }
        else if (detail.operands[0].size == 1) { //dec [op]

        }


    }
    else if (detail.operands[0].type == X86_OP_REG) {//dec reg

        cs_x86_op * reg_op = &detail.operands[0];


        if (reg_op->size == 4) { //dec reg


        }
        else if (reg_op->size == 2) { //dec reg


        }
        else if (reg_op->size == 1) { //dec reg

        }


    }

    
}

void fukutate_86_not(mutation_context& ctx) {

    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_MEM) { //not [op]

        if (detail.operands[0].size == 4) { //not [op]

        }
        else if (detail.operands[0].size == 2) { //not [op]

        }
        else if (detail.operands[0].size == 1) { //not [op]

        }


    }
    else if (detail.operands[0].type == X86_OP_REG) {//not reg

        cs_x86_op * reg_op = &detail.operands[0];


        if (reg_op->size == 4) { //not reg


        }
        else if (reg_op->size == 2) { //not reg


        }
        else if (reg_op->size == 1) { //not reg

        }


    }

    
}
void fukutate_86_neg(mutation_context& ctx) {

    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_MEM) { //neg [op]

        if (detail.operands[0].size == 4) { //neg [op]

        }
        else if (detail.operands[0].size == 2) { //neg [op]

        }
        else if (detail.operands[0].size == 1) { //neg [op]

        }


    }
    else if (detail.operands[0].type == X86_OP_REG) {//neg reg

        cs_x86_op * reg_op = &detail.operands[0];


        if (reg_op->size == 4) { //neg reg


        }
        else if (reg_op->size == 2) { //neg reg


        }
        else if (reg_op->size == 1) { //neg reg

        }


    }

    
}
void fukutate_86_mul(mutation_context& ctx) {

    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_MEM) { //mul [op]

        if (detail.operands[0].size == 4) { //mul [op]

        }
        else if (detail.operands[0].size == 2) { //mul [op]

        }
        else if (detail.operands[0].size == 1) { //mul [op]

        }


    }
    else if (detail.operands[0].type == X86_OP_REG) {//mul reg

        cs_x86_op * reg_op = &detail.operands[0];


        if (reg_op->size == 4) { //mul reg


        }
        else if (reg_op->size == 2) { //mul reg


        }
        else if (reg_op->size == 1) { //mul reg

        }


    }

    
}
void fukutate_86_imul(mutation_context& ctx) {

    
}

void fukutate_86_div(mutation_context& ctx) {

    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_MEM) { //div [op]

        if (detail.operands[0].size == 4) { //div [op]

        }
        else if (detail.operands[0].size == 2) { //div [op]

        }
        else if (detail.operands[0].size == 1) { //div [op]

        }


    }
    else if (detail.operands[0].type == X86_OP_REG) {//div reg

        cs_x86_op * reg_op = &detail.operands[0];


        if (reg_op->size == 4) { //div reg


        }
        else if (reg_op->size == 2) { //div reg


        }
        else if (reg_op->size == 1) { //div reg

        }


    }

    
}
void fukutate_86_idiv(mutation_context& ctx) {

    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_MEM) { //idiv [op]

        if (detail.operands[0].size == 4) { //idiv [op]

        }
        else if (detail.operands[0].size == 2) { //idiv [op]

        }
        else if (detail.operands[0].size == 1) { //idiv [op]

        }


    }
    else if (detail.operands[0].type == X86_OP_REG) {//idiv reg

        cs_x86_op * reg_op = &detail.operands[0];


        if (reg_op->size == 4) { //idiv reg


        }
        else if (reg_op->size == 2) { //idiv reg


        }
        else if (reg_op->size == 1) { //idiv reg

        }


    }

    
}


void fukutate_86_rol(mutation_context& ctx) {

    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_REG) {
        cs_x86_op * reg_op = &detail.operands[0];

        if (detail.operands[1].type == X86_OP_REG) {//rol reg, cl

            if (reg_op->size == 4) {

            }
            else if (reg_op->size == 2) {

            }
            else if (reg_op->size == 1) {

            }

        }
        else if (detail.operands[1].type == X86_OP_IMM) {//rol reg, imm

            if (reg_op->size == 4) {

            }
            else if (reg_op->size == 2) {

            }
            else if (reg_op->size == 1) {

            }

        }
    }
    else if (detail.operands[0].type == X86_OP_MEM) {
        cs_x86_op * reg_op = &detail.operands[0];

        if (detail.operands[1].type == X86_OP_REG) {//rol [op], cl

            if (reg_op->size == 4) {

            }
            else if (reg_op->size == 2) {

            }
            else if (reg_op->size == 1) {

            }

        }
        else if (detail.operands[1].type == X86_OP_IMM) {//rol [op], imm

            if (reg_op->size == 4) {

            }
            else if (reg_op->size == 2) {

            }
            else if (reg_op->size == 1) {

            }
        }
    }

    
}

void fukutate_86_ror(mutation_context& ctx) {

    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_REG) {
        cs_x86_op * reg_op = &detail.operands[0];

        if (detail.operands[1].type == X86_OP_REG) {//ror reg, cl

            if (reg_op->size == 4) {

            }
            else if (reg_op->size == 2) {

            }
            else if (reg_op->size == 1) {

            }

        }
        else if (detail.operands[1].type == X86_OP_IMM) {//ror reg, imm

            if (reg_op->size == 4) {

            }
            else if (reg_op->size == 2) {

            }
            else if (reg_op->size == 1) {

            }

        }
    }
    else if (detail.operands[0].type == X86_OP_MEM) {
        cs_x86_op * reg_op = &detail.operands[0];

        if (detail.operands[1].type == X86_OP_REG) {//ror [op], cl

            if (reg_op->size == 4) {

            }
            else if (reg_op->size == 2) {

            }
            else if (reg_op->size == 1) {

            }

        }
        else if (detail.operands[1].type == X86_OP_IMM) {//ror [op], imm

            if (reg_op->size == 4) {

            }
            else if (reg_op->size == 2) {

            }
            else if (reg_op->size == 1) {

            }
        }
    }

    
}


void fukutate_86_rcl(mutation_context& ctx) {

    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_REG) {
        cs_x86_op * reg_op = &detail.operands[0];

        if (detail.operands[1].type == X86_OP_REG) {//rcl reg, cl

            if (reg_op->size == 4) {

            }
            else if (reg_op->size == 2) {

            }
            else if (reg_op->size == 1) {

            }

        }
        else if (detail.operands[1].type == X86_OP_IMM) {//rcl reg, imm

            if (reg_op->size == 4) {

            }
            else if (reg_op->size == 2) {

            }
            else if (reg_op->size == 1) {

            }

        }
    }
    else if (detail.operands[0].type == X86_OP_MEM) {
        cs_x86_op * reg_op = &detail.operands[0];

        if (detail.operands[1].type == X86_OP_REG) {//rcl [op], cl

            if (reg_op->size == 4) {

            }
            else if (reg_op->size == 2) {

            }
            else if (reg_op->size == 1) {

            }

        }
        else if (detail.operands[1].type == X86_OP_IMM) {//rcl [op], imm

            if (reg_op->size == 4) {

            }
            else if (reg_op->size == 2) {

            }
            else if (reg_op->size == 1) {

            }
        }
    }

    
}


void fukutate_86_rcr(mutation_context& ctx) {

    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_REG) {
        cs_x86_op * reg_op = &detail.operands[0];

        if (detail.operands[1].type == X86_OP_REG) {//rcr reg, cl

            if (reg_op->size == 4) {

            }
            else if (reg_op->size == 2) {

            }
            else if (reg_op->size == 1) {

            }

        }
        else if (detail.operands[1].type == X86_OP_IMM) {//rcr reg, imm

            if (reg_op->size == 4) {

            }
            else if (reg_op->size == 2) {

            }
            else if (reg_op->size == 1) {

            }

        }
    }
    else if (detail.operands[0].type == X86_OP_MEM) {
        cs_x86_op * reg_op = &detail.operands[0];

        if (detail.operands[1].type == X86_OP_REG) {//rcr [op], cl

            if (reg_op->size == 4) {

            }
            else if (reg_op->size == 2) {

            }
            else if (reg_op->size == 1) {

            }

        }
        else if (detail.operands[1].type == X86_OP_IMM) {//rcr [op], imm

            if (reg_op->size == 4) {

            }
            else if (reg_op->size == 2) {

            }
            else if (reg_op->size == 1) {

            }
        }
    }

    
}


void fukutate_86_shl(mutation_context& ctx) {

    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_REG) {
        cs_x86_op * reg_op = &detail.operands[0];

        if (detail.operands[1].type == X86_OP_REG) {//shl reg, cl

            if (reg_op->size == 4) {

            }
            else if (reg_op->size == 2) {

            }
            else if (reg_op->size == 1) {

            }

        }
        else if (detail.operands[1].type == X86_OP_IMM) {//shl reg, imm

            if (reg_op->size == 4) {

            }
            else if (reg_op->size == 2) {

            }
            else if (reg_op->size == 1) {

            }

        }
    }
    else if (detail.operands[0].type == X86_OP_MEM) {
        cs_x86_op * reg_op = &detail.operands[0];

        if (detail.operands[1].type == X86_OP_REG) {//shl [op], cl

            if (reg_op->size == 4) {

            }
            else if (reg_op->size == 2) {

            }
            else if (reg_op->size == 1) {

            }

        }
        else if (detail.operands[1].type == X86_OP_IMM) {//shl [op], imm

            if (reg_op->size == 4) {

            }
            else if (reg_op->size == 2) {

            }
            else if (reg_op->size == 1) {

            }
        }
    }

    
}


void fukutate_86_shr(mutation_context& ctx) {

    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_REG) {
        cs_x86_op * reg_op = &detail.operands[0];

        if (detail.operands[1].type == X86_OP_REG) {//shr reg, cl

            if (reg_op->size == 4) {

            }
            else if (reg_op->size == 2) {

            }
            else if (reg_op->size == 1) {

            }

        }
        else if (detail.operands[1].type == X86_OP_IMM) {//shr reg, imm

            if (reg_op->size == 4) {

            }
            else if (reg_op->size == 2) {

            }
            else if (reg_op->size == 1) {

            }

        }
    }
    else if (detail.operands[0].type == X86_OP_MEM) {
        cs_x86_op * reg_op = &detail.operands[0];

        if (detail.operands[1].type == X86_OP_REG) {//shr [op], cl

            if (reg_op->size == 4) {

            }
            else if (reg_op->size == 2) {

            }
            else if (reg_op->size == 1) {

            }

        }
        else if (detail.operands[1].type == X86_OP_IMM) {//shr [op], imm

            if (reg_op->size == 4) {

            }
            else if (reg_op->size == 2) {

            }
            else if (reg_op->size == 1) {

            }
        }
    }

    
}


void fukutate_86_sar(mutation_context& ctx) {

    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_REG) {
        cs_x86_op * reg_op = &detail.operands[0];

        if (detail.operands[1].type == X86_OP_REG) {//sar reg, cl

            if (reg_op->size == 4) {

            }
            else if (reg_op->size == 2) {

            }
            else if (reg_op->size == 1) {

            }

        }
        else if (detail.operands[1].type == X86_OP_IMM) {//sar reg, imm

            if (reg_op->size == 4) {

            }
            else if (reg_op->size == 2) {

            }
            else if (reg_op->size == 1) {

            }

        }
    }
    else if (detail.operands[0].type == X86_OP_MEM) {
        cs_x86_op * reg_op = &detail.operands[0];

        if (detail.operands[1].type == X86_OP_REG) {//sar [op], cl

            if (reg_op->size == 4) {

            }
            else if (reg_op->size == 2) {

            }
            else if (reg_op->size == 1) {

            }

        }
        else if (detail.operands[1].type == X86_OP_IMM) {//sar [op], imm

            if (reg_op->size == 4) {

            }
            else if (reg_op->size == 2) {

            }
            else if (reg_op->size == 1) {

            }
        }
    }

    
}


void fukutate_86_bt(mutation_context& ctx) {


    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[1].type == X86_OP_REG) { 
        cs_x86_op * reg_op = &detail.operands[0];

        if (detail.operands[0].type == X86_OP_REG) {//bt reg, reg

            if (reg_op->size == 4) { 

            }
            else if (reg_op->size == 2) {

            }

        }
        else if (detail.operands[0].type == X86_OP_MEM) {//bt [op], reg
            cs_x86_op * reg_op = &detail.operands[0];

            if (reg_op->size == 4) {

            }
            else if (reg_op->size == 2) {

            }

        }

    }
    else if (detail.operands[1].type == X86_OP_IMM) { 

        if (detail.operands[0].type == X86_OP_REG) {//bt reg, imm

            cs_x86_op * reg_op = &detail.operands[0];

            if (reg_op->size == 4) {


            }
            else if (reg_op->size == 2) {


            }
        }
        else if (detail.operands[0].type == X86_OP_MEM) {//bt [op], imm

            cs_x86_op * reg_op = &detail.operands[0];

            if (reg_op->size == 4) {


            }
            else if (reg_op->size == 2) {


            }

        }

    }

    
}

void fukutate_86_bts(mutation_context& ctx) {


    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[1].type == X86_OP_REG) {
        cs_x86_op * reg_op = &detail.operands[0];

        if (detail.operands[0].type == X86_OP_REG) {//bts reg, reg

            if (reg_op->size == 4) {


            }
            else if (reg_op->size == 2) {

            }

        }
        else if (detail.operands[0].type == X86_OP_MEM) {//bts [op], reg
            cs_x86_op * reg_op = &detail.operands[0];

            if (reg_op->size == 4) {


            }
            else if (reg_op->size == 2) {


            }

        }

    }
    else if (detail.operands[1].type == X86_OP_IMM) {

        if (detail.operands[0].type == X86_OP_REG) {//bts reg, imm

            cs_x86_op * reg_op = &detail.operands[0];

            if (reg_op->size == 4) {


            }
            else if (reg_op->size == 2) {


            }
        }
        else if (detail.operands[0].type == X86_OP_MEM) {//bts [op], imm

            cs_x86_op * reg_op = &detail.operands[0];

            if (reg_op->size == 4) {


            }
            else if (reg_op->size == 2) {


            }

        }

    }

    
}

void fukutate_86_btr(mutation_context& ctx) {


    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[1].type == X86_OP_REG) {
        cs_x86_op * reg_op = &detail.operands[0];

        if (detail.operands[0].type == X86_OP_REG) {//btr reg, reg

            if (reg_op->size == 4) {


            }
            else if (reg_op->size == 2) {

            }

        }
        else if (detail.operands[0].type == X86_OP_MEM) {//btr [op], reg
            cs_x86_op * reg_op = &detail.operands[0];

            if (reg_op->size == 4) {


            }
            else if (reg_op->size == 2) {


            }

        }

    }
    else if (detail.operands[1].type == X86_OP_IMM) {

        if (detail.operands[0].type == X86_OP_REG) {//btr reg, imm

            cs_x86_op * reg_op = &detail.operands[0];

            if (reg_op->size == 4) {


            }
            else if (reg_op->size == 2) {


            }
        }
        else if (detail.operands[0].type == X86_OP_MEM) {//btr [op], imm

            cs_x86_op * reg_op = &detail.operands[0];

            if (reg_op->size == 4) {


            }
            else if (reg_op->size == 2) {


            }

        }

    }

    
}

void fukutate_86_btc(mutation_context& ctx) {


    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[1].type == X86_OP_REG) {
        cs_x86_op * reg_op = &detail.operands[0];

        if (detail.operands[0].type == X86_OP_REG) {//btc reg, reg

            if (reg_op->size == 4) {


            }
            else if (reg_op->size == 2) {

            }

        }
        else if (detail.operands[0].type == X86_OP_MEM) {//btc [op], reg
            cs_x86_op * reg_op = &detail.operands[0];

            if (reg_op->size == 4) {


            }
            else if (reg_op->size == 2) {


            }

        }

    }
    else if (detail.operands[1].type == X86_OP_IMM) {

        if (detail.operands[0].type == X86_OP_REG) {//btc reg, imm

            cs_x86_op * reg_op = &detail.operands[0];

            if (reg_op->size == 4) {


            }
            else if (reg_op->size == 2) {


            }
        }
        else if (detail.operands[0].type == X86_OP_MEM) {//btc [op], imm

            cs_x86_op * reg_op = &detail.operands[0];

            if (reg_op->size == 4) {


            }
            else if (reg_op->size == 2) {


            }

        }

    }

    
}

void fukutate_86_bsf(mutation_context& ctx) {


    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_REG) {
        cs_x86_op * reg_op = &detail.operands[0];

        if (detail.operands[1].type == X86_OP_REG) {//bsf reg, reg

            if (reg_op->size == 4) {


            }
            else if (reg_op->size == 2) {

            }

        }
        else if (detail.operands[1].type == X86_OP_MEM) {//bsf reg, [op]
            cs_x86_op * reg_op = &detail.operands[0];

            if (reg_op->size == 4) {


            }
            else if (reg_op->size == 2) {


            }

        }

    }

    
}

void fukutate_86_bsr(mutation_context& ctx) {

    auto detail = ctx.instruction->detail->x86;

    if (detail.operands[0].type == X86_OP_REG) {
        cs_x86_op * reg_op = &detail.operands[0];

        if (detail.operands[1].type == X86_OP_REG) {//bsr reg, reg

            if (reg_op->size == 4) {


            }
            else if (reg_op->size == 2) {

            }

        }
        else if (detail.operands[1].type == X86_OP_MEM) {//bsr reg, [op]
            cs_x86_op * reg_op = &detail.operands[0];

            if (reg_op->size == 4) {


            }
            else if (reg_op->size == 2) {


            }

        }

    }

    
}

