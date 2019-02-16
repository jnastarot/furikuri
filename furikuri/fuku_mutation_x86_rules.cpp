#include "stdafx.h"
#include "fuku_mutation_x86_rules.h"

#define IsAllowedStackOperations (!HAS_FULL_MASK(instruction_flags, FUKU_INST_BAD_STACK))

static uint64_t di_fl_jcc[] = {
    X86_EFLAGS_MOD_OF , X86_EFLAGS_MOD_OF, //jo   / jno
    X86_EFLAGS_MOD_CF , X86_EFLAGS_MOD_CF, //jb   / jae
    X86_EFLAGS_MOD_ZF , X86_EFLAGS_MOD_ZF, //je   / jne
    X86_EFLAGS_MOD_ZF | X86_EFLAGS_MOD_CF, X86_EFLAGS_MOD_ZF | X86_EFLAGS_MOD_CF, //jbe / jnbe
    X86_EFLAGS_MOD_SF , X86_EFLAGS_MOD_SF, //js   / jns
    X86_EFLAGS_MOD_PF , X86_EFLAGS_MOD_PF, //jp   / jnp
    X86_EFLAGS_MOD_OF | X86_EFLAGS_MOD_SF, X86_EFLAGS_MOD_OF | X86_EFLAGS_MOD_SF, //jnge / jge
    X86_EFLAGS_MOD_OF | X86_EFLAGS_MOD_SF | X86_EFLAGS_MOD_ZF, X86_EFLAGS_MOD_OF | X86_EFLAGS_MOD_SF | X86_EFLAGS_MOD_ZF //jng / jnle
};


/*
JCC MUTATE RULES

1: exmpl for je
    jne inst_after_je
    jmp jccdst

*/
bool fukutate_jcc(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator lines_iter) {

    uint32_t instruction_flags = lines_iter->get_instruction_flags();

    auto next_line = lines_iter; next_line++;
    if (next_line != code_holder.get_lines().end()) { //if not last instruction
        //inverted jcc to next_inst_after real jcc
        //jmp jcc_dst

        fuku_condition cond = capstone_to_fuku_cond((x86_insn)instruction->id);
        uint64_t custom_eflags = lines_iter->get_eflags();
        size_t rel_idx = lines_iter->get_rip_relocation_idx();

        f_asm.jcc(fuku_condition(cond ^ 1), imm(-1));
        f_asm.get_context().inst->
            set_eflags(custom_eflags)
            .set_rip_relocation_idx(code_holder.create_rip_relocation(f_asm.get_context().immediate_offset, &(*next_line)))
            .set_instruction_flags(FUKU_INST_NO_MUTATE | instruction_flags);

        f_asm.jmp(imm(-1));
        f_asm.get_context().inst->
            set_eflags(custom_eflags)
            .set_rip_relocation_idx(rel_idx)
            .set_instruction_flags(FUKU_INST_NO_MUTATE | instruction_flags);

        code_holder.get_rip_relocations()[rel_idx].offset = f_asm.get_context().immediate_offset;

        return true;
    }

    return false;
}

/*
JMP MUTATE RULES

1:
    push jmpdst
    ret

2:
    je  jmpdst
    jne jmpdst

3:
    mov randreg, dst
    jmp randreg

*/
bool fukutate_jmp(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {

    auto detail = instruction->detail->x86;
    uint32_t instruction_flags = lines_iter->get_instruction_flags();

    if (detail.operands[0].type == X86_OP_REG) { //jmp reg32


    }
    else if (detail.operands[0].type == X86_OP_MEM) { //jmp [op]


    }
    else if (detail.operands[0].type == X86_OP_IMM) { //jmp imm

        uint64_t custom_regs = lines_iter->get_custom_flags();
        uint64_t custom_eflags = lines_iter->get_eflags();
        size_t rip_label_orig = lines_iter->get_rip_relocation_idx();
        size_t rip_label_idx = code_holder.get_rip_relocations()[rip_label_orig].label_idx;

        switch (FUKU_GET_RAND(0, 2)) {
            //push jmpdst
            //ret   
        case 0: {

            if (IsAllowedStackOperations) {
                

                f_asm.push(imm(0xFFFFFFFF));
                f_asm.get_context().inst->
                    set_eflags(custom_eflags)
                    .set_custom_flags(custom_regs)
                    .set_relocation_first_idx(
                        code_holder.create_relocation_lb(
                            f_asm.get_context().immediate_offset, rip_label_idx, 0
                        )
                    );

                f_asm.ret(imm(0));
                f_asm.get_context().inst->
                    set_eflags(custom_eflags)
                    .set_custom_flags(custom_regs);

                code_holder.delete_rip_relocation(rip_label_orig);
            }
            else {
                return false;
            }
            break;
        }

        case 1: {
            //je  dst
            //jne dst

            uint8_t cond = FUKU_GET_RAND(0, 15);

            f_asm.jcc(fuku_condition(cond), imm(-1));
            f_asm.get_context().inst->
                set_eflags(custom_eflags)
                .set_custom_flags(custom_regs)
                .set_rip_relocation_idx(code_holder.create_rip_relocation_lb(f_asm.get_context().immediate_offset, rip_label_idx))
                .set_instruction_flags(instruction_flags | FUKU_INST_NO_MUTATE);

            f_asm.jcc(fuku_condition(cond ^ 1), imm(-1));
            f_asm.get_context().inst->
                set_eflags(custom_eflags & (~di_fl_jcc[fuku_condition(cond ^ 1)]))
                .set_custom_flags(custom_regs)
                .set_rip_relocation_idx(code_holder.create_rip_relocation_lb(f_asm.get_context().immediate_offset, rip_label_idx))
                .set_instruction_flags(instruction_flags | FUKU_INST_NO_MUTATE);

            code_holder.delete_rip_relocation(rip_label_orig);

            break;
        }
        case 2: {
            //mov randreg, dst
            //jmp randreg

            fuku_register rand_reg = get_random_free_flag_reg(*lines_iter, 4, true);

            if (rand_reg.get_reg() != FUKU_REG_NONE) {

                uint64_t flag_reg = convert_fuku_reg_to_complex_flag_reg(rand_reg);

                f_asm.mov(rand_reg, imm(0xFFFFFFFF));
                f_asm.get_context().inst->
                    set_eflags(custom_eflags)
                    .set_custom_flags(custom_regs)
                    .set_relocation_first_idx(
                        code_holder.create_relocation_lb(
                            f_asm.get_context().immediate_offset, rip_label_idx, 0
                        )
                    );

                f_asm.jmp(rand_reg);
                f_asm.get_context().inst->
                    set_eflags(custom_eflags )
                    .set_custom_flags(custom_regs & (~flag_reg));

                code_holder.delete_rip_relocation(rip_label_orig);
            }
            else {
                return false;
            }

            break;
        }

        }

        return true;
    }

    return false;
}


/*
CALL MUTATE RULES

*/
bool fukutate_call(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {

    auto detail = instruction->detail->x86;
    uint32_t instruction_flags = lines_iter->get_instruction_flags();

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


        if (reg_op->size == 4) { //call reg32


        }
        else if (reg_op->size == 2) { //call reg16


        }
        else if (reg_op->size == 1) { //call reg8

        }


    }
    else if (detail.operands[0].type == X86_OP_IMM) {

        auto next_line = lines_iter; next_line++;
        if (next_line != code_holder.get_lines().end()) { //if not last instruction

            uint64_t custom_eflags = lines_iter->get_eflags();
            size_t rip_label_orig = lines_iter->get_rip_relocation_idx();

            f_asm.push(imm(0xFFFFFFFF));
            f_asm.get_context().inst->
                set_eflags(custom_eflags)
                .set_relocation_first_idx(
                    code_holder.create_relocation(
                        f_asm.get_context().immediate_offset, &(*next_line), 0
                    )
                );

            f_asm.jmp(imm(0xFFFFFFFF));
            f_asm.get_context().inst->
                set_eflags(custom_eflags)
                .set_rip_relocation_idx(rip_label_orig);

            code_holder.get_rip_relocations()[rip_label_orig].offset = f_asm.get_context().immediate_offset;

            return true;
        }
    }

    return false;
}


/*
RET MUTATE RULES

1:
    lea esp,[esp + (4 + stack_offset)]
    jmp [esp - 4 - stack_offset] <- bad esp here

*/
bool fukutate_ret(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {

    auto detail = instruction->detail->x86;
    uint32_t instruction_flags = lines_iter->get_instruction_flags();
    if (IsAllowedStackOperations) {

        //lea esp,[esp + (4 + stack_offset)]
        //jmp [esp - 4 - stack_offset] <- bad esp here
        uint16_t ret_stack = 0;

        if (detail.op_count) { //ret 0x0000
            ret_stack = (uint16_t)detail.operands[0].imm;
        }

        uint64_t custom_eflags = lines_iter->get_eflags();

        f_asm.lea(reg_(FUKU_REG_ESP), dword_ptr(FUKU_REG_ESP, imm(4 + ret_stack)));
        f_asm.get_context().inst->
            set_eflags(custom_eflags);

        f_asm.jmp(dword_ptr(FUKU_REG_ESP, imm(-4 - ret_stack)));
        f_asm.get_context().inst->
            set_eflags(custom_eflags)
            .set_instruction_flags(FUKU_INST_BAD_STACK);

        return true;
    }

    return false;
}

/*
PUSH MUTATE RULES
    
reg
1:
    (sub esp,4) or (lea esp,[esp - 4])
    mov [esp],reg <- bad esp here

imm
1:  (sub esp,4) or (lea esp,[esp - 4]) 
    mov [esp], value <- bad esp here
    
*/
bool fukutate_push(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {

    auto detail = instruction->detail->x86;
    uint32_t instruction_flags = lines_iter->get_instruction_flags();

    if (detail.operands[0].type == X86_OP_REG) {

        if (detail.operands[0].size == 4) { //push reg32
            //(sub esp,4) or (lea esp,[esp - 4]) 
            //mov [esp],reg

            if (IsAllowedStackOperations) {
                fuku_register_enum reg = capstone_to_fuku_reg(detail.operands[0].reg);
                uint64_t custom_eflags = lines_iter->get_eflags();

                if (has_inst_free_eflags(custom_eflags,
                    X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_CF | X86_EFLAGS_MODIFY_PF)) {

                    f_asm.sub(reg_(FUKU_REG_ESP), imm(4));
                    f_asm.get_context().inst->
                        set_eflags(lines_iter->get_eflags());
                }
                else {
                    f_asm.lea(reg_(FUKU_REG_ESP), dword_ptr(FUKU_REG_ESP, imm(-4)));
                    f_asm.get_context().inst->
                        set_eflags(lines_iter->get_eflags());
                }

                f_asm.mov(dword_ptr(FUKU_REG_ESP), reg_(reg));
                f_asm.get_context().inst->
                    set_eflags(lines_iter->get_eflags())
                    .set_instruction_flags(FUKU_INST_BAD_STACK);
            }
            else {
                return false;
            }

            return true;
        }
        else if (detail.operands[0].size == 2) { //push reg16


        }
        else if (detail.operands[0].size == 1) { //push reg8

        }
    }
    else if (detail.operands[0].type == X86_OP_MEM) { //push [op]


    }
    else if (detail.operands[0].type == X86_OP_IMM) { //push imm8/imm32
        //(sub esp,4) or (lea esp,[esp - 4]) 
        //mov [esp],value

        if (IsAllowedStackOperations) {
            uint64_t custom_eflags = lines_iter->get_eflags();
            size_t reloc_idx = lines_iter->get_relocation_first_idx();
            uint32_t val = reloc_idx != -1 ? -1 : (uint32_t)detail.operands[0].imm;


            if (has_inst_free_eflags(custom_eflags, 
                X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_CF | X86_EFLAGS_MODIFY_PF)) {

                f_asm.sub(reg_(FUKU_REG_ESP), imm(4));
                f_asm.get_context().inst->
                    set_eflags(custom_eflags);
            }
            else {
                f_asm.lea(reg_(FUKU_REG_ESP), dword_ptr(FUKU_REG_ESP, imm(-4)));
                f_asm.get_context().inst->
                    set_eflags(custom_eflags);
            }

            f_asm.mov(dword_ptr(FUKU_REG_ESP), imm(val));
            f_asm.get_context().inst->
                set_eflags(custom_eflags)
                .set_instruction_flags(FUKU_INST_BAD_STACK);


            if (reloc_idx != -1) {
                f_asm.get_context().inst->
                    set_relocation_first_idx(reloc_idx);

                code_holder.get_relocations()[reloc_idx].offset = f_asm.get_context().immediate_offset;
            }
        }
        else {
            return false;
        }

        return true;
    }

    return false;
}


/*
POP MUTATE RULES

reg
1:
    mov reg,[esp] 
    (add esp,4) or (lea esp,[esp - 4])   <- bad esp here

2: 
    add esp,4
    (add esp,4) or (lea esp,[esp - 4])   <- bad esp here

*/
bool fukutate_pop(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {

    auto detail = instruction->detail->x86;
    uint32_t instruction_flags = lines_iter->get_instruction_flags();

    if (detail.operands[0].type == X86_OP_REG) { //pop reg


        if (detail.operands[0].size == 4) {      //pop reg32

            if (IsAllowedStackOperations) {
                fuku_register_enum reg = capstone_to_fuku_reg(detail.operands[0].reg);
                uint64_t custom_eflags = lines_iter->get_eflags();

                if (FUKU_GET_RAND(0, 10) < 5) {
                    //mov reg,[esp]
                    //add esp,4
            
                    f_asm.mov(reg_(reg), dword_ptr(FUKU_REG_ESP));
                    f_asm.get_context().inst->
                        set_eflags(custom_eflags);

                    if (has_inst_free_eflags(custom_eflags, 
                        X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_CF | X86_EFLAGS_MODIFY_PF)) {

                        f_asm.add(reg_(FUKU_REG_ESP), imm(4));
                        f_asm.get_context().inst->
                            set_eflags(custom_eflags)
                            .set_instruction_flags(FUKU_INST_BAD_STACK);
                    }
                    else {
                        f_asm.lea(reg_(FUKU_REG_ESP), dword_ptr(FUKU_REG_ESP, imm(4)));
                        f_asm.get_context().inst->
                            set_eflags(custom_eflags)
                            .set_instruction_flags(FUKU_INST_BAD_STACK);
                    }
                }
                else {
                    //add esp,4
                    //mov reg,[esp - 4]

                    if (has_inst_free_eflags(custom_eflags, 
                        X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_CF | X86_EFLAGS_MODIFY_PF)) {

                        f_asm.add(reg_(FUKU_REG_ESP), imm(4));
                        f_asm.get_context().inst->
                            set_eflags(custom_eflags);
                    }
                    else {
                        f_asm.lea(reg_(FUKU_REG_ESP), dword_ptr(FUKU_REG_ESP, imm(4)));
                        f_asm.get_context().inst->
                            set_eflags(custom_eflags);
                    }

                    f_asm.mov(reg_(reg), dword_ptr(FUKU_REG_ESP, imm(-4)));
                    f_asm.get_context().inst->
                        set_eflags(custom_eflags)
                        .set_instruction_flags(FUKU_INST_BAD_STACK);
                }
            }
            else {
                return false;
            }

            return true;
        }
        else if (detail.operands[0].size == 2) { //pop reg16


        }
        else if (detail.operands[0].size == 1) { //pop reg8

        }

    }
    else if (detail.operands[0].type == X86_OP_MEM) { //pop [op]

    }


    return false;
}


bool fukutate_mov(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {

    return false;
}
bool fukutate_xchg(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {

    return false;
}
bool fukutate_lea(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {

    return false;
}

bool fukutate_add(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {

    auto detail = instruction->detail->x86;
    uint32_t instruction_flags = lines_iter->get_instruction_flags();

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

    return false;
}
bool fukutate_or(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {

    auto detail = instruction->detail->x86;
    uint32_t instruction_flags = lines_iter->get_instruction_flags();

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

    return false;
}
bool fukutate_adc(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {

    auto detail = instruction->detail->x86;
    uint32_t instruction_flags = lines_iter->get_instruction_flags();

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

    return false;
}
bool fukutate_sbb(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {

    auto detail = instruction->detail->x86;
    uint32_t instruction_flags = lines_iter->get_instruction_flags();

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

    return false;
}
bool fukutate_and(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {

    auto detail = instruction->detail->x86;
    uint32_t instruction_flags = lines_iter->get_instruction_flags();

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

    return false;
}

bool fukutate_sub(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {

    auto detail = instruction->detail->x86;
    uint32_t instruction_flags = lines_iter->get_instruction_flags();

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

    return false;
}
bool fukutate_xor(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {

    auto detail = instruction->detail->x86;
    uint32_t instruction_flags = lines_iter->get_instruction_flags();

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

    return false;
}
bool fukutate_cmp(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {

    auto detail = instruction->detail->x86;
    uint32_t instruction_flags = lines_iter->get_instruction_flags();

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

    return false;
}

bool fukutate_test(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {

    auto detail = instruction->detail->x86;
    uint32_t instruction_flags = lines_iter->get_instruction_flags();

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

    return false;
}


bool fukutate_inc(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {

    auto detail = instruction->detail->x86;
    uint32_t instruction_flags = lines_iter->get_instruction_flags();

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

    return false;
}

bool fukutate_dec(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {

    auto detail = instruction->detail->x86;
    uint32_t instruction_flags = lines_iter->get_instruction_flags();

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

    return false;
}

bool fukutate_not(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {

    auto detail = instruction->detail->x86;
    uint32_t instruction_flags = lines_iter->get_instruction_flags();

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

    return false;
}
bool fukutate_neg(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {

    auto detail = instruction->detail->x86;
    uint32_t instruction_flags = lines_iter->get_instruction_flags();

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

    return false;
}
bool fukutate_mul(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {

    auto detail = instruction->detail->x86;
    uint32_t instruction_flags = lines_iter->get_instruction_flags();

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

    return false;
}
bool fukutate_imul(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {

    return false;
}

bool fukutate_div(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {

    auto detail = instruction->detail->x86;
    uint32_t instruction_flags = lines_iter->get_instruction_flags();

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

    return false;
}
bool fukutate_idiv(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {

    auto detail = instruction->detail->x86;
    uint32_t instruction_flags = lines_iter->get_instruction_flags();

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

    return false;
}


bool fukutate_rol(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {

    auto detail = instruction->detail->x86;
    uint32_t instruction_flags = lines_iter->get_instruction_flags();

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

    return false;
}

bool fukutate_ror(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {

    auto detail = instruction->detail->x86;
    uint32_t instruction_flags = lines_iter->get_instruction_flags();

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

    return false;
}


bool fukutate_rcl(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {

    auto detail = instruction->detail->x86;
    uint32_t instruction_flags = lines_iter->get_instruction_flags();

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

    return false;
}


bool fukutate_rcr(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {

    auto detail = instruction->detail->x86;
    uint32_t instruction_flags = lines_iter->get_instruction_flags();

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

    return false;
}


bool fukutate_shl(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {

    auto detail = instruction->detail->x86;
    uint32_t instruction_flags = lines_iter->get_instruction_flags();

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

    return false;
}


bool fukutate_shr(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {

    auto detail = instruction->detail->x86;
    uint32_t instruction_flags = lines_iter->get_instruction_flags();

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

    return false;
}


bool fukutate_sar(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {

    auto detail = instruction->detail->x86;
    uint32_t instruction_flags = lines_iter->get_instruction_flags();

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

    return false;
}


bool fukutate_bt(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {


    auto detail = instruction->detail->x86;
    uint32_t instruction_flags = lines_iter->get_instruction_flags();

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

    return false;
}

bool fukutate_bts(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {


    auto detail = instruction->detail->x86;
    uint32_t instruction_flags = lines_iter->get_instruction_flags();

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

    return false;
}

bool fukutate_btr(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {


    auto detail = instruction->detail->x86;
    uint32_t instruction_flags = lines_iter->get_instruction_flags();

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

    return false;
}

bool fukutate_btc(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {


    auto detail = instruction->detail->x86;
    uint32_t instruction_flags = lines_iter->get_instruction_flags();

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

    return false;
}

bool fukutate_bsf(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {


    auto detail = instruction->detail->x86;
    uint32_t instruction_flags = lines_iter->get_instruction_flags();

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

    return false;
}

bool fukutate_bsr(cs_insn *instruction, fuku_assambler& f_asm, fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {


    auto detail = instruction->detail->x86;
    uint32_t instruction_flags = lines_iter->get_instruction_flags();

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

    return false;
}

