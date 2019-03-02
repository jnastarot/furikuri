#include "stdafx.h"
#include "fuku_mutation_x86.h"
#include "fuku_mutation_x86_rules.h"
#include "fuku_mutation_x86_junk.h"

fuku_mutation_x86::fuku_mutation_x86(const fuku_settings_obfuscation& settings)
: settings(settings){
    f_asm.get_context().arch = FUKU_ASSAMBLER_ARCH_X86;
    cs_open(CS_ARCH_X86, CS_MODE_32, &cap_handle);
    cs_option(cap_handle, CS_OPT_DETAIL, CS_OPT_ON);
}

fuku_mutation_x86::~fuku_mutation_x86() {
    cs_close(&cap_handle);
}

void fuku_mutation_x86::obfuscate_lines(fuku_code_holder& code_holder, linestorage::iterator lines_iter_begin, linestorage::iterator lines_iter_end, unsigned int recurse_idx) {

    for (linestorage::iterator lines_iter = lines_iter_begin; lines_iter != lines_iter_end; ++lines_iter) {

        fukutation(code_holder, lines_iter);

        unsigned int recurse_idx_up = 0;
        if (recurse_idx == -1) {
            recurse_idx_up = rand() % settings.get_complexity() + 1;
        }
        else {
            recurse_idx_up = recurse_idx - 1;
        }

        if (recurse_idx_up) {
            auto next_iter = lines_iter; ++next_iter;
            obfuscate_lines(code_holder, lines_iter, next_iter, recurse_idx_up);
        }
    }
}

void fuku_mutation_x86::obfuscate(fuku_code_holder& code_holder) {
    obfuscate_lines(code_holder, code_holder.get_lines().begin(), code_holder.get_lines().end(), -1);
}

void fuku_mutation_x86::fukutation(fuku_code_holder& code_holder, linestorage::iterator lines_iter) {

    if (lines_iter->get_instruction_flags() & FUKU_INST_JUNK_CODE) {
        return;
    }

    mutation_context ctx;
    ctx.f_asm = &this->f_asm;
    ctx.code_holder = &code_holder;

    ctx.first_junk_line_iter = lines_iter;
    ctx.first_line_iter      = lines_iter;
    ctx.current_line_iter    = lines_iter;
    ctx.next_line_iter       = lines_iter; ++ctx.next_line_iter;

    ctx.has_unstable_stack  = lines_iter->get_instruction_flags() & FUKU_INST_BAD_STACK;
    ctx.is_first_line_begin = lines_iter == code_holder.get_lines().begin();
    ctx.is_next_line_end    = ctx.next_line_iter == code_holder.get_lines().end();
    ctx.was_mutated = false;
    ctx.was_junked = false;

    ctx.label_idx = lines_iter->get_label_idx();
    ctx.source_virtual_address = lines_iter->get_source_virtual_address();
    
    ctx.instruction_flags = lines_iter->get_instruction_flags();
    ctx.eflags_changes    = lines_iter->get_eflags();
    ctx.regs_changes      = lines_iter->get_custom_flags();

    ctx.swap_junk_label = false;

    cs_disasm(cap_handle, lines_iter->get_op_code(), lines_iter->get_op_length(), 0, 1, &ctx.instruction);

    if (!ctx.instruction) { 
        FUKU_DEBUG;
    }

    f_asm.get_context().short_cfg = 0xFF & ~(this->settings.get_asm_cfg() & FUKU_GET_RAND(0, 0xFF));

    
    if (FUKU_GET_CHANCE(settings.get_junk_chance())) {

        if (!ctx.is_first_line_begin) {
            --ctx.first_junk_line_iter;
        }
        
        fuku_junk(ctx);

        if (!ctx.is_first_line_begin) {
            ++ctx.first_junk_line_iter;
        }
        else {
            ctx.first_junk_line_iter = code_holder.get_lines().begin();
        }

        if (ctx.is_next_line_end) {
            ctx.first_line_iter = code_holder.get_lines().end();
        }
        else {
            ctx.first_line_iter = ctx.next_line_iter;
        }

        --ctx.first_line_iter;
    }
    

    f_asm.set_holder(&code_holder, ASSAMBLER_HOLD_TYPE_FIRST_OVERWRITE)
        .set_position(lines_iter)
        .set_first_emit(true);


    if ( (lines_iter->get_instruction_flags() & FUKU_INST_NO_MUTATE) == 0 &&
        FUKU_GET_CHANCE(settings.get_mutate_chance())) {

        switch (lines_iter->get_id()) {

//CONTROL GRAPH

        case X86_INS_JMP: {
            fukutate_86_jmp(ctx);
            break;
        }
        case X86_INS_CALL: {
            fukutate_86_call(ctx);
            break;
        }
        case  X86_INS_JO: case  X86_INS_JNO:
        case  X86_INS_JB: case  X86_INS_JAE:
        case  X86_INS_JE: case  X86_INS_JNE:
        case  X86_INS_JBE:case  X86_INS_JA:
        case  X86_INS_JS: case  X86_INS_JNS:
        case  X86_INS_JP: case  X86_INS_JNP:
        case  X86_INS_JL: case  X86_INS_JGE:
        case  X86_INS_JLE:case  X86_INS_JG: {
            fukutate_86_jcc(ctx);
            break;
        }
        case X86_INS_RET: {
            fukutate_86_ret(ctx);
            break;
        }

        case X86_INS_MOV: {
            fukutate_86_mov(ctx);
            break;
        }

        case X86_INS_XCHG: {
            fukutate_86_xchg(ctx);
            break;
        }

        case X86_INS_LEA: {
            fukutate_86_lea(ctx);
            break;
        }

//STACK CONTROL
        case X86_INS_PUSH: {
            fukutate_86_push(ctx);
            break;
        }
   
        case X86_INS_POP: {
            fukutate_86_pop(ctx);
            break;
        }
                          
//ARITHMETIC
        case X86_INS_ADD: {
            fukutate_86_add(ctx);
            break;
        }
        case X86_INS_OR: {
            fukutate_86_or(ctx);
            break;
        }
        case X86_INS_ADC: {
            fukutate_86_adc(ctx);
            break;
        }
        case X86_INS_SBB: {
            fukutate_86_sbb(ctx);
            break;
        }
        case X86_INS_AND: {
            fukutate_86_and(ctx);
            break;
        }
        case X86_INS_SUB: {
            fukutate_86_sub(ctx);
            break;
        } 
        case X86_INS_XOR: {
            fukutate_86_xor(ctx);
            break;
        }
        case X86_INS_CMP: {
            fukutate_86_cmp(ctx);
            break;
        }
        case X86_INS_INC: {
            fukutate_86_inc(ctx);
            break;
        }
        case X86_INS_DEC: {
            fukutate_86_dec(ctx);
            break;
        }
        case X86_INS_TEST: {
            fukutate_86_test(ctx);
            break;
        }
       
        case X86_INS_NOT: {
            fukutate_86_not(ctx);
            break;
        }
        case X86_INS_NEG: {
            fukutate_86_neg(ctx);
            break;
        }
        case X86_INS_MUL: {
            fukutate_86_mul(ctx);
            break;
        }
        case X86_INS_IMUL: {
            fukutate_86_imul(ctx);
            break;
        }
        case X86_INS_DIV: {
            fukutate_86_div(ctx);
            break;
        }
        case X86_INS_IDIV: {
            fukutate_86_idiv(ctx);
            break;
        }
         
//SHIFT
        case X86_INS_ROL: {
            fukutate_86_rol(ctx);
            break;
        }

        case X86_INS_ROR: {
            fukutate_86_ror(ctx);
            break;
        }
        case X86_INS_RCL: {
            fukutate_86_rcl(ctx);
            break;
        }
        case X86_INS_RCR: {
            fukutate_86_rcr(ctx);
            break;
        }
        case X86_INS_SAL: //SAL is too SHL
        case X86_INS_SHL: {
            fukutate_86_shl(ctx);
            break;
        }
        case X86_INS_SHR: {
            fukutate_86_shr(ctx);
            break;
        }
        case X86_INS_SAR: {
            fukutate_86_sar(ctx);
            break;
        }

//BITTEST
        case X86_INS_BT: {
            fukutate_86_bt(ctx);
            break;
        }
        case X86_INS_BTS: {
            fukutate_86_bts(ctx);
            break;
        }
        case X86_INS_BTR: {
            fukutate_86_btr(ctx);
            break;
        }
        case X86_INS_BTC: {
            fukutate_86_btc(ctx);
            break;
        }
        case X86_INS_BSF: {
            fukutate_86_bsf(ctx);
            break;
        }
        case X86_INS_BSR: {
            fukutate_86_bsr(ctx);
            break;
        }
       


        }
    }

    cs_free(ctx.instruction, 1);

    if(ctx.was_junked || ctx.was_mutated) { //move label_idx and source_address to start of instruction's array 

        if (!ctx.was_mutated) {
            ctx.first_line_iter->set_label_idx(-1);
        }

        if (ctx.was_junked) {
           
            ctx.first_junk_line_iter->set_label_idx(ctx.label_idx);

            if (ctx.swap_junk_label) {

                ctx.first_line_iter->set_label_idx(ctx.junk_label_idx);

                code_holder.get_labels()[ctx.junk_label_idx].instruction = &(*ctx.first_line_iter);

                if (ctx.label_idx != -1) {
                    code_holder.get_labels()[ctx.label_idx].instruction = &(*ctx.first_junk_line_iter);
                }
            }

            ctx.first_junk_line_iter->set_source_virtual_address(ctx.source_virtual_address);
        }
        else {
            ctx.first_line_iter->set_label_idx(ctx.label_idx);
            ctx.first_line_iter->set_source_virtual_address(ctx.source_virtual_address);
        }


        if (ctx.is_next_line_end) {
            ctx.next_line_iter = code_holder.get_lines().end();
        }

        auto& start_line = (ctx.was_junked == true ? ctx.first_junk_line_iter : ctx.first_line_iter);

        for (auto current_line = start_line; current_line != ctx.next_line_iter; ++current_line) {
        
            if (ctx.has_unstable_stack) {
                current_line->set_instruction_flags(current_line->get_instruction_flags() | FUKU_INST_BAD_STACK);
            }
            if (current_line != start_line) {
                current_line->set_source_virtual_address(-1);
            }
        }
    }
}

void fuku_mutation_x86::fuku_junk(mutation_context& ctx) {
   
    f_asm.set_holder(ctx.code_holder, ASSAMBLER_HOLD_TYPE_NOOVERWRITE)
        .set_position(ctx.current_line_iter)
        .set_first_emit(false);

    fuku_junk_86_generic(ctx);
}

void fuku_mutation_x86::get_junk(
    fuku_code_holder& code_holder, size_t junk_size, bool unstable_stack,
    uint64_t eflags_changes, uint64_t regs_changes) {

    f_asm.get_context().short_cfg = 0xFF;
    f_asm.set_holder(&code_holder, ASSAMBLER_HOLD_TYPE_NOOVERWRITE)
        .set_position(code_holder.get_lines().end())
        .set_first_emit(true);


    size_t current_size = 0;

  
}