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

    cs_insn *instruction;
    linestorage::iterator first_junk_line_iter = lines_iter;
    linestorage::iterator first_line_iter = lines_iter;
    linestorage::iterator next_line_iter = lines_iter; ++next_line_iter;

    bool has_unstable_stack = lines_iter->get_instruction_flags() & FUKU_INST_BAD_STACK;
    bool is_first_line_begin = lines_iter == code_holder.get_lines().begin();
    bool is_next_line_end = next_line_iter == code_holder.get_lines().end();
    bool was_mutated = false;
    bool was_junked = false;

    size_t   label_idx = lines_iter->get_label_idx();
    uint64_t source_virtual_address = lines_iter->get_source_virtual_address();
    
    cs_disasm(cap_handle, lines_iter->get_op_code(), lines_iter->get_op_length(), 0, 1, &instruction);

    if (!instruction) { FUKU_DEBUG; }

    

    f_asm.get_context().short_cfg = this->settings.get_asm_cfg() & FUKU_GET_RAND(0, 0xFF);

    
    if (FUKU_GET_CHANCE(settings.get_junk_chance())) {

        if (!is_first_line_begin) {
            --first_junk_line_iter;
        }
        
        fuku_junk(code_holder, lines_iter); was_junked = true;

        if (!is_first_line_begin) {
            ++first_junk_line_iter;
        }
        else {
            first_junk_line_iter = code_holder.get_lines().begin();
        }

        if (is_next_line_end) {
            first_line_iter = code_holder.get_lines().end();
        }
        else {
            first_line_iter = next_line_iter;
        }

        --first_line_iter;
    }
    

    f_asm.set_holder(&code_holder, ASSAMBLER_HOLD_TYPE_FIRST_OVERWRITE)
        .set_position(lines_iter)
        .set_first_emit(true);


    if ( (lines_iter->get_instruction_flags() & FUKU_INST_NO_MUTATE) == 0 &&
        FUKU_GET_CHANCE(settings.get_mutate_chance())) {

        switch (lines_iter->get_id()) {

//CONTROL GRAPH

        case X86_INS_JMP: {
            was_mutated = fukutate_jmp(instruction, f_asm, code_holder, lines_iter);
            break;
        }
        case X86_INS_CALL: {
            was_mutated = fukutate_call(instruction, f_asm, code_holder, lines_iter);
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
            if (!is_next_line_end) { //idk but it check dont works in fukutate_jcc \_(._.)/
                was_mutated = fukutate_jcc(instruction, f_asm, code_holder, lines_iter);
            }
            break;
        }
        case X86_INS_RET: {
            was_mutated = fukutate_ret(instruction, f_asm, code_holder, lines_iter);
            break;
        }

        case X86_INS_MOV: {
            was_mutated = fukutate_mov(instruction, f_asm, code_holder, lines_iter);
            break;
        }

        case X86_INS_XCHG: {
            was_mutated = fukutate_xchg(instruction, f_asm, code_holder, lines_iter);
            break;
        }

        case X86_INS_LEA: {
            was_mutated = fukutate_lea(instruction, f_asm, code_holder, lines_iter);
            break;
        }

//STACK CONTROL
        case X86_INS_PUSH: {
            was_mutated = fukutate_push(instruction, f_asm, code_holder, lines_iter);
            break;
        }
   
        case X86_INS_POP: {
            was_mutated = fukutate_pop(instruction, f_asm, code_holder, lines_iter);
            break;
        }

//ARITHMETIC
        case X86_INS_ADD: {
            was_mutated = fukutate_add(instruction, f_asm, code_holder, lines_iter);
            break;
        }
        case X86_INS_OR: {
            was_mutated = fukutate_or(instruction, f_asm, code_holder, lines_iter);
            break;
        }
        case X86_INS_ADC: {
            was_mutated = fukutate_adc(instruction, f_asm, code_holder, lines_iter);
            break;
        }
        case X86_INS_SBB: {
            was_mutated = fukutate_sbb(instruction, f_asm, code_holder, lines_iter);
            break;
        }
        case X86_INS_AND: {
            was_mutated = fukutate_and(instruction, f_asm, code_holder, lines_iter);
            break;
        }
        case X86_INS_SUB: {
            was_mutated = fukutate_sub(instruction, f_asm, code_holder, lines_iter);
            break;
        }
        case X86_INS_XOR: {
            was_mutated = fukutate_xor(instruction, f_asm, code_holder, lines_iter);
            break;
        }
        case X86_INS_CMP: {
            was_mutated = fukutate_cmp(instruction, f_asm, code_holder, lines_iter);
            break;
        }
        case X86_INS_INC: {
            was_mutated = fukutate_inc(instruction, f_asm, code_holder, lines_iter);
            break;
        }
        case X86_INS_DEC: {
            was_mutated = fukutate_dec(instruction, f_asm, code_holder, lines_iter);
            break;
        }
        case X86_INS_TEST: {
            was_mutated = fukutate_test(instruction, f_asm, code_holder, lines_iter);
            break;
        }

        case X86_INS_NOT: {
            was_mutated = fukutate_not(instruction, f_asm, code_holder, lines_iter);
            break;
        }
        case X86_INS_NEG: {
            was_mutated = fukutate_neg(instruction, f_asm, code_holder, lines_iter);
            break;
        }
        case X86_INS_MUL: {
            was_mutated = fukutate_mul(instruction, f_asm, code_holder, lines_iter);
            break;
        }
        case X86_INS_IMUL: {
            was_mutated = fukutate_imul(instruction, f_asm, code_holder, lines_iter);
            break;
        }
        case X86_INS_DIV: {
            was_mutated = fukutate_div(instruction, f_asm, code_holder, lines_iter);
            break;
        }
        case X86_INS_IDIV: {
            was_mutated = fukutate_idiv(instruction, f_asm, code_holder, lines_iter);
            break;
        }

//SHIFT
        case X86_INS_ROL: {
            was_mutated = fukutate_rol(instruction, f_asm, code_holder, lines_iter);
            break;
        }

        case X86_INS_ROR: {
            was_mutated = fukutate_ror(instruction, f_asm, code_holder, lines_iter);
            break;
        }
        case X86_INS_RCL: {
            was_mutated = fukutate_rcl(instruction, f_asm, code_holder, lines_iter);
            break;
        }
        case X86_INS_RCR: {
            was_mutated = fukutate_rcr(instruction, f_asm, code_holder, lines_iter);
            break;
        }
        case X86_INS_SAL: //SAL is too SHL
        case X86_INS_SHL: {
            was_mutated = fukutate_shl(instruction, f_asm, code_holder, lines_iter);
            break;
        }
        case X86_INS_SHR: {
            was_mutated = fukutate_shr(instruction, f_asm, code_holder, lines_iter);
            break;
        }
        case X86_INS_SAR: {
            was_mutated = fukutate_sar(instruction, f_asm, code_holder, lines_iter);
            break;
        }

//BITTEST
        case X86_INS_BT: {
            was_mutated = fukutate_bt(instruction, f_asm, code_holder, lines_iter);
            break;
        }
        case X86_INS_BTS: {
            was_mutated = fukutate_bts(instruction, f_asm, code_holder, lines_iter);
            break;
        }
        case X86_INS_BTR: {
            was_mutated = fukutate_btr(instruction, f_asm, code_holder, lines_iter);
            break;
        }
        case X86_INS_BTC: {
            was_mutated = fukutate_btc(instruction, f_asm, code_holder, lines_iter);
            break;
        }
        case X86_INS_BSF: {
            was_mutated = fukutate_bsf(instruction, f_asm, code_holder, lines_iter);
            break;
        }
        case X86_INS_BSR: {
            was_mutated = fukutate_bsr(instruction, f_asm, code_holder, lines_iter);
            break;
        }
        


        }
    }

    cs_free(instruction, 1);

    if(was_junked || was_mutated) { //move label_idx and source_address to start of instruction's array 

        if (!was_mutated) {
            first_line_iter->set_label_idx(-1);
        }

        if (was_junked) {
            first_junk_line_iter->set_label_idx(label_idx);
            first_junk_line_iter->set_source_virtual_address(source_virtual_address);
        }
        else {
            first_line_iter->set_label_idx(label_idx);
            first_line_iter->set_source_virtual_address(source_virtual_address);
        }


        if (is_next_line_end) {
            next_line_iter = code_holder.get_lines().end();
        }

        auto& start_line = (was_junked == true ? first_junk_line_iter : first_line_iter);

        for (auto current_line = start_line; current_line != next_line_iter; ++current_line) {
        
            if (has_unstable_stack) {
                current_line->set_instruction_flags(current_line->get_instruction_flags() | FUKU_INST_BAD_STACK);
            }
            if (current_line != start_line) {
                current_line->set_source_virtual_address(-1);
            }
        }
    }
}

void fuku_mutation_x86::fuku_junk(fuku_code_holder& code_holder, linestorage::iterator& lines_iter) {
   
    uint32_t instruction_flags = lines_iter->get_instruction_flags();
    uint64_t eflags_changes = lines_iter->get_eflags();
    uint64_t regs_changes = lines_iter->get_custom_flags();

    f_asm.set_holder(&code_holder, ASSAMBLER_HOLD_TYPE_NOOVERWRITE)
        .set_position(lines_iter)
        .set_first_emit(false);

    fuku_junk_generic(f_asm, code_holder, lines_iter, instruction_flags, eflags_changes, regs_changes);
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