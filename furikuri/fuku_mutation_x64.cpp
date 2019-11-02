#include "stdafx.h"
#include "fuku_mutation_x64.h"

#include "fuku_mutation_x64_rules.h"
#include "fuku_mutation_x64_junk.h"

fuku_mutation_x64::fuku_mutation_x64(const fuku_settings_obfuscation& settings)
: settings(settings){
    f_asm.get_context().arch = FUKU_ASSAMBLER_ARCH_X64;
    cs_open(CS_ARCH_X86, CS_MODE_64, &cap_handle);
    cs_option(cap_handle, CS_OPT_DETAIL, CS_OPT_ON);

    inst_changers = new _fukutate_instruction[X86_INS_ENDING];
    memset(inst_changers, 0, sizeof(_fukutate_instruction) * X86_INS_ENDING);

    init_x64_rules((_fukutate_instruction*)inst_changers);
}

fuku_mutation_x64::~fuku_mutation_x64() {
    
    cs_close(&cap_handle);

    if (inst_changers) {

        delete inst_changers;
    }
}

void fuku_mutation_x64::obfuscate_lines(mutation_context& ctx, inststorage::iterator lines_iter_begin, inststorage::iterator lines_iter_end, unsigned int recurse_idx) {

    for (inststorage::iterator lines_iter = lines_iter_begin; lines_iter != lines_iter_end; ++lines_iter) {

        fukutation(ctx, lines_iter);

        unsigned int recurse_idx_up = 0;
        if (recurse_idx == -1) {
            recurse_idx_up = rand() % settings.get_complexity() + 1;
        }
        else {
            recurse_idx_up = recurse_idx - 1;
        }

        if (recurse_idx_up) {
            auto next_iter = lines_iter; ++next_iter;
            obfuscate_lines(ctx, lines_iter, next_iter, recurse_idx_up);
        }
    }
}

void fuku_mutation_x64::obfuscate(fuku_code_holder& code_holder) {

    mutation_context ctx;
    ctx.f_asm = &this->f_asm;
    ctx.code_holder = &code_holder;
    ctx.instruction = cs_malloc(cap_handle);
    ctx.settings = &settings;

    obfuscate_lines(ctx, code_holder.get_insts().begin(), code_holder.get_insts().end(), -1);

    cs_free(ctx.instruction, 1);
}

void fuku_mutation_x64::fukutation(mutation_context& ctx, inststorage::iterator& lines_iter) {

    if (lines_iter->get_inst_flags() & FUKU_INST_JUNK_CODE) {
        return;
    }

    bool is_chansed_junk = FUKU_GET_CHANCE(settings.get_junk_chance());
    bool is_chansed_mutate = (lines_iter->get_inst_flags() & FUKU_INST_NO_MUTATE) == 0 &&
        FUKU_GET_CHANCE(settings.get_mutate_chance());

    if (!is_chansed_junk &&
        !is_chansed_mutate) {

        return;
    }


    ctx.initialize_context(lines_iter);

    {
        size_t _size = lines_iter->get_oplength();
        const uint8_t* code = lines_iter->get_opcode();
        uint64_t address_ = 0;

        if (!cs_disasm_iter(cap_handle, &code, &_size, &address_, ctx.instruction)) {

            FUKU_DEBUG;
        }

    }

    f_asm.get_context().short_cfg = 0xFF & ~(this->settings.get_asm_cfg() & FUKU_GET_RAND(0, 0xFF));

    bool was_mutated = false;
    bool was_junked = false;

    if (is_chansed_junk) {

        was_junked = fuku_junk(ctx);

        if (was_junked) {
            ctx.update_payload_inst_iter();
        }
    }

    if (is_chansed_mutate) {

        _fukutate_instruction fukutate = ((_fukutate_instruction*)inst_changers)[lines_iter->get_id()];

        if (fukutate) {

            f_asm.set_holder(ctx.code_holder, ASSAMBLER_HOLD_TYPE_FIRST_OVERWRITE)
                .set_position(lines_iter)
                .set_first_emit(true);

            was_mutated = fukutate(ctx);
        }
    }

    if (was_junked || was_mutated) { //move label_idx and source_address to start of instruction's array 

        //reset labels
        if (ctx.original_start_label) {
            ctx.original_start_label->inst->set_label(0);
            ctx.calc_original_inst_iter()->set_label(ctx.original_start_label);
        }

        if (ctx.payload_start_label) {
            ctx.payload_inst_iter->set_label(ctx.payload_start_label);
        }

        //reset source address and flags
        if (ctx.has_source_address || 
            (ctx.settings->is_not_allowed_unstable_stack() == false && ctx.inst_flags & FUKU_INST_BAD_STACK) ) {

            auto& start_inst = ctx.calc_original_inst_iter();


            for (auto current_inst = start_inst; current_inst != ctx.calc_next_inst_iter(); ++current_inst) {

                if (ctx.inst_flags & FUKU_INST_BAD_STACK) {

                    current_inst->set_inst_flags(current_inst->get_inst_flags() | FUKU_INST_BAD_STACK);
                }

                if (ctx.has_source_address) {

                    if (current_inst != start_inst) {
                        current_inst->invalidate_source_address();
                    }
                    else {
                        current_inst->set_source_address(ctx.source_address);
                    }
                }
            }
        }
    }

}

bool fuku_mutation_x64::fuku_junk(mutation_context& ctx) {

    f_asm.set_holder(ctx.code_holder, ASSAMBLER_HOLD_TYPE_NOOVERWRITE)
        .set_position(ctx.payload_inst_iter)
        .set_first_emit(false);

   return fuku_junk_64_generic(ctx);
}

void fuku_mutation_x64::get_junk(
    fuku_code_holder& code_holder, size_t junk_size, bool unstable_stack,
    uint64_t eflags_changes, uint64_t regs_changes) {


    f_asm.set_holder(&code_holder, ASSAMBLER_HOLD_TYPE_NOOVERWRITE)
        .set_position(code_holder.get_insts().end())
        .set_first_emit(true);


    size_t current_size = 0;

    
}