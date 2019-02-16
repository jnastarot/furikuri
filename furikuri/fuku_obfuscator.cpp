#include "stdafx.h"
#include "fuku_obfuscator.h"



fuku_obfuscator::fuku_obfuscator()
    :code(0), destination_virtual_address(0){}


fuku_obfuscator::~fuku_obfuscator(){
}

void fuku_obfuscator::set_code(fuku_code_holder* code_holder) {
    this->code = code_holder;
}

void fuku_obfuscator::set_destination_virtual_address(uint64_t destination_virtual_address) {
    this->destination_virtual_address = destination_virtual_address;
}

void fuku_obfuscator::set_settings(const fuku_settings_obfuscation& settings) {
    memcpy(&this->settings,&settings,sizeof(fuku_settings_obfuscation));
}

fuku_assambler_arch fuku_obfuscator::get_arch() const {
    return this->code->get_arch();
}

uint64_t     fuku_obfuscator::get_destination_virtual_address() const {
    return this->destination_virtual_address;
}

const fuku_settings_obfuscation& fuku_obfuscator::get_settings() const {
    return this->settings;
}

fuku_code_holder* fuku_obfuscator::get_code() {
    return this->code;
}

const fuku_code_holder* fuku_obfuscator::get_code() const {
    return this->code;
}

void fuku_obfuscator::obfuscate_code() {

    if (code == nullptr) {
        return;
    }


    fuku_mutation * mutator = (code->get_arch() == fuku_assambler_arch::FUKU_ASSAMBLER_ARCH_X86) ?
        (fuku_mutation*)(new fuku_mutation_x86(settings)) : (fuku_mutation*)(new fuku_mutation_x64(settings));


    handle_jmps();

    for (unsigned int passes = 0; passes < settings.get_number_of_passes(); passes++) {

        if (settings.get_junk_chance() > 0.f || settings.get_mutate_chance() > 0.f) {
            mutator->obfuscate(*code);
        }

        if (settings.get_block_chance() > 0.f) {
            spagetti_code(); //mix lines
        }
    }

    if (code->get_arch() == fuku_assambler_arch::FUKU_ASSAMBLER_ARCH_X86) {
        delete (fuku_mutation_x86*)mutator;
    }
    else {
        delete (fuku_mutation_x64*)mutator;
    }

    code->update_virtual_address(destination_virtual_address);
    code->update_origin_idxs();
}

void fuku_obfuscator::spagetti_code() {

    std::vector<linestorage> line_blocks;

    fuku_assambler_ctx context;
    fuku_instruction inst;

    context.arch = code->get_arch();
    context.inst = &inst;
    _jmp(context, imm(0));
    //generate blocks of lines
    {
        std::vector<size_t> block_lens;
 
        {
            size_t lines_total = code->get_lines().size();
            size_t lines_in_blocks = 0;
            size_t current_block_size = 0;

            while (lines_in_blocks < lines_total) {

                if (FUKU_GET_CHANCE(settings.get_block_chance())) {

                    block_lens.push_back(current_block_size);
                    current_block_size = 0;
                }
                else {
                    lines_in_blocks++;
                    current_block_size++;
                }

            }

            if (current_block_size) {
                block_lens.push_back(current_block_size);
            }
        }

        line_blocks.resize(block_lens.size());

        for (size_t block_idx = 0; block_idx < block_lens.size(); block_idx++) {

            size_t block_len = block_lens[block_idx];
            uint32_t inst_flags = 0;
            uint64_t inst_eflags = 0;
            uint64_t inst_customflags = 0;

            if (block_len) {
                auto start = code->get_lines().begin();
                auto end = start;

                std::advance(end, block_len);

                line_blocks[block_idx].splice(line_blocks[block_idx].begin(), code->get_lines(), start, end);   
            }

            if (code->get_lines().size()) {
                inst_flags = (code->get_lines().begin()->get_instruction_flags());
                inst_eflags = code->get_lines().begin()->get_eflags();
                inst_customflags = code->get_lines().begin()->get_custom_flags();
            }

            if (block_idx + 1 != block_lens.size()) { //insert jmp to next block
                line_blocks[block_idx].push_back(
                    inst.set_instruction_flags(inst_flags)
                    .set_eflags(inst_eflags)
                    .set_custom_flags(inst_customflags)
                );
            }

            if (block_idx) {

                auto& prev_block_jmp = line_blocks[block_idx - 1].back();
                auto& first_item_of_current_block = line_blocks[block_idx].begin();

                prev_block_jmp.set_rip_relocation_idx(code->create_rip_relocation(1, &(*first_item_of_current_block)));
                prev_block_jmp.set_eflags(first_item_of_current_block->get_eflags());
            }

        }

    }

    //rand blocks
    {
        std::vector<size_t> block_idxs;
        block_idxs.resize(line_blocks.size());

        for (size_t idx = 0; idx < block_idxs.size(); idx++) {
            block_idxs[idx] = idx;
        }

        if (line_blocks.size() > 2) {
            for (size_t r_block = 0; r_block < block_idxs.size(); r_block++) {
                std::swap(block_idxs[r_block], block_idxs[FUKU_GET_RAND(0, block_idxs.size() - 1)]);
            }
        }

        
        //push lines
        {
            auto& code_lines = code->get_lines();
            for (size_t block_idx : block_idxs) {
                code_lines.splice(code_lines.end(), line_blocks[block_idx]);
            }
        }

    }
}

void fuku_obfuscator::handle_jmps() {

    fuku_assambler fuku_asm(code->get_arch());
    fuku_asm.set_holder(code, ASSAMBLER_HOLD_TYPE_FIRST_OVERWRITE);

    for (auto& line_iter = code->get_lines().begin(); line_iter != code->get_lines().end(); ++line_iter) {

        fuku_instruction& line = *line_iter;

        switch (line.get_id()) {

        case X86_INS_JMP: {

            if (line.get_op_code()[line.get_op_pref_size()] == 0xEB) { //near jump

                uint8_t op_code[16];
                memcpy(op_code, line.get_op_code(), line.get_op_length());

                op_code[line.get_op_pref_size()] = 0xE9;

                line.set_op_code(op_code, line.get_op_length() + 3);
            }

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

            if ( (line.get_op_code()[line.get_op_pref_size()] & 0xF0) == 0x70) { //near jump

                uint8_t op_code[16];
                memcpy(op_code, line.get_op_code(), line.get_op_length());

                op_code[line.get_op_pref_size()] = 0x0F;
                op_code[line.get_op_pref_size() + 1] = 0x80 | (line.get_op_code()[line.get_op_pref_size()] & 0x0F);
                line.set_op_code(op_code, line.get_op_length() + 4);

                code->get_rip_relocations()[line.get_rip_relocation_idx()].offset = 2;
            }

            break;
        }


        case X86_INS_JCXZ:
        case X86_INS_JECXZ: {

            fuku_asm.set_first_emit(true).set_position(line_iter);

            size_t label_idx_f = line.get_label_idx();
            size_t rip_label_idx = line.get_rip_relocation_idx();

            fuku_register reg;

            if (line.get_id() == X86_INS_JECXZ) { //or ecx,ecx
                reg = reg_(FUKU_REG_ECX);
            }
            else { //or cx,cx
                reg = reg_(FUKU_REG_CX);
            }

            fuku_asm.or_(reg, reg);
            fuku_asm.get_context().inst->set_label_idx(label_idx_f);

            fuku_asm.jcc(FUKU_CONDITION_EQUAL, fuku_immediate(0));
            fuku_asm.get_context().inst->set_rip_relocation_idx(rip_label_idx);
            code->get_rip_relocations()[line.get_rip_relocation_idx()].offset = fuku_asm.get_context().immediate_offset;

            ++line_iter;
            break;
        }


        case X86_INS_LOOP: {
            fuku_asm.set_first_emit(true).set_position(line_iter);

            size_t label_idx_f = line.get_label_idx();
            size_t rip_label_idx = line.get_rip_relocation_idx();

            fuku_asm.dec(reg_(FUKU_REG_ECX));                  //dec ecx
            fuku_asm.get_context().inst->set_label_idx(label_idx_f);

            fuku_asm.jcc(FUKU_CONDITION_NOT_EQUAL, imm(0));      //jnz
            fuku_asm.get_context().inst->set_rip_relocation_idx(rip_label_idx);
            code->get_rip_relocations()[line.get_rip_relocation_idx()].offset = fuku_asm.get_context().immediate_offset;

            ++line_iter;
            break;
        }

        case X86_INS_LOOPE: {
            fuku_asm.set_first_emit(true).set_position(line_iter);

            size_t label_idx_f = line.get_label_idx();
            size_t rip_label_idx = line.get_rip_relocation_idx();

            fuku_asm.dec(reg_(FUKU_REG_ECX));                  //dec ecx
            fuku_asm.get_context().inst->set_label_idx(label_idx_f);

            fuku_asm.jcc(FUKU_CONDITION_EQUAL, imm(0));      //jz
            fuku_asm.get_context().inst->set_rip_relocation_idx(rip_label_idx);
            code->get_rip_relocations()[line.get_rip_relocation_idx()].offset = fuku_asm.get_context().immediate_offset;

            ++line_iter;
            break;
        }

        case X86_INS_LOOPNE: {
            fuku_asm.set_first_emit(true).set_position(line_iter);

            size_t label_idx_f = line.get_label_idx();
            size_t rip_label_idx = line.get_rip_relocation_idx();

            fuku_asm.dec(reg_(FUKU_REG_ECX));                  //dec ecx
            fuku_asm.get_context().inst->set_label_idx(label_idx_f);

            fuku_asm.jcc(FUKU_CONDITION_NOT_EQUAL, imm(0));      //jne
            fuku_asm.get_context().inst->set_rip_relocation_idx(rip_label_idx);
            code->get_rip_relocations()[line.get_rip_relocation_idx()].offset = fuku_asm.get_context().immediate_offset;

            ++line_iter;
            break;
        }

        default:break;
        }
    }
}

