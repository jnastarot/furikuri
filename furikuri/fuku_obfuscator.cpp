#include "stdafx.h"
#include "fuku_obfuscator.h"


fuku_obfuscator::fuku_obfuscator()
    : destination_virtual_address(0),
    settings({ 1 , 2 , 10.f, 10.f, 10.f }),
    association_table(0), relocation_table(0){}


fuku_obfuscator::~fuku_obfuscator(){
}

void fuku_obfuscator::set_code(const fuku_code_analyzer& code_analyzer) {
    this->code = code_analyzer;
}

void fuku_obfuscator::set_code(const fuku_code_holder& code_holder) {
    this->code = code_holder;
}

void fuku_obfuscator::set_destination_virtual_address(uint64_t destination_virtual_address) {
    this->destination_virtual_address = destination_virtual_address;
}

void fuku_obfuscator::set_settings(const fuku_ob_settings& settings) {
    memcpy(&this->settings,&settings,sizeof(fuku_ob_settings));
}

void fuku_obfuscator::set_association_table(std::vector<fuku_code_association>*	associations) {
    this->association_table = associations;
}

void fuku_obfuscator::set_relocation_table(std::vector<fuku_image_relocation>* relocations) {
    this->relocation_table = relocations;
}

fuku_arch   fuku_obfuscator::get_arch() const {
    return this->code.get_arch();
}

uint64_t     fuku_obfuscator::get_destination_virtual_address() const {
    return this->destination_virtual_address;
}

fuku_ob_settings fuku_obfuscator::get_settings() const {
    return this->settings;
}

const std::vector<fuku_code_association> fuku_obfuscator::get_association_table() const {
    return *this->association_table;
}

const std::vector<fuku_image_relocation> fuku_obfuscator::get_relocation_table() const {
    return *this->relocation_table;
}


const fuku_code_holder& fuku_obfuscator::get_code() const {
    return this->code;
}

void fuku_obfuscator::obfuscate_code() {

    if (code.get_arch() == fuku_arch::fuku_arch_unknown) {
        return;
    }


    fuku_mutation * mutator = (code.get_arch() == fuku_arch::fuku_arch_x32) ?
        (fuku_mutation*)(new fuku_mutation_x86(settings)) : (fuku_mutation*)(new fuku_mutation_x64(settings));


    handle_jmps();

    useless_flags_profiler();

    for (unsigned int passes = 0; passes < settings.number_of_passes; passes++) {

        lines_correction(destination_virtual_address);
        mutator->obfuscate(code);
        
        if (settings.block_chance > 0.f) {
            spagetti_code(destination_virtual_address); //mix lines
        }
    }

    if (code.get_arch() == fuku_arch::fuku_arch_x32) {
        delete (fuku_mutation_x86*)mutator;
    }
    else {
        delete (fuku_mutation_x64*)mutator;
    }

    finalize_code();
}

void fuku_obfuscator::spagetti_code(uint64_t virtual_address) {

    lines_correction(virtual_address);


    std::vector<linestorage> line_blocks;

    fuku_asm_x86 fuku_asm;

    //generate blocks of lines
    {
        size_t lines_total = code.get_lines().size();
        size_t lines_in_blocks = 0;
        size_t current_block_size = 0;

        while (lines_in_blocks < lines_total) {

            if (FUKU_GET_CHANCE(settings.block_chance)) {
                line_blocks.push_back(linestorage());

                auto start = code.get_lines().begin();
                auto end = start;

                if (current_block_size) {
                    std::advance(end, current_block_size);

                    line_blocks[line_blocks.size() - 1].splice(line_blocks[line_blocks.size() - 1].begin(), code.get_lines(), start, end);
                }

                if (++end != code.get_lines().end()) {

                    fuku_instruction jmp_instruction = fuku_asm.jmp(0);
                    jmp_instruction.set_rip_relocation_idx(code.create_rip_relocation(1, &(*end)));
                    jmp_instruction.set_instruction_flags(end->get_instruction_flags() & (fuku_instruction_bad_stack));
                    jmp_instruction.set_custom_flags(end->get_custom_flags());

                    line_blocks[line_blocks.size() - 1].push_back(jmp_instruction);
                }

                current_block_size = 0;
            }
            else {
                lines_in_blocks++;
                current_block_size++;
            }

        }

        if (current_block_size) {
            auto start = code.get_lines().begin();
            auto end = start;
            std::advance(end, current_block_size);

            line_blocks[line_blocks.size() - 1].splice(line_blocks[line_blocks.size() - 1].begin(), code.get_lines(), start, end);
        }

    }

    //rand blocks
    if (line_blocks.size() > 2) {
        for (size_t r_block = 0; r_block < line_blocks.size()/2; r_block++) {
            size_t block_1 = FUKU_GET_RAND(0, line_blocks.size() - 1);
            size_t block_2 = FUKU_GET_RAND(0, line_blocks.size() - 1);
            
            if (block_1 != block_2) {
                line_blocks[block_1].swap(line_blocks[block_2]);
            }
        }
    }

    //push lines
    {
        auto& code_lines = code.get_lines();

        for (size_t block_idx = 0; block_idx < line_blocks.size(); block_idx++) {
            code_lines.splice(code_lines.end(), line_blocks[block_idx]);
        }
    }
}

void fuku_obfuscator::lines_correction(uint64_t virtual_address) {
    uint64_t _virtual_address = virtual_address;
    
    for (auto& line : code.get_lines()) {

        line.set_virtual_address(_virtual_address);
        _virtual_address += line.get_op_length();
    }
}

void fuku_obfuscator::handle_jmps() {

    for (auto& line_iter = code.get_lines().begin(); line_iter != code.get_lines().end(); line_iter++) {

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

            if (line.get_op_code()[line.get_op_pref_size()] & 0xF0 == 0x70) { //near jump

                uint8_t op_code[16];
                memcpy(op_code, line.get_op_code(), line.get_op_length());

                op_code[line.get_op_pref_size()] = 0x0F;
                op_code[line.get_op_pref_size() + 1] = 0x80 | (line.get_op_code()[line.get_op_pref_size()] & 0x0F);
                line.set_op_code(op_code, line.get_op_length() + 4);
            }

            break;
        }


        case X86_INS_JCXZ:
        case X86_INS_JECXZ: {

            if (line.get_id() == X86_INS_JECXZ) {
                fuku_instruction cc_line = fuku_asm_x86().or(fuku_reg86::r_ECX, fuku_reg86::r_ECX);//or ecx,ecx
                
                line.set_op_code(cc_line.get_op_code(), cc_line.get_op_length());
            }
            else { //todo with cx
                fuku_instruction cc_line = fuku_asm_x86(). or(fuku_reg86::r_ECX, fuku_reg86::r_ECX);//or cx,cx
                
                line.set_op_code(cc_line.get_op_code(), cc_line.get_op_length());       
            }

            fuku_instruction jcc_line = fuku_asm_x86().jcc(fuku_condition::equal, 0);//jz
            jcc_line.set_rip_relocation_idx(line.get_rip_relocation_idx());

            code.get_rip_relocations()[line.get_rip_relocation_idx()].offset = 1;

            line.set_rip_relocation_idx(-1);

            code.get_lines().insert(++line_iter, jcc_line);
            break;
        }


        case X86_INS_LOOP: {

            fuku_instruction cc_line = fuku_asm_x86().dec(fuku_reg86::r_ECX);//dec ecx
            cc_line.set_source_virtual_address(line.get_source_virtual_address());
            cc_line.set_virtual_address(line.get_virtual_address());

            fuku_instruction jcc_line = fuku_asm_x86().jcc(fuku_condition::not_equal, line.get_jump_imm());//jnz
            jcc_line.set_source_virtual_address(line.get_source_virtual_address() + 1);
            jcc_line.set_virtual_address(line.get_virtual_address() + 1);
            jcc_line.set_ip_relocation_disp_offset(2);

            lines[line_idx] = cc_line;
            lines.insert(lines.begin() + line_idx, line);

            break;
        }

        case X86_INS_LOOPE: {

            fuku_instruction cc_line = fuku_asm_x86().dec(fuku_reg86::r_ECX);//dec ecx
            cc_line.set_source_virtual_address(line.get_source_virtual_address());
            cc_line.set_virtual_address(line.get_virtual_address());

            fuku_instruction jcc_line = fuku_asm_x86().jcc(fuku_condition::equal, line.get_jump_imm());//je
            jcc_line.set_source_virtual_address(line.get_source_virtual_address() + 1);
            jcc_line.set_virtual_address(line.get_virtual_address() + 1);
            jcc_line.set_ip_relocation_disp_offset(2);

            lines[line_idx] = cc_line;
            lines.insert(lines.begin() + line_idx, line);

            break;
        }

        case X86_INS_LOOPNE: {

            fuku_instruction cc_line = fuku_asm_x86().dec(fuku_reg86::r_ECX);//dec ecx
            cc_line.set_source_virtual_address(line.get_source_virtual_address());
            cc_line.set_virtual_address(line.get_virtual_address());

            fuku_instruction jcc_line = fuku_asm_x86().jcc(fuku_condition::not_equal, line.get_jump_imm());//jne
            jcc_line.set_source_virtual_address(line.get_source_virtual_address() + 1);
            jcc_line.set_virtual_address(line.get_virtual_address() + 1);
            jcc_line.set_ip_relocation_disp_offset(2);

            lines[line_idx] = cc_line;
            lines.insert(lines.begin() + line_idx, line);

            break;
        }

        default:break;
        }
    }
}

void fuku_obfuscator::useless_flags_profiler() {

    for (auto& line_iter = code.get_lines().begin(); line_iter != code.get_lines().end(); line_idx++) {

        uint64_t useless_flags = 0;

        if (line_idx + 1 < code.lines.size()) {

            if (code.lines[line_idx].get_tested_flags() == 0) {

                for (uint32_t next_line_idx = line_idx + 1; next_line_idx < code.lines.size(); next_line_idx++) {

                    if (useless_flags == 0xED5 || code.lines[next_line_idx].get_tested_flags() || code.lines[next_line_idx].get_label_id()) {
                        break;
                    }

                    uint16_t type = code.lines[next_line_idx].get_type();

                    switch (type)
                    {
                        
                    case X86_INS_JMP: case X86_INS_RET: case X86_INS_CALL: {
                        goto routine_exit;
                    }

                    default: {
                        break;
                    }
                    }

                    useless_flags |= code.lines[next_line_idx].get_modified_flags();
                }
            }
        routine_exit:;
        }
            
        line_iter->set_custom_flags(useless_flags);
    }
}

void fuku_obfuscator::finalize_code() {
    lines_correction(destination_virtual_address);

    if (association_table)   { association_table->clear(); }
    if (relocation_table)    { relocation_table->clear(); }


    fuku_arch arch = code.get_arch();

    auto& labels = code.get_labels();
    auto& relocs = code.get_relocations();
    auto& rip_relocs = code.get_rip_relocations();

    for (auto &line : code.get_lines()) {
        
        if (association_table) {
            if (line.get_source_virtual_address() != -1) {
                association_table->push_back({ line.get_source_virtual_address(), line.get_virtual_address() });
            }
        }
    
        if (line.get_relocation_first_idx() != -1) {

            auto& reloc = relocs[line.get_relocation_first_idx()];
            auto& reloc_label = labels[reloc.label_idx];

            if (arch == fuku_arch::fuku_arch_x32) {

                if (reloc_label.has_linked_instruction) {
                    *(uint32_t*)(&line.get_op_code()[reloc.offset]) = (uint32_t)reloc_label.instruction->get_virtual_address();
                }
                else {
                    *(uint32_t*)(&line.get_op_code()[reloc.offset]) = (uint32_t)reloc_label.dst_address;
                }
            }
            else {

                if (reloc_label.has_linked_instruction) {
                    *(uint64_t*)(&line.get_op_code()[reloc.offset]) = reloc_label.instruction->get_virtual_address();
                }
                else {
                    *(uint64_t*)(&line.get_op_code()[reloc.offset]) = reloc_label.dst_address;
                }
            }


            if (relocation_table) {
                relocation_table->push_back({ (line.get_virtual_address() + reloc.offset), reloc.relocation_id });
            }
        }
    
        if (line.get_relocation_second_idx() != -1) {

            auto& reloc = relocs[line.get_relocation_second_idx()];
            auto& reloc_label = labels[reloc.label_idx];

            if (arch == fuku_arch::fuku_arch_x32) {

                if (reloc_label.has_linked_instruction) {
                    *(uint32_t*)(&line.get_op_code()[reloc.offset]) = (uint32_t)reloc_label.instruction->get_virtual_address();
                }
                else {
                    *(uint32_t*)(&line.get_op_code()[reloc.offset]) = (uint32_t)reloc_label.dst_address;
                }
            }
            else {

                if (reloc_label.has_linked_instruction) {
                    *(uint64_t*)(&line.get_op_code()[reloc.offset]) = reloc_label.instruction->get_virtual_address();
                }
                else {
                    *(uint64_t*)(&line.get_op_code()[reloc.offset]) = reloc_label.dst_address;
                }
            }


            if (relocation_table) {
                relocation_table->push_back({ (line.get_virtual_address() + reloc.offset), reloc.relocation_id });
            }
        }

        if (line.get_rip_relocation_idx() != -1) {

            auto& reloc = relocs[line.get_relocation_second_idx()];
            auto& reloc_label = labels[reloc.label_idx];


            if (reloc_label.has_linked_instruction) {
                *(uint32_t*)(&line.get_op_code()[reloc.offset]) =          
                    uint32_t(reloc_label.instruction->get_virtual_address() - line.get_virtual_address() - line.get_op_length());
            }
            else {
                *(uint32_t*)(&line.get_op_code()[reloc.offset]) = 
                    uint32_t(reloc_label.dst_address - line.get_virtual_address() - line.get_op_length());
            }
        }

    }
}