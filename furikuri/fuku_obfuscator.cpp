#include "stdafx.h"
#include "fuku_obfuscator.h"


fuku_obfuscator::fuku_obfuscator(){
    this->arch = fuku_arch::fuku_arch_x32;

    this->destination_virtual_address = 0;

    this->label_seed = 1;

    this->settings.complexity       = 1;
    this->settings.number_of_passes = 2;
    this->settings.junk_chance      = 10.f;
    this->settings.block_chance     = 10.f;
    this->settings.mutate_chance    = 10.f;

    this->association_table = 0; 
    this->relocation_table = 0;
}


fuku_obfuscator::~fuku_obfuscator(){
}

void fuku_obfuscator::set_arch(fuku_arch arch) {
    this->arch = arch;
}

void fuku_obfuscator::set_destination_virtual_address(uint64_t destination_virtual_address) {
    this->destination_virtual_address = destination_virtual_address;
}

void fuku_obfuscator::set_settings(const ob_fuku_sensitivity& settings) {
    memcpy(&this->settings,&settings,sizeof(ob_fuku_sensitivity));
}

void fuku_obfuscator::set_association_table(std::vector<ob_fuku_association>*	associations) {
    this->association_table = associations;
}

void fuku_obfuscator::set_relocation_table(std::vector<ob_fuku_relocation>* relocations) {
    this->relocation_table = relocations;
}

fuku_arch   fuku_obfuscator::get_arch() const {
    return this->arch;
}

uint64_t     fuku_obfuscator::get_destination_virtual_address() const {
    return this->destination_virtual_address;
}

ob_fuku_sensitivity fuku_obfuscator::get_settings() const {
    return this->settings;
}
std::vector<ob_fuku_association>*    fuku_obfuscator::get_association_table() {
    return this->association_table;
}

std::vector<ob_fuku_relocation>*     fuku_obfuscator::get_relocation_table() {
    return this->relocation_table;
}

std::vector<uint8_t> fuku_obfuscator::obfuscate_code() {

    fuku_mutation * mutator = (arch == fuku_arch::fuku_arch_x32) ?
        (fuku_mutation*)(new fuku_mutation_x86(settings, this)) : (fuku_mutation*)(new fuku_mutation_x64(settings, this));


    handle_jmps(lines);

    useless_flags_profiler();

    for (unsigned int passes = 0; passes < settings.number_of_passes; passes++) {

        lines_correction(lines, destination_virtual_address);
        mutator->obfuscate(this->lines);
        
        if (settings.block_chance > 0.f) {
            spagetti_code(lines, destination_virtual_address); //mix lines
        }
    }

    delete mutator;
  
    finalize_code();

    return lines_to_bin(lines);
}

void fuku_obfuscator::spagetti_code(std::vector<fuku_instruction>& lines, uint64_t virtual_address) {

    lines_correction(lines, virtual_address);

    struct block_lines {
        std::vector<fuku_instruction> lines;
        block_lines::block_lines(const std::vector<fuku_instruction>& lines) { this->lines = lines; }
        void block_lines::swap(block_lines& block) {
            std::swap(this->lines, block.lines);
        };
    };
    std::vector<block_lines> line_blocks;

    fuku_asm_x86 fuku_asm;

    //generate blocks of lines
    for (uint32_t line_idx = 0; line_idx < lines.size(); ) {
        std::vector<fuku_instruction> line_block;


        for (; line_idx < lines.size(); line_idx++) {
            if (FUKU_GET_CHANCE(settings.block_chance)) {

                fuku_instruction jmp_instruction = fuku_asm.jmp(0);              
                jmp_instruction.set_ip_relocation_disp_offset(1);
                jmp_instruction.set_flags(
                    lines[line_idx].get_flags()&(ob_fuku_instruction_bad_stack)
                );
                jmp_instruction.set_useless_flags(lines[line_idx].get_useless_flags());

                line_block.push_back(jmp_instruction);
                break;
            }

            line_block.push_back(lines[line_idx]); //push line
        }


        line_blocks.push_back(block_lines(line_block)); //push block of lines
    }

    for (uint32_t block_idx = 0; block_idx+1 < line_blocks.size(); block_idx++) {
        auto& current_block = line_blocks[block_idx];
        current_block.lines[current_block.lines.size()-1].set_link_label_id(set_label(line_blocks[block_idx+1].lines[0]));//set jmp to next instruction
    }

    //rand blocks without first block
    if (line_blocks.size() > 2) {
        for (unsigned int r_block = 0; r_block < line_blocks.size()/2; r_block++) {
            size_t block_1 = FUKU_GET_RAND(1, line_blocks.size() - 1);
            size_t block_2 = FUKU_GET_RAND(1, line_blocks.size() - 1);
            
            if (block_1 != block_2) {
                line_blocks[block_1].swap(line_blocks[block_2]);

                //printf("%d %d\n", block_1, block_2);
            }
        }
    }


    lines.clear();

    //push lines
    for (unsigned int r_block = 0; r_block < line_blocks.size(); r_block++) {
        for (unsigned int r_block_line = 0; r_block_line < line_blocks[r_block].lines.size(); r_block_line++) {
            lines.push_back(line_blocks[r_block].lines[r_block_line]);
        }
    }
}

void fuku_obfuscator::lines_correction(std::vector<fuku_instruction>& lines, uint64_t virtual_address) {
    uint64_t _virtual_address = virtual_address;
    this->labels_cache.clear();
    this->jumps_idx_cache.clear();
    this->rel_idx_cache.clear();
    this->ip_rel_idx_cache.clear();

    this->labels_cache.resize(label_seed - 1);


    for (uint32_t line_idx = 0; line_idx < lines.size(); line_idx++) {
        auto &line = lines[line_idx];
        line.set_virtual_address(_virtual_address);
        _virtual_address += line.get_op_length();

        if (line.get_label_id()) { 
            labels_cache[line.get_label_id() - 1] = line_idx; 
        }

        uint32_t flags = line.get_flags();

        if (flags&ob_fuku_instruction_has_relocation) {
            rel_idx_cache.push_back(line_idx);
        }
        else if (flags&ob_fuku_instruction_has_ip_relocation) {
            ip_rel_idx_cache.push_back(line_idx);
        }
        else if (line.is_jump()) {
            jumps_idx_cache.push_back(line_idx);
        }
    }
}

fuku_instruction * fuku_obfuscator::get_line_by_va(std::vector<fuku_instruction>& lines, uint64_t virtual_address) {

    size_t left = 0;
    size_t right = lines.size();
    size_t mid = 0;

    while (left < right) {
        mid = left + (right - left) / 2;

        if (lines[mid].get_virtual_address() <= virtual_address &&
            lines[mid].get_source_virtual_address() + lines[mid].get_op_length() > virtual_address) {

            return &lines[mid];
        }
        else if (lines[mid].get_virtual_address() > virtual_address) {
            right = mid;
        }
        else {
            left = mid + 1;
        }
    }

    return 0;
}

fuku_instruction * fuku_obfuscator::get_line_by_label_id(unsigned int label_id) {

    if (this->labels_cache.size()) {
        if (label_id > 0 && label_id <= this->labels_cache.size()) {
            return &this->lines[this->labels_cache[label_id - 1]];
        }
    }

    return 0;
}

void fuku_obfuscator::handle_jmps(std::vector<fuku_instruction>& lines) {

    for (size_t line_idx = 0; line_idx < lines.size(); line_idx++) {

        auto& line = lines[line_idx];

        if (line.is_jump()) {
            unsigned int prefixes_number = line.get_op_pref_size();

            uint8_t op_code[16];
            memset(op_code, 0, sizeof(op_code));

            switch (line.get_op_code()[prefixes_number]) {

                //near jmp
            case 0xEB: {

                if (prefixes_number) {
                    op_code[0] = line.get_op_code()[prefixes_number - 1];
                    op_code[1] = 0xE9;
                    *(int32_t*)&op_code[2] = line.get_jump_imm() - 3;

                    line.set_op_code(op_code, 6);
                    line.set_ip_relocation_disp_offset(2);
                }
                else {
                    op_code[0] = 0xE9;
                    *(int32_t*)&op_code[1] = line.get_jump_imm() - 3;

                    line.set_op_code(op_code, 5);
                    line.set_ip_relocation_disp_offset(1);
                }

                break;
            }

                       //near jcc
            case 0x70:case 0x71:case 0x72:case 0x73:case 0x74:case 0x75:case 0x76:case 0x77:
            case 0x78:case 0x79:case 0x7A:case 0x7B:case 0x7C:case 0x7D:case 0x7E:case 0x7F: {

                

                if (prefixes_number) {
                    op_code[0] = line.get_op_code()[prefixes_number - 1];
                    op_code[1] = 0x0F;
                    op_code[2] = 0x80 + (line.get_op_code()[prefixes_number]&0xF);
                    *(int32_t*)&op_code[3] = line.get_jump_imm();

                    line.set_op_code(op_code, 7);
                    line.set_ip_relocation_disp_offset(3);
                }
                else {
                    op_code[0] = 0x0F;
                    op_code[1] = 0x80 + (line.get_op_code()[prefixes_number]&0xF);
                    *(int32_t*)&op_code[2] = line.get_jump_imm();

                    line.set_op_code(op_code, 6);
                    line.set_ip_relocation_disp_offset(2);
                }

                break;
            }

            //loopnz
            case 0xE0: {

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

            //loopz
            case 0xE1: {

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

            //loop
            case 0xE2: {

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

            //jcxz
            case 0xE3: {
                
                fuku_instruction cc_line = fuku_asm_x86().or_(fuku_reg86::r_ECX, fuku_reg86::r_ECX);//or ecx,ecx
                cc_line.set_source_virtual_address(line.get_source_virtual_address());
                cc_line.set_virtual_address(line.get_virtual_address());

                fuku_instruction jcc_line = fuku_asm_x86().jcc(fuku_condition::equal, line.get_jump_imm());//jz
                jcc_line.set_source_virtual_address(line.get_source_virtual_address() + 1);
                jcc_line.set_virtual_address(line.get_virtual_address() + 1);
                jcc_line.set_ip_relocation_disp_offset(2);

                lines[line_idx] = cc_line;
                lines.insert(lines.begin() + line_idx, line);
                break;
            }

            default: {break; }
            }
        }
    }
}

void fuku_obfuscator::useless_flags_profiler() {

    for (uint32_t line_idx = 0; line_idx < lines.size();line_idx++) {

        uint16_t useless_flags = 0;

        if (line_idx + 1 < lines.size()) {

            if (lines[line_idx].get_tested_flags() == 0) {
                for (uint32_t next_line_idx = line_idx + 1; next_line_idx < lines.size(); next_line_idx++) {

                    if (useless_flags == 0xED5 || lines[next_line_idx].get_tested_flags() || lines[next_line_idx].get_label_id()) {
                        break;
                    }

                    uint16_t type = lines[next_line_idx].get_type();

                    switch (type)
                    {
                    case I_IRET:case I_JMP:case I_JMP_FAR: case I_RET: case I_CALL: {
                        goto routine_exit;
                    }

                    default: {
                        break;
                    }
                    }

                    useless_flags |= lines[next_line_idx].get_modified_flags();
                }
            }
        routine_exit:;
        }
            
        lines[line_idx].set_useless_flags(useless_flags);
    }
}

void fuku_obfuscator::finalize_code() {
    lines_correction(lines, destination_virtual_address);


    if (association_table)   { association_table->clear(); }
    if (relocation_table)    { relocation_table->clear(); }


    if (association_table) {
        for (auto &line : lines) {
            if (line.get_source_virtual_address() != -1) {
                association_table->push_back({ line.get_source_virtual_address(), line.get_virtual_address() });
            }
        }
    }

    for (uint32_t jump_idx : jumps_idx_cache) {
        auto &line = lines[jump_idx];

        uint8_t op_code[16];
        memcpy(op_code, line.get_op_code(), 16);

        if (line.get_link_label_id()) {
            fuku_instruction * line_destination = get_line_by_label_id(line.get_link_label_id());

            if (line_destination) {
                line.set_jump_imm(line_destination->get_virtual_address());
            }
        }
        else {
            line.set_jump_imm(line.get_ip_relocation_destination());
        }
    }

    for (uint32_t ip_rel_idx : ip_rel_idx_cache) {
        auto &line = lines[ip_rel_idx];

        uint8_t op_code[16];
        memcpy(op_code, line.get_op_code(), 16);

        if (line.get_link_label_id()) {
            fuku_instruction * line_destination = get_line_by_label_id(line.get_link_label_id());

            if (line_destination) {
                *(uint32_t*)&op_code[line.get_ip_relocation_disp_offset()] =
                    uint32_t(line_destination->get_virtual_address() - line.get_virtual_address() - line.get_op_length());
                line.set_op_code(op_code, line.get_op_length());
            }
        }
        else {
            *(uint32_t*)&op_code[line.get_ip_relocation_disp_offset()] =
                uint32_t(line.get_ip_relocation_destination() - line.get_virtual_address() - line.get_op_length());
            line.set_op_code(op_code, line.get_op_length());
        }
    }

    for (uint32_t rel_idx : rel_idx_cache) {
        auto &line = lines[rel_idx];

        uint8_t op_code[16];
        memcpy(op_code, line.get_op_code(), 16);

        if (line.get_relocation_f_label_id()) {
            if (arch == fuku_arch::fuku_arch_x32) {
                *(uint32_t*)&op_code[line.get_relocation_f_imm_offset()] =
                    uint32_t(get_line_by_label_id(line.get_relocation_f_label_id())->get_virtual_address());
            }
            else {
                *(uint64_t*)&op_code[line.get_relocation_f_imm_offset()] =
                    uint64_t(get_line_by_label_id(line.get_relocation_f_label_id())->get_virtual_address());
            }
        }

        if (line.get_relocation_s_label_id()) {
            if (arch == fuku_arch::fuku_arch_x32) {
                *(uint32_t*)&op_code[line.get_relocation_s_imm_offset()] =
                    uint32_t(get_line_by_label_id(line.get_relocation_s_label_id())->get_virtual_address());
            }
            else {
                *(uint64_t*)&op_code[line.get_relocation_s_imm_offset()] =
                    uint64_t(get_line_by_label_id(line.get_relocation_s_label_id())->get_virtual_address());
            }
        }


        if (relocation_table && line.get_relocation_f_imm_offset()) {
            relocation_table->push_back({ (line.get_virtual_address() + line.get_relocation_f_imm_offset()),line.get_relocation_f_id() });
        }
        if (relocation_table && line.get_relocation_s_imm_offset()) {
            relocation_table->push_back({ (line.get_virtual_address() + line.get_relocation_s_imm_offset()),line.get_relocation_s_id() });
        }


        line.set_op_code(op_code, line.get_op_length());
    }
}

std::vector<uint8_t>  fuku_obfuscator::lines_to_bin(std::vector<fuku_instruction>&  lines) {

    std::vector<uint8_t> lines_dump;
    size_t dump_size = 0;

    for (size_t line_idx = 0; line_idx < lines.size(); line_idx++) { dump_size += lines[line_idx].get_op_length(); }
    lines_dump.resize(dump_size);

    size_t opcode_caret = 0;
    for (auto &line : lines) {
        memcpy(&lines_dump.data()[opcode_caret], line.get_op_code(), line.get_op_length());
        opcode_caret += line.get_op_length();
    }

    return lines_dump;
}

uint32_t fuku_obfuscator::set_label(fuku_instruction& line) {
    if (!line.get_label_id()) {
        line.set_label_id(this->label_seed);
        this->label_seed++;
    }
    return line.get_label_id();
}

uint32_t fuku_obfuscator::get_maxlabel() const {
    return this->label_seed;
}