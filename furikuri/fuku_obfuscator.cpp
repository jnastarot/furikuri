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


    handle_jmps(code);

    useless_flags_profiler();

    for (unsigned int passes = 0; passes < settings.number_of_passes; passes++) {

        lines_correction(code, destination_virtual_address);
        mutator->obfuscate(code);
        
        if (settings.block_chance > 0.f) {
            spagetti_code(code, destination_virtual_address); //mix lines
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

void fuku_obfuscator::spagetti_code(linestorage& lines, uint64_t virtual_address) {

    lines_correction(lines, virtual_address);

    struct block_lines {
        linestorage lines;
        block_lines::block_lines(const linestorage& lines) { this->lines = lines; }
        void block_lines::swap(block_lines& block) {
            std::swap(this->lines, block.lines);
        };
    };
    std::vector<block_lines> line_blocks;

    fuku_asm_x86 fuku_asm;

    //generate blocks of lines
    for (uint32_t line_idx = 0; line_idx < lines.size(); ) {
        linestorage line_block;


        for (; line_idx < lines.size(); line_idx++) {
            if (FUKU_GET_CHANCE(settings.block_chance)) {

                fuku_instruction jmp_instruction = fuku_asm.jmp(0);              
                jmp_instruction.set_ip_relocation_disp_offset(1);
                jmp_instruction.set_flags(
                    lines[line_idx].get_flags() & (fuku_instruction_bad_stack)
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

void fuku_obfuscator::lines_correction(linestorage& lines, uint64_t virtual_address) {
    uint64_t _virtual_address = virtual_address;
    this->code.labels_cache.clear();
    this->code.jumps_idx_cache.clear();
    this->code.rel_idx_cache.clear();
    this->code.ip_rel_idx_cache.clear();

    this->code.labels_cache.resize(code.label_seed - 1);
   // memset(this->code.labels_cache.data(), 0, this->code.labels_cache.size() * sizeof(uint32_t));

    for (uint32_t line_idx = 0; line_idx < lines.size(); line_idx++) {
        auto &line = lines[line_idx];
        line.set_virtual_address(_virtual_address);
        _virtual_address += line.get_op_length();

        if (line.get_label_id()) { 
            code.labels_cache[line.get_label_id() - 1] = line_idx;
        }

        uint32_t flags = line.get_flags();

        if (flags & fuku_instruction_has_relocation) {
            code.rel_idx_cache.push_back(line_idx);
        }
        else if (flags & fuku_instruction_has_ip_relocation) {
            code.ip_rel_idx_cache.push_back(line_idx);
        }
        else if (line.is_jump()) {
            code.jumps_idx_cache.push_back(line_idx);
        }
    }
}

void fuku_obfuscator::handle_jmps(linestorage& lines) {

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
                
                fuku_instruction cc_line = fuku_asm_x86().or(fuku_reg86::r_ECX, fuku_reg86::r_ECX);//or ecx,ecx
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

    for (uint32_t line_idx = 0; line_idx < code.lines.size();line_idx++) {

        uint16_t useless_flags = 0;

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
            
        code.lines[line_idx].set_useless_flags(useless_flags);
    }
}

void fuku_obfuscator::finalize_code() {
    lines_correction(code.lines, destination_virtual_address);


    if (association_table)   { association_table->clear(); }
    if (relocation_table)    { relocation_table->clear(); }
    if (ip_relocation_table) { ip_relocation_table->clear(); }

    if (association_table) {
        for (auto &line : code.lines) {
            if (line.get_source_virtual_address() != -1) {
                association_table->push_back({ line.get_source_virtual_address(), line.get_virtual_address() });
            }
        }
    }

    for (uint32_t jump_idx : code.jumps_idx_cache) {
        auto &line = code.lines[jump_idx];

        uint8_t op_code[16];
        memcpy(op_code, line.get_op_code(), 16);

        if (line.get_link_label_id()) {
            fuku_instruction * line_destination = get_line_by_label_id(code, line.get_link_label_id());

            if (line_destination) {
                line.set_jump_imm(line_destination->get_virtual_address());
            }
        }
        else {
            line.set_jump_imm(line.get_ip_relocation_destination());

            if (ip_relocation_table) {
                ip_relocation_table->push_back({
                    line.get_virtual_address(),
                    line.get_ip_relocation_destination(),
                    line.get_ip_relocation_disp_offset(),
                    line.get_op_length()
                 });
            }
        }      
    }

    for (uint32_t ip_rel_idx : code.ip_rel_idx_cache) {
        auto &line = code.lines[ip_rel_idx];

        uint8_t op_code[16];
        memcpy(op_code, line.get_op_code(), 16);

        if (line.get_link_label_id()) {
            fuku_instruction * line_destination = get_line_by_label_id(code, line.get_link_label_id());

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

            if (ip_relocation_table) {
                ip_relocation_table->push_back({
                    line.get_virtual_address(),
                    line.get_ip_relocation_destination(),
                    line.get_ip_relocation_disp_offset(),
                    line.get_op_length()
                    });
            }
        }
    }

    for (uint32_t rel_idx : code.rel_idx_cache) {
        auto &line = code.lines[rel_idx];

        uint8_t op_code[16];
        memcpy(op_code, line.get_op_code(), 16);

        if (line.get_relocation_f_imm_offset()) {
            if (line.get_relocation_f_label_id()) {
                if (code.arch == fuku_arch::fuku_arch_x32) {
                    *(uint32_t*)&op_code[line.get_relocation_f_imm_offset()] =
                        uint32_t(get_line_by_label_id(code, line.get_relocation_f_label_id())->get_virtual_address());
                }
                else {
                    *(uint64_t*)&op_code[line.get_relocation_f_imm_offset()] =
                        uint64_t(get_line_by_label_id(code, line.get_relocation_f_label_id())->get_virtual_address());
                }
            }
            else {
                if (code.arch == fuku_arch::fuku_arch_x32) {
                    *(uint32_t*)&op_code[line.get_relocation_f_imm_offset()] = uint32_t(line.get_relocation_f_destination());
                }
                else {
                    *(uint64_t*)&op_code[line.get_relocation_f_imm_offset()] = uint64_t(line.get_relocation_f_destination());
                }
            }
        }

        if (line.get_relocation_s_imm_offset()) {
            if (line.get_relocation_s_label_id()) {
                if (code.arch == fuku_arch::fuku_arch_x32) {
                    *(uint32_t*)&op_code[line.get_relocation_s_imm_offset()] =
                        uint32_t(get_line_by_label_id(code, line.get_relocation_s_label_id())->get_virtual_address());
                }
                else {
                    *(uint64_t*)&op_code[line.get_relocation_s_imm_offset()] =
                        uint64_t(get_line_by_label_id(code, line.get_relocation_s_label_id())->get_virtual_address());
                }
            }
            else {
                if (code.arch == fuku_arch::fuku_arch_x32) {
                    *(uint32_t*)&op_code[line.get_relocation_s_imm_offset()] = uint32_t(line.get_relocation_s_destination());
                }
                else {
                    *(uint64_t*)&op_code[line.get_relocation_s_imm_offset()] = uint64_t(line.get_relocation_s_destination());
                }
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