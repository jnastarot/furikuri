#include "stdafx.h"
#include "obfurikuriator.h"


obfurikuriator::obfurikuriator(){
    this->arch = obfkt_arch::obfkt_arch_x32;

    this->destination_virtual_address = 0;

    this->complexity = 1;
    this->number_of_passes = 1;

    this->association_table = 0; 
    this->relocations       = 0;
    this->ip_relocations    = 0;
}


obfurikuriator::~obfurikuriator(){
}

void obfurikuriator::set_arch(obfkt_arch arch) {
    this->arch = arch;
}

void obfurikuriator::set_destination_virtual_address(uint64_t destination_virtual_address) {
    this->destination_virtual_address = destination_virtual_address;
}

void obfurikuriator::set_complexity(unsigned int complexity) {
    this->complexity = complexity;
}

void obfurikuriator::set_number_of_passes(unsigned int number_of_passes) {
    this->number_of_passes = number_of_passes;
}

void obfurikuriator::set_association_table(std::vector<obfkt_association>*	associations) {
    this->association_table = associations;
}

void obfurikuriator::set_relocation_table(std::vector<obfkt_relocation>* relocations) {
    this->relocations = relocations;
}

void obfurikuriator::set_ip_relocation_table(std::vector<obfkt_ip_relocations>* ip_relocations) {
    this->ip_relocations = ip_relocations;
}

obfkt_arch   obfurikuriator::get_arch() {
    return this->arch;
}

uint64_t     obfurikuriator::get_destination_virtual_address() {
    return this->destination_virtual_address;
}

unsigned int obfurikuriator::get_complexity() {
    return this->complexity;
}

unsigned int obfurikuriator::get_number_of_passes() {
    return this->number_of_passes;
}

std::vector<obfkt_association>*    obfurikuriator::get_association_table() {
    return this->association_table;
}

std::vector<obfkt_relocation>*     obfurikuriator::get_relocation_table() {
    return this->relocations;
}

std::vector<obfkt_ip_relocations>* obfurikuriator::get_ip_relocation_table() {
    return this->ip_relocations;
}


std::vector<uint8_t> obfurikuriator::obfuscate(std::vector<obfurikuristruction>& lines,unsigned int recurse_idx) {

    

    return lines_to_bin(lines);
}


bool obfurikuriator::analyze_code(
    uint8_t * src, uint32_t src_len,
    uint64_t virtual_address,
    std::vector<obfurikuristruction>&  lines,
    std::vector<obfkt_relocation>*	relocations) {

    unsigned int current_len = 0;
    unsigned int line_counter = 0;

    _CodeInfo code_info = { 0,0, src ,src_len ,
        arch == obfkt_arch::obfkt_arch_x32 ? _DecodeType::Decode32Bits : _DecodeType::Decode64Bits,
        0
    };

    std::vector<_DInst> distorm_instructions;
    unsigned int instructions_number = 0;
    distorm_instructions.resize(src_len);

    _DecodeResult di_result = distorm_decompose64(&code_info, distorm_instructions.data(), src_len, &instructions_number);

    if (di_result == _DecodeResult::DECRES_SUCCESS) {
        distorm_instructions.resize(instructions_number);
        lines.reserve(instructions_number);

        for (const auto &distorm_line : distorm_instructions) {
            obfurikuristruction line;

            line.set_source_virtual_address(virtual_address + distorm_line.addr);
            line.set_virtual_address(virtual_address + distorm_line.addr);
            line.set_op_code(&src[distorm_line.addr], distorm_line.size);
            line.set_type((_InstructionType)distorm_line.opcode);
            line.set_modified_flags(distorm_line.modifiedFlagsMask);
            line.set_tested_flags(distorm_line.testedFlagsMask);

            if (distorm_line.flags&FLAG_RIP_RELATIVE) {
                line.set_flags(line.get_flags() | obfkst_instruction_has_ip_relocation);
                line.set_ip_relocation_destination(INSTRUCTION_GET_RIP_TARGET(&distorm_line) + virtual_address);
                line.set_ip_relocation_disp_offset(distorm_line.disp_offset - &src[distorm_line.addr]);
            }

            lines.push_back(line);
        }


        if (relocations) {
            for (auto reloc : *relocations) { //associate relocs

                obfurikuristruction * line = this->get_line_by_source_va(lines, reloc.virtual_address);
                if (line) {
                    line->set_flags(line->get_flags() | obfkst_instruction_has_relocation);
                    line->set_relocation_id(reloc.relocation_id);
                    line->set_relocation_imm_offset((uint8_t)(reloc.virtual_address - line->get_virtual_address()));
                }
            }
        }


        for (auto &line : lines) {//jmp set labels

            if (line.get_flags()&obfkst_instruction_has_ip_relocation) { //disp to local code

                obfurikuristruction * dst_line = this->get_line_by_source_va(lines, line.get_ip_relocation_destination());

                if (dst_line) {
                    line.set_link_label_id(set_label(*dst_line));
                }
            }
            else {
                if (line.is_jump()) {
                    uint64_t rel_rva = line.get_virtual_address() +
                        line.get_op_length() +
                        line.get_jump_imm();

                    obfurikuristruction * dst_line = get_line_by_source_va(lines, rel_rva);

                    if (dst_line) {
                        line.set_link_label_id(set_label(*dst_line));
                    }
                    else {
                        unsigned int prefixes_number = line.get_op_pref_size();

                        if (
                            (line.get_op_code()[prefixes_number] == 0x0f &&
                            (line.get_op_code()[prefixes_number + 1] & 0xf0) == 0x80)
                            ) { //far jcc
                            line.set_ip_relocation_disp_offset(prefixes_number + 2);
                        }
                        else if (
                            line.get_op_code()[prefixes_number] == 0xE9 ||
                            line.get_op_code()[prefixes_number] == 0xE8
                            ) {	   //jmp \ call
                            line.set_ip_relocation_disp_offset(prefixes_number + 1);
                        }

                        line.set_flags(line.get_flags() | obfkst_instruction_has_ip_relocation);
                        line.set_ip_relocation_destination(rel_rva);
                    }
                }
            }
        }

        handle_jmps(lines);
        return true;
    }
    return false;
}

std::vector<uint8_t> obfurikuriator::obfuscate() {
    return obfuscate(this->lines, -1);
}

bool obfurikuriator::push_code(
    uint8_t * src, uint32_t src_len,
    uint64_t virtual_address,
    std::vector<obfkt_relocation>*	relocations) {

    std::vector<obfurikuristruction> new_lines;

    if (analyze_code(src, src_len, virtual_address, new_lines, relocations)) {


        for (auto& stored_line : lines) {  //link stored lines with new lines

            if (!stored_line.get_link_label_id()) {

                if (stored_line.is_jump()) {

                }
                else if (stored_line.get_flags()&obfkst_instruction_has_ip_relocation) {

                }
            }
        }

        for (auto& new_line : new_lines) {

            if (!new_line.get_link_label_id()) {

                if (new_line.is_jump()) {

                }
                else if (new_line.get_flags()&obfkst_instruction_has_ip_relocation) {

                }
            }
        }


        lines_correction(this->lines, this->destination_virtual_address);
    }

    return false;
}


void obfurikuriator::spagetti_code(std::vector<obfurikuristruction>& lines, uint64_t virtual_address) {

    lines_correction(lines, virtual_address);
    //todo
}

void obfurikuriator::lines_correction(std::vector<obfurikuristruction>& lines, uint64_t virtual_address) {
    uint64_t _virtual_address = virtual_address;
    this->labels_cache.clear();
    this->labels_cache.resize(label_seed - 1);

    for (auto &line : lines) {
        line.set_virtual_address(_virtual_address);
        _virtual_address += line.get_op_length();

        if (line.get_label_id()) { labels_cache[line.get_label_id() - 1] = &line; }
    }
}

obfurikuristruction * obfurikuriator::get_line_by_source_va(std::vector<obfurikuristruction>& lines, uint64_t virtual_address) {

    unsigned int left = 0;
    unsigned int right = lines.size();
    unsigned int mid = 0;

    while (left < right) {
        mid = left + (right - left) / 2;

        if (lines[mid].get_source_virtual_address() == virtual_address ) {

            return &lines[mid];
        }
        else if (lines[mid].get_source_virtual_address() > virtual_address) {
            right = mid;
        }
        else {
            left = mid + 1;
        }
    }

    return 0;
}

obfurikuristruction * obfurikuriator::get_line_by_va(std::vector<obfurikuristruction>& lines, uint64_t virtual_address) {

    unsigned int left = 0;
    unsigned int right = lines.size();
    unsigned int mid = 0;

    while (left < right) {
        mid = left + (right - left) / 2;

        if (lines[mid].get_virtual_address() == virtual_address) {
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

obfurikuristruction * obfurikuriator::get_line_by_label_id(unsigned int label_id) {

    if (label_id - 1 >= 0 && label_id - 1 < this->labels_cache.size()) {
        return this->labels_cache[label_id - 1];
    }

    return 0;
}

void obfurikuriator::handle_jmps(std::vector<obfurikuristruction>& lines) {

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
                    *(int32_t*)&op_code[2] = line.get_jump_imm();

                    line.set_op_code(op_code, 6);
                }
                else {
                    op_code[0] = 0xE9;
                    *(int32_t*)&op_code[1] = line.get_jump_imm();

                    line.set_op_code(op_code, 5);
                }

                break;
            }

                       //near jcc
            case 0x70:case 0x71:case 0x72:case 0x73:case 0x74:case 0x75:case 0x76:case 0x77:
            case 0x78:case 0x79:case 0x7A:case 0x7B:case 0x7C:case 0x7D:case 0x7E:case 0x7F: {


                if (prefixes_number) {
                    op_code[0] = line.get_op_code()[prefixes_number - 1];
                    op_code[1] = 0x0F;
                    op_code[2] = line.get_op_code()[prefixes_number] + 0x10;
                    *(int32_t*)&op_code[3] = line.get_jump_imm();

                    line.set_op_code(op_code, 7);
                }
                else {
                    op_code[0] = 0x0F;
                    op_code[1] = line.get_op_code()[prefixes_number] + 0x10;
                    *(int32_t*)&op_code[2] = line.get_jump_imm();

                    line.set_op_code(op_code, 6);
                }

                break;
            }

            //loopnz
            case 0xE0: {

                uint8_t new_line_opcode = 0x49;//dec ecx
                obfurikuristruction new_line;
                new_line.set_source_virtual_address(line.get_source_virtual_address());
                new_line.set_virtual_address(line.get_virtual_address());
                new_line.set_op_code(&new_line_opcode, 1);

                op_code[0] = 0x74;//loopnz to je
                op_code[1] = line.get_jump_imm();
                line.set_op_code(op_code, 2);
                line.set_source_virtual_address(line.get_source_virtual_address() + 1);
                line.set_virtual_address(line.get_virtual_address() + 1);

                lines.insert(lines.begin() + line_idx, line);
                break;
            }

            //loopz
            case 0xE1: {

                uint8_t new_line_opcode = 0x49;//dec ecx
                obfurikuristruction new_line;
                new_line.set_source_virtual_address(line.get_source_virtual_address());
                new_line.set_virtual_address(line.get_virtual_address());
                new_line.set_op_code(&new_line_opcode, 1);

                op_code[0] = 0x75;//loopz to jne
                op_code[1] = line.get_jump_imm();
                line.set_op_code(op_code, 2);
                line.set_source_virtual_address(line.get_source_virtual_address() + 1);
                line.set_virtual_address(line.get_virtual_address() + 1);

                lines.insert(lines.begin() + line_idx, line);

                break;
            }

            //loop
            case 0xE2: {

                uint8_t new_line_opcode = 0x49;//dec ecx
                obfurikuristruction new_line;
                new_line.set_source_virtual_address(line.get_source_virtual_address());
                new_line.set_virtual_address(line.get_virtual_address());
                new_line.set_op_code(&new_line_opcode, 1);

                op_code[0] = 0x75;//loop to jne
                op_code[1] = line.get_jump_imm();
                line.set_op_code(op_code, 2);
                line.set_source_virtual_address(line.get_source_virtual_address() + 1);
                line.set_virtual_address(line.get_virtual_address() + 1);

                lines.insert(lines.begin() + line_idx, line);

                break;
            }

            //jcxz
            case 0xE3: {
                
                uint8_t new_line_opcode[2];//or ecx,ecx
                obfurikuristruction new_line;
                new_line_opcode[0] = 0x09;
                new_line_opcode[1] = 0xC9;

                new_line.set_source_virtual_address(line.get_source_virtual_address());
                new_line.set_virtual_address(line.get_virtual_address());
                new_line.set_op_code(new_line_opcode, 2);

                op_code[0] = 0x74;//jcxz to jz
                op_code[1] = line.get_jump_imm();
                line.set_op_code(op_code, 2);

                line.set_source_virtual_address(line.get_source_virtual_address() + 1);
                line.set_virtual_address(line.get_virtual_address() + 1);

                lines.insert(lines.begin() + line_idx, line);

                break;
            }

            default: {break; }
            }
        }
    }
}

void obfurikuriator::finalize_jmps(std::vector<obfurikuristruction>& lines) {

    for (auto &line : lines) {

        if (!(line.get_flags()&obfkst_instruction_has_relocation)) {

            if (line.get_link_label_id()) {

                if (line.get_flags()&obfkst_instruction_has_ip_relocation) {

                    if (line.get_link_label_id()) {
                        uint8_t op_code[16];
                        memcpy(op_code, line.get_op_code(),16);

                        *(uint32_t*)&op_code[line.get_ip_relocation_disp_offset()] =
                            (line.get_ip_relocation_destination() - line.get_virtual_address() - line.get_op_length());
                    }
                }
                else {
                    obfurikuristruction * line_destination = get_line_by_label_id(line.get_link_label_id());

                    if (line_destination) {
                        line.set_jump_imm(line_destination->get_virtual_address());
                    }
                }
            }
        }
    }
}

std::vector<uint8_t>  obfurikuriator::lines_to_bin(std::vector<obfurikuristruction>&  lines) {

    std::vector<uint8_t> lines_dump;
    unsigned int dump_size = 0;

    for (size_t line_idx = 0; line_idx < lines.size(); line_idx++) { dump_size += lines[line_idx].get_op_length(); }
    lines_dump.resize(dump_size);

    unsigned int opcode_caret = 0;
    for (auto &line : lines) {
        memcpy(&lines_dump.data()[opcode_caret], line.get_op_code(), line.get_op_length());
        opcode_caret += line.get_op_length();
    }

    return lines_dump;
}

uint32_t obfurikuriator::set_label(obfurikuristruction& line) {
    if (!line.get_label_id()) {
        line.set_label_id(this->label_seed);
        this->label_seed++;
    }
    return line.get_label_id();
}

uint32_t obfurikuriator::get_maxlabel() {
    return this->label_seed;
}