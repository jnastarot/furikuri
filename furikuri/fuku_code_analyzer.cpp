#include "stdafx.h"
#include "fuku_code_analyzer.h"


fuku_code_analyzer::fuku_code_analyzer()
    :arch(fuku_arch::fuku_arch_x32), label_seed(1){}

fuku_code_analyzer::fuku_code_analyzer(const fuku_code_analyzer& analyze) {
    this->operator=(analyze);
}

fuku_code_analyzer::~fuku_code_analyzer(){}


fuku_code_analyzer& fuku_code_analyzer::operator=(const fuku_code_analyzer& analyze) {

    this->arch          = analyze.arch;
    this->label_seed        = analyze.label_seed;
    this->labels_cache      = analyze.labels_cache;
    this->jumps_idx_cache   = analyze.jumps_idx_cache;
    this->rel_idx_cache     = analyze.rel_idx_cache;
    this->ip_rel_idx_cache  = analyze.ip_rel_idx_cache;

    this->lines         = analyze.lines;
    

    return *this;
}

bool fuku_code_analyzer::analyze_code(
    const uint8_t * src, uint32_t src_len,
    uint64_t virtual_address,
    linestorage&  lines,
    const std::vector<fuku_code_relocation>*	relocations) {


    unsigned int current_len = 0;
    unsigned int line_counter = 0;

    _CodeInfo code_info = { 0,0, src ,(int)src_len ,
        arch == fuku_arch::fuku_arch_x32 ? _DecodeType::Decode32Bits : _DecodeType::Decode64Bits,
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
            fuku_instruction line;

            line.set_source_virtual_address(virtual_address + distorm_line.addr)
                .set_virtual_address(virtual_address + distorm_line.addr)
                .set_op_code(&src[distorm_line.addr], distorm_line.size)
                .set_type((_InstructionType)distorm_line.opcode)
                .set_modified_flags(distorm_line.modifiedFlagsMask)
                .set_tested_flags(distorm_line.testedFlagsMask);

            if (distorm_line.flags&FLAG_RIP_RELATIVE) {
                line.set_flags(line.get_flags() | fuku_instruction_has_ip_relocation)
                    .set_ip_relocation_destination(INSTRUCTION_GET_RIP_TARGET(&distorm_line) + virtual_address)
                    .set_ip_relocation_disp_offset(distorm_line.disp_offset - &src[distorm_line.addr]);
            }

            lines.push_back(line);
        }


        if (relocations) {
            for (auto reloc : *relocations) { //associate relocs

                fuku_instruction * line = this->get_range_line_by_source_va(lines, reloc.virtual_address);
                if (line) {
                    line->set_flags(line->get_flags() | fuku_instruction_has_relocation);

                    if (!line->get_relocation_f_imm_offset()) {
                        line->set_relocation_f_id(reloc.relocation_id);
                        line->set_relocation_f_imm_offset((uint8_t)(reloc.virtual_address - line->get_virtual_address()));

                        if (arch == fuku_arch::fuku_arch_x32) {
                            line->set_relocation_f_destination(*(uint32_t*)&line->get_op_code()[line->get_relocation_f_imm_offset()]);
                        }
                        else {
                            line->set_relocation_f_destination(*(uint64_t*)&line->get_op_code()[line->get_relocation_f_imm_offset()]);
                        }
                    }
                    else if (!line->get_relocation_s_imm_offset()) {
                        line->set_relocation_s_id(reloc.relocation_id);
                        line->set_relocation_s_imm_offset((uint8_t)(reloc.virtual_address - line->get_virtual_address()));

                        if (arch == fuku_arch::fuku_arch_x32) {
                            line->set_relocation_s_destination(*(uint32_t*)&line->get_op_code()[line->get_relocation_s_imm_offset()]);
                        }
                        else {
                            line->set_relocation_s_destination(*(uint64_t*)&line->get_op_code()[line->get_relocation_s_imm_offset()]);
                        }
                    }
                }
            }
        }


        for (auto &line : lines) {//jmp set labels

            if (line.get_flags() & fuku_instruction_has_ip_relocation) { //disp to local code

                fuku_instruction * dst_line = this->get_direct_line_by_source_va(lines, line.get_ip_relocation_destination());

                if (dst_line) {
                    line.set_link_label_id(set_label(*dst_line));
                }
            }
            else if (line.is_jump()) {

                uint64_t jmp_dst_va = line.get_virtual_address() +
                    line.get_op_length() +
                    line.get_jump_imm();

                fuku_instruction * dst_line = get_direct_line_by_source_va(lines, jmp_dst_va);

                if (dst_line) {
                    line.set_link_label_id(set_label(*dst_line));
                }
                else {
                    size_t prefixes_number = line.get_op_pref_size();

                    if (
                        (line.get_op_code()[prefixes_number] == 0x0f &&
                        (line.get_op_code()[prefixes_number + 1] & 0xf0) == 0x80)
                        ) { //far jcc
                        line.set_ip_relocation_disp_offset((uint8_t)prefixes_number + 2);
                    }
                    else if (
                        line.get_op_code()[prefixes_number] == 0xE9 ||
                        line.get_op_code()[prefixes_number] == 0xE8
                        ) {	   //jmp \ call
                        line.set_ip_relocation_disp_offset((uint8_t)prefixes_number + 1);
                    }

                    line.set_ip_relocation_destination(jmp_dst_va);
                }
            }
        }

        return true;
    }
    return false;
}



bool fuku_code_analyzer::merge_code(linestorage&  new_lines) {


    for (auto&jump_idx : jumps_idx_cache) {
        auto& jump_line = lines[jump_idx];

        if (!jump_line.get_link_label_id()) {
            uint64_t jmp_dst_va = jump_line.get_source_virtual_address() +
                jump_line.get_op_length() +
                jump_line.get_jump_imm();

            fuku_instruction * dst_line = get_direct_line_by_source_va(new_lines, jmp_dst_va);

            if (dst_line) {
                jump_line.set_link_label_id(set_label(*dst_line));
            }
        }
    }

    for (auto&rel_idx : rel_idx_cache) {
        auto& rel_line = lines[rel_idx];

        if (rel_line.get_relocation_f_imm_offset() && !rel_line.get_relocation_f_label_id()) {
            fuku_instruction * dst_line = get_direct_line_by_source_va(new_lines, rel_line.get_relocation_f_destination());

            if (dst_line) {
                rel_line.set_relocation_f_label_id(set_label(*dst_line));
            }
        }
        if (rel_line.get_relocation_s_imm_offset() && !rel_line.get_relocation_s_label_id()) {
            fuku_instruction * dst_line = get_direct_line_by_source_va(new_lines, rel_line.get_relocation_s_destination());

            if (dst_line) {
                rel_line.set_relocation_s_label_id(set_label(*dst_line));
            }
        }
    }

    for (auto&ip_rel_idx : ip_rel_idx_cache) {
        auto& ip_rel_line = lines[ip_rel_idx];

        if (!ip_rel_line.get_link_label_id()) {
            fuku_instruction * dst_line = get_direct_line_by_source_va(new_lines, ip_rel_line.get_ip_relocation_destination());

            if (dst_line) {
                ip_rel_line.set_link_label_id(set_label(*dst_line));
            }
        }
    }

    for (uint32_t new_line_idx = 0; new_line_idx < new_lines.size(); new_line_idx++) {//link new lines with stored lines
        auto& new_line = new_lines[new_line_idx];

        if (new_line.get_flags() & fuku_instruction_has_relocation) {
            rel_idx_cache.push_back(lines.size() + new_line_idx);

            if (new_line.get_relocation_f_imm_offset()) {
                fuku_instruction * dst_line = get_direct_line_by_source_va(lines, new_line.get_relocation_f_destination());

                if (dst_line) {
                    new_line.set_relocation_f_label_id(set_label(*dst_line));
                }
            }
            if (new_line.get_relocation_s_imm_offset()) {
                fuku_instruction * dst_line = get_direct_line_by_source_va(lines, new_line.get_relocation_s_destination());

                if (dst_line) {
                    new_line.set_relocation_s_label_id(set_label(*dst_line));
                }
            }

        }
        else if (!new_line.get_link_label_id()) {

            if (new_line.get_flags() & fuku_instruction_has_ip_relocation) {
                ip_rel_idx_cache.push_back(lines.size() + new_line_idx);

                fuku_instruction * dst_line = get_direct_line_by_source_va(lines, new_line.get_ip_relocation_destination());

                if (dst_line) {
                    new_line.set_link_label_id(set_label(*dst_line));
                }
            }
            else if (new_line.is_jump()) {
                jumps_idx_cache.push_back(lines.size() + new_line_idx);

                uint64_t jmp_dst_va = new_line.get_source_virtual_address() +
                    new_line.get_op_length() +
                    new_line.get_jump_imm();

                fuku_instruction * dst_line = get_direct_line_by_source_va(lines, jmp_dst_va);

                if (dst_line) {
                    new_line.set_link_label_id(set_label(*dst_line));
                }
            }
        }
    }


    lines.insert(lines.end(), new_lines.begin(), new_lines.end());

    return true;
}

bool fuku_code_analyzer::push_code(
    const uint8_t * src, uint32_t src_len,
    uint64_t virtual_address,
    const std::vector<fuku_code_relocation>*	relocations) {


    linestorage new_lines;

    if (analyze_code(src, src_len, virtual_address, new_lines, relocations)) {

        return merge_code(new_lines);
    }

    return false;
}

bool fuku_code_analyzer::push_code(const linestorage&  code_lines) {

    linestorage new_lines = code_lines;

    unsigned int new_label_seed = 0;
    

    for(auto& line : new_lines){ //fix old labels to new labels

        uint32_t label_id = line.get_label_id();
        uint32_t link_label_id = line.get_link_label_id();
        uint32_t rel_f_label_id = line.get_relocation_f_label_id();
        uint32_t rel_s_label_id = line.get_relocation_s_label_id();

        if (label_id) {
            if (new_label_seed < label_id) {
                new_label_seed = label_id;
            }

            line.set_label_id(label_id + this->label_seed - 1);
        }

        if (link_label_id) {
            line.set_link_label_id(link_label_id + this->label_seed - 1);
        }

        if (rel_f_label_id) {
            line.set_relocation_f_label_id(rel_f_label_id + this->label_seed - 1);
        }

        if (rel_s_label_id) {
            line.set_relocation_s_label_id(rel_s_label_id + this->label_seed - 1);
        }
    }

    this->label_seed += new_label_seed;

    return merge_code(new_lines);
}


uint32_t fuku_code_analyzer::set_label(fuku_instruction& line) {
    if (!line.get_label_id()) {
        line.set_label_id(this->label_seed);
        this->label_seed++;
    }
    return line.get_label_id();
}

fuku_instruction * fuku_code_analyzer::get_range_line_by_source_va(linestorage& lines, uint64_t virtual_address) {


    size_t left = 0;
    size_t right = lines.size();
    size_t mid = 0;

    while (left < right) {
        mid = left + (right - left) / 2;

        if (lines[mid].get_source_virtual_address() <= virtual_address &&
            lines[mid].get_source_virtual_address() + lines[mid].get_op_length() > virtual_address) {

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

fuku_instruction * fuku_code_analyzer::get_direct_line_by_source_va(linestorage& lines, uint64_t virtual_address) {

    size_t left = 0;
    size_t right = lines.size();
    size_t mid = 0;

    while (left < right) {
        mid = left + (right - left) / 2;

        if (lines[mid].get_source_virtual_address() == virtual_address) {
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

void fuku_code_analyzer::set_arch(fuku_arch arch) {
    this->arch = arch;
}

void fuku_code_analyzer::clear() {

    label_seed = 1;

    labels_cache.clear();
    jumps_idx_cache.clear();
    rel_idx_cache.clear();
    ip_rel_idx_cache.clear();
    lines.clear();
}

fuku_arch    fuku_code_analyzer::get_arch() const {
    return arch;
}

unsigned int fuku_code_analyzer::get_label_seed() const {
    return this->label_seed;
}

linestorage  fuku_code_analyzer::get_lines() const {
    return this->lines;
}