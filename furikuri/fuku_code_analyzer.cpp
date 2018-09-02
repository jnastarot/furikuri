#include "stdafx.h"
#include "fuku_code_analyzer.h"


fuku_analyzed_code::fuku_analyzed_code() {
    this->arch = fuku_arch::fuku_arch_unknown;
    this->label_seed = 1;
}
fuku_analyzed_code::fuku_analyzed_code(const fuku_code_analyzer& analyzer) {
    this->operator=(analyzer);
}

fuku_analyzed_code& fuku_analyzed_code::operator=(const fuku_analyzed_code& an_code) {
    this->arch              = an_code.arch;
    this->label_seed        = an_code.label_seed;
    this->labels_cache      = an_code.labels_cache;
    this->jumps_idx_cache   = an_code.jumps_idx_cache;
    this->rel_idx_cache     = an_code.rel_idx_cache;
    this->ip_rel_idx_cache  = an_code.ip_rel_idx_cache;
    this->lines             = an_code.lines;

    return *this;
}
fuku_analyzed_code& fuku_analyzed_code::operator=(const fuku_code_analyzer& analyzer) {
    this->arch              = analyzer.get_arch();
    this->label_seed        = analyzer.get_label_seed();
    this->labels_cache      = analyzer.get_labels_cache();
    this->jumps_idx_cache   = analyzer.get_jumps_idx_cache();
    this->rel_idx_cache     = analyzer.get_rel_idx_cache();
    this->ip_rel_idx_cache  = analyzer.get_ip_rel_idx_cache();
    this->lines             = analyzer.get_lines();

    return *this;
}

void fuku_analyzed_code::clear() {
    this->arch = fuku_arch::fuku_arch_unknown;
    this->label_seed = 1;
    this->labels_cache.clear();
    this->jumps_idx_cache.clear();
    this->rel_idx_cache.clear();
    this->ip_rel_idx_cache.clear();
    this->lines.clear();
}

fuku_code_analyzer::fuku_code_analyzer() {}

fuku_code_analyzer::fuku_code_analyzer(const fuku_code_analyzer& analyze) {
    this->operator=(analyze);
}

fuku_code_analyzer::~fuku_code_analyzer(){}


fuku_code_analyzer& fuku_code_analyzer::operator=(const fuku_code_analyzer& code) {

    this->code.arch          = code.code.arch;
    this->code.label_seed        = code.code.label_seed;
    this->code.labels_cache      = code.code.labels_cache;
    this->code.jumps_idx_cache   = code.code.jumps_idx_cache;
    this->code.rel_idx_cache     = code.code.rel_idx_cache;
    this->code.ip_rel_idx_cache  = code.code.ip_rel_idx_cache;

    this->code.lines         = code.code.lines;
    this->original_lines_idx = code.original_lines_idx;

    return *this;
}

fuku_code_analyzer& fuku_code_analyzer::operator=(const fuku_analyzed_code& code) {

    this->code = code;
    
    this->original_lines_idx.clear();

    for (size_t line_idx = 0; line_idx < code.lines.size(); line_idx++) {
        if (code.lines[line_idx].get_source_virtual_address() != -1) {
            original_lines_idx.push_back(line_idx);
        }
    }

    std::sort(original_lines_idx.begin(), original_lines_idx.end(), [&, this](const uint32_t l_idx, const uint32_t r_idx) {
        return this->code.lines[l_idx].get_source_virtual_address() < this->code.lines[r_idx].get_source_virtual_address();
    });

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
        code.arch == fuku_arch::fuku_arch_x32 ? _DecodeType::Decode32Bits : _DecodeType::Decode64Bits,
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

                        if (code.arch == fuku_arch::fuku_arch_x32) {
                            line->set_relocation_f_destination(*(uint32_t*)&line->get_op_code()[line->get_relocation_f_imm_offset()]);
                        }
                        else {
                            line->set_relocation_f_destination(*(uint64_t*)&line->get_op_code()[line->get_relocation_f_imm_offset()]);
                        }
                    }
                    else if (!line->get_relocation_s_imm_offset()) {
                        line->set_relocation_s_id(reloc.relocation_id);
                        line->set_relocation_s_imm_offset((uint8_t)(reloc.virtual_address - line->get_virtual_address()));

                        if (code.arch == fuku_arch::fuku_arch_x32) {
                            line->set_relocation_s_destination(*(uint32_t*)&line->get_op_code()[line->get_relocation_s_imm_offset()]);
                        }
                        else {
                            line->set_relocation_s_destination(*(uint64_t*)&line->get_op_code()[line->get_relocation_s_imm_offset()]);
                        }
                    }
                }
                else {
                    FUKU_DEBUG;
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



bool fuku_code_analyzer::merge_code(linestorage&  new_lines,const std::vector<size_t>* cached_new_lines_idxs) {

    std::vector<size_t> new_lines_idxs;

    if (cached_new_lines_idxs) {
        new_lines_idxs = *cached_new_lines_idxs;
    }
    else {
        for (size_t line_idx = 0; line_idx < new_lines.size(); line_idx++) {
            if (new_lines[line_idx].get_source_virtual_address() != -1) {
                new_lines_idxs.push_back(line_idx);
            }
        }
    }


    for (auto&jump_idx : code.jumps_idx_cache) {
        auto& jump_line = code.lines[jump_idx];

        if (!jump_line.get_link_label_id()) {
            uint64_t jmp_dst_va = jump_line.get_source_virtual_address() +
                jump_line.get_op_length() +
                jump_line.get_jump_imm();

            fuku_instruction * dst_line = get_direct_line_by_source_va_in_idx(new_lines, new_lines_idxs, jmp_dst_va);

            if (dst_line) {
                jump_line.set_link_label_id(set_label(*dst_line));
            }
        }
    }

    for (auto&rel_idx : code.rel_idx_cache) {
        auto& rel_line = code.lines[rel_idx];

        if (rel_line.get_relocation_f_imm_offset() && !rel_line.get_relocation_f_label_id()) {
            fuku_instruction * dst_line = get_direct_line_by_source_va_in_idx(new_lines, new_lines_idxs, rel_line.get_relocation_f_destination());

            if (dst_line) {
                rel_line.set_relocation_f_label_id(set_label(*dst_line));
            }
        }
        if (rel_line.get_relocation_s_imm_offset() && !rel_line.get_relocation_s_label_id()) {
            fuku_instruction * dst_line = get_direct_line_by_source_va_in_idx(new_lines, new_lines_idxs, rel_line.get_relocation_s_destination());

            if (dst_line) {
                rel_line.set_relocation_s_label_id(set_label(*dst_line));
            }
        }
    }

    for (auto&ip_rel_idx : code.ip_rel_idx_cache) {
        auto& ip_rel_line = code.lines[ip_rel_idx];

        if (!ip_rel_line.get_link_label_id()) {
            fuku_instruction * dst_line = get_direct_line_by_source_va_in_idx(new_lines, new_lines_idxs, ip_rel_line.get_ip_relocation_destination());

            if (dst_line) {
                ip_rel_line.set_link_label_id(set_label(*dst_line));
            }
        }
    }

    for (uint32_t new_line_idx = 0; new_line_idx < new_lines.size(); new_line_idx++) {//link new lines with stored lines
        auto& new_line = new_lines[new_line_idx];

        if (new_line.get_label_id()) {
            code.labels_cache.push_back(code.lines.size() + new_line_idx);
        }

        if (new_line.get_flags() & fuku_instruction_has_relocation) {
            code.rel_idx_cache.push_back(code.lines.size() + new_line_idx);

            if (new_line.get_relocation_f_imm_offset()) {
                fuku_instruction * dst_line = get_direct_line_by_source_va_in_idx(code.lines, original_lines_idx, new_line.get_relocation_f_destination());

                if (dst_line) {
                    new_line.set_relocation_f_label_id(set_label(*dst_line));
                }
            }
            if (new_line.get_relocation_s_imm_offset()) {
                fuku_instruction * dst_line = get_direct_line_by_source_va_in_idx(code.lines, original_lines_idx, new_line.get_relocation_s_destination());

                if (dst_line) {
                    new_line.set_relocation_s_label_id(set_label(*dst_line));
                }
            }

        }
        else if (!new_line.get_link_label_id()) {

            if (new_line.get_flags() & fuku_instruction_has_ip_relocation) {
                code.ip_rel_idx_cache.push_back(code.lines.size() + new_line_idx);

                fuku_instruction * dst_line = get_direct_line_by_source_va_in_idx(code.lines, original_lines_idx, new_line.get_ip_relocation_destination());

                if (dst_line) {
                    new_line.set_link_label_id(set_label(*dst_line));
                }
            }
            else if (new_line.is_jump()) {
                code.jumps_idx_cache.push_back(code.lines.size() + new_line_idx);

                uint64_t jmp_dst_va = new_line.get_source_virtual_address() +
                    new_line.get_op_length() +
                    new_line.get_jump_imm();

                fuku_instruction * dst_line = get_direct_line_by_source_va_in_idx(code.lines, original_lines_idx, jmp_dst_va);

                if (dst_line) {
                    new_line.set_link_label_id(set_label(*dst_line));
                }
            }
        }
    }

    size_t top_idx = code.lines.size();

    for (size_t line_idx = 0; line_idx < new_lines_idxs.size(); line_idx++) {
        new_lines_idxs[line_idx] += top_idx;
    }

    code.lines.insert(code.lines.end(), new_lines.begin(), new_lines.end());
    original_lines_idx.insert(original_lines_idx.end(), new_lines_idxs.begin(), new_lines_idxs.end());

    std::sort(original_lines_idx.begin(), original_lines_idx.end(), [&, this](const uint32_t l_idx, const uint32_t r_idx) {
        return this->code.lines[l_idx].get_source_virtual_address() < this->code.lines[r_idx].get_source_virtual_address();
    });
    
    return true;
}

bool fuku_code_analyzer::push_code(
    const uint8_t * src, uint32_t src_len,
    uint64_t virtual_address,
    const std::vector<fuku_code_relocation>*	relocations) {


    linestorage new_lines;

    if (analyze_code(src, src_len, virtual_address, new_lines, relocations)) {

        return merge_code(new_lines, 0);
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

            line.set_label_id(label_id + this->code.label_seed - 1);
        }

        if (link_label_id) {
            line.set_link_label_id(link_label_id + this->code.label_seed - 1);
        }

        if (rel_f_label_id) {
            line.set_relocation_f_label_id(rel_f_label_id + this->code.label_seed - 1);
        }

        if (rel_s_label_id) {
            line.set_relocation_s_label_id(rel_s_label_id + this->code.label_seed - 1);
        }
    }

    this->code.label_seed += new_label_seed;

    return merge_code(new_lines, 0);
}

bool fuku_code_analyzer::push_code(const fuku_code_analyzer&  code) {

    if (code.code.arch != this->code.arch) { return false; }

    linestorage new_lines = code.code.lines;
    
    unsigned int new_label_seed = 0;

    for (auto& line : new_lines) { //fix old labels to new labels

        uint32_t label_id = line.get_label_id();
        uint32_t link_label_id = line.get_link_label_id();
        uint32_t rel_f_label_id = line.get_relocation_f_label_id();
        uint32_t rel_s_label_id = line.get_relocation_s_label_id();

        if (label_id) {
            if (new_label_seed < label_id) {
                new_label_seed = label_id;
            }

            line.set_label_id(label_id + this->code.label_seed - 1);
        }

        if (link_label_id) {
            line.set_link_label_id(link_label_id + this->code.label_seed - 1);
        }

        if (rel_f_label_id) {
            line.set_relocation_f_label_id(rel_f_label_id + this->code.label_seed - 1);
        }

        if (rel_s_label_id) {
            line.set_relocation_s_label_id(rel_s_label_id + this->code.label_seed - 1);
        }
    }

    this->code.label_seed += new_label_seed;

    return merge_code(new_lines, &code.original_lines_idx);
}

uint32_t fuku_code_analyzer::set_label(fuku_instruction& line) {
    if (!line.get_label_id()) {
        line.set_label_id(this->code.label_seed);
        this->code.label_seed++;
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

fuku_instruction * fuku_code_analyzer::get_direct_line_by_source_va_in_idx(linestorage& lines, std::vector<size_t>& original_lines_idx, uint64_t virtual_address) {

    size_t left = 0;
    size_t right = original_lines_idx.size();
    size_t mid = 0;

    while (left < right) {
        mid = left + (right - left) / 2;

        if (lines[original_lines_idx[mid]].get_source_virtual_address() == virtual_address) {
            return &lines[original_lines_idx[mid]];
        }
        else if (lines[original_lines_idx[mid]].get_source_virtual_address() > virtual_address) {
            right = mid;
        }
        else {
            left = mid + 1;
        }
    }

    return 0;
}

void fuku_code_analyzer::set_arch(fuku_arch arch) {
    this->code.arch = arch;
}

void fuku_code_analyzer::clear() {

    code.label_seed = 1;

    code.labels_cache.clear();
    code.jumps_idx_cache.clear();
    code.rel_idx_cache.clear();
    code.ip_rel_idx_cache.clear();
    code.lines.clear();

    original_lines_idx.clear();
}

fuku_arch    fuku_code_analyzer::get_arch() const {
    return code.arch;
}

unsigned int fuku_code_analyzer::get_label_seed() const {
    return this->code.label_seed;
}

std::vector<uint32_t> fuku_code_analyzer::get_labels_cache() const {
    return this->code.labels_cache;
}
std::vector<uint32_t> fuku_code_analyzer::get_jumps_idx_cache() const {
    return this->code.jumps_idx_cache;
}
std::vector<uint32_t> fuku_code_analyzer::get_rel_idx_cache() const {
    return this->code.rel_idx_cache;
}
std::vector<uint32_t> fuku_code_analyzer::get_ip_rel_idx_cache() const {
    return this->code.ip_rel_idx_cache;
}

linestorage  fuku_code_analyzer::get_lines() const {
    return this->code.lines;
}

fuku_instruction * get_line_by_label_id(const fuku_analyzed_code& code, unsigned int label_id) {

    if (code.labels_cache.size()) {
        if (label_id > 0 && label_id <= code.labels_cache.size()) {
            return (fuku_instruction *)&code.lines[code.labels_cache[label_id - 1]];
        }
    }

    return 0;
}
