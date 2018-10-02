#include "stdafx.h"
#include "fuku_code_analyzer.h"


fuku_code_analyzer::fuku_code_analyzer() {}

fuku_code_analyzer::fuku_code_analyzer(fuku_arch arch) {
    this->code.set_arch(arch);
}

fuku_code_analyzer::fuku_code_analyzer(const fuku_code_analyzer& code_analyzer) {
    this->operator=(code_analyzer);
}

fuku_code_analyzer::fuku_code_analyzer(const fuku_code_holder& code_holder) {
    this->operator=(code_holder);
}

fuku_code_analyzer::~fuku_code_analyzer(){}


fuku_code_analyzer& fuku_code_analyzer::operator=(const fuku_code_analyzer& code_analyzer) {

    this->code = code_analyzer.code;

    return *this;
}

fuku_code_analyzer& fuku_code_analyzer::operator=(const fuku_code_holder& code_holder) {

    this->code = code_holder;
    
    return *this;
}

bool fuku_code_analyzer::analyze_code(
    const uint8_t * src, size_t src_len,
    uint64_t virtual_address,
    const std::vector<fuku_image_relocation>* relocations,
    fuku_code_holder& analyzed_code) {

    analyzed_code.clear();

    if (code.get_arch() == fuku_arch::fuku_arch_unknown) {
    
        return false; 
    }


    csh handle;
    cs_insn *insn;
    size_t count;

    if (cs_open(CS_ARCH_X86, code.get_arch() == fuku_arch::fuku_arch_x32 ? CS_MODE_32 : CS_MODE_64, &handle) != CS_ERR_OK) {

        return false;
    }

    count = cs_disasm(handle, src, src_len, 0, 0, &insn);

    if (count) {

        for (size_t insn_idx = 0; insn_idx < count; insn_idx++) {
            fuku_instruction &line = analyzed_code.add_line();

            auto& current_insn = insn[insn_idx];
           
            line.set_source_virtual_address(virtual_address + current_insn.address)
                .set_virtual_address(virtual_address + current_insn.address)
                .set_op_code(&src[current_insn.address], current_insn.size)
                .set_eflags(current_insn.detail->x86.eflags)
                .set_id(current_insn.id);
            

            for (uint8_t op_idx = 0; op_idx < current_insn.detail->x86.op_count;op_idx++) {
                auto& operand = current_insn.detail->x86.operands[op_idx];

                if (operand.type == X86_OP_MEM) {

                    if (operand.mem.base == X86_REG_RIP) {

                        line.set_rip_relocation_idx(analyzed_code.create_rip_relocation(current_insn.detail->x86.encoding.disp_offset, X86_REL_ADDR(current_insn)));
                        break;
                    }
                }
            }

            switch (current_insn.id) {
                case  X86_INS_JO: case  X86_INS_JNO:
                case  X86_INS_JB: case  X86_INS_JAE:
                case  X86_INS_JE: case  X86_INS_JNE:
                case  X86_INS_JBE:case  X86_INS_JA:
                case  X86_INS_JS: case  X86_INS_JNS:
                case  X86_INS_JP: case  X86_INS_JNP:
                case  X86_INS_JL: case  X86_INS_JGE:
                case  X86_INS_JLE:case  X86_INS_JG: 
                case  X86_INS_JMP:
                case  X86_INS_JECXZ:case X86_INS_JCXZ: {

                    if (current_insn.detail->x86.operands[0].type == X86_OP_IMM) {
                        
                        line.set_rip_relocation_idx(analyzed_code.create_rip_relocation(current_insn.detail->x86.encoding.imm_offset, X86_REL_ADDR(current_insn)));              
                    }

                    break;
                }

                default:break;
            }

            analyzed_code.get_lines().push_back(line);
        }

        analyzed_code.update_origin_idxs();


        if (relocations) {

            for (auto reloc : *relocations) { //associate relocs

                fuku_instruction * line = analyzed_code.get_range_line_by_source_va(reloc.virtual_address);

                if (line) {
                    uint8_t  reloc_offset = (uint8_t)(reloc.virtual_address - line->get_virtual_address());
                    uint64_t reloc_dst = ((code.get_arch() == fuku_arch::fuku_arch_x32) ?
                        *(uint32_t*)&line->get_op_code()[reloc_offset] :
                        *(uint64_t*)&line->get_op_code()[reloc_offset]);


                    if (line->get_relocation_first_idx() == -1) {
                        line->set_relocation_first_idx(analyzed_code.create_relocation(reloc_offset, reloc_dst, reloc.relocation_id));
                    }
                    else {
                        line->set_relocation_second_idx(analyzed_code.create_relocation(reloc_offset, reloc_dst, reloc.relocation_id));
                    }

                }
                else {
                    FUKU_DEBUG;
                }
            }
        }



        merge_labels();

        


        cs_free(insn, count);

        cs_close(&handle);

        return true;
    }

    cs_close(&handle);

    return false;
}

bool fuku_code_analyzer::merge_labels() {

    struct label_item{
        size_t new_label_idx;
        fuku_code_label label;
    };

    std::vector<label_item> new_labels_chain;
    new_labels_chain.reserve(code.get_labels().size());
    
    for (size_t label_idx = 0; label_idx < code.get_labels().size(); label_idx++) { //associate labels

        auto& label = code.get_labels()[label_idx];
        
        if (label.has_linked_instruction) {
            new_labels_chain.push_back( { label_idx, label.has_linked_instruction, label.dst_address } );
        }
        else {

            fuku_instruction * line = code.get_direct_line_by_source_va(label.dst_address);

            if (line) {

                if (line->get_label_idx() != -1) {
                    new_labels_chain.push_back({ line->get_label_idx(), label.has_linked_instruction, label.dst_address });
                }
                else {
                    line->set_label_idx(code.create_label(line));

                    new_labels_chain.push_back({ line->get_label_idx(), label.has_linked_instruction, label.dst_address });
                }
            }
            else {

                new_labels_chain.push_back({ label_idx, label.has_linked_instruction, label.dst_address });
            }
        }
     }


    {
        std::vector<fuku_code_label> labels;
        std::vector<size_t> label_new_map;

        labels.reserve(new_labels_chain.size());
        label_new_map.resize(new_labels_chain.size());

        for (size_t label_idx = 0, idx_delta = 0; label_idx < new_labels_chain.size(); label_idx++) {

            auto& label = new_labels_chain[label_idx];
            
            if (label.new_label_idx == label_idx) {

            }
            else {

            }

            labels.push_back();
        }


        this->code.set_labels(labels);
    }



    /*
        auto& dst_labels = code.get_labels();

        std::vector<size_t> label_idxs_deleted;

        for (size_t label_idx = 0; label_idx < dst_labels.size(); label_idx++) {

            auto& label = dst_labels[label_idx];

            if (!label.has_linked_instruction) {

                fuku_instruction * line = this->code.get_direct_line_by_source_va(label.dst_address);

                if (line) {

                    if (line->get_label_idx() != -1) {
                        //delete labels and create new
                        label_idxs_deleted.push_back(label_idx);

                    }
                    else {
                        label.has_linked_instruction = 1;
                        label.instruction = line;
                    }
                }
            }
        }

    */

    return true;
}

bool fuku_code_analyzer::merge_code(const fuku_code_holder& code_holder) {

    if (!code_holder.get_lines().size()) { return true; }

    if (this->code.get_lines().size()) {

        linestorage& src_lines = this->code.get_lines();
        linestorage::iterator src_iter = src_lines.end()--;

        src_lines.insert(
            src_lines.end(),
            code_holder.get_lines().begin(), code_holder.get_lines().end()
        );

        src_iter++;

        size_t label_count = code.get_labels_count();
        size_t reloc_count = code.get_relocations().size();
        size_t rip_reloc_count = code.get_rip_relocations().size();


        if (code_holder.get_labels_count()) { 

            std::vector<fuku_instruction* > labels_cache;
            labels_cache.resize(code_holder.get_labels_count());

            for (; src_iter != src_lines.end(); src_iter++) { //fix new items label idxs

                if (src_iter->get_label_idx() != -1) {

                    labels_cache[src_iter->get_label_idx()] = ( &(*src_iter) );

                    if (label_count) {
                        src_iter->set_label_idx(label_count + src_iter->get_label_idx());
                    }
                }

                if (label_count) {

                    if (src_iter->get_link_label_idx() != -1) {
                        src_iter->set_link_label_idx(label_count + src_iter->get_link_label_idx());
                    }

                    if (src_iter->get_relocation_first_idx() != -1) {
                        src_iter->set_relocation_first_idx(reloc_count + src_iter->get_relocation_first_idx());
                    }

                    if (src_iter->get_relocation_second_idx() != -1) {
                        src_iter->set_relocation_second_idx(reloc_count + src_iter->get_relocation_second_idx());
                    }

                    if (src_iter->get_rip_relocation_idx() != -1) {
                        src_iter->set_rip_relocation_idx(rip_reloc_count + src_iter->get_rip_relocation_idx());
                    }
                }
            }

            if (label_count) { //fix new items label idxs

                auto& dst_relocs = code.get_relocations();
                auto& dst_rip_relocs = code.get_rip_relocations();

                auto& src_relocs = code_holder.get_relocations();
                auto& src_rip_relocs = code_holder.get_rip_relocations();

                if (src_relocs.size()) {
                    size_t current_idx = dst_relocs.size();
                    dst_relocs.insert(dst_relocs.end(), src_relocs.begin(), src_relocs.end());

                    for (; current_idx < dst_relocs.size(); current_idx++) {
                        dst_relocs[current_idx].label_idx += label_count;
                    }
                }

                if (src_rip_relocs.size()) {
                    size_t current_idx = dst_rip_relocs.size();

                    dst_rip_relocs.insert(dst_rip_relocs.end(), src_rip_relocs.begin(), src_rip_relocs.end());

                    for (; current_idx < dst_rip_relocs.size(); current_idx++) {
                        dst_rip_relocs[current_idx].label_idx += label_count;
                    }
                }
            }

            auto& dst_labels = code.get_labels();
            auto& src_labels = code_holder.get_labels();

            dst_labels.insert(dst_labels.end(), src_labels.begin(), src_labels.end());
            
            for (size_t label_idx = label_count; label_idx < dst_labels.size(); label_idx++) {

                if (dst_labels[label_idx].has_linked_instruction) {
                    dst_labels[label_idx].instruction = labels_cache[label_idx - label_count];
                }
            }
        }

        this->code.update_origin_idxs();
        

        merge_labels();

    }
    else {
        this->code = code_holder;
    }




    /*
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
    */


    return true;
}

bool fuku_code_analyzer::push_code(
    const uint8_t * src, uint32_t src_len,
    uint64_t virtual_address,
    const std::vector<fuku_image_relocation>*	relocations) {


    fuku_code_holder code_holder;

    if (analyze_code(src, src_len, virtual_address, relocations, code_holder)) {

        return merge_code(code_holder);
    }

    return false;
}

bool fuku_code_analyzer::push_code(const fuku_code_holder& code_holder) {

    if (code_holder.get_arch() != this->code.get_arch()) { return false; }

    return merge_code(code_holder);
}

bool fuku_code_analyzer::push_code(const fuku_code_analyzer&  code_analyzer) {

    if (code_analyzer.code.get_arch() != this->code.get_arch()) { return false; }

    return merge_code(code_analyzer.code);
}


void fuku_code_analyzer::set_arch(fuku_arch arch) {
    this->code.set_arch(arch);
}

void fuku_code_analyzer::clear() {
    return this->code.clear();
}

fuku_code_holder& fuku_code_analyzer::get_code() {
    return this->code;
}

const fuku_code_holder& fuku_code_analyzer::get_code() const {
    return this->code;
}