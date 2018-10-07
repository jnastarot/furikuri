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

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    count = cs_disasm(handle, src, src_len, 0, 0, &insn);

    if (count) {

        for (size_t insn_idx = 0; insn_idx < count; insn_idx++) {
            fuku_instruction &line = analyzed_code.add_line();

            auto& current_insn = insn[insn_idx];
           
            line.set_source_virtual_address(virtual_address + current_insn.address)
                .set_virtual_address(virtual_address + current_insn.address)
                .set_op_code(&src[current_insn.address], (uint8_t)current_insn.size)
                .set_eflags(current_insn.detail->x86.eflags)
                .set_id(current_insn.id);
            

            for (uint8_t op_idx = 0; op_idx < current_insn.detail->x86.op_count;op_idx++) {
                auto& operand = current_insn.detail->x86.operands[op_idx];

                if (operand.type == X86_OP_MEM) {

                    if (operand.mem.base == X86_REG_RIP) {

                        line.set_rip_relocation_idx(analyzed_code.create_rip_relocation(current_insn.detail->x86.encoding.disp_offset, 
                            virtual_address + X86_REL_ADDR(current_insn)));

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
                        
                        line.set_rip_relocation_idx(analyzed_code.create_rip_relocation(current_insn.detail->x86.encoding.imm_offset, 
                            virtual_address + X86_REL_ADDR(current_insn)));

                    }

                    break;
                }

                default:break;
            }

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
    new_labels_chain.resize(code.get_labels_count());
    
    for (size_t label_idx = 0; label_idx < code.get_labels().size(); label_idx++) { //associate labels

        auto& label = code.get_labels()[label_idx];
        
        if (label.has_linked_instruction) {
            new_labels_chain[label_idx] = { label_idx, label.has_linked_instruction, label.dst_address };
        }
        else {

            fuku_instruction * line = code.get_direct_line_by_source_va(label.dst_address);

            if (line) {

                if (line->get_label_idx() == -1) {
                    line->set_label_idx(label_idx);
                }
                
                new_labels_chain[label_idx] = { line->get_label_idx(), 1, (uint64_t)line };
            }
            else {

                new_labels_chain[label_idx] = { label_idx, label.has_linked_instruction, label.dst_address };
            }
        }
     }


    {
        std::vector<fuku_code_label> labels;
        std::vector<size_t> label_new_map;

        labels.reserve(new_labels_chain.size());
        label_new_map.resize(code.get_labels_count());

        for (size_t label_idx = 0; label_idx < new_labels_chain.size(); label_idx++) {

            auto& label_chain = new_labels_chain[label_idx];
            
            if (label_chain.new_label_idx == label_idx) {

                label_new_map[label_idx] = labels.size();
                labels.push_back( label_chain.label );
            }
        }


        for (size_t label_idx = 0; label_idx < new_labels_chain.size(); label_idx++) {

            auto& label_chain = new_labels_chain[label_idx];

            if (label_chain.new_label_idx != label_idx) {

                label_new_map[label_idx] = label_new_map[label_chain.new_label_idx];
            }
        }


        for (auto& line : code.get_lines()) {

            if (line.get_label_idx() != -1) {
                line.set_label_idx(label_new_map[line.get_label_idx()]);
            }
        }

        for (auto& reloc : code.get_relocations()) {
            reloc.label_idx = label_new_map[reloc.label_idx];
        }
        for (auto& rip_reloc : code.get_rip_relocations()) {
            rip_reloc.label_idx = label_new_map[rip_reloc.label_idx];
        }

        this->code.set_labels(labels);
    }

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

        code.update_origin_idxs();
        merge_labels();

    }
    else {
        code = code_holder;
        code.update_origin_idxs();
        merge_labels();
    }

    return true;
}

bool fuku_code_analyzer::push_code(
    const uint8_t * src, uint32_t src_len,
    uint64_t virtual_address,
    const std::vector<fuku_image_relocation>*	relocations) {


    fuku_code_holder code_holder;
    code_holder.set_arch(code.get_arch());

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