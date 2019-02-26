#include "stdafx.h"
#include "fuku_code_analyzer.h"


fuku_code_analyzer::fuku_code_analyzer() {}

fuku_code_analyzer::fuku_code_analyzer(fuku_assambler_arch arch) {
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


    csh handle;
    cs_insn *insn;
    size_t count;
    
    if (cs_open(CS_ARCH_X86, code.get_arch() == FUKU_ASSAMBLER_ARCH_X86 ? CS_MODE_32 : CS_MODE_64, &handle) != CS_ERR_OK) {

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
                .set_id(current_insn.id)
                .set_custom_flags(current_insn.detail->x86.encoding.disp_offset << 8 | current_insn.detail->x86.encoding.imm_offset);
            

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
            case  X86_INS_CALL:
         //       __debugbreak();
                case  X86_INS_JO: case  X86_INS_JNO:
                case  X86_INS_JB: case  X86_INS_JAE:
                case  X86_INS_JE: case  X86_INS_JNE:
                case  X86_INS_JBE:case  X86_INS_JA:
                case  X86_INS_JS: case  X86_INS_JNS:
                case  X86_INS_JP: case  X86_INS_JNP:
                case  X86_INS_JL: case  X86_INS_JGE:
                case  X86_INS_JLE:case  X86_INS_JG: 
                case  X86_INS_JMP:
                case  X86_INS_JECXZ:case X86_INS_JCXZ:
                case  X86_INS_LOOP: case X86_INS_LOOPE: case X86_INS_LOOPNE: {



                    if (current_insn.detail->x86.operands[0].type == X86_OP_IMM) {
                        
                        line.set_rip_relocation_idx(analyzed_code.create_rip_relocation(current_insn.detail->x86.encoding.imm_offset, 
                            virtual_address + (int32_t)(current_insn.detail->x86.operands[0].imm) ));
                        
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
                    uint64_t reloc_dst = ((code.get_arch() == FUKU_ASSAMBLER_ARCH_X86) ?
                        *(uint32_t*)&line->get_op_code()[reloc_offset] :
                        *(uint64_t*)&line->get_op_code()[reloc_offset]);


                    if (reloc_offset == (line->get_custom_flags() & 0xFF) ) {
                        line->set_relocation_imm_idx(analyzed_code.create_relocation(reloc_offset, reloc_dst, reloc.relocation_id));

                    } else if (reloc_offset == ((line->get_custom_flags() >> 8) & 0xFF) ) {
                        line->set_relocation_disp_idx(analyzed_code.create_relocation(reloc_offset, reloc_dst, reloc.relocation_id));
                    }
                    else {
                        FUKU_DEBUG;
                    }

                }
                else {
                    FUKU_DEBUG;
                }
            }
        }



        analyzed_code.merge_labels();

        cs_free(insn, count);
        cs_close(&handle);
        return true;
    }

    cs_close(&handle);

    return false;
}

bool fuku_code_analyzer::analyze_code(fuku_code_holder& code_holder,
    const uint8_t * src, size_t src_len,
    uint64_t virtual_address,
    const std::vector<fuku_image_relocation>*	relocations) {

    code_holder.set_arch(code.get_arch());

    return analyze_code(src, src_len, virtual_address, relocations, code_holder);
}

bool fuku_code_analyzer::push_code(const fuku_code_holder& code_holder) {

    if (code_holder.get_arch() != this->code.get_arch()) { return false; }

    return code.merge_code(code_holder);
}

bool fuku_code_analyzer::push_code(const fuku_code_analyzer&  code_analyzer) {

    if (code_analyzer.code.get_arch() != this->code.get_arch()) { return false; }

    return code.merge_code(code_analyzer.code);
}

bool fuku_code_analyzer::splice_code(fuku_code_holder& code_holder) {
    if (code_holder.get_arch() != this->code.get_arch()) { return false; }

    return code.splice_code(code_holder);
}

bool fuku_code_analyzer::splice_code(fuku_code_analyzer& code_analyzer) {
    if (code_analyzer.code.get_arch() != this->code.get_arch()) { return false; }

    return code.splice_code(code_analyzer.code);
}


void fuku_code_analyzer::set_arch(fuku_assambler_arch arch) {
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