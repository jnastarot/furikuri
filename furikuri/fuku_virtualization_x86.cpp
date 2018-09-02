#include "stdafx.h"
#include "fuku_virtualization_x86.h"

#include "..\vm_fuku_x86\vm_internal.h"

fuku_virtualization_x86::fuku_virtualization_x86() {}
fuku_virtualization_x86::~fuku_virtualization_x86(){}


fuku_vm_result fuku_virtualization_x86::build_bytecode(fuku_analyzed_code& code, 
    std::vector<fuku_code_relocation>& relocation_table, std::vector<fuku_code_association>& association_table, 
    uint64_t destination_virtual_address) {

    _CodeInfo code_info = { 0, 0, 0, 0 ,
        code.arch == fuku_arch::fuku_arch_x32 ? _DecodeType::Decode32Bits : _DecodeType::Decode64Bits,
        0
    };

    _DInst current_inst[4];
    uint32_t used_inst;

    for (size_t line_idx = 0; line_idx < code.lines.size(); line_idx++) {
        auto& cur_line = code.lines[line_idx];

        uint8_t bbb[] = {
            0x8B, 0xC1,
            0x89, 0xC8,
            0x8B, 0xC8,
            0x89, 0xC1
        };

        code_info.code = bbb;// cur_line.get_op_code();
        code_info.codeLen = sizeof(bbb);// cur_line.get_op_length();
        code_info.codeOffset = cur_line.get_virtual_address();

        distorm_decompose64(&code_info, current_inst, 4, &used_inst);



        switch (cur_line.get_type()) {


        default: {

        }

        }
    }

    return fuku_vm_result::fuku_vm_error;
}

std::vector<uint8_t> fuku_virtualization_x86::create_vm_jumpout(uint64_t src_address, uint64_t dst_address) const {

    return std::vector<uint8_t>();
}

std::vector<uint8_t> fuku_virtualization_x86::get_bytecode() const {
    return std::vector<uint8_t>();
}

fuku_arch fuku_virtualization_x86::get_target_arch() const { 
    return fuku_arch::fuku_arch_x32;
}

