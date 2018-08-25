#include "stdafx.h"
#include "fuku_virtualization_x86.h"

//#include "..\vm_fuku_x86\vm_internal.h"

fuku_virtualization_x86::fuku_virtualization_x86() {}
fuku_virtualization_x86::~fuku_virtualization_x86(){}


fuku_vm_result fuku_virtualization_x86::build_bytecode(fuku_analyzed_code& code, std::vector<fuku_code_relocation>& relocation_table, uint64_t destination_virtual_address) {

    for (size_t line_idx = 0; line_idx < code.lines.size(); line_idx++) {





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

