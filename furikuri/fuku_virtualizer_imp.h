#pragma once

enum fuku_vm_result {
    fuku_vm_ok,
    fuku_vm_unsetted,
    fuku_vm_bad_arch,

    fuku_vm_error
};

class fuku_virtualizer {

public:
    virtual fuku_virtualizer::~fuku_virtualizer() {};

    virtual fuku_vm_result fuku_virtualizer::build_bytecode(const fuku_code_holder& code_holder,
        std::vector<fuku_image_relocation>& relocation_table, std::vector<fuku_code_association>& association_table,
        uint64_t destination_virtual_address) = 0;

    virtual std::vector<uint8_t> fuku_virtualizer::create_vm_jumpout(uint64_t src_address, uint64_t dst_address, uint64_t vm_entry_address, std::vector<fuku_image_relocation>& relocation_table) const = 0;
    virtual std::vector<uint8_t> fuku_virtualizer::get_bytecode() const = 0;

    virtual fuku_assambler_arch fuku_virtualizer::get_target_arch() const { return fuku_assambler_arch::FUKU_ASSAMBLER_ARCH_X86; };
};

#include "fuku_virtualization_x86.h"
#include "fuku_virtualization_x64.h"