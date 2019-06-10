#pragma once

enum fuku_vm_result {
    fuku_vm_ok,
    fuku_vm_unsetted,
    fuku_vm_bad_arch,

    fuku_vm_error
};

class fuku_virtualizer {

public:
    virtual ~fuku_virtualizer() {};

    virtual fuku_vm_result build_bytecode(shibari_module& target_module, fuku_code_holder& code_holder,
        std::vector<uint32_t>& external_calls_dst, std::vector<fuku_image_relocation>& relocation_table) = 0;

    virtual std::vector<uint8_t> create_vm_jumpout(uint64_t src_address, uint64_t dst_address, uint64_t vm_entry_address, std::vector<fuku_image_relocation>& relocation_table) const = 0;
    virtual std::vector<uint8_t> get_bytecode() const = 0;

    virtual fuku_assambler_arch get_target_arch() const { return fuku_assambler_arch::FUKU_ASSAMBLER_ARCH_X86; };
};