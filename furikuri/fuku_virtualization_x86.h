#pragma once
class fuku_virtualization_x86 :
    public fuku_virtualization {


public:
    fuku_virtualization_x86();
    ~fuku_virtualization_x86();

    std::vector<fuku_vm_instruction> fuku_virtualization_x86::build_pcode(linestorage& lines, uint64_t destination_virtual_address);
};

