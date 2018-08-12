#pragma once
class fuku_virtualization_x64 :
    public fuku_virtualization {

public:
    fuku_virtualization_x64();
    ~fuku_virtualization_x64();

    std::vector<fuku_vm_instruction> fuku_virtualization_x64::build_pcode(linestorage& lines, uint64_t destination_virtual_address);
};

