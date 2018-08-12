#pragma once

class fuku_virtualization {


public:
    virtual fuku_virtualization::~fuku_virtualization() {};

    virtual std::vector<fuku_vm_instruction> fuku_virtualization::build_pcode(linestorage& lines, uint64_t destination_virtual_address) {};
};

#include "fuku_virtualization_x86.h"
#include "fuku_virtualization_x64.h"