#pragma once

class fuku_virtualizer {


public:
    virtual fuku_virtualizer::~fuku_virtualizer() {};

    virtual std::vector<fuku_vm_instruction> fuku_virtualizer::build_pcode(linestorage& lines, uint64_t destination_virtual_address) {};
};

#include "fuku_virtualization_x86.h"
#include "fuku_virtualization_x64.h"