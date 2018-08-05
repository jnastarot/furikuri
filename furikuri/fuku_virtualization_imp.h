#pragma once

class fuku_virtualization {


public:
    virtual fuku_virtualization::~fuku_virtualization() {};

    virtual std::vector<fuku_vm_instruction> fuku_virtualization::build_pcode(std::vector<fuku_instruction>& lines) {};
};