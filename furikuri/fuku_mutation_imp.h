#pragma once

class fuku_mutation {
public:
    virtual fuku_mutation::~fuku_mutation() {};

    virtual void fuku_mutation::obfuscate(fuku_code_holder& code_holder) {};
    virtual void fuku_mutation::generate_junk(std::vector<uint8_t>& junk, size_t junk_size) {};
};


#include "fuku_mutation_x86.h"
#include "fuku_mutation_x64.h"

