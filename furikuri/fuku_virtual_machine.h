#pragma once


#include "fuku_virtualization_imp.h"

class fuku_virtual_machine{

    unsigned int label_seed;
    std::vector<uint32_t> labels_cache;
    std::vector<uint32_t> jumps_idx_cache;
    std::vector<uint32_t> rel_idx_cache;
    std::vector<uint32_t> ip_rel_idx_cache;

    std::vector<fuku_instruction>  lines;

public:
    fuku_virtual_machine();
    ~fuku_virtual_machine();
};

