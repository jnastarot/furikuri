#pragma once


#include "fuku_virtualization_imp.h"

class fuku_virtual_machine{

    fuku_arch arch;

    unsigned int label_seed;
    std::vector<uint32_t> labels_cache;
    std::vector<uint32_t> jumps_idx_cache;
    std::vector<uint32_t> rel_idx_cache;
    std::vector<uint32_t> ip_rel_idx_cache;

    linestorage  lines;

    uint64_t destination_virtual_address;

    fuku_vm_settings settings;
public:
    fuku_virtual_machine::fuku_virtual_machine();
    fuku_virtual_machine::~fuku_virtual_machine();

public:
    void fuku_virtual_machine::set_code(const fuku_code_analyzer& code);
    void fuku_virtual_machine::set_destination_virtual_address(uint64_t destination_virtual_address);
    void fuku_virtual_machine::set_settings(const fuku_vm_settings& settings);

    void fuku_virtual_machine::set_association_table(std::vector<fuku_code_association>*	associations);

public:
    fuku_arch           fuku_virtual_machine::get_arch() const;
    const linestorage& fuku_virtual_machine::get_lines() const;
    uint64_t            fuku_virtual_machine::get_destination_virtual_address() const;
    fuku_vm_settings    fuku_virtual_machine::get_settings() const;

    std::vector<fuku_code_association>*    fuku_virtual_machine::get_association_table();
    std::vector<fuku_code_relocation>*     fuku_virtual_machine::get_relocation_table();

};

